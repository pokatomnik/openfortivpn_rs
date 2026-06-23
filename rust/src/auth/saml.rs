use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::error::{OpenfortivpnError, Result};
use crate::http::url_encode;
use crate::logger;

pub const MAX_SAML_SESSION_ID_LENGTH: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SamlRequestError {
    BadMethodOrPath,
    MissingIdTerminator,
    EmptyId,
    TooLong,
    InvalidCharacter,
}

pub fn authentication_url(config: &Config) -> String {
    let realm = config.realm.as_deref().unwrap_or_default();
    if realm.is_empty() {
        format!(
            "https://{}:{}/remote/saml/start?redirect=1",
            config.gateway_host, config.gateway_port
        )
    } else {
        format!(
            "https://{}:{}/remote/saml/start?redirect=1&realm={}",
            config.gateway_host,
            config.gateway_port,
            url_encode(realm)
        )
    }
}

pub fn parse_callback_request(request: &str) -> std::result::Result<String, SamlRequestError> {
    const REQUEST_HEAD: &str = "GET /?id=";

    let rest = request
        .strip_prefix(REQUEST_HEAD)
        .ok_or(SamlRequestError::BadMethodOrPath)?;

    let end = rest
        .find(|ch| matches!(ch, ' ' | '&' | '\r' | '\n'))
        .ok_or(SamlRequestError::MissingIdTerminator)?;
    let id = &rest[..end];

    if id.is_empty() {
        return Err(SamlRequestError::EmptyId);
    }
    if id.len() >= MAX_SAML_SESSION_ID_LENGTH {
        return Err(SamlRequestError::TooLong);
    }
    if !id.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '-') {
        return Err(SamlRequestError::InvalidCharacter);
    }

    Ok(id.to_owned())
}

pub fn wait_for_session_id(config: &Config) -> Result<String> {
    let port = config.saml_port.ok_or_else(|| {
        OpenfortivpnError::Auth("SAML callback port is not configured".to_owned())
    })?;
    let listener = TcpListener::bind(("127.0.0.1", port)).map_err(|err| {
        OpenfortivpnError::Network(format!(
            "failed to bind SAML callback server to port {port}: {err}"
        ))
    })?;
    listener.set_nonblocking(true)?;

    logger::info(&format!("Listening for SAML login on port {port}"));
    logger::info(&format!("Authenticate at '{}'", authentication_url(config)));

    wait_for_session_id_on_listener(&listener, 5, Duration::from_secs(10))
}

fn wait_for_session_id_on_listener(
    listener: &TcpListener,
    max_tries: usize,
    timeout_per_try: Duration,
) -> Result<String> {
    for _ in 0..max_tries {
        let deadline = Instant::now() + timeout_per_try;
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => match process_callback_stream(&mut stream) {
                    Ok(id) => return Ok(id),
                    Err(err) => {
                        logger::warn(&format!("failed to process SAML callback request: {err}"));
                        break;
                    }
                },
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        logger::warn("SAML callback wait timed out");
                        break;
                    }
                    thread::sleep(Duration::from_millis(100));
                }
                Err(err) => {
                    return Err(OpenfortivpnError::Network(format!(
                        "failed to accept SAML callback connection: {err}"
                    )));
                }
            }
        }
    }

    Err(OpenfortivpnError::Auth(
        "failed to retrieve SAML authentication token".to_owned(),
    ))
}

fn process_callback_stream(stream: &mut TcpStream) -> Result<String> {
    stream.set_nodelay(true)?;

    let mut request = [0_u8; 1024];
    let read = stream.read(&mut request[..1023])?;
    let request = String::from_utf8_lossy(&request[..read]);

    match parse_callback_request(&request) {
        Ok(id) => {
            send_status_response(stream, success_response_body())?;
            Ok(id)
        }
        Err(err) => {
            send_status_response(
                stream,
                "Invalid redirect response from Fortinet server. VPN could not be established.",
            )?;
            Err(OpenfortivpnError::Auth(format!(
                "invalid SAML callback request: {err:?}"
            )))
        }
    }
}

fn send_status_response(stream: &mut TcpStream, user_message: &str) -> std::io::Result<()> {
    let body = format!("<!DOCTYPE html>\r\n<html><body>\r\n{user_message}</body></html>\r\n");
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body.as_bytes())?;
    stream.flush()
}

pub fn success_response_body() -> &'static str {
    "SAML session id received from Fortinet server. VPN will be established...<br>\r\n\
     You may close this browser tab now.<br>\r\n\
     <script>\r\n\
     window.setTimeout(() => { window.close(); }, 5000);\r\n\
     document.write(\"<br>This window will close automatically in 5 seconds.\");\r\n\
     </script>\r\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_authentication_url() {
        let mut cfg = Config::default();
        cfg.gateway_host = "vpn.example.com".to_owned();
        cfg.gateway_port = 8443;
        assert_eq!(
            authentication_url(&cfg),
            "https://vpn.example.com:8443/remote/saml/start?redirect=1"
        );

        cfg.realm = Some("hello world".to_owned());
        assert_eq!(
            authentication_url(&cfg),
            "https://vpn.example.com:8443/remote/saml/start?redirect=1&realm=hello%20world"
        );
    }

    #[test]
    fn parses_valid_callback_request() {
        let request = "GET /?id=abc-123 HTTP/1.1\r\nHost: localhost\r\n\r\n";
        assert_eq!(parse_callback_request(request).unwrap(), "abc-123");
    }

    #[test]
    fn rejects_invalid_callback_request() {
        assert_eq!(
            parse_callback_request("POST /?id=abc HTTP/1.1\r\n").unwrap_err(),
            SamlRequestError::BadMethodOrPath
        );
        assert_eq!(
            parse_callback_request("GET /?id=a_b HTTP/1.1\r\n").unwrap_err(),
            SamlRequestError::InvalidCharacter
        );
    }

    #[test]
    fn receives_callback_over_loopback() {
        use std::net::TcpStream;

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();

        let client = thread::spawn(move || {
            let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
            stream
                .write_all(b"GET /?id=abc-123 HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
            assert!(response.contains("SAML session id received"));
        });

        let id = wait_for_session_id_on_listener(&listener, 1, Duration::from_secs(2)).unwrap();
        client.join().unwrap();
        assert_eq!(id, "abc-123");
    }
}
