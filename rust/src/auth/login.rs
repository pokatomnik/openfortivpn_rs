use std::io::{Read, Write};
use std::thread;
use std::time::Duration;

use crate::config::Config;
use crate::error::{OpenfortivpnError, Result};
use crate::http::{do_http_request, url_encode, HttpResponse};
use crate::user_input;

const FORM_CONTENT_TYPE: (&str, &str) = ("Content-Type", "application/x-www-form-urlencoded");

pub fn authenticate<S: Read + Write>(stream: &mut S, config: &Config) -> Result<String> {
    if let Some(cookie) = &config.cookie {
        return Ok(cookie.clone());
    }

    let host = http_host(config);
    let user_agent = ("User-Agent", config.user_agent.as_str());
    let mut response = if config.username.is_empty() && config.password.is_none() {
        do_http_request(stream, &host, "GET", "/remote/login", &[user_agent], b"")?
    } else {
        post_logincheck(stream, config, &host, &initial_login_body(config)?)?
    };

    validate_auth_response(&response)?;

    if response.status_code == 401 {
        delay_otp(config);
        response = try_otp_challenge(stream, config, &host, &response)?;
        validate_auth_response(&response)?;
    }
    ensure_status_ok(&response)?;

    if let Some(cookie) = response.svpn_cookie() {
        return Ok(cookie);
    }

    if let Some(tokeninfo) = get_value(response.body_as_str().unwrap_or_default(), "tokeninfo=") {
        let second_body = otp_login_body(
            config,
            response.body_as_str().unwrap_or_default(),
            &tokeninfo,
        )?;
        delay_otp(config);
        response = post_logincheck(stream, config, &host, &second_body)?;
        validate_auth_response(&response)?;
        ensure_status_ok(&response)?;

        if let Some(cookie) = response.svpn_cookie() {
            return Ok(cookie);
        }
    }

    Err(OpenfortivpnError::Auth(
        "gateway did not return SVPNCOOKIE".to_owned(),
    ))
}

pub fn authenticate_with_saml_session<S: Read + Write>(
    stream: &mut S,
    config: &Config,
    saml_session_id: &str,
) -> Result<String> {
    if !is_valid_saml_session_id(saml_session_id) {
        return Err(OpenfortivpnError::Auth(
            "invalid SAML session id".to_owned(),
        ));
    }

    let host = http_host(config);
    let path = format!("/remote/saml/auth_id?id={saml_session_id}");
    let response = do_http_request(
        stream,
        &host,
        "GET",
        &path,
        &[("User-Agent", config.user_agent.as_str())],
        b"",
    )?;
    ensure_status_ok(&response)?;

    response.svpn_cookie().ok_or_else(|| {
        OpenfortivpnError::Auth("SAML authentication did not return SVPNCOOKIE".to_owned())
    })
}

fn post_logincheck<S: Read + Write>(
    stream: &mut S,
    config: &Config,
    host: &str,
    body: &str,
) -> Result<HttpResponse> {
    post_form(stream, config, host, "/remote/logincheck", body)
}

fn post_form<S: Read + Write>(
    stream: &mut S,
    config: &Config,
    host: &str,
    path: &str,
    body: &str,
) -> Result<HttpResponse> {
    do_http_request(
        stream,
        host,
        "POST",
        path,
        &[
            FORM_CONTENT_TYPE,
            ("User-Agent", config.user_agent.as_str()),
        ],
        body.as_bytes(),
    )
}

fn initial_login_body(config: &Config) -> Result<String> {
    let username = url_encode(&config.username);
    let realm = url_encode(config.realm.as_deref().unwrap_or_default());

    if let Some(password) = &config.password {
        let mut body = format!(
            "username={}&credential={}&realm={}&ajax=1",
            username,
            url_encode(password),
            realm
        );
        append_hostcheck_fields(config, &mut body);
        Ok(body)
    } else {
        let mut body = format!(
            "username={username}&realm={realm}&ajax=1&redir=%2Fremote%2Findex&just_logged_in=1"
        );
        append_hostcheck_fields(config, &mut body);
        Ok(body)
    }
}

fn append_hostcheck_fields(config: &Config, body: &mut String) {
    if config.hostcheck.is_none() && config.check_virtual_desktop.is_none() {
        return;
    }

    body.push_str("&hostcheck=");
    body.push_str(&url_encode(config.hostcheck.as_deref().unwrap_or_default()));
    body.push_str("&check_virtual_desktop=");
    body.push_str(&url_encode(
        config.check_virtual_desktop.as_deref().unwrap_or_default(),
    ));
}

fn try_otp_challenge<S: Read + Write>(
    stream: &mut S,
    config: &Config,
    host: &str,
    response: &HttpResponse,
) -> Result<HttpResponse> {
    let body = response.body_as_str().ok_or_else(|| {
        OpenfortivpnError::Auth("OTP challenge response is not valid UTF-8".to_owned())
    })?;
    let (path, form_body, _prompt) = otp_challenge_form(config, body)?;
    post_form(stream, config, host, &path, &form_body)
}

fn otp_challenge_form(config: &Config, html: &str) -> Result<(String, String, String)> {
    let form_start = find_ascii_case_insensitive(html, "<form").ok_or_else(|| {
        OpenfortivpnError::Auth("OTP challenge response does not contain a form".to_owned())
    })?;
    let action_key_start = find_ascii_case_insensitive(&html[form_start..], "action=\"")
        .map(|index| form_start + index + "action=\"".len())
        .ok_or_else(|| {
            OpenfortivpnError::Auth("OTP challenge form does not contain an action".to_owned())
        })?;
    let action_end = html[action_key_start..].find('"').ok_or_else(|| {
        OpenfortivpnError::Auth("OTP challenge form action is unterminated".to_owned())
    })? + action_key_start;
    let path = html[action_key_start..action_end].to_owned();

    let prompt = otp_challenge_prompt(config, &html[action_end..]);
    let otp = otp_value_with_purpose(config, "otp", &prompt)?;
    let mut fields = Vec::new();
    let mut search_from = form_start;

    while let Some(input_rel) = find_ascii_case_insensitive(&html[search_from..], "<input") {
        let input_start = search_from + input_rel;
        let input_end = html[input_start..]
            .find('>')
            .map(|index| input_start + index)
            .unwrap_or(html.len());
        let input = &html[input_start..input_end];
        let input_type = html_attr(input, "type").unwrap_or_default();
        if input_type.eq_ignore_ascii_case("hidden") || input_type.eq_ignore_ascii_case("password")
        {
            let name = html_attr(input, "name").ok_or_else(|| {
                OpenfortivpnError::Auth("OTP challenge input is missing a name".to_owned())
            })?;
            let value = if input_type.eq_ignore_ascii_case("hidden") {
                html_attr(input, "value").ok_or_else(|| {
                    OpenfortivpnError::Auth(
                        "OTP challenge hidden input is missing a value".to_owned(),
                    )
                })?
            } else {
                otp.clone()
            };
            fields.push(format!("{}={}", url_encode(&name), url_encode(&value)));

            if input_type.eq_ignore_ascii_case("password") {
                if let Some(realm) = config.realm.as_deref().filter(|realm| !realm.is_empty()) {
                    fields.push(format!("realm={}", url_encode(realm)));
                }
            }
        }
        search_from = input_end.saturating_add(1);
    }

    if fields.is_empty() {
        return Err(OpenfortivpnError::Auth(
            "OTP challenge form does not contain hidden or password inputs".to_owned(),
        ));
    }

    Ok((path, fields.join("&"), prompt))
}

fn otp_challenge_prompt(config: &Config, html_after_action: &str) -> String {
    let marker = config.otp_prompt.as_deref().unwrap_or("Please");
    if let Some(start) = html_after_action.find(marker) {
        if let Some(end) = html_after_action[start..].find('<') {
            return html_after_action[start..start + end].to_owned();
        }
    }
    "Please enter one-time password: ".to_owned()
}

fn html_attr(tag: &str, name: &str) -> Option<String> {
    let needle = format!("{name}=\"");
    let start = find_ascii_case_insensitive(tag, &needle)? + needle.len();
    let end = tag[start..].find('"')? + start;
    Some(tag[start..end].to_owned())
}

fn find_ascii_case_insensitive(haystack: &str, needle: &str) -> Option<usize> {
    let needle = needle.as_bytes();
    haystack
        .as_bytes()
        .windows(needle.len())
        .position(|window| window.eq_ignore_ascii_case(needle))
}

fn otp_login_body(config: &Config, previous_body: &str, tokeninfo: &str) -> Result<String> {
    let username = url_encode(&config.username);
    let realm = url_encode(config.realm.as_deref().unwrap_or_default());
    let reqid = get_value(previous_body, "reqid=").unwrap_or_default();
    let polid = get_value(previous_body, "polid=").unwrap_or_default();
    let group = get_value(previous_body, "grp=").unwrap_or_default();
    let portal = get_value(previous_body, "portal=").unwrap_or_default();
    let magic = get_value(previous_body, "magic=").unwrap_or_default();
    let peer = get_value(previous_body, "peer=").unwrap_or_default();

    let tokenparams =
        if config.otp.is_none() && tokeninfo.starts_with("ftm_push") && !config.no_ftm_push {
            "ftmpush=1".to_owned()
        } else {
            let otp = otp_value_with_purpose(config, "2fa", "Two-factor authentication token: ")?;
            format!("code={}&code2=&magic={}", url_encode(&otp), magic)
        };

    Ok(format!(
        "username={username}&realm={realm}&reqid={reqid}&polid={polid}&grp={group}&portal={portal}&peer={peer}&{tokenparams}"
    ))
}

fn otp_value_with_purpose(config: &Config, purpose: &str, prompt: &str) -> Result<String> {
    if let Some(otp) = config.otp.as_deref().filter(|value| !value.is_empty()) {
        return Ok(otp.to_owned());
    }

    let hint = user_input::secret_hint(
        &config.username,
        config.realm.as_deref(),
        &config.gateway_host,
        purpose,
    );
    let otp = user_input::read_secret(config.pinentry.as_deref(), &hint, prompt)?;
    if otp.is_empty() {
        Err(OpenfortivpnError::Auth("No token specified".to_owned()))
    } else {
        Ok(otp)
    }
}

fn validate_auth_response(response: &HttpResponse) -> Result<()> {
    let body = response.body_as_str().unwrap_or_default();
    if let Some(ret) = get_value(body, "ret=") {
        match ret.parse::<u32>() {
            Ok(0) => return Err(OpenfortivpnError::PermissionDenied),
            Ok(1) => {}
            Ok(6) => {
                return Err(OpenfortivpnError::Auth(
                    "gateway replied with an unsupported authentication challenge".to_owned(),
                ))
            }
            Ok(other) => {
                return Err(OpenfortivpnError::Auth(format!(
                    "unknown authentication result: {other}"
                )))
            }
            Err(_) => {
                return Err(OpenfortivpnError::Auth(format!(
                    "invalid authentication result: {ret}"
                )))
            }
        }
    }
    Ok(())
}

fn ensure_status_ok(response: &HttpResponse) -> Result<()> {
    if response.status_code == 200 {
        Ok(())
    } else {
        Err(OpenfortivpnError::HttpProtocol(format!(
            "unexpected HTTP status: {} {}",
            response.status_code, response.reason
        )))
    }
}

fn get_value(body: &str, key: &str) -> Option<String> {
    let start = body.find(key)? + key.len();
    let rest = &body[start..];
    let end = rest
        .find(|ch| matches!(ch, '&' | '\r' | '\n' | '\0'))
        .unwrap_or(rest.len());
    Some(rest[..end].to_owned())
}

fn http_host(config: &Config) -> String {
    if config.gateway_port == 443 {
        config.gateway_host.clone()
    } else {
        format!("{}:{}", config.gateway_host, config.gateway_port)
    }
}

fn delay_otp(config: &Config) {
    if config.otp_delay > 0 {
        thread::sleep(Duration::from_secs(config.otp_delay.into()));
    }
}

fn is_valid_saml_session_id(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io::{Cursor, Read, Write};

    use super::*;

    #[test]
    fn builds_initial_password_login_body() {
        let cfg = Config {
            username: "u ser".to_owned(),
            password: Some("p+ss".to_owned()),
            realm: Some("r/m".to_owned()),
            ..Config::default()
        };

        assert_eq!(
            initial_login_body(&cfg).unwrap(),
            "username=u%20ser&credential=p%2Bss&realm=r%2Fm&ajax=1"
        );
    }

    #[test]
    fn extracts_value_until_separator() {
        assert_eq!(
            get_value("ret=1&tokeninfo=ftm_push\r\n", "tokeninfo=").as_deref(),
            Some("ftm_push")
        );
    }

    #[test]
    fn accepts_cookie_from_password_login() {
        let mut cfg = Config {
            gateway_host: "vpn.example".to_owned(),
            username: "user".to_owned(),
            password: Some("pass".to_owned()),
            ..Config::default()
        };
        cfg.gateway_port = 8443;
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nSet-Cookie: SVPNCOOKIE=abc; Path=/\r\n\r\nret=1".to_vec();
        let mut stream = MockStream::new(response);

        let cookie = authenticate(&mut stream, &cfg).unwrap();

        assert_eq!(cookie, "SVPNCOOKIE=abc");
        let written = String::from_utf8(stream.written).unwrap();
        assert!(written.contains("Host: vpn.example:8443\r\n"));
        assert!(written.contains("POST /remote/logincheck HTTP/1.1\r\n"));
        assert!(written.ends_with("username=user&credential=pass&realm=&ajax=1"));
    }

    #[test]
    fn sends_second_factor_code_when_tokeninfo_present() {
        let cfg = Config {
            gateway_host: "vpn.example".to_owned(),
            username: "user".to_owned(),
            password: Some("pass".to_owned()),
            otp: Some("123456".to_owned()),
            ..Config::default()
        };
        let first = b"HTTP/1.1 200 OK\r\nContent-Length: 57\r\n\r\nret=1&tokeninfo=sms&reqid=req&polid=pol&grp=grp&magic=mag";
        let second = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nSet-Cookie: SVPNCOOKIE=otp; Path=/\r\n\r\nret=1";
        let mut stream = MockStream::new_sequence(vec![first.to_vec(), second.to_vec()]);

        let cookie = authenticate(&mut stream, &cfg).unwrap();

        assert_eq!(cookie, "SVPNCOOKIE=otp");
        let written = String::from_utf8(stream.written).unwrap();
        assert!(written.contains("code=123456&code2=&magic=mag"));
    }

    #[test]
    fn builds_otp_challenge_form_from_html() {
        let cfg = Config {
            gateway_host: "vpn.example".to_owned(),
            username: "user".to_owned(),
            realm: Some("realm/name".to_owned()),
            otp: Some("12 34".to_owned()),
            ..Config::default()
        };
        let html = r#"<html><FORM METHOD="post" ACTION="/remote/otpcheck">
            Please enter token:<br>
            <INPUT TYPE="hidden" NAME="magic" VALUE="m+g">
            <INPUT TYPE="password" NAME="token">
            <INPUT TYPE="submit" NAME="submit" VALUE="OK">
        </FORM></html>"#;

        let (path, body, prompt) = otp_challenge_form(&cfg, html).unwrap();

        assert_eq!(path, "/remote/otpcheck");
        assert_eq!(prompt, "Please enter token:");
        assert_eq!(body, "magic=m%2Bg&token=12%2034&realm=realm%2Fname");
    }

    #[test]
    fn accepts_cookie_after_401_otp_challenge() {
        let cfg = Config {
            gateway_host: "vpn.example".to_owned(),
            username: "user".to_owned(),
            password: Some("pass".to_owned()),
            otp: Some("654321".to_owned()),
            ..Config::default()
        };
        let challenge_body = r#"<form action="/remote/otpcheck">
            Please enter OTP:<input type="hidden" name="magic" value="abc">
            <input type="password" name="credential">
        </form>"#;
        let first = http_response(401, "Authorization Required", &[], challenge_body);
        let second = http_response(
            200,
            "OK",
            &[("Set-Cookie", "SVPNCOOKIE=otp401; Path=/")],
            "ret=1",
        );
        let mut stream = MockStream::new_sequence(vec![first, second]);

        let cookie = authenticate(&mut stream, &cfg).unwrap();

        assert_eq!(cookie, "SVPNCOOKIE=otp401");
        let written = String::from_utf8(stream.written).unwrap();
        assert!(written.contains("POST /remote/logincheck HTTP/1.1\r\n"));
        assert!(written.contains("POST /remote/otpcheck HTTP/1.1\r\n"));
        assert!(written.ends_with("magic=abc&credential=654321"));
    }

    #[test]
    fn uses_provided_cookie_without_network_io() {
        let cfg = Config {
            cookie: Some("SVPNCOOKIE=already".to_owned()),
            ..Config::default()
        };
        let mut stream = MockStream::new(Vec::new());

        let cookie = authenticate(&mut stream, &cfg).unwrap();

        assert_eq!(cookie, "SVPNCOOKIE=already");
        assert!(stream.written.is_empty());
    }

    fn http_response(status: u16, reason: &str, headers: &[(&str, &str)], body: &str) -> Vec<u8> {
        let mut response = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\n",
            body.len()
        );
        for (name, value) in headers {
            response.push_str(name);
            response.push_str(": ");
            response.push_str(value);
            response.push_str("\r\n");
        }
        response.push_str("\r\n");
        response.push_str(body);
        response.into_bytes()
    }

    struct MockStream {
        reads: VecDeque<Cursor<Vec<u8>>>,
        written: Vec<u8>,
    }

    impl MockStream {
        fn new(read: Vec<u8>) -> Self {
            Self::new_sequence(vec![read])
        }

        fn new_sequence(reads: Vec<Vec<u8>>) -> Self {
            Self {
                reads: reads.into_iter().map(Cursor::new).collect(),
                written: Vec::new(),
            }
        }
    }

    impl Read for MockStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            loop {
                let Some(front) = self.reads.front_mut() else {
                    return Ok(0);
                };
                let read = front.read(buf)?;
                if read != 0 {
                    return Ok(read);
                }
                self.reads.pop_front();
            }
        }
    }

    impl Write for MockStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
}
