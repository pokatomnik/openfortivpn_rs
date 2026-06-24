use std::io::{Read, Write};

use crate::config::SHA256_DIGEST_HEX_LEN;
use crate::error::{OpenfortivpnError, Result};
use crate::logger;

pub const COOKIE_SIZE: usize = 4096;
const MAX_HEADER_SIZE: usize = 64 * 1024;
const READ_CHUNK_SIZE: usize = 4096;

const PERMISSION_DENIED_MARKERS: &[&[u8]] = &[
    b"<!--sslvpnerrmsgkey=sslvpn_login_permission_denied-->",
    b"permission_denied denied",
    b"Permission denied",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status_code: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub fn headers<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.headers
            .iter()
            .filter(move |(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub fn body_as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.body).ok()
    }

    pub fn svpn_cookie(&self) -> Option<String> {
        self.headers("Set-Cookie")
            .find_map(extract_svpn_cookie_from_header)
    }

    pub fn cookie_header(&self) -> Option<String> {
        let cookies: Vec<String> = self
            .headers("Set-Cookie")
            .filter_map(extract_cookie_pair_from_set_cookie_header)
            .collect();
        if cookies.is_empty() {
            None
        } else {
            Some(cookies.join("; "))
        }
    }

    pub fn set_cookie_names(&self) -> Vec<String> {
        self.headers("Set-Cookie")
            .filter_map(cookie_name_from_set_cookie_header)
            .collect()
    }

    pub fn header_names(&self) -> Vec<String> {
        self.headers.iter().map(|(name, _)| name.clone()).collect()
    }

    pub fn body_preview(&self, max_chars: usize) -> Option<String> {
        let body = self.body_as_str()?.trim();
        if body.is_empty() {
            return None;
        }
        let mut preview = String::new();
        for ch in body.chars().take(max_chars) {
            if ch.is_control() && ch != '\n' && ch != '\r' && ch != '\t' {
                preview.push(' ');
            } else {
                preview.push(ch);
            }
        }
        Some(preview.replace(['\r', '\n', '\t'], " "))
    }
}

pub fn do_http_request<S: Read + Write>(
    stream: &mut S,
    host: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Result<HttpResponse> {
    logger::debug(&format!("HTTP request: {method} {path}"));
    logger::debug(&format!(
        "HTTP request header preview: {}",
        request_header_preview(host, method, path, headers, body.len())
    ));
    if let Some(cookie) = header_value_in(headers, "Cookie") {
        let names = cookie_names_from_cookie_header(cookie);
        if !names.is_empty() {
            logger::debug(&format!("HTTP request cookies: {}", names.join(", ")));
        }
    }
    http_send(stream, host, method, path, headers, body)?;
    let response = http_receive(stream)?;
    logger::debug(&format!(
        "HTTP response: {method} {path} -> {} {}",
        response.status_code, response.reason
    ));
    let set_cookie_names = response.set_cookie_names();
    if !set_cookie_names.is_empty() {
        logger::debug(&format!(
            "HTTP response set-cookie names: {}",
            set_cookie_names.join(", ")
        ));
    }
    Ok(response)
}

pub fn http_send<W: Write>(
    writer: &mut W,
    host: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Result<()> {
    let user_agent = header_value_in(headers, "User-Agent").unwrap_or("openfortivpn-rs");
    let content_type =
        header_value_in(headers, "Content-Type").unwrap_or("application/x-www-form-urlencoded");
    let cookie = header_value_in(headers, "Cookie").unwrap_or("");

    write!(writer, "{method} {path} HTTP/1.1\r\n")?;
    write!(writer, "Host: {host}\r\n")?;
    write!(writer, "User-Agent: {user_agent}\r\n")?;
    writer.write_all(b"Accept: */*\r\n")?;
    writer.write_all(b"Accept-Encoding: identity\r\n")?;
    writer.write_all(b"Pragma: no-cache\r\n")?;
    writer.write_all(b"Cache-Control: no-store, no-cache, must-revalidate\r\n")?;
    writer.write_all(b"If-Modified-Since: Sat, 1 Jan 2000 00:00:00 GMT\r\n")?;
    write!(writer, "Content-Type: {content_type}\r\n")?;
    write!(writer, "Cookie: {cookie}\r\n")?;
    write!(writer, "Content-Length: {}\r\n", body.len())?;

    for (name, value) in headers {
        if is_managed_request_header(name) {
            continue;
        }
        write!(writer, "{name}: {value}\r\n")?;
    }

    writer.write_all(b"\r\n")?;
    writer.write_all(body)?;
    writer.flush()?;
    Ok(())
}

pub fn http_receive<R: Read>(reader: &mut R) -> Result<HttpResponse> {
    let mut buffer = Vec::new();
    let header_end = read_until_headers_complete(reader, &mut buffer)?;
    let (status_code, reason, headers) = parse_headers(&buffer[..header_end])?;
    let mut body = buffer[header_end..].to_vec();

    if let Some(content_length) = header_value(&headers, "Content-Length") {
        let expected = content_length
            .trim()
            .parse::<usize>()
            .map_err(|_| OpenfortivpnError::HttpProtocol("invalid Content-Length".to_owned()))?;
        while body.len() < expected {
            let mut chunk = [0u8; READ_CHUNK_SIZE];
            let read = reader.read(&mut chunk)?;
            if read == 0 {
                return Err(OpenfortivpnError::HttpProtocol(
                    "connection closed before full HTTP body was received".to_owned(),
                ));
            }
            body.extend_from_slice(&chunk[..read]);
        }
        body.truncate(expected);
    } else if header_value(&headers, "Transfer-Encoding")
        .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"))
    {
        while chunked_body_end(&body).is_none() {
            let mut chunk = [0u8; READ_CHUNK_SIZE];
            let read = reader.read(&mut chunk)?;
            if read == 0 {
                return Err(OpenfortivpnError::HttpProtocol(
                    "connection closed before chunked HTTP body ended".to_owned(),
                ));
            }
            body.extend_from_slice(&chunk[..read]);
        }
        if let Some(end) = chunked_body_end(&body) {
            body.truncate(end);
        }
    }

    if contains_permission_denied_marker(&body) {
        return Err(OpenfortivpnError::PermissionDenied);
    }

    Ok(HttpResponse {
        status_code,
        reason,
        headers,
        body,
    })
}

fn header_value_in<'a>(headers: &'a [(&str, &str)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| *value)
}

fn request_header_preview(
    host: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body_len: usize,
) -> String {
    let user_agent = header_value_in(headers, "User-Agent").unwrap_or("openfortivpn-rs");
    let content_type =
        header_value_in(headers, "Content-Type").unwrap_or("application/x-www-form-urlencoded");
    let cookie_names = header_value_in(headers, "Cookie")
        .map(cookie_names_from_cookie_header)
        .unwrap_or_default();
    let cookie_preview = if cookie_names.is_empty() {
        "<empty>".to_owned()
    } else {
        cookie_names
            .into_iter()
            .map(|name| format!("{name}=<redacted>"))
            .collect::<Vec<_>>()
            .join("; ")
    };

    [
        format!("{method} {path} HTTP/1.1"),
        format!("Host: {host}"),
        format!("User-Agent: {user_agent}"),
        "Accept: */*".to_owned(),
        "Accept-Encoding: identity".to_owned(),
        "Pragma: no-cache".to_owned(),
        "Cache-Control: no-store, no-cache, must-revalidate".to_owned(),
        "If-Modified-Since: Sat, 1 Jan 2000 00:00:00 GMT".to_owned(),
        format!("Content-Type: {content_type}"),
        format!("Cookie: {cookie_preview}"),
        format!("Content-Length: {body_len}"),
    ]
    .join(" | ")
}

fn is_managed_request_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "user-agent" | "content-type" | "cookie" | "content-length"
    )
}

pub fn url_encode(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len());

    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char)
            }
            _ => {
                const HEX: &[u8; 16] = b"0123456789ABCDEF";
                encoded.push('%');
                encoded.push(HEX[(byte >> 4) as usize] as char);
                encoded.push(HEX[(byte & 0x0f) as usize] as char);
            }
        }
    }

    encoded
}

pub fn find_header<'a>(response: &'a str, header: &str) -> Option<&'a str> {
    let headers = response.split("\r\n\r\n").next().unwrap_or(response);
    headers.lines().find_map(|line| {
        if line.len() >= header.len() && line[..header.len()].eq_ignore_ascii_case(header) {
            Some(&line[header.len()..])
        } else {
            None
        }
    })
}

pub fn extract_svpn_cookie_from_header(line: &str) -> Option<String> {
    let start = line.find("SVPNCOOKIE=")?;
    let cookie_start = &line[start..];
    let end = cookie_start
        .find(|ch| matches!(ch, '\r' | '\n' | ';'))
        .unwrap_or(cookie_start.len());
    valid_cookie_pair(&cookie_start[..end])
}

pub fn extract_cookie_pair_from_set_cookie_header(line: &str) -> Option<String> {
    let cookie = line
        .split_once(';')
        .map(|(cookie, _)| cookie)
        .unwrap_or(line)
        .trim();
    valid_cookie_pair(cookie)
}

fn cookie_name_from_set_cookie_header(line: &str) -> Option<String> {
    let cookie = line
        .split_once(';')
        .map(|(cookie, _)| cookie)
        .unwrap_or(line)
        .trim();
    let (name, value) = cookie.split_once('=')?;
    if name.is_empty() || value.is_empty() {
        None
    } else {
        Some(name.to_owned())
    }
}

fn cookie_names_from_cookie_header(header: &str) -> Vec<String> {
    header
        .split(';')
        .filter_map(|cookie| {
            let (name, value) = cookie.trim().split_once('=')?;
            if name.is_empty() || value.is_empty() {
                None
            } else {
                Some(name.to_owned())
            }
        })
        .collect()
}

fn valid_cookie_pair(cookie: &str) -> Option<String> {
    let Some((name, value)) = cookie.split_once('=') else {
        return None;
    };
    if cookie.len() > COOKIE_SIZE || name.is_empty() || value.is_empty() {
        None
    } else {
        Some(cookie.to_owned())
    }
}

pub fn extract_svpn_cookie(response: &str) -> Option<String> {
    let headers = response.split("\r\n\r\n").next().unwrap_or(response);
    headers.lines().find_map(|line| {
        let value = if line.len() >= "Set-Cookie: ".len()
            && line[.."Set-Cookie: ".len()].eq_ignore_ascii_case("Set-Cookie: ")
        {
            &line["Set-Cookie: ".len()..]
        } else {
            return None;
        };
        extract_svpn_cookie_from_header(value)
    })
}

pub fn is_sha256_hex_digest(value: &str) -> bool {
    value.len() == SHA256_DIGEST_HEX_LEN && value.chars().all(|c| c.is_ascii_hexdigit())
}

fn read_until_headers_complete<R: Read>(reader: &mut R, buffer: &mut Vec<u8>) -> Result<usize> {
    loop {
        if let Some(header_end) = find_bytes(buffer, b"\r\n\r\n") {
            return Ok(header_end + 4);
        }
        if buffer.len() > MAX_HEADER_SIZE {
            return Err(OpenfortivpnError::HttpProtocol(
                "HTTP headers exceed maximum size".to_owned(),
            ));
        }

        let mut chunk = [0u8; READ_CHUNK_SIZE];
        let read = reader.read(&mut chunk)?;
        if read == 0 {
            return Err(OpenfortivpnError::HttpProtocol(
                "connection closed before HTTP headers were complete".to_owned(),
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
}

fn parse_headers(raw_headers: &[u8]) -> Result<(u16, String, Vec<(String, String)>)> {
    let text = std::str::from_utf8(raw_headers)
        .map_err(|_| OpenfortivpnError::HttpProtocol("headers are not valid UTF-8".to_owned()))?;
    let mut lines = text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| OpenfortivpnError::HttpProtocol("missing status line".to_owned()))?;
    let mut status_parts = status_line.splitn(3, ' ');
    let version = status_parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/") {
        return Err(OpenfortivpnError::HttpProtocol(
            "status line does not start with HTTP/".to_owned(),
        ));
    }
    let status_code = status_parts
        .next()
        .ok_or_else(|| OpenfortivpnError::HttpProtocol("missing status code".to_owned()))?
        .parse::<u16>()
        .map_err(|_| OpenfortivpnError::HttpProtocol("invalid status code".to_owned()))?;
    let reason = status_parts.next().unwrap_or_default().to_owned();

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(OpenfortivpnError::HttpProtocol(format!(
                "malformed HTTP header: {line}"
            )));
        };
        headers.push((name.trim().to_owned(), value.trim().to_owned()));
    }

    Ok((status_code, reason, headers))
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn chunked_body_end(body: &[u8]) -> Option<usize> {
    let marker = find_bytes(body, b"\r\n0\r\n")?;
    let end = marker + b"\r\n0\r\n".len();
    if body.get(end..end + 2) == Some(b"\r\n") {
        Some(end + 2)
    } else {
        Some(end)
    }
}

fn contains_permission_denied_marker(body: &[u8]) -> bool {
    PERMISSION_DENIED_MARKERS
        .iter()
        .any(|marker| body.windows(marker.len()).any(|window| window == *marker))
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read, Write};

    use super::*;

    #[test]
    fn url_encode_matches_c_rules() {
        assert_eq!(url_encode("abcXYZ09-_.~"), "abcXYZ09-_.~");
        assert_eq!(url_encode("a b+c/ä"), "a%20b%2Bc%2F%C3%A4");
        assert_eq!(url_encode("\u{0}"), "%00");
    }

    #[test]
    fn extracts_cookie_from_set_cookie_header() {
        let response = "HTTP/1.1 200 OK\r\nSet-Cookie: other=1; Path=/\r\nSet-Cookie: SVPNCOOKIE=abc123; Path=/; Secure\r\n\r\n";
        assert_eq!(
            extract_svpn_cookie(response).as_deref(),
            Some("SVPNCOOKIE=abc123")
        );
    }

    #[test]
    fn builds_cookie_header_from_all_set_cookie_headers() {
        let response = HttpResponse {
            status_code: 200,
            reason: "OK".to_owned(),
            headers: vec![
                ("Set-Cookie".to_owned(), "APSCOOKIE=xyz; Path=/".to_owned()),
                (
                    "Set-Cookie".to_owned(),
                    "SVPNCOOKIE=abc; Path=/; Secure".to_owned(),
                ),
            ],
            body: Vec::new(),
        };

        assert_eq!(
            response.cookie_header().as_deref(),
            Some("APSCOOKIE=xyz; SVPNCOOKIE=abc")
        );
    }

    #[test]
    fn rejects_empty_cookie() {
        assert_eq!(extract_svpn_cookie_from_header("SVPNCOOKIE=; Path=/"), None);
    }

    #[test]
    fn extracts_cookie_names_without_values_for_debug() {
        assert_eq!(
            cookie_names_from_cookie_header("APSCOOKIE=secret; SVPNCOOKIE=very-secret"),
            ["APSCOOKIE", "SVPNCOOKIE"]
        );
        assert_eq!(
            cookie_name_from_set_cookie_header("SVPNCOOKIE=very-secret; Path=/").as_deref(),
            Some("SVPNCOOKIE")
        );
    }

    #[test]
    fn accepts_cookie_value_with_base64_padding() {
        assert_eq!(
            extract_svpn_cookie_from_header("SVPNCOOKIE=abc==; Path=/").as_deref(),
            Some("SVPNCOOKIE=abc==")
        );
    }

    #[test]
    fn receives_response_with_content_length() {
        let mut input = Cursor::new(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nSet-Cookie: SVPNCOOKIE=abc; Path=/\r\n\r\nhelloextra".to_vec());
        let response = http_receive(&mut input).unwrap();

        assert_eq!(response.status_code, 200);
        assert_eq!(response.body, b"hello");
        assert_eq!(response.svpn_cookie().as_deref(), Some("SVPNCOOKIE=abc"));
    }

    #[test]
    fn receives_chunked_response_until_terminator() {
        let mut input = Cursor::new(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\ntrailing"
                .to_vec(),
        );
        let response = http_receive(&mut input).unwrap();

        assert!(response.body.ends_with(b"\r\n0\r\n\r\n"));
    }

    #[test]
    fn detects_permission_denied_marker() {
        let mut input =
            Cursor::new(b"HTTP/1.1 200 OK\r\nContent-Length: 17\r\n\r\nPermission denied".to_vec());

        assert!(matches!(
            http_receive(&mut input),
            Err(OpenfortivpnError::PermissionDenied)
        ));
    }

    #[test]
    fn builds_request_header_preview_without_cookie_values() {
        let preview = request_header_preview(
            "vpn.example:54443",
            "GET",
            "/remote/index",
            &[("Cookie", "SVPNCOOKIE=secret")],
            0,
        );

        assert!(preview.contains("GET /remote/index HTTP/1.1"));
        assert!(preview.contains("Host: vpn.example:54443"));
        assert!(preview.contains("Cookie: SVPNCOOKIE=<redacted>"));
        assert!(!preview.contains("secret"));
    }

    #[test]
    fn builds_sanitized_body_preview() {
        let response = HttpResponse {
            status_code: 403,
            reason: "Forbidden".to_owned(),
            headers: vec![("Content-Type".to_owned(), "text/html".to_owned())],
            body: b"<html>\nPermission denied\t</html>".to_vec(),
        };

        assert_eq!(
            response.body_preview(512).as_deref(),
            Some("<html> Permission denied </html>")
        );
        assert_eq!(response.header_names(), ["Content-Type"]);
    }

    #[test]
    fn sends_get_request_like_original_c_template() {
        let mut out = Vec::new();

        http_send(
            &mut out,
            "vpn.example:54443",
            "GET",
            "/remote/index",
            &[("Cookie", "SVPNCOOKIE=abc")],
            b"",
        )
        .unwrap();

        let written = String::from_utf8(out).unwrap();
        assert!(written.starts_with("GET /remote/index HTTP/1.1\r\n"));
        assert!(written.contains("Host: vpn.example:54443\r\n"));
        assert!(written.contains("Accept-Encoding: identity\r\n"));
        assert!(written.contains("Pragma: no-cache\r\n"));
        assert!(written.contains("Cache-Control: no-store, no-cache, must-revalidate\r\n"));
        assert!(written.contains("If-Modified-Since: Sat, 1 Jan 2000 00:00:00 GMT\r\n"));
        assert!(written.contains("Content-Type: application/x-www-form-urlencoded\r\n"));
        assert!(written.contains("Cookie: SVPNCOOKIE=abc\r\n"));
        assert!(written.contains("Content-Length: 0\r\n"));
        assert!(!written.contains("Connection: keep-alive\r\n"));
    }

    #[test]
    fn sends_http_request() {
        let mut stream =
            MockStream::new(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_vec());
        let response = do_http_request(
            &mut stream,
            "vpn.example",
            "POST",
            "/remote/logincheck",
            &[("Content-Type", "application/x-www-form-urlencoded")],
            b"username=a",
        )
        .unwrap();

        assert_eq!(response.status_code, 204);
        let written = String::from_utf8(stream.written).unwrap();
        assert!(written.starts_with("POST /remote/logincheck HTTP/1.1\r\n"));
        assert!(written.contains("Host: vpn.example\r\n"));
        assert!(written.contains("Content-Length: 10\r\n"));
        assert!(written.ends_with("\r\n\r\nusername=a"));
    }

    struct MockStream {
        read: Cursor<Vec<u8>>,
        written: Vec<u8>,
    }

    impl MockStream {
        fn new(read: Vec<u8>) -> Self {
            Self {
                read: Cursor::new(read),
                written: Vec::new(),
            }
        }
    }

    impl Read for MockStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.read.read(buf)
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
