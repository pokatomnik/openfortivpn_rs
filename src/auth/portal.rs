use std::io::{Read, Write};

use crate::config::Config;
use crate::error::{OpenfortivpnError, Result};
use crate::http::{do_http_request, HttpResponse};
use crate::logger;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnConfigXml {
    pub raw_xml: String,
    /// Address advertised by Fortinet in `<assigned-addr ipv4="...">`.
    /// The original C code uses this as the peer/gateway address for split routes.
    pub gateway: Option<String>,
    /// Backward-compatible field for early text-node parsing experiments.
    pub assigned_ip: Option<String>,
    pub dns_servers: Vec<String>,
    pub dns_suffix: Option<String>,
    pub split_routes: Vec<Ipv4Route>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Route {
    pub destination: String,
    pub mask: String,
    pub gateway: Option<String>,
}

pub fn request_vpn_allocation<S: Read + Write>(
    stream: &mut S,
    config: &Config,
    cookie: &str,
    portal_redirect: Option<&str>,
) -> Result<()> {
    let host = http_host(config);
    let cookie_header = [
        ("Cookie", cookie),
        ("User-Agent", config.user_agent.as_str()),
    ];

    if let Some(path) = valid_redirect_path(portal_redirect) {
        logger::info(&format!("following post-login portal redirect: {path}"));
        ensure_success(
            path,
            do_http_request(stream, &host, "GET", path, &cookie_header, b"")?,
        )?;
    } else {
        ensure_success(
            "/remote/index",
            do_http_request(stream, &host, "GET", "/remote/index", &cookie_header, b"")?,
        )?;
    }

    ensure_success(
        "/remote/fortisslvpn",
        do_http_request(
            stream,
            &host,
            "GET",
            "/remote/fortisslvpn",
            &cookie_header,
            b"",
        )?,
    )?;

    Ok(())
}

pub fn get_vpn_config<S: Read + Write>(
    stream: &mut S,
    config: &Config,
    cookie: &str,
) -> Result<VpnConfigXml> {
    let host = http_host(config);
    let response = do_http_request(
        stream,
        &host,
        "GET",
        "/remote/fortisslvpn_xml",
        &[
            ("Cookie", cookie),
            ("User-Agent", config.user_agent.as_str()),
        ],
        b"",
    )?;
    ensure_success("/remote/fortisslvpn_xml", response.clone())?;
    let raw_xml = response
        .body_as_str()
        .ok_or_else(|| OpenfortivpnError::HttpProtocol("VPN config XML is not UTF-8".to_owned()))?
        .to_owned();

    Ok(parse_vpn_config_xml(&raw_xml))
}

pub fn log_out<S: Read + Write>(stream: &mut S, config: &Config, cookie: &str) -> Result<()> {
    let host = http_host(config);
    ensure_success(
        "/remote/logout",
        do_http_request(
            stream,
            &host,
            "GET",
            "/remote/logout",
            &[
                ("Cookie", cookie),
                ("User-Agent", config.user_agent.as_str()),
            ],
            b"",
        )?,
    )
}

pub fn parse_vpn_config_xml(raw_xml: &str) -> VpnConfigXml {
    let gateway = first_tag_attr(raw_xml, "assigned-addr", "ipv4");
    let assigned_ip = gateway
        .clone()
        .or_else(|| first_xml_value(raw_xml, "assigned-addr"))
        .or_else(|| first_xml_value(raw_xml, "ip"))
        .or_else(|| first_xml_value(raw_xml, "addr"));

    let mut dns_servers = tag_attr_values(raw_xml, "dns", "ip");
    dns_servers.extend(xml_values(raw_xml, "dns-server"));
    if dns_servers.is_empty() {
        dns_servers.extend(xml_values(raw_xml, "dns"));
    }

    let dns_suffix = first_tag_attr(raw_xml, "dns", "domain")
        .or_else(|| first_xml_value(raw_xml, "dns-suffix"))
        .or_else(|| first_xml_value(raw_xml, "domain"));

    let split_routes = parse_split_routes(raw_xml, gateway.as_deref());

    VpnConfigXml {
        raw_xml: raw_xml.to_owned(),
        gateway,
        assigned_ip,
        dns_servers,
        dns_suffix,
        split_routes,
    }
}

fn valid_redirect_path(path: Option<&str>) -> Option<&str> {
    path.filter(|path| path.starts_with('/') && !path.starts_with("//"))
}

fn ensure_success(path: &str, response: HttpResponse) -> Result<()> {
    if (200..300).contains(&response.status_code) {
        Ok(())
    } else {
        log_http_error_context(path, &response);
        Err(OpenfortivpnError::HttpProtocol(format!(
            "{path}: unexpected HTTP status: {} {}",
            response.status_code, response.reason
        )))
    }
}

fn log_http_error_context(path: &str, response: &HttpResponse) {
    let header_names = response.header_names();
    if !header_names.is_empty() {
        logger::debug(&format!(
            "HTTP error response headers for {path}: {}",
            header_names.join(", ")
        ));
    }
    if let Some(preview) = response.body_preview(512) {
        logger::debug(&format!(
            "HTTP error response body preview for {path}: {preview}"
        ));
    }
}

fn first_xml_value(xml: &str, tag: &str) -> Option<String> {
    xml_values(xml, tag).into_iter().next()
}

fn first_tag_attr(xml: &str, tag: &str, attr: &str) -> Option<String> {
    tag_attr_values(xml, tag, attr).into_iter().next()
}

fn tag_attr_values(xml: &str, tag: &str, attr: &str) -> Vec<String> {
    start_tags(xml, tag)
        .into_iter()
        .filter_map(|start_tag| attr_value(start_tag, attr))
        .collect()
}

fn parse_split_routes(xml: &str, gateway: Option<&str>) -> Vec<Ipv4Route> {
    element_bodies(xml, "split-tunnel-info")
        .into_iter()
        .flat_map(|body| start_tags(body, "addr"))
        .filter_map(|start_tag| {
            let destination = attr_value(start_tag, "ip")?;
            let mask = attr_value(start_tag, "mask")?;
            Some(Ipv4Route {
                destination,
                mask,
                gateway: gateway.map(str::to_owned),
            })
        })
        .collect()
}

fn start_tags<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    let mut tags = Vec::new();
    let mut offset = 0;

    while let Some(relative_start) = xml[offset..].find('<') {
        let start = offset + relative_start;
        let after_lt = start + 1;
        if xml[after_lt..].starts_with('/')
            || xml[after_lt..].starts_with('!')
            || xml[after_lt..].starts_with('?')
        {
            offset = after_lt;
            continue;
        }

        if xml[after_lt..].starts_with(tag) {
            let after_name = after_lt + tag.len();
            let boundary = xml[after_name..]
                .chars()
                .next()
                .map(|ch| ch.is_ascii_whitespace() || ch == '/' || ch == '>')
                .unwrap_or(true);
            if boundary {
                if let Some(relative_end) = xml[after_name..].find('>') {
                    let end = after_name + relative_end;
                    tags.push(&xml[after_lt..end]);
                    offset = end + 1;
                    continue;
                }
                break;
            }
        }

        offset = after_lt;
    }

    tags
}

fn element_bodies<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    let mut bodies = Vec::new();
    let mut offset = 0;
    let close = format!("</{tag}>");

    while let Some(relative_start) = xml[offset..].find('<') {
        let start = offset + relative_start;
        let after_lt = start + 1;
        if !xml[after_lt..].starts_with(tag) {
            offset = after_lt;
            continue;
        }

        let after_name = after_lt + tag.len();
        let boundary = xml[after_name..]
            .chars()
            .next()
            .map(|ch| ch.is_ascii_whitespace() || ch == '/' || ch == '>')
            .unwrap_or(true);
        if !boundary {
            offset = after_lt;
            continue;
        }

        let Some(relative_open_end) = xml[after_name..].find('>') else {
            break;
        };
        let open_end = after_name + relative_open_end;
        if xml[start..=open_end].trim_end().ends_with("/>") {
            offset = open_end + 1;
            continue;
        }

        let body_start = open_end + 1;
        let Some(relative_close_start) = xml[body_start..].find(&close) else {
            break;
        };
        let close_start = body_start + relative_close_start;
        bodies.push(&xml[body_start..close_start]);
        offset = close_start + close.len();
    }

    bodies
}

fn attr_value(start_tag: &str, attr: &str) -> Option<String> {
    let mut rest = start_tag.trim_start();
    if let Some((_, after_name)) = rest.split_once(char::is_whitespace) {
        rest = after_name;
    } else {
        return None;
    }

    while !rest.is_empty() {
        rest = rest.trim_start();
        if rest.starts_with('/') {
            return None;
        }

        let name_end = rest
            .find(|ch: char| ch.is_ascii_whitespace() || ch == '=' || ch == '/' || ch == '>')
            .unwrap_or(rest.len());
        if name_end == 0 {
            return None;
        }
        let name = &rest[..name_end];
        rest = rest[name_end..].trim_start();

        if !rest.starts_with('=') {
            continue;
        }
        rest = rest[1..].trim_start();
        let quote = rest.chars().next()?;
        if quote != '\'' && quote != '"' {
            return None;
        }
        let value_start = quote.len_utf8();
        let value_rest = &rest[value_start..];
        let value_end = value_rest.find(quote)?;
        let value = &value_rest[..value_end];
        rest = &value_rest[value_end + quote.len_utf8()..];

        if name == attr {
            return Some(xml_unescape(value));
        }
    }

    None
}

fn xml_values(xml: &str, tag: &str) -> Vec<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut values = Vec::new();
    let mut rest = xml;

    while let Some(start) = rest.find(&open) {
        let value_start = start + open.len();
        let Some(end) = rest[value_start..].find(&close) else {
            break;
        };
        values.push(xml_unescape(rest[value_start..value_start + end].trim()));
        rest = &rest[value_start + end + close.len()..];
    }

    values
}

fn xml_unescape(value: &str) -> String {
    value
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

fn http_host(config: &Config) -> String {
    if config.gateway_port == 443 {
        config.gateway_host.clone()
    } else {
        format!("{}:{}", config.gateway_host, config.gateway_port)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io::{Cursor, Read, Write};

    use super::*;

    #[test]
    fn requests_vpn_allocation_endpoints_with_cookie() {
        let cfg = Config {
            gateway_host: "vpn.example".to_owned(),
            ..Config::default()
        };
        let first = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let second = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let mut stream = MockStream::new_sequence(vec![first.to_vec(), second.to_vec()]);

        request_vpn_allocation(&mut stream, &cfg, "SVPNCOOKIE=abc", None).unwrap();

        let written = String::from_utf8(stream.written).unwrap();
        assert!(written.contains("GET /remote/index HTTP/1.1\r\n"));
        assert!(written.contains("GET /remote/fortisslvpn HTTP/1.1\r\n"));
        assert_eq!(written.matches("Cookie: SVPNCOOKIE=abc\r\n").count(), 2);
    }

    #[test]
    fn follows_portal_redirect_instead_of_remote_index() {
        let cfg = Config {
            gateway_host: "vpn.example".to_owned(),
            ..Config::default()
        };
        let first = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let second = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let mut stream = MockStream::new_sequence(vec![first.to_vec(), second.to_vec()]);

        request_vpn_allocation(
            &mut stream,
            &cfg,
            "SVPNCOOKIE=abc",
            Some("/sslvpn/portal.html"),
        )
        .unwrap();

        let written = String::from_utf8(stream.written).unwrap();
        assert!(written.contains("GET /sslvpn/portal.html HTTP/1.1\r\n"));
        assert!(!written.contains("GET /remote/index HTTP/1.1\r\n"));
        assert!(written.contains("GET /remote/fortisslvpn HTTP/1.1\r\n"));
        assert_eq!(written.matches("Cookie: SVPNCOOKIE=abc\r\n").count(), 2);
    }

    #[test]
    fn parses_basic_xml_values() {
        let parsed = parse_vpn_config_xml(
            "<root><assigned-addr>10.0.0.2</assigned-addr><dns-server>1.1.1.1</dns-server><dns-server>8.8.8.8</dns-server><dns-suffix>corp&amp;vpn</dns-suffix></root>",
        );

        assert_eq!(parsed.gateway, None);
        assert_eq!(parsed.assigned_ip.as_deref(), Some("10.0.0.2"));
        assert_eq!(parsed.dns_servers, ["1.1.1.1", "8.8.8.8"]);
        assert_eq!(parsed.dns_suffix.as_deref(), Some("corp&vpn"));
        assert!(parsed.split_routes.is_empty());
    }

    #[test]
    fn parses_fortinet_xml_attributes() {
        let parsed = parse_vpn_config_xml(
            r#"<root>
                <assigned-addr ipv4="10.212.134.200"/>
                <dns ip="10.0.0.10"/>
                <dns ip='10.0.0.11'/>
                <dns domain="corp.example"/>
                <split-tunnel-info>
                    <addr ip="10.10.0.0" mask="255.255.0.0"/>
                    <addr ip="192.168.1.0" mask="255.255.255.0"/>
                </split-tunnel-info>
            </root>"#,
        );

        assert_eq!(parsed.gateway.as_deref(), Some("10.212.134.200"));
        assert_eq!(parsed.assigned_ip.as_deref(), Some("10.212.134.200"));
        assert_eq!(parsed.dns_servers, ["10.0.0.10", "10.0.0.11"]);
        assert_eq!(parsed.dns_suffix.as_deref(), Some("corp.example"));
        assert_eq!(
            parsed.split_routes,
            [
                Ipv4Route {
                    destination: "10.10.0.0".to_owned(),
                    mask: "255.255.0.0".to_owned(),
                    gateway: Some("10.212.134.200".to_owned()),
                },
                Ipv4Route {
                    destination: "192.168.1.0".to_owned(),
                    mask: "255.255.255.0".to_owned(),
                    gateway: Some("10.212.134.200".to_owned()),
                },
            ]
        );
    }

    #[test]
    fn gets_raw_vpn_config() {
        let cfg = Config {
            gateway_host: "vpn.example".to_owned(),
            ..Config::default()
        };
        let body = "<root><assigned-addr>10.0.0.2</assigned-addr></root>";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let mut stream = MockStream::new(response.into_bytes());

        let parsed = get_vpn_config(&mut stream, &cfg, "SVPNCOOKIE=abc").unwrap();

        assert_eq!(parsed.raw_xml, body);
        assert_eq!(parsed.assigned_ip.as_deref(), Some("10.0.0.2"));
        assert!(parsed.split_routes.is_empty());
    }

    #[test]
    fn reports_endpoint_on_http_status_error() {
        let cfg = Config {
            gateway_host: "vpn.example".to_owned(),
            ..Config::default()
        };
        let mut stream =
            MockStream::new(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".to_vec());

        let err = get_vpn_config(&mut stream, &cfg, "SVPNCOOKIE=abc").unwrap_err();

        assert_eq!(
            err.to_string(),
            "HTTP protocol error: /remote/fortisslvpn_xml: unexpected HTTP status: 403 Forbidden"
        );
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
