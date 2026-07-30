use std::fs;
use std::net::SocketAddr;
use std::path::Path;

use crate::cli::Cli;
use crate::error::{OpenfortivpnError, Result};

pub const DEFAULT_GATEWAY_PORT: u16 = 443;
pub const SHA256_DIGEST_HEX_LEN: usize = 64;
pub const DEFAULT_LOG_VERBOSITY: u8 = 3;
pub const MAX_LOG_VERBOSITY: u8 = 6;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsVersion {
    Tls10,
    Tls11,
    Tls12,
    Tls13,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub gateway_host: String,
    pub gateway_port: u16,
    pub username: String,
    pub password: Option<String>,
    pub cookie: Option<String>,
    pub cookie_on_stdin: bool,
    pub saml_port: Option<u16>,
    pub saml_session_id: Option<String>,
    pub otp: Option<String>,
    pub otp_prompt: Option<String>,
    pub otp_delay: u32,
    pub no_ftm_push: bool,
    pub pinentry: Option<String>,
    pub realm: Option<String>,
    pub iface_name: Option<String>,
    pub sni: Option<String>,
    pub set_routes: bool,
    pub set_dns: bool,
    pub half_internet_routes: bool,
    pub reconnect_delay: Option<u32>,
    pub max_reconnects: u32,
    pub use_syslog: bool,
    pub log_verbosity: u8,
    pub use_resolvconf: bool,
    pub user_agent: String,
    pub hostcheck: Option<String>,
    pub check_virtual_desktop: Option<String>,
    pub pppd_use_peerdns: bool,
    pub pppd_log: Option<String>,
    pub pppd_plugin: Option<String>,
    pub pppd_ipparam: Option<String>,
    pub pppd_ifname: Option<String>,
    pub pppd_call: Option<String>,
    pub pppd_accept_remote: bool,
    pub ppp_system: Option<String>,
    pub ca_file: Option<String>,
    pub user_cert: Option<String>,
    pub user_key: Option<String>,
    pub pem_passphrase: Option<String>,
    pub insecure_ssl: bool,
    pub cipher_list: Option<String>,
    pub min_tls: Option<TlsVersion>,
    pub seclevel_1: bool,
    pub trusted_certs: Vec<String>,
    pub proxy: Option<SocketAddr>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            gateway_host: String::new(),
            gateway_port: DEFAULT_GATEWAY_PORT,
            username: String::new(),
            password: None,
            cookie: None,
            cookie_on_stdin: false,
            saml_port: None,
            saml_session_id: None,
            otp: None,
            otp_prompt: None,
            otp_delay: 0,
            no_ftm_push: false,
            pinentry: None,
            realm: None,
            iface_name: None,
            sni: None,
            set_routes: true,
            set_dns: true,
            half_internet_routes: false,
            reconnect_delay: None,
            max_reconnects: 0,
            use_syslog: false,
            log_verbosity: DEFAULT_LOG_VERBOSITY,
            use_resolvconf: true,
            user_agent: "Mozilla/5.0 SV1".to_owned(),
            hostcheck: None,
            check_virtual_desktop: None,
            pppd_use_peerdns: false,
            pppd_log: None,
            pppd_plugin: None,
            pppd_ipparam: None,
            pppd_ifname: None,
            pppd_call: None,
            // Matches current non-legacy pppd default in main.c.
            pppd_accept_remote: true,
            ppp_system: None,
            ca_file: None,
            user_cert: None,
            user_key: None,
            pem_passphrase: None,
            insecure_ssl: false,
            cipher_list: None,
            min_tls: None,
            seclevel_1: false,
            trusted_certs: Vec::new(),
            proxy: None,
        }
    }
}

impl Config {
    pub fn from_sources(cli: &Cli) -> Result<Self> {
        let mut cfg = Config::default();

        if let Some(config_path) = cli.config.as_deref() {
            cfg.merge(Self::from_file(config_path)?);
        }

        cfg.apply_cli(cli)?;
        Ok(cfg)
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let contents = fs::read_to_string(path)?;
        Self::parse_config_file(&contents)
    }

    pub fn parse_config_file(contents: &str) -> Result<Self> {
        let mut cfg = Config::default();

        for raw_line in contents.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let Some((key, value)) = line.split_once('=') else {
                // The C implementation warns and continues. For the Rust parser
                // we keep that compatibility by ignoring malformed non-key lines.
                continue;
            };

            cfg.apply_pair(key.trim(), value.trim())?;
        }

        Ok(cfg)
    }

    fn merge(&mut self, other: Self) {
        if !other.gateway_host.is_empty() {
            self.gateway_host = other.gateway_host;
        }
        if other.gateway_port != DEFAULT_GATEWAY_PORT {
            self.gateway_port = other.gateway_port;
        }
        if !other.username.is_empty() {
            self.username = other.username;
        }
        merge_option(&mut self.password, other.password);
        merge_option(&mut self.cookie, other.cookie);
        self.cookie_on_stdin |= other.cookie_on_stdin;
        merge_option(&mut self.saml_port, other.saml_port);
        merge_option(&mut self.saml_session_id, other.saml_session_id);
        merge_option(&mut self.otp, other.otp);
        merge_option(&mut self.otp_prompt, other.otp_prompt);
        if other.otp_delay != 0 {
            self.otp_delay = other.otp_delay;
        }
        self.no_ftm_push |= other.no_ftm_push;
        merge_option(&mut self.pinentry, other.pinentry);
        merge_option(&mut self.realm, other.realm);
        merge_option(&mut self.iface_name, other.iface_name);
        merge_option(&mut self.sni, other.sni);
        self.set_routes = other.set_routes;
        self.set_dns = other.set_dns;
        self.half_internet_routes = other.half_internet_routes;
        merge_option(&mut self.reconnect_delay, other.reconnect_delay);
        if other.max_reconnects != 0 {
            self.max_reconnects = other.max_reconnects;
        }
        self.use_syslog |= other.use_syslog;
        self.log_verbosity = other.log_verbosity;
        self.use_resolvconf = other.use_resolvconf;
        if other.user_agent != Config::default().user_agent {
            self.user_agent = other.user_agent;
        }
        merge_option(&mut self.hostcheck, other.hostcheck);
        merge_option(&mut self.check_virtual_desktop, other.check_virtual_desktop);
        self.pppd_use_peerdns = other.pppd_use_peerdns;
        merge_option(&mut self.pppd_log, other.pppd_log);
        merge_option(&mut self.pppd_plugin, other.pppd_plugin);
        merge_option(&mut self.pppd_ipparam, other.pppd_ipparam);
        merge_option(&mut self.pppd_ifname, other.pppd_ifname);
        merge_option(&mut self.pppd_call, other.pppd_call);
        self.pppd_accept_remote = other.pppd_accept_remote;
        merge_option(&mut self.ppp_system, other.ppp_system);
        merge_option(&mut self.ca_file, other.ca_file);
        merge_option(&mut self.user_cert, other.user_cert);
        merge_option(&mut self.user_key, other.user_key);
        merge_option(&mut self.pem_passphrase, other.pem_passphrase);
        self.insecure_ssl |= other.insecure_ssl;
        merge_option(&mut self.cipher_list, other.cipher_list);
        merge_option(&mut self.min_tls, other.min_tls);
        self.seclevel_1 |= other.seclevel_1;
        self.trusted_certs.extend(other.trusted_certs);
        merge_option(&mut self.proxy, other.proxy);
    }

    fn apply_pair(&mut self, key: &str, value: &str) -> Result<()> {
        match key {
            "host" => self.gateway_host = value.to_owned(),
            "port" => self.gateway_port = parse_port(key, value)?,
            "username" => self.username = value.to_owned(),
            "password" => self.password = Some(value.to_owned()),
            "otp" => self.otp = Some(value.to_owned()),
            "otp-prompt" => self.otp_prompt = Some(value.to_owned()),
            "otp-delay" => self.otp_delay = parse_u32(key, value)?,
            "cookie" | "cookie-on-stdin" => {}
            "no-ftm-push" => self.no_ftm_push = parse_bool(value)?,
            "pinentry" => self.pinentry = Some(value.to_owned()),
            "realm" => self.realm = Some(value.to_owned()),
            "ifname" => self.iface_name = Some(value.to_owned()),
            "sni" => self.sni = Some(value.to_owned()),
            "set-routes" => self.set_routes = parse_bool(value)?,
            "half-internet-routes" => self.half_internet_routes = parse_bool(value)?,
            "reconnect-delay" | "reconnect_delay" | "persistent" => {
                self.reconnect_delay = Some(parse_u32(key, value)?)
            }
            "max_recoonects" | "max_reconnects" | "max-reconnects" => {
                self.max_reconnects = parse_u32(key, value)?
            }
            "set-dns" => self.set_dns = parse_bool(value)?,
            "pppd-use-peerdns" => self.pppd_use_peerdns = parse_bool(value)?,
            "pppd-log" => self.pppd_log = Some(value.to_owned()),
            "pppd-plugin" => self.pppd_plugin = Some(value.to_owned()),
            "pppd-ipparam" => self.pppd_ipparam = Some(value.to_owned()),
            "pppd-ifname" => self.pppd_ifname = Some(value.to_owned()),
            "pppd-call" => self.pppd_call = Some(value.to_owned()),
            "pppd-accept-remote" => self.pppd_accept_remote = parse_bool(value)?,
            "ppp-system" => self.ppp_system = Some(value.to_owned()),
            "use-syslog" => self.use_syslog = parse_bool(value)?,
            "use-resolvconf" => self.use_resolvconf = parse_bool(value)?,
            "trusted-cert" => self.push_trusted_cert(value)?,
            "ca-file" => self.ca_file = Some(value.to_owned()),
            "user-cert" => self.user_cert = Some(value.to_owned()),
            "saml-login" => self.saml_port = Some(parse_port(key, value)?),
            "user-key" => self.user_key = Some(value.to_owned()),
            "pem-passphrase" => self.pem_passphrase = Some(value.to_owned()),
            "insecure-ssl" => self.insecure_ssl = parse_bool(value)?,
            "cipher-list" => self.cipher_list = Some(value.to_owned()),
            "min-tls" => self.min_tls = Some(parse_tls_version(value)?),
            "seclevel-1" => self.seclevel_1 = parse_bool(value)?,
            "user-agent" => self.user_agent = value.to_owned(),
            "hostcheck" => self.hostcheck = Some(value.to_owned()),
            "check-virtual-desktop" => self.check_virtual_desktop = Some(value.to_owned()),
            "proxy" => self.proxy = Some(parse_socket_addr("proxy", value)?),
            other => return Err(OpenfortivpnError::UnknownConfigKey(other.to_owned())),
        }

        Ok(())
    }

    fn apply_cli(&mut self, cli: &Cli) -> Result<()> {
        if let Some(gateway) = &cli.gateway {
            let (host, port) = parse_gateway(gateway)?;
            self.gateway_host = host;
            if let Some(port) = port {
                self.gateway_port = port;
            }
        }

        if let Some(value) = &cli.username {
            self.username = value.clone();
        }
        if let Some(value) = &cli.password {
            self.password = Some(value.clone());
        }
        if let Some(value) = &cli.cookie {
            self.cookie = Some(svpn_cookie_with_prefix(value));
        }
        if cli.cookie_on_stdin {
            self.cookie_on_stdin = true;
        }
        if let Some(value) = cli.saml_login {
            self.saml_port = Some(value);
        }
        if let Some(value) = &cli.otp {
            self.otp = Some(value.clone());
        }
        if let Some(value) = &cli.otp_prompt {
            self.otp_prompt = Some(value.clone());
        }
        if let Some(value) = cli.otp_delay {
            self.otp_delay = value;
        }
        if cli.no_ftm_push {
            self.no_ftm_push = true;
        }
        if let Some(value) = &cli.pinentry {
            self.pinentry = Some(value.clone());
        }
        if let Some(value) = &cli.realm {
            self.realm = Some(value.clone());
        }
        if let Some(value) = &cli.ifname {
            self.iface_name = Some(value.clone());
        }
        if let Some(value) = &cli.sni {
            self.sni = Some(value.clone());
        }
        if let Some(value) = cli.set_routes {
            self.set_routes = value;
        }
        if cli.no_routes {
            self.set_routes = false;
        }
        if let Some(value) = cli.half_internet_routes {
            self.half_internet_routes = value;
        }
        if let Some(value) = cli.set_dns {
            self.set_dns = value;
        }
        if cli.no_dns {
            self.set_dns = false;
        }
        if let Some(value) = &cli.ca_file {
            self.ca_file = Some(value.clone());
        }
        if let Some(value) = &cli.user_cert {
            self.user_cert = Some(value.clone());
        }
        if let Some(value) = &cli.user_key {
            self.user_key = Some(value.clone());
        }
        if let Some(value) = &cli.pem_passphrase {
            self.pem_passphrase = Some(value.clone());
        }
        if cli.use_syslog {
            self.use_syslog = true;
        }
        self.log_verbosity = cli_log_verbosity(cli.verbose, cli.quiet);
        if let Some(value) = cli.use_resolvconf {
            self.use_resolvconf = value;
        }
        if let Some(value) = &cli.user_agent {
            self.user_agent = value.clone();
        }
        if let Some(value) = &cli.hostcheck {
            self.hostcheck = Some(value.clone());
        }
        if let Some(value) = &cli.check_virtual_desktop {
            self.check_virtual_desktop = Some(value.clone());
        }
        for digest in &cli.trusted_cert {
            self.push_trusted_cert(digest)?;
        }
        if cli.insecure_ssl {
            self.insecure_ssl = true;
        }
        if let Some(value) = &cli.cipher_list {
            self.cipher_list = Some(value.clone());
        }
        if let Some(value) = &cli.min_tls {
            self.min_tls = Some(parse_tls_version(value)?);
        }
        if cli.seclevel_1 {
            self.seclevel_1 = true;
        }
        if let Some(value) = cli.reconnect_delay.or(cli.persistent) {
            self.reconnect_delay = Some(value);
        }
        if let Some(value) = cli.max_reconnects {
            self.max_reconnects = value;
        }
        if let Some(value) = cli.pppd_use_peerdns {
            self.pppd_use_peerdns = value;
        }
        if cli.pppd_no_peerdns {
            self.pppd_use_peerdns = false;
        }
        if let Some(value) = &cli.pppd_log {
            self.pppd_log = Some(value.clone());
        }
        if let Some(value) = &cli.pppd_plugin {
            self.pppd_plugin = Some(value.clone());
        }
        if let Some(value) = &cli.pppd_ifname {
            self.pppd_ifname = Some(value.clone());
        }
        if let Some(value) = &cli.pppd_ipparam {
            self.pppd_ipparam = Some(value.clone());
        }
        if let Some(value) = &cli.pppd_call {
            self.pppd_call = Some(value.clone());
        }
        if let Some(value) = cli.pppd_accept_remote {
            self.pppd_accept_remote = value;
        }
        if let Some(value) = &cli.ppp_system {
            self.ppp_system = Some(value.clone());
        }
        if let Some(value) = cli.proxy {
            self.proxy = Some(value);
        }

        Ok(())
    }

    fn push_trusted_cert(&mut self, digest: &str) -> Result<()> {
        if digest.len() != SHA256_DIGEST_HEX_LEN || !digest.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(OpenfortivpnError::BadCertificateDigest(digest.to_owned()));
        }
        self.trusted_certs.push(digest.to_ascii_lowercase());
        Ok(())
    }
}

pub fn svpn_cookie_with_prefix(value: &str) -> String {
    if value.starts_with("SVPNCOOKIE=") {
        value.to_owned()
    } else {
        format!("SVPNCOOKIE={value}")
    }
}

fn cli_log_verbosity(verbose: u8, quiet: u8) -> u8 {
    let adjusted = i16::from(DEFAULT_LOG_VERBOSITY) + i16::from(verbose) - i16::from(quiet);
    adjusted.clamp(0, i16::from(MAX_LOG_VERBOSITY)) as u8
}

pub fn parse_bool(value: &str) -> Result<bool> {
    if value.is_empty() {
        return Ok(false);
    }
    if value.eq_ignore_ascii_case("true") {
        return Ok(true);
    }
    if value.eq_ignore_ascii_case("false") {
        return Ok(false);
    }
    match value.parse::<u8>() {
        Ok(0) => Ok(false),
        Ok(1) => Ok(true),
        _ => Err(OpenfortivpnError::BadBoolean(value.to_owned())),
    }
}

fn parse_socket_addr(key: &str, value: &str) -> Result<SocketAddr> {
    value
        .parse()
        .map_err(|_| OpenfortivpnError::Network(format!("bad socket address for {key}: {value}")))
}

fn parse_port(key: &str, value: &str) -> Result<u16> {
    let port = value
        .parse::<u16>()
        .map_err(|_| OpenfortivpnError::BadPort {
            key: key.to_owned(),
            value: value.to_owned(),
        })?;
    if port == 0 {
        return Err(OpenfortivpnError::BadPort {
            key: key.to_owned(),
            value: value.to_owned(),
        });
    }
    Ok(port)
}

fn parse_u32(key: &str, value: &str) -> Result<u32> {
    value
        .parse::<u32>()
        .map_err(|_| OpenfortivpnError::BadInteger {
            key: key.to_owned(),
            value: value.to_owned(),
        })
}

fn parse_tls_version(value: &str) -> Result<TlsVersion> {
    match value {
        "1.0" => Ok(TlsVersion::Tls10),
        "1.1" => Ok(TlsVersion::Tls11),
        "1.2" => Ok(TlsVersion::Tls12),
        "1.3" => Ok(TlsVersion::Tls13),
        other => Err(OpenfortivpnError::BadTlsVersion(other.to_owned())),
    }
}

fn parse_gateway(value: &str) -> Result<(String, Option<u16>)> {
    if let Some((host, port)) = value.rsplit_once(':') {
        if !host.is_empty() && !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
            return Ok((host.to_owned(), Some(parse_port("gateway", port)?)));
        }
    }
    Ok((value.to_owned(), None))
}

fn merge_option<T>(dst: &mut Option<T>, src: Option<T>) {
    if src.is_some() {
        *dst = src;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_cli_verbosity_like_c() {
        assert_eq!(cli_log_verbosity(0, 0), 3);
        assert_eq!(cli_log_verbosity(1, 0), 4);
        assert_eq!(cli_log_verbosity(9, 0), 6);
        assert_eq!(cli_log_verbosity(0, 1), 2);
        assert_eq!(cli_log_verbosity(0, 9), 0);
    }

    #[test]
    fn parses_bool_like_c() {
        assert!(!parse_bool("").unwrap());
        assert!(parse_bool("true").unwrap());
        assert!(!parse_bool("false").unwrap());
        assert!(parse_bool("1").unwrap());
        assert!(!parse_bool("0").unwrap());
        assert!(parse_bool("2").is_err());
        assert!(parse_bool("yes").is_err());
    }

    #[test]
    fn parses_basic_config_file() {
        let cfg = Config::parse_config_file(
            r#"
            # comment
            host = vpn-gateway
            port = 8443
            username = foo
            password = bar
            set-dns = 0
            trusted-cert = e46d4aff08ba6914e64daa85bc6112a422fa7ce16631bff0b592a28556f993db
            max_recoonects = 2
            reconnect-delay = 5
            "#,
        )
        .unwrap();

        assert_eq!(cfg.gateway_host, "vpn-gateway");
        assert_eq!(cfg.gateway_port, 8443);
        assert_eq!(cfg.username, "foo");
        assert_eq!(cfg.password.as_deref(), Some("bar"));
        assert!(!cfg.set_dns);
        assert_eq!(cfg.trusted_certs.len(), 1);
        assert_eq!(cfg.max_reconnects, 2);
        assert_eq!(cfg.reconnect_delay, Some(5));
    }

    #[test]
    fn parses_legacy_persistent_as_reconnect_delay() {
        let cfg = Config::parse_config_file("persistent = 7").unwrap();
        assert_eq!(cfg.reconnect_delay, Some(7));
    }

    #[test]
    fn config_max_reconnects_defaults_to_zero() {
        assert_eq!(Config::default().max_reconnects, 0);
    }

    #[test]
    fn parses_gateway_host_port() {
        assert_eq!(
            parse_gateway("host:8443").unwrap(),
            ("host".to_owned(), Some(8443))
        );
        assert_eq!(parse_gateway("host").unwrap(), ("host".to_owned(), None));
    }

    #[test]
    fn prefixes_svpn_cookie_when_missing() {
        assert_eq!(svpn_cookie_with_prefix("abc"), "SVPNCOOKIE=abc");
        assert_eq!(svpn_cookie_with_prefix("SVPNCOOKIE=abc"), "SVPNCOOKIE=abc");
    }

    #[test]
    fn from_sources_does_not_load_default_config_path() {
        use clap::Parser;

        let cli = Cli::parse_from(["openfortivpn", "vpn.example"]);
        let cfg = Config::from_sources(&cli).unwrap();
        assert_eq!(cfg.gateway_host, "vpn.example");
    }
}
