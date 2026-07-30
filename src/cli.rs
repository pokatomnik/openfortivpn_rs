use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{ArgAction, Parser};

#[derive(Debug, Parser)]
#[command(name = "openfortivpn")]
#[command(about = "Client for PPP+TLS VPN tunnel services", long_about = None)]
#[command(disable_version_flag = true)]
pub struct Cli {
    /// Gateway as host[:port]
    pub gateway: Option<String>,

    /// Show version and exit
    #[arg(long, action = ArgAction::SetTrue)]
    pub version: bool,

    /// Specify a custom configuration file
    #[arg(short = 'c', long = "config")]
    pub config: Option<PathBuf>,

    /// VPN account username
    #[arg(short = 'u', long = "username")]
    pub username: Option<String>,

    /// VPN account password
    #[arg(short = 'p', long = "password")]
    pub password: Option<String>,

    /// Valid session cookie (SVPNCOOKIE)
    #[arg(long = "cookie")]
    pub cookie: Option<String>,

    /// Read the cookie from stdin
    #[arg(long = "cookie-on-stdin", action = ArgAction::SetTrue)]
    pub cookie_on_stdin: bool,

    /// Run a local HTTP server to handle SAML login requests; optional port
    #[arg(
        long = "saml-login",
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "8020"
    )]
    pub saml_login: Option<u16>,

    /// One-time password
    #[arg(short = 'o', long = "otp")]
    pub otp: Option<String>,

    /// Search for the OTP prompt starting with this string
    #[arg(long = "otp-prompt")]
    pub otp_prompt: Option<String>,

    /// Wait this many seconds before sending the OTP
    #[arg(long = "otp-delay")]
    pub otp_delay: Option<u32>,

    /// Do not use FTM push
    #[arg(long = "no-ftm-push", action = ArgAction::SetTrue)]
    pub no_ftm_push: bool,

    /// Pinentry program for secret input
    #[arg(long = "pinentry")]
    pub pinentry: Option<String>,

    /// Authentication realm
    #[arg(long = "realm")]
    pub realm: Option<String>,

    /// Bind to interface
    #[arg(long = "ifname")]
    pub ifname: Option<String>,

    /// Override SNI host
    #[arg(long = "sni")]
    pub sni: Option<String>,

    /// Set routes
    #[arg(long = "set-routes", value_parser = parse_cli_bool)]
    pub set_routes: Option<bool>,

    /// Do not configure routes
    #[arg(long = "no-routes", action = ArgAction::SetTrue)]
    pub no_routes: bool,

    /// Use half-internet routes
    #[arg(long = "half-internet-routes", value_parser = parse_cli_bool)]
    pub half_internet_routes: Option<bool>,

    /// Set DNS
    #[arg(long = "set-dns", value_parser = parse_cli_bool)]
    pub set_dns: Option<bool>,

    /// Do not configure DNS
    #[arg(long = "no-dns", action = ArgAction::SetTrue)]
    pub no_dns: bool,

    /// CA bundle path
    #[arg(long = "ca-file")]
    pub ca_file: Option<String>,

    /// User certificate PEM path (PKCS#11 URIs are not supported with rustls)
    #[arg(long = "user-cert")]
    pub user_cert: Option<String>,

    /// User key path
    #[arg(long = "user-key")]
    pub user_key: Option<String>,

    /// PEM key passphrase
    #[arg(long = "pem-passphrase")]
    pub pem_passphrase: Option<String>,

    /// Use syslog
    #[arg(long = "use-syslog", action = ArgAction::SetTrue)]
    pub use_syslog: bool,

    /// Use resolvconf if available for DNS updates
    #[arg(long = "use-resolvconf", value_parser = parse_cli_bool)]
    pub use_resolvconf: Option<bool>,

    /// HTTP User-Agent header
    #[arg(long = "user-agent")]
    pub user_agent: Option<String>,

    /// Hostcheck value submitted during login
    #[arg(long = "hostcheck")]
    pub hostcheck: Option<String>,

    /// Virtual desktop check value submitted during login
    #[arg(long = "check-virtual-desktop")]
    pub check_virtual_desktop: Option<String>,

    /// Trusted gateway certificate SHA256 digest
    #[arg(long = "trusted-cert", action = ArgAction::Append)]
    pub trusted_cert: Vec<String>,

    /// Allow insecure TLS settings
    #[arg(long = "insecure-ssl", action = ArgAction::SetTrue)]
    pub insecure_ssl: bool,

    /// OpenSSL-compatible cipher list (unsupported with rustls)
    #[arg(long = "cipher-list")]
    pub cipher_list: Option<String>,

    /// Minimum TLS version: 1.0, 1.1, 1.2, 1.3
    #[arg(long = "min-tls")]
    pub min_tls: Option<String>,

    /// Lower OpenSSL security level to 1 (unsupported with rustls)
    #[arg(long = "seclevel-1", action = ArgAction::SetTrue)]
    pub seclevel_1: bool,

    /// Reconnect delay in seconds; used only when --max-reconnects is greater than 0
    #[arg(long = "reconnect-delay")]
    pub reconnect_delay: Option<u32>,

    /// Legacy alias for --reconnect-delay
    #[arg(long = "persistent", hide = true)]
    pub persistent: Option<u32>,

    /// Maximum number of reconnect attempts; 0 disables reconnects
    #[arg(long = "max-reconnects")]
    pub max_reconnects: Option<u32>,

    /// Increase verbosity; can be repeated
    #[arg(short = 'v', action = ArgAction::Count)]
    pub verbose: u8,

    /// Decrease verbosity; can be repeated
    #[arg(short = 'q', action = ArgAction::Count)]
    pub quiet: u8,

    /// Whether to ask pppd for DNS server addresses
    #[arg(long = "pppd-use-peerdns", value_parser = parse_cli_bool)]
    pub pppd_use_peerdns: Option<bool>,

    /// Same as --pppd-use-peerdns=0
    #[arg(long = "pppd-no-peerdns", action = ArgAction::SetTrue)]
    pub pppd_no_peerdns: bool,

    #[arg(long = "pppd-log")]
    pub pppd_log: Option<String>,

    #[arg(long = "pppd-plugin")]
    pub pppd_plugin: Option<String>,

    #[arg(long = "pppd-ifname")]
    pub pppd_ifname: Option<String>,

    #[arg(long = "pppd-ipparam")]
    pub pppd_ipparam: Option<String>,

    #[arg(long = "pppd-call")]
    pub pppd_call: Option<String>,

    #[arg(
        long = "pppd-accept-remote",
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true",
        value_parser = parse_cli_bool
    )]
    pub pppd_accept_remote: Option<bool>,

    #[arg(long = "ppp-system")]
    pub ppp_system: Option<String>,

    /// Run isolated SOCKS5H proxy mode on the given local address instead of creating an OS VPN tunnel
    #[arg(long = "proxy")]
    pub proxy: Option<SocketAddr>,
}

fn parse_cli_bool(value: &str) -> Result<bool, String> {
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
        _ => Err(format!("bad boolean value: {value}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parses_saml_login_default_port_like_c() {
        let cli = Cli::parse_from(["openfortivpn", "--saml-login", "vpn.example"]);
        assert_eq!(cli.saml_login, Some(8020));
        assert_eq!(cli.gateway.as_deref(), Some("vpn.example"));
    }

    #[test]
    fn parses_saml_login_explicit_port_like_c() {
        let cli = Cli::parse_from(["openfortivpn", "--saml-login=8123", "vpn.example"]);
        assert_eq!(cli.saml_login, Some(8123));
    }

    #[test]
    fn parses_optional_pppd_accept_remote_like_c() {
        let cli = Cli::parse_from(["openfortivpn", "--pppd-accept-remote", "vpn.example"]);
        assert_eq!(cli.pppd_accept_remote, Some(true));

        let cli = Cli::parse_from(["openfortivpn", "--pppd-accept-remote=0", "vpn.example"]);
        assert_eq!(cli.pppd_accept_remote, Some(false));
    }

    #[test]
    fn parses_proxy_listen_address() {
        let cli = Cli::parse_from(["openfortivpn", "--proxy", "127.0.0.1:1080", "vpn.example"]);
        assert_eq!(cli.proxy, Some("127.0.0.1:1080".parse().unwrap()));
    }

    #[test]
    fn parses_max_reconnects() {
        let cli = Cli::parse_from(["openfortivpn", "--max-reconnects", "2", "vpn.example"]);
        assert_eq!(cli.max_reconnects, Some(2));
    }

    #[test]
    fn parses_reconnect_delay() {
        let cli = Cli::parse_from(["openfortivpn", "--reconnect-delay", "5", "vpn.example"]);
        assert_eq!(cli.reconnect_delay, Some(5));
    }

    #[test]
    fn parses_legacy_persistent_alias() {
        let cli = Cli::parse_from(["openfortivpn", "--persistent", "5", "vpn.example"]);
        assert_eq!(cli.persistent, Some(5));
    }

    #[test]
    fn parses_required_bool_options_like_c() {
        let cli = Cli::parse_from([
            "openfortivpn",
            "--set-routes=0",
            "--set-dns=1",
            "--half-internet-routes=true",
            "--use-resolvconf=false",
            "vpn.example",
        ]);
        assert_eq!(cli.set_routes, Some(false));
        assert_eq!(cli.set_dns, Some(true));
        assert_eq!(cli.half_internet_routes, Some(true));
        assert_eq!(cli.use_resolvconf, Some(false));
    }
}
