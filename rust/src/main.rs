use std::io::Read;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use clap::Parser;
use openfortivpn_rs::auth::{portal::VpnConfigXml, saml};
use openfortivpn_rs::cli::Cli;
use openfortivpn_rs::config::{svpn_cookie_with_prefix, Config};
use openfortivpn_rs::error::{OpenfortivpnError, Result};
use openfortivpn_rs::logger;
use openfortivpn_rs::net_apply::{apply_network_plan, AppliedNetworkPlan, ApplyOptions};
use openfortivpn_rs::net_plan::{plan_network_actions, NetworkAction, Platform};
use openfortivpn_rs::tunnel::forward;
use openfortivpn_rs::tunnel::interface::wait_for_up_ppp_interface;
#[cfg(unix)]
use openfortivpn_rs::tunnel::pppd::terminate_pppd;
use openfortivpn_rs::tunnel::pppd::{
    build_ppp_command, build_pppd_command, spawn_pppd, DEFAULT_PPPD_PATH, DEFAULT_PPP_PATH,
};
use openfortivpn_rs::tunnel::session::TunnelSession;
use openfortivpn_rs::user_input;

fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.version {
        println!("{}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    let mut config = Config::from_sources(&cli)?;
    logger::init(config.use_syslog, config.log_verbosity);
    apply_stdin_cookie(&mut config)?;

    if config.gateway_host.is_empty() {
        return Err(OpenfortivpnError::Auth(
            "Specify a valid host:port couple.".to_owned(),
        ));
    }

    validate_and_complete_auth_config(&mut config)?;

    require_root()?;

    if config.saml_port.is_some() {
        let saml_session_id = saml::wait_for_session_id(&config)?;
        if saml_session_id.is_empty() {
            return Err(OpenfortivpnError::Auth(
                "failed to receive SAML session id".to_owned(),
            ));
        }
        config.saml_session_id = Some(saml_session_id);
    }

    let stop_requested = Arc::new(AtomicBool::new(false));
    install_ctrlc_handler(stop_requested.clone())?;
    run_with_persistence(config, stop_requested)
}

fn validate_and_complete_auth_config(config: &mut Config) -> Result<()> {
    if config.username.is_empty()
        && config.cookie.is_none()
        && config.saml_port.is_none()
        && config.user_cert.is_none()
    {
        return Err(OpenfortivpnError::Auth("Specify a username.".to_owned()));
    }

    if config.password.is_none()
        && !config.username.is_empty()
        && config.cookie.is_none()
        && config.saml_port.is_none()
    {
        config.password = Some(read_secret(config, "password", "VPN account password: ")?);
    }

    Ok(())
}

fn read_secret(config: &Config, purpose: &str, prompt: &str) -> Result<String> {
    let hint = user_input::secret_hint(
        &config.username,
        config.realm.as_deref(),
        &config.gateway_host,
        purpose,
    );
    user_input::read_secret(config.pinentry.as_deref(), &hint, prompt)
}

fn apply_stdin_cookie(config: &mut Config) -> Result<()> {
    if !config.cookie_on_stdin || config.cookie.is_some() {
        return Ok(());
    }

    let mut cookie = String::new();
    std::io::stdin().read_to_string(&mut cookie)?;
    let cookie = cookie
        .trim_matches(|ch| ch == '\r' || ch == '\n')
        .to_owned();
    if cookie.is_empty() {
        return Err(OpenfortivpnError::Auth(
            "--cookie-on-stdin was set but stdin did not contain a cookie".to_owned(),
        ));
    }
    config.cookie = Some(svpn_cookie_with_prefix(&cookie));
    Ok(())
}

fn run_with_persistence(config: Config, stop_requested: Arc<AtomicBool>) -> Result<()> {
    loop {
        let result = run_tunnel(config.clone(), stop_requested.clone());
        if stop_requested.load(Ordering::SeqCst) || config.persistent.is_none() {
            return result;
        }

        if let Err(err) = &result {
            logger::warn(&format!("VPN tunnel terminated: {err}"));
        }

        let interval = config.persistent.unwrap_or_default();
        if interval > 0 {
            logger::info(&format!("reconnecting in {interval} second(s)"));
            for _ in 0..interval {
                if stop_requested.load(Ordering::SeqCst) {
                    return result;
                }
                thread::sleep(Duration::from_secs(1));
            }
        } else {
            logger::info("reconnecting immediately");
        }
    }
}

fn run_tunnel(config: Config, stop_requested: Arc<AtomicBool>) -> Result<()> {
    if config.gateway_host.is_empty() {
        return Err(OpenfortivpnError::Auth(
            "gateway host is required".to_owned(),
        ));
    }

    logger::info("preparing TLS/authenticated tunnel");
    let session = TunnelSession::prepare(&config)?;
    let cookie = session.prepared.cookie.clone();
    logger::info(&format!(
        "authenticated; peer certificate sha256: {} ({:?})",
        session.prepared.peer_cert_sha256, session.prepared.certificate_verification
    ));
    if let Some(gateway) = &session.prepared.vpn_config.gateway {
        logger::info(&format!("gateway XML peer address: {gateway}"));
    }
    if let Some(ip) = &session.prepared.vpn_config.assigned_ip {
        logger::info(&format!("gateway XML assigned IP: {ip}"));
    }
    if !session.prepared.vpn_config.dns_servers.is_empty() {
        logger::info(&format!(
            "gateway XML DNS servers: {}",
            session.prepared.vpn_config.dns_servers.join(", ")
        ));
    }
    if let Some(suffix) = &session.prepared.vpn_config.dns_suffix {
        logger::info(&format!("gateway XML DNS suffix: {suffix}"));
    }
    if !session.prepared.vpn_config.split_routes.is_empty() {
        logger::info(&format!(
            "gateway XML split routes: {} route(s)",
            session.prepared.vpn_config.split_routes.len()
        ));
    }

    let interface_name = config
        .pppd_ifname
        .as_deref()
        .or(config.iface_name.as_deref())
        .unwrap_or("ppp0");
    if let Some(platform) = current_platform() {
        let plan = plan_network_actions(
            &config,
            &session.prepared.vpn_config,
            platform,
            interface_name,
            tunnel_endpoint_ipv4(session.prepared.tcp_peer_addr),
        );
        if plan.actions.is_empty() {
            logger::info("no route/DNS actions planned from VPN XML/config");
        } else {
            logger::info(&format!("planned route/DNS actions for {interface_name}:"));
            for action in &plan.actions {
                logger::info(&format!("  {}", describe_network_action(action)));
            }
        }
    }

    let ppp_command = build_ppp_backend_command(&config);
    logger::info(&format!(
        "spawning {} {}",
        ppp_command.program,
        ppp_command.args.join(" ")
    ));
    let pppd = spawn_pppd(&ppp_command)?;
    #[cfg(unix)]
    let pppd_pid = pppd.pid;
    #[cfg(unix)]
    logger::debug(&format!("spawned pppd with pid {}", pppd_pid));

    let mut network_apply_thread = None;
    let apply_network = config.set_routes || config.set_dns;
    let apply_config = config.clone();
    let apply_vpn_config = session.prepared.vpn_config.clone();
    let expected_interface_addr = vpn_config_interface_addr(&apply_vpn_config);
    let apply_tunnel_endpoint = tunnel_endpoint_ipv4(session.prepared.tcp_peer_addr);
    let apply_platform = current_platform();
    let preferred_interface = config
        .pppd_ifname
        .clone()
        .or_else(|| config.iface_name.clone());

    logger::info("starting forwarding loop");
    let forward_result = forward::forward_with_callbacks(
        pppd.master,
        session.stream,
        |addr| {
            logger::info(&format!("observed IPCP IPv4 address: {addr}"));
            if !apply_network || network_apply_thread.is_some() {
                return;
            }
            if let Some(expected) = expected_interface_addr {
                if addr != expected {
                    logger::debug(&format!(
                        "ignoring IPCP IPv4 address {addr}; waiting for VPN interface address {expected}"
                    ));
                    return;
                }
            }
            let Some(platform) = apply_platform else {
                logger::warn("network configuration skipped: unsupported platform");
                return;
            };
            let network_config = apply_config.clone();
            let vpn_config = apply_vpn_config.clone();
            let preferred_interface = preferred_interface.clone();
            let tunnel_endpoint = apply_tunnel_endpoint;
            network_apply_thread = Some(thread::spawn(move || {
                apply_network_after_interface_up(
                    network_config,
                    vpn_config,
                    platform,
                    addr,
                    preferred_interface,
                    tunnel_endpoint,
                )
            }));
        },
        || stop_requested.load(Ordering::SeqCst),
    );

    match &forward_result {
        Ok(stats) => {
            logger::info(&format!(
                "forwarding stopped: pty->tls packets={}, tls->pty packets={}",
                stats.pty_to_tls_packets, stats.tls_to_pty_packets
            ));
            if let Some(addr) = stats.last_ipcp_ipv4 {
                logger::debug(&format!("last IPCP IPv4 address observed: {addr}"));
            }
        }
        Err(err) => logger::error(&format!("forwarding stopped with error: {err}")),
    }

    if let Some(handle) = network_apply_thread {
        logger::info("waiting for network setup thread");
        match handle.join() {
            Ok(Ok(Some(applied))) => {
                if !applied.is_empty() {
                    logger::info("restoring network configuration");
                    if let Err(err) = applied.rollback() {
                        logger::error(&format!("network cleanup failed: {err}"));
                    }
                }
            }
            Ok(Ok(None)) => {}
            Ok(Err(err)) => logger::error(&format!("network setup failed: {err}")),
            Err(_) => logger::error("network setup thread panicked"),
        }
    }

    #[cfg(unix)]
    {
        logger::info("terminating PPP process");
        if let Err(err) = terminate_pppd(pppd_pid) {
            logger::error(&format!("failed to terminate PPP process cleanly: {err}"));
        }
    }

    logger::info("logging out from gateway");
    if let Err(err) = TunnelSession::logout(&config, &cookie) {
        logger::error(&format!("logout failed: {err}"));
    }

    forward_result.map(|_| ())
}

fn build_ppp_backend_command(config: &Config) -> openfortivpn_rs::tunnel::pppd::PppdCommand {
    if config.ppp_system.is_some() {
        build_ppp_command(config, DEFAULT_PPP_PATH)
    } else {
        build_pppd_command(config, DEFAULT_PPPD_PATH)
    }
}

fn install_ctrlc_handler(stop_requested: Arc<AtomicBool>) -> Result<()> {
    ctrlc::set_handler(move || {
        stop_requested.store(true, Ordering::SeqCst);
    })
    .map_err(|err| OpenfortivpnError::Network(format!("failed to install Ctrl-C handler: {err}")))
}

#[cfg(unix)]
fn require_root() -> Result<()> {
    if unsafe { nix::libc::geteuid() } == 0 {
        Ok(())
    } else {
        Err(OpenfortivpnError::Network(
            "openfortivpn must be run as root to start pppd and configure routes/DNS".to_owned(),
        ))
    }
}

#[cfg(not(unix))]
fn require_root() -> Result<()> {
    Ok(())
}

fn apply_network_after_interface_up(
    config: Config,
    vpn_config: VpnConfigXml,
    platform: Platform,
    ipcp_addr: std::net::Ipv4Addr,
    preferred_interface: Option<String>,
    tunnel_endpoint: Option<Ipv4Addr>,
) -> Result<Option<AppliedNetworkPlan>> {
    let interface = wait_for_up_ppp_interface(
        ipcp_addr,
        preferred_interface.as_deref(),
        Duration::from_secs(60),
        Duration::from_millis(200),
    )?
    .ok_or_else(|| {
        OpenfortivpnError::Network(format!(
            "timed out waiting for PPP interface with IPv4 address {ipcp_addr}"
        ))
    })?;

    logger::info(&format!(
        "PPP interface {} is up with {}; applying network configuration",
        interface.name, interface.address
    ));
    let options = ApplyOptions {
        use_resolvconf: config.use_resolvconf,
    };
    let plan = plan_network_actions(
        &config,
        &vpn_config,
        platform,
        &interface.name,
        tunnel_endpoint,
    );
    if plan.actions.is_empty() {
        logger::info("no network configuration to apply");
        return Ok(None);
    }

    let applied = apply_network_plan(&plan, &options)?;
    logger::info("network configuration applied");
    Ok(Some(applied))
}

fn vpn_config_interface_addr(vpn_config: &VpnConfigXml) -> Option<Ipv4Addr> {
    vpn_config
        .assigned_ip
        .as_deref()
        .or(vpn_config.gateway.as_deref())
        .and_then(|addr| addr.parse().ok())
}

fn tunnel_endpoint_ipv4(addr: std::net::SocketAddr) -> Option<Ipv4Addr> {
    match addr.ip() {
        std::net::IpAddr::V4(addr) => Some(addr),
        std::net::IpAddr::V6(_) => None,
    }
}

fn current_platform() -> Option<Platform> {
    #[cfg(target_os = "linux")]
    {
        Some(Platform::Linux)
    }
    #[cfg(target_os = "macos")]
    {
        Some(Platform::MacOs)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        None
    }
}

fn describe_network_action(action: &NetworkAction) -> String {
    match action {
        NetworkAction::DropWrongTunnelRoute {
            platform: _,
            endpoint,
            interface,
        } => format!("drop wrong route to VPN endpoint {endpoint} via {interface}"),
        NetworkAction::ProtectTunnelRoute {
            platform: _,
            endpoint,
        } => format!("protect route to VPN endpoint {endpoint}"),
        NetworkAction::RunCommand { program, args } => {
            format!("{} {}", program, args.join(" "))
        }
        NetworkAction::ReplaceDefaultRoute {
            platform: _,
            interface,
        } => format!("replace default route via {interface}"),
        NetworkAction::ConfigureDns {
            platform: _,
            interface,
            servers,
            search_domain,
        } => {
            let mut parts = vec![format!("configure DNS on {interface}")];
            if !servers.is_empty() {
                parts.push(format!("servers={}", servers.join(",")));
            }
            if let Some(search_domain) = search_domain {
                parts.push(format!("search={search_domain}"));
            }
            parts.join(" ")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vpn_config_interface_addr_prefers_assigned_ip() {
        let vpn_config = VpnConfigXml {
            raw_xml: String::new(),
            gateway: Some("10.0.0.1".to_owned()),
            assigned_ip: Some("10.0.0.2".to_owned()),
            dns_servers: Vec::new(),
            dns_suffix: None,
            split_routes: Vec::new(),
        };

        assert_eq!(
            vpn_config_interface_addr(&vpn_config),
            Some("10.0.0.2".parse().unwrap())
        );
    }

    #[test]
    fn vpn_config_interface_addr_falls_back_to_gateway() {
        let vpn_config = VpnConfigXml {
            raw_xml: String::new(),
            gateway: Some("10.0.0.1".to_owned()),
            assigned_ip: None,
            dns_servers: Vec::new(),
            dns_suffix: None,
            split_routes: Vec::new(),
        };

        assert_eq!(
            vpn_config_interface_addr(&vpn_config),
            Some("10.0.0.1".parse().unwrap())
        );
    }
}
