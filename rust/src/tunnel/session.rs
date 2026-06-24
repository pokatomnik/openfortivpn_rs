use std::net::SocketAddr;

use crate::auth::{login, portal};
use crate::config::Config;
use crate::error::Result;
use crate::logger;
use crate::tls::{CertificateVerification, TlsConnection};
use crate::tunnel::io::send_start_tunnel_request;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedTunnel {
    pub cookie: String,
    pub vpn_config: portal::VpnConfigXml,
    pub peer_cert_sha256: String,
    pub certificate_verification: CertificateVerification,
    pub tcp_peer_addr: SocketAddr,
}

pub struct TunnelSession {
    pub prepared: PreparedTunnel,
    pub stream: TlsConnection,
}

impl TunnelSession {
    pub fn prepare(config: &Config) -> Result<Self> {
        // Step 1/2 in C: connect and authenticate.
        logger::info(&format!(
            "connecting to VPN gateway {}:{}",
            config.gateway_host, config.gateway_port
        ));
        let mut auth_stream = TlsConnection::connect(config)?;
        let peer_cert_sha256 = auth_stream.peer_cert_sha256().to_owned();
        let certificate_verification = auth_stream.verification();
        let auth_session = if let Some(saml_session_id) = &config.saml_session_id {
            login::authenticate_with_saml_session(&mut auth_stream, config, saml_session_id)?
        } else {
            login::authenticate(&mut auth_stream, config)?
        };
        let cookie = auth_session.cookie.clone();
        logger::info("authentication completed; requesting VPN allocation");

        // Step 2b in C: request VPN allocation on the authenticated HTTP connection.
        portal::request_vpn_allocation(
            &mut auth_stream,
            config,
            &cookie,
            auth_session.portal_redirect.as_deref(),
        )?;
        drop(auth_stream);

        // Step 3 in C: reconnect and retrieve VPN config.
        logger::info("VPN allocation completed; reconnecting for tunnel configuration");
        let mut tunnel_stream = TlsConnection::connect(config)?;
        let tcp_peer_addr = tunnel_stream.tcp_peer_addr();
        let vpn_config = portal::get_vpn_config(&mut tunnel_stream, config, &cookie)?;
        logger::info("VPN configuration retrieved; starting SSLVPN tunnel request");

        // Step 5 in C: switch this TLS connection to PPP tunnel mode.
        // Step 4 (pppd spawn) and Step 6 (forwarding loop) are wired separately.
        send_start_tunnel_request(&mut tunnel_stream, &cookie)?;

        Ok(Self {
            prepared: PreparedTunnel {
                cookie,
                vpn_config,
                peer_cert_sha256,
                certificate_verification,
                tcp_peer_addr,
            },
            stream: tunnel_stream,
        })
    }

    pub fn logout(config: &Config, cookie: &str) -> Result<()> {
        let mut stream = TlsConnection::connect(config)?;
        portal::log_out(&mut stream, config, cookie)
    }
}
