pub mod dns;
pub mod netstack;
pub mod route_table;
pub mod runtime;
pub mod socks5;

use std::io::ErrorKind;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::error::{OpenfortivpnError, Result};
use crate::logger;
use crate::tunnel::fortinet::FortinetTransport;
use crate::tunnel::ppp_engine::{PppEngine, PppEvent};
use crate::tunnel::session::TunnelSession;

const PPP_NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(30);
const PPP_READ_TIMEOUT: Duration = Duration::from_millis(250);

pub fn run(config: Config, stop_requested: Arc<AtomicBool>) -> Result<()> {
    if stop_requested.load(Ordering::SeqCst) {
        return Ok(());
    }

    logger::info("preparing TLS/authenticated tunnel for proxy mode");
    let session = TunnelSession::prepare(&config)?;
    let TunnelSession { prepared, stream } = session;
    logger::info(&format!(
        "authenticated; peer certificate sha256: {} ({:?})",
        prepared.peer_cert_sha256, prepared.certificate_verification
    ));

    let route_table = route_table::ProxyRouteTable::from_config(&config, &prepared.vpn_config);
    let dns_servers = prepared
        .vpn_config
        .dns_servers
        .iter()
        .filter_map(|addr| addr.parse().ok())
        .collect::<Vec<_>>();
    logger::info(&format!(
        "proxy route table prepared with {} route(s); DNS server(s): {}",
        route_table.len(),
        dns_servers.len()
    ));

    let mut transport = FortinetTransport::new(stream);
    let listen = config.proxy.ok_or_else(|| {
        OpenfortivpnError::Network("proxy mode requires --proxy listen address".to_owned())
    })?;
    let runtime_result = match establish_ppp(&mut transport, &stop_requested) {
        Ok(ppp) => runtime::run(
            listen,
            transport,
            ppp,
            route_table,
            dns_servers,
            &stop_requested,
        ),
        Err(err) => Err(err),
    };

    logger::info("logging out from gateway");
    if let Err(err) = TunnelSession::logout(&config, &prepared.cookie) {
        logger::error(&format!("logout failed: {err}"));
    }

    runtime_result
}

fn establish_ppp(
    transport: &mut FortinetTransport,
    stop_requested: &AtomicBool,
) -> Result<PppEngine> {
    transport.set_read_timeout(Some(PPP_READ_TIMEOUT))?;
    transport.set_write_timeout(Some(PPP_READ_TIMEOUT))?;

    let deadline = Instant::now() + PPP_NEGOTIATION_TIMEOUT;
    let mut ppp = PppEngine::new();
    ppp.start();
    flush_ppp_outgoing(transport, &mut ppp)?;
    logger::info("proxy PPP negotiation started");

    while Instant::now() < deadline {
        if stop_requested.load(Ordering::SeqCst) {
            return Err(OpenfortivpnError::Pppd(
                "proxy PPP negotiation interrupted".to_owned(),
            ));
        }

        let packet = match transport.read_packet() {
            Ok(packet) => packet,
            Err(OpenfortivpnError::Io(err))
                if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
            {
                continue;
            }
            Err(err) => return Err(err),
        };

        for event in ppp.handle_incoming(&packet)? {
            match event {
                PppEvent::Up { local_ip, .. } => {
                    flush_ppp_outgoing(transport, &mut ppp)?;
                    logger::info(&format!(
                        "proxy PPP negotiation completed; local IPv4 {local_ip}"
                    ));
                    return Ok(ppp);
                }
                PppEvent::Down => {
                    return Err(OpenfortivpnError::Pppd(
                        "proxy PPP negotiation terminated by peer".to_owned(),
                    ));
                }
                PppEvent::Ipv4Packet(_) => {}
            }
        }
        flush_ppp_outgoing(transport, &mut ppp)?;
    }

    Err(OpenfortivpnError::Pppd(
        "timed out waiting for proxy PPP negotiation".to_owned(),
    ))
}

fn flush_ppp_outgoing(transport: &mut FortinetTransport, ppp: &mut PppEngine) -> Result<()> {
    while let Some(packet) = ppp.next_outgoing() {
        transport.write_packet(&packet)?;
    }
    Ok(())
}
