use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant as StdInstant};

use smoltcp::iface::SocketHandle;
use smoltcp::time::Instant as SmolInstant;

use crate::error::{OpenfortivpnError, Result};
use crate::logger;
use crate::proxy::dns;
use crate::proxy::netstack::ProxyNetStack;
use crate::proxy::route_table::ProxyRouteTable;
use crate::proxy::socks5::{self, SocksTarget};
use crate::tunnel::fortinet::FortinetTransport;
use crate::tunnel::ppp_engine::{PppEngine, PppEvent};

const ACCEPT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const DNS_RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);
const RUNTIME_READ_TIMEOUT: Duration = Duration::from_millis(10);
const LOOP_SLEEP: Duration = Duration::from_millis(5);
const IO_BUFFER_SIZE: usize = 16 * 1024;

pub fn run(
    listen: SocketAddr,
    mut transport: FortinetTransport,
    mut ppp: PppEngine,
    route_table: ProxyRouteTable,
    dns_servers: Vec<Ipv4Addr>,
    stop_requested: &AtomicBool,
) -> Result<()> {
    let local_ip = ppp.local_ip().ok_or_else(|| {
        OpenfortivpnError::Pppd("proxy runtime requires an opened PPP link".to_owned())
    })?;
    let peer_ip = ppp.peer_ip();
    let mut netstack = ProxyNetStack::new(local_ip, peer_ip, smol_now());
    transport.set_read_timeout(Some(RUNTIME_READ_TIMEOUT))?;
    transport.set_write_timeout(Some(RUNTIME_READ_TIMEOUT))?;

    let listener = TcpListener::bind(listen)?;
    listener.set_nonblocking(true)?;
    logger::info(&format!("SOCKS5H proxy listening on {listen}"));

    let mut sessions = Vec::<ProxySession>::new();
    let mut next_session_id = 1u64;
    while !stop_requested.load(Ordering::SeqCst) {
        accept_ready_clients(
            &listener,
            &mut transport,
            &mut ppp,
            &mut netstack,
            &route_table,
            &dns_servers,
            &mut next_session_id,
            &mut sessions,
        )?;
        read_fortinet_packets(&mut transport, &mut ppp, &mut netstack)?;
        pump_local_to_tcp(&mut sessions, &mut netstack)?;
        netstack.poll(smol_now());
        pump_tcp_to_local(&mut sessions, &mut netstack)?;
        drain_netstack_to_fortinet(&mut netstack, &mut ppp, &mut transport)?;
        cleanup_sessions(&mut sessions, &mut netstack);
        std::thread::sleep(LOOP_SLEEP);
    }

    for session in &mut sessions {
        netstack.tcp_close(session.handle);
    }
    drain_netstack_to_fortinet(&mut netstack, &mut ppp, &mut transport)?;
    Ok(())
}

#[derive(Debug)]
struct ProxySession {
    id: u64,
    client: TcpStream,
    handle: SocketHandle,
    to_remote: VecDeque<u8>,
    to_client: VecDeque<u8>,
    socks_replied: bool,
    local_closed: bool,
    remote_closed: bool,
    client_to_remote_bytes: u64,
    remote_to_client_bytes: u64,
    client_addr: SocketAddr,
    target: String,
    close_reason: Option<String>,
}

fn accept_ready_clients(
    listener: &TcpListener,
    transport: &mut FortinetTransport,
    ppp: &mut PppEngine,
    netstack: &mut ProxyNetStack<'_>,
    route_table: &ProxyRouteTable,
    dns_servers: &[Ipv4Addr],
    next_session_id: &mut u64,
    sessions: &mut Vec<ProxySession>,
) -> Result<()> {
    loop {
        let (mut client, addr) = match listener.accept() {
            Ok(accepted) => accepted,
            Err(err) if err.kind() == ErrorKind::WouldBlock => return Ok(()),
            Err(err) => return Err(err.into()),
        };

        client.set_nonblocking(false)?;
        client.set_read_timeout(Some(ACCEPT_HANDSHAKE_TIMEOUT))?;
        client.set_write_timeout(Some(ACCEPT_HANDSHAKE_TIMEOUT))?;
        let mut client_writer = client.try_clone()?;
        let request = match socks5::read_connect_request(&mut client, &mut client_writer) {
            Ok(request) => request,
            Err(err) => {
                logger::warn(&format!("SOCKS5 handshake from {addr} failed: {err}"));
                continue;
            }
        };

        let destination = match request.target {
            SocksTarget::Ipv4(addr) => addr,
            SocksTarget::Domain(domain) => {
                match resolve_domain(&domain, dns_servers, transport, ppp, netstack, route_table) {
                    Ok(addr) => {
                        logger::info(&format!("resolved {domain} via VPN DNS to {addr}"));
                        addr
                    }
                    Err(err) => {
                        let _ = socks5::write_failure(&mut client, socks5::REPLY_HOST_UNREACHABLE);
                        logger::warn(&format!("failed to resolve {domain} via VPN DNS: {err}"));
                        continue;
                    }
                }
            }
        };

        if !route_table.can_route(destination) {
            let _ = socks5::write_failure(&mut client, socks5::REPLY_HOST_UNREACHABLE);
            logger::warn(&format!(
                "SOCKS5 target {}:{} rejected by proxy route table",
                destination, request.port
            ));
            continue;
        }

        let handle = netstack.add_tcp_socket();
        if let Err(err) = netstack.connect_tcp(handle, destination, request.port) {
            netstack.remove_tcp_socket(handle);
            let _ = socks5::write_failure(&mut client, socks5::REPLY_GENERAL_FAILURE);
            logger::warn(&format!(
                "failed to start proxy TCP connection to {}:{}: {err:?}",
                destination, request.port
            ));
            continue;
        }

        let session_id = *next_session_id;
        *next_session_id = next_session_id.wrapping_add(1).max(1);
        let target = format!("{}:{}", destination, request.port);

        client.set_read_timeout(None)?;
        client.set_write_timeout(None)?;
        client.set_nonblocking(true)?;
        logger::info(&format!(
            "SOCKS5 proxy session #{session_id} from {addr} to {target}"
        ));
        sessions.push(ProxySession {
            id: session_id,
            client,
            handle,
            to_remote: VecDeque::new(),
            to_client: VecDeque::new(),
            socks_replied: false,
            local_closed: false,
            remote_closed: false,
            client_to_remote_bytes: 0,
            remote_to_client_bytes: 0,
            client_addr: addr,
            target,
            close_reason: None,
        });
    }
}

fn resolve_domain(
    domain: &str,
    dns_servers: &[Ipv4Addr],
    transport: &mut FortinetTransport,
    ppp: &mut PppEngine,
    netstack: &mut ProxyNetStack<'_>,
    route_table: &ProxyRouteTable,
) -> Result<Ipv4Addr> {
    if dns_servers.is_empty() {
        return Err(OpenfortivpnError::Network(
            "VPN configuration did not provide DNS servers".to_owned(),
        ));
    }

    let query_id = dns_query_id(domain);
    let query = dns::build_tcp_query(query_id, domain)?;
    let mut last_error = None;

    for dns_server in dns_servers {
        let handle = netstack.add_tcp_socket();
        if let Err(err) = netstack.connect_tcp(handle, *dns_server, 53) {
            netstack.remove_tcp_socket(handle);
            last_error = Some(OpenfortivpnError::Network(format!(
                "failed to connect to DNS server {dns_server}: {err:?}"
            )));
            continue;
        }

        let deadline = StdInstant::now() + DNS_RESOLVE_TIMEOUT;
        let mut sent = false;
        let mut response = Vec::new();
        while StdInstant::now() < deadline {
            read_fortinet_packets(transport, ppp, netstack)?;
            netstack.poll(smol_now());

            if netstack.tcp_is_established(handle) && !sent {
                match netstack.tcp_send(handle, &query) {
                    Ok(written) if written == query.len() => sent = true,
                    Ok(_) => {
                        last_error = Some(OpenfortivpnError::Network(
                            "partial DNS query write".to_owned(),
                        ));
                        break;
                    }
                    Err(err) => {
                        last_error = Some(OpenfortivpnError::Network(format!(
                            "failed to send DNS query to {dns_server}: {err:?}"
                        )));
                        break;
                    }
                }
            }

            drain_netstack_to_fortinet(netstack, ppp, transport)?;

            if sent {
                let mut buf = [0; IO_BUFFER_SIZE];
                match netstack.tcp_recv(handle, &mut buf) {
                    Ok(0) => {}
                    Ok(n) => {
                        response.extend_from_slice(&buf[..n]);
                        match dns::parse_tcp_response(&response, query_id) {
                            Ok(addrs) if !addrs.is_empty() => {
                                netstack.tcp_close(handle);
                                netstack.remove_tcp_socket(handle);
                                if let Some(addr) = addrs
                                    .iter()
                                    .copied()
                                    .find(|addr| route_table.can_route(*addr))
                                {
                                    return Ok(addr);
                                }
                                return Ok(addrs[0]);
                            }
                            Ok(_) => {}
                            Err(err) => {
                                last_error = Some(err);
                                break;
                            }
                        }
                    }
                    Err(_) => {}
                }
            }

            if !netstack.tcp_is_active(handle) && sent {
                break;
            }
            std::thread::sleep(LOOP_SLEEP);
        }

        netstack.tcp_close(handle);
        netstack.remove_tcp_socket(handle);
    }

    Err(last_error.unwrap_or_else(|| {
        OpenfortivpnError::Network(format!("timed out resolving {domain} via VPN DNS"))
    }))
}

fn dns_query_id(domain: &str) -> u16 {
    domain
        .as_bytes()
        .iter()
        .fold(0x4f56u16, |acc, byte| acc.rotate_left(5) ^ u16::from(*byte))
}

fn read_fortinet_packets(
    transport: &mut FortinetTransport,
    ppp: &mut PppEngine,
    netstack: &mut ProxyNetStack<'_>,
) -> Result<()> {
    loop {
        let packet = match transport.read_packet() {
            Ok(packet) => packet,
            Err(OpenfortivpnError::Io(err))
                if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
            {
                return Ok(())
            }
            Err(err) => return Err(err),
        };

        for event in ppp.handle_incoming(&packet)? {
            match event {
                PppEvent::Ipv4Packet(packet) => netstack.push_rx_ipv4(packet),
                PppEvent::Down => {
                    return Err(OpenfortivpnError::Pppd(
                        "proxy PPP link terminated by peer".to_owned(),
                    ))
                }
                PppEvent::Up { .. } => {}
            }
        }
        flush_ppp_control(transport, ppp)?;
    }
}

fn pump_local_to_tcp(
    sessions: &mut [ProxySession],
    netstack: &mut ProxyNetStack<'_>,
) -> Result<()> {
    let mut buf = [0; IO_BUFFER_SIZE];
    for session in sessions {
        if session.local_closed || !session.socks_replied {
            continue;
        }

        while netstack.tcp_can_send(session.handle) && !session.to_remote.is_empty() {
            let chunk = drain_chunk(&mut session.to_remote, IO_BUFFER_SIZE);
            match netstack.tcp_send(session.handle, &chunk) {
                Ok(written) if written < chunk.len() => {
                    session.client_to_remote_bytes += written as u64;
                    push_front_bytes(&mut session.to_remote, &chunk[written..]);
                    break;
                }
                Ok(written) => {
                    session.client_to_remote_bytes += written as u64;
                }
                Err(err) => {
                    mark_closed(session, format!("proxy TCP send failed: {err:?}"));
                    netstack.tcp_close(session.handle);
                    break;
                }
            }
        }

        while netstack.tcp_can_send(session.handle) {
            match session.client.read(&mut buf) {
                Ok(0) => {
                    session.local_closed = true;
                    mark_closed(session, "client closed connection".to_owned());
                    netstack.tcp_close(session.handle);
                    break;
                }
                Ok(n) => match netstack.tcp_send(session.handle, &buf[..n]) {
                    Ok(written) if written < n => {
                        session.client_to_remote_bytes += written as u64;
                        session.to_remote.extend(&buf[written..n]);
                        break;
                    }
                    Ok(written) => {
                        session.client_to_remote_bytes += written as u64;
                    }
                    Err(err) => {
                        mark_closed(session, format!("proxy TCP send failed: {err:?}"));
                        netstack.tcp_close(session.handle);
                        break;
                    }
                },
                Err(err) if err.kind() == ErrorKind::WouldBlock => break,
                Err(err) => {
                    mark_closed(session, format!("client read failed: {err}"));
                    netstack.tcp_close(session.handle);
                    break;
                }
            }
        }
    }
    Ok(())
}

fn pump_tcp_to_local(
    sessions: &mut [ProxySession],
    netstack: &mut ProxyNetStack<'_>,
) -> Result<()> {
    let mut buf = [0; IO_BUFFER_SIZE];
    for session in sessions {
        if !session.socks_replied && netstack.tcp_is_established(session.handle) {
            socks5::write_success(&mut session.client, Ipv4Addr::UNSPECIFIED, 0)?;
            session.socks_replied = true;
        }

        loop {
            match netstack.tcp_recv(session.handle, &mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    session.remote_to_client_bytes += n as u64;
                    session.to_client.extend(&buf[..n]);
                }
                Err(err) => {
                    let _ = err;
                    break;
                }
            }
        }

        while !session.to_client.is_empty() {
            let chunk = drain_chunk(&mut session.to_client, IO_BUFFER_SIZE);
            match session.client.write(&chunk) {
                Ok(0) => {
                    push_front_bytes(&mut session.to_client, &chunk);
                    mark_closed(session, "client write returned zero".to_owned());
                    netstack.tcp_close(session.handle);
                    break;
                }
                Ok(written) if written < chunk.len() => {
                    push_front_bytes(&mut session.to_client, &chunk[written..]);
                    break;
                }
                Ok(_) => {}
                Err(err) if err.kind() == ErrorKind::WouldBlock => {
                    push_front_bytes(&mut session.to_client, &chunk);
                    break;
                }
                Err(err) => {
                    mark_closed(session, format!("client write failed: {err}"));
                    netstack.tcp_close(session.handle);
                    break;
                }
            }
        }
    }
    Ok(())
}

fn drain_netstack_to_fortinet(
    netstack: &mut ProxyNetStack<'_>,
    ppp: &mut PppEngine,
    transport: &mut FortinetTransport,
) -> Result<()> {
    while let Some(packet) = netstack.pop_tx_ipv4() {
        let ppp_packet = ppp.encode_ipv4_packet(&packet)?;
        transport.write_packet(&ppp_packet)?;
    }
    flush_ppp_control(transport, ppp)
}

fn flush_ppp_control(transport: &mut FortinetTransport, ppp: &mut PppEngine) -> Result<()> {
    while let Some(packet) = ppp.next_outgoing() {
        transport.write_packet(&packet)?;
    }
    Ok(())
}

fn cleanup_sessions(sessions: &mut Vec<ProxySession>, netstack: &mut ProxyNetStack<'_>) {
    let mut index = 0;
    while index < sessions.len() {
        let active = netstack.tcp_is_active(sessions[index].handle);
        if !active && !sessions[index].remote_closed {
            sessions[index].remote_closed = true;
            mark_closed(&mut sessions[index], "remote TCP closed".to_owned());
        }

        let remove = (sessions[index].local_closed || sessions[index].remote_closed)
            && sessions[index].to_client.is_empty()
            && sessions[index].to_remote.is_empty()
            && !active;
        if remove {
            let session = sessions.remove(index);
            logger::info(&format!(
                "SOCKS5 proxy session #{} closed: {} -> {}; client->remote={} bytes, remote->client={} bytes; reason: {}",
                session.id,
                session.client_addr,
                session.target,
                session.client_to_remote_bytes,
                session.remote_to_client_bytes,
                session.close_reason.as_deref().unwrap_or("unknown")
            ));
            netstack.remove_tcp_socket(session.handle);
        } else {
            index += 1;
        }
    }
}

fn mark_closed(session: &mut ProxySession, reason: String) {
    if session.close_reason.is_none() {
        session.close_reason = Some(reason);
    }
}

fn drain_chunk(queue: &mut VecDeque<u8>, max_len: usize) -> Vec<u8> {
    let len = queue.len().min(max_len);
    queue.drain(..len).collect()
}

fn push_front_bytes(queue: &mut VecDeque<u8>, bytes: &[u8]) {
    for byte in bytes.iter().rev() {
        queue.push_front(*byte);
    }
}

fn smol_now() -> SmolInstant {
    static START: std::sync::OnceLock<StdInstant> = std::sync::OnceLock::new();
    let start = START.get_or_init(StdInstant::now);
    SmolInstant::from_millis(start.elapsed().as_millis() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_helpers_preserve_order() {
        let mut queue = VecDeque::from(vec![1, 2, 3, 4]);
        let chunk = drain_chunk(&mut queue, 3);
        assert_eq!(chunk, [1, 2, 3]);
        assert_eq!(queue, VecDeque::from(vec![4]));

        push_front_bytes(&mut queue, &[8, 9]);
        assert_eq!(queue, VecDeque::from(vec![8, 9, 4]));
    }
}
