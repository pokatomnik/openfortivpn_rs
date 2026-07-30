use std::collections::VecDeque;
use std::net::Ipv4Addr;

use crate::error::{OpenfortivpnError, Result};
use crate::tunnel::packet::PppPacket;

const PROTOCOL_IPV4: u16 = 0x0021;
const PROTOCOL_LCP: u16 = 0xc021;
const PROTOCOL_IPCP: u16 = 0x8021;

const CODE_CONFIGURE_REQUEST: u8 = 1;
const CODE_CONFIGURE_ACK: u8 = 2;
const CODE_CONFIGURE_NAK: u8 = 3;
const CODE_CONFIGURE_REJECT: u8 = 4;
const CODE_TERMINATE_REQUEST: u8 = 5;
const CODE_TERMINATE_ACK: u8 = 6;
const CODE_CODE_REJECT: u8 = 7;
const CODE_PROTOCOL_REJECT: u8 = 8;
const CODE_ECHO_REQUEST: u8 = 9;
const CODE_ECHO_REPLY: u8 = 10;

const LCP_OPTION_MRU: u8 = 1;
const LCP_DEFAULT_MRU: u16 = 1354;
const IPCP_OPTION_IP_ADDRESS: u8 = 3;
const PPP_CONTROL_HEADER_LEN: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PppEvent {
    Up {
        local_ip: Ipv4Addr,
        peer_ip: Option<Ipv4Addr>,
        dns_servers: Vec<Ipv4Addr>,
    },
    Ipv4Packet(Vec<u8>),
    Down,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinkState {
    Initial,
    LcpRequestSent,
    LcpOpened,
    IpcpRequestSent,
    Opened,
    Closed,
}

impl Default for LinkState {
    fn default() -> Self {
        Self::Initial
    }
}

#[derive(Debug)]
pub struct PppEngine {
    state: LinkState,
    next_identifier: u8,
    lcp_identifier: Option<u8>,
    ipcp_identifier: Option<u8>,
    requested_ip: Ipv4Addr,
    local_ip: Option<Ipv4Addr>,
    peer_ip: Option<Ipv4Addr>,
    outgoing: VecDeque<PppPacket>,
}

impl Default for PppEngine {
    fn default() -> Self {
        Self {
            state: LinkState::Initial,
            next_identifier: 1,
            lcp_identifier: None,
            ipcp_identifier: None,
            requested_ip: Ipv4Addr::UNSPECIFIED,
            local_ip: None,
            peer_ip: None,
            outgoing: VecDeque::new(),
        }
    }
}

impl PppEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn start(&mut self) {
        if self.state != LinkState::Initial {
            return;
        }
        self.send_lcp_configure_request();
        self.state = LinkState::LcpRequestSent;
    }

    pub fn handle_incoming(&mut self, packet: &PppPacket) -> Result<Vec<PppEvent>> {
        match ppp_protocol(&packet.data)? {
            PROTOCOL_IPV4 => Ok(vec![PppEvent::Ipv4Packet(packet.data[2..].to_vec())]),
            PROTOCOL_LCP => self.handle_lcp(&packet.data[2..]),
            PROTOCOL_IPCP => self.handle_ipcp(&packet.data[2..]),
            protocol => {
                self.queue_protocol_reject(protocol, &packet.data[2..]);
                Ok(Vec::new())
            }
        }
    }

    pub fn next_outgoing(&mut self) -> Option<PppPacket> {
        self.outgoing.pop_front()
    }

    pub fn drain_outgoing(&mut self) -> Vec<PppPacket> {
        self.outgoing.drain(..).collect()
    }

    pub fn is_open(&self) -> bool {
        self.state == LinkState::Opened
    }

    pub fn encode_ipv4_packet(&self, packet: &[u8]) -> Result<PppPacket> {
        if packet.is_empty() || packet[0] >> 4 != 4 {
            return Err(OpenfortivpnError::Pppd(
                "proxy PPP engine can only send IPv4 packets".to_owned(),
            ));
        }

        let mut data = Vec::with_capacity(2 + packet.len());
        data.extend_from_slice(&PROTOCOL_IPV4.to_be_bytes());
        data.extend_from_slice(packet);
        Ok(PppPacket::new(data))
    }

    pub fn local_ip(&self) -> Option<Ipv4Addr> {
        self.local_ip
    }

    pub fn peer_ip(&self) -> Option<Ipv4Addr> {
        self.peer_ip
    }

    fn handle_lcp(&mut self, payload: &[u8]) -> Result<Vec<PppEvent>> {
        let packet = parse_control_packet(payload)?;
        match packet.code {
            CODE_CONFIGURE_REQUEST => {
                self.queue_control(
                    PROTOCOL_LCP,
                    CODE_CONFIGURE_ACK,
                    packet.identifier,
                    packet.options,
                );
                if matches!(self.state, LinkState::Initial) {
                    self.send_lcp_configure_request();
                    self.state = LinkState::LcpRequestSent;
                }
                Ok(Vec::new())
            }
            CODE_CONFIGURE_ACK if Some(packet.identifier) == self.lcp_identifier => {
                if matches!(self.state, LinkState::LcpRequestSent | LinkState::Initial) {
                    self.state = LinkState::LcpOpened;
                    self.send_ipcp_configure_request();
                    self.state = LinkState::IpcpRequestSent;
                }
                Ok(Vec::new())
            }
            CODE_CONFIGURE_NAK | CODE_CONFIGURE_REJECT
                if Some(packet.identifier) == self.lcp_identifier =>
            {
                self.send_lcp_configure_request();
                Ok(Vec::new())
            }
            CODE_ECHO_REQUEST => {
                let mut reply = Vec::new();
                reply.extend_from_slice(&0u32.to_be_bytes());
                if packet.options.len() > 4 {
                    reply.extend_from_slice(&packet.options[4..]);
                }
                self.queue_control(PROTOCOL_LCP, CODE_ECHO_REPLY, packet.identifier, &reply);
                Ok(Vec::new())
            }
            CODE_TERMINATE_REQUEST => {
                self.queue_control(
                    PROTOCOL_LCP,
                    CODE_TERMINATE_ACK,
                    packet.identifier,
                    packet.options,
                );
                self.state = LinkState::Closed;
                Ok(vec![PppEvent::Down])
            }
            CODE_CODE_REJECT | CODE_PROTOCOL_REJECT | CODE_ECHO_REPLY | CODE_TERMINATE_ACK => {
                Ok(Vec::new())
            }
            _ => {
                self.queue_control(PROTOCOL_LCP, CODE_CODE_REJECT, packet.identifier, payload);
                Ok(Vec::new())
            }
        }
    }

    fn handle_ipcp(&mut self, payload: &[u8]) -> Result<Vec<PppEvent>> {
        let packet = parse_control_packet(payload)?;
        match packet.code {
            CODE_CONFIGURE_REQUEST => {
                self.peer_ip = parse_ipcp_ip_address(packet.options);
                self.queue_control(
                    PROTOCOL_IPCP,
                    CODE_CONFIGURE_ACK,
                    packet.identifier,
                    packet.options,
                );
                Ok(Vec::new())
            }
            CODE_CONFIGURE_ACK if Some(packet.identifier) == self.ipcp_identifier => {
                let acknowledged_ip =
                    parse_ipcp_ip_address(packet.options).unwrap_or(self.requested_ip);
                if acknowledged_ip != Ipv4Addr::UNSPECIFIED {
                    self.local_ip = Some(acknowledged_ip);
                    self.state = LinkState::Opened;
                    Ok(vec![PppEvent::Up {
                        local_ip: acknowledged_ip,
                        peer_ip: self.peer_ip,
                        dns_servers: Vec::new(),
                    }])
                } else {
                    self.send_ipcp_configure_request();
                    Ok(Vec::new())
                }
            }
            CODE_CONFIGURE_NAK if Some(packet.identifier) == self.ipcp_identifier => {
                if let Some(ip) = parse_ipcp_ip_address(packet.options) {
                    self.requested_ip = ip;
                }
                self.send_ipcp_configure_request();
                Ok(Vec::new())
            }
            CODE_CONFIGURE_REJECT if Some(packet.identifier) == self.ipcp_identifier => {
                self.requested_ip = Ipv4Addr::UNSPECIFIED;
                self.send_ipcp_configure_request();
                Ok(Vec::new())
            }
            CODE_TERMINATE_REQUEST => {
                self.queue_control(
                    PROTOCOL_IPCP,
                    CODE_TERMINATE_ACK,
                    packet.identifier,
                    packet.options,
                );
                self.state = LinkState::Closed;
                Ok(vec![PppEvent::Down])
            }
            CODE_CODE_REJECT | CODE_TERMINATE_ACK => Ok(Vec::new()),
            _ => {
                self.queue_control(PROTOCOL_IPCP, CODE_CODE_REJECT, packet.identifier, payload);
                Ok(Vec::new())
            }
        }
    }

    fn send_lcp_configure_request(&mut self) {
        let identifier = self.next_identifier();
        self.lcp_identifier = Some(identifier);
        let mut options = Vec::new();
        options.extend_from_slice(&[LCP_OPTION_MRU, 4]);
        options.extend_from_slice(&LCP_DEFAULT_MRU.to_be_bytes());
        self.queue_control(PROTOCOL_LCP, CODE_CONFIGURE_REQUEST, identifier, &options);
    }

    fn send_ipcp_configure_request(&mut self) {
        let identifier = self.next_identifier();
        self.ipcp_identifier = Some(identifier);
        let mut options = Vec::new();
        options.extend_from_slice(&[IPCP_OPTION_IP_ADDRESS, 6]);
        options.extend_from_slice(&self.requested_ip.octets());
        self.queue_control(PROTOCOL_IPCP, CODE_CONFIGURE_REQUEST, identifier, &options);
    }

    fn queue_control(&mut self, protocol: u16, code: u8, identifier: u8, payload: &[u8]) {
        let length = (PPP_CONTROL_HEADER_LEN + payload.len()) as u16;
        let mut data = Vec::with_capacity(2 + PPP_CONTROL_HEADER_LEN + payload.len());
        data.extend_from_slice(&protocol.to_be_bytes());
        data.push(code);
        data.push(identifier);
        data.extend_from_slice(&length.to_be_bytes());
        data.extend_from_slice(payload);
        self.outgoing.push_back(PppPacket::new(data));
    }

    fn queue_protocol_reject(&mut self, protocol: u16, payload: &[u8]) {
        let identifier = self.next_identifier();
        let mut rejected = Vec::with_capacity(2 + payload.len());
        rejected.extend_from_slice(&protocol.to_be_bytes());
        rejected.extend_from_slice(payload);
        self.queue_control(PROTOCOL_LCP, CODE_PROTOCOL_REJECT, identifier, &rejected);
    }

    fn next_identifier(&mut self) -> u8 {
        let id = self.next_identifier;
        self.next_identifier = self.next_identifier.wrapping_add(1);
        if self.next_identifier == 0 {
            self.next_identifier = 1;
        }
        id
    }
}

#[derive(Debug, Clone, Copy)]
struct ControlPacket<'a> {
    code: u8,
    identifier: u8,
    options: &'a [u8],
}

fn parse_control_packet(payload: &[u8]) -> Result<ControlPacket<'_>> {
    if payload.len() < PPP_CONTROL_HEADER_LEN {
        return Err(OpenfortivpnError::HdlcInvalidFrame);
    }
    let length = u16::from_be_bytes([payload[2], payload[3]]) as usize;
    if length < PPP_CONTROL_HEADER_LEN || payload.len() < length {
        return Err(OpenfortivpnError::HdlcInvalidFrame);
    }
    Ok(ControlPacket {
        code: payload[0],
        identifier: payload[1],
        options: &payload[PPP_CONTROL_HEADER_LEN..length],
    })
}

fn parse_ipcp_ip_address(options: &[u8]) -> Option<Ipv4Addr> {
    let mut offset = 0;
    while offset + 2 <= options.len() {
        let option_type = options[offset];
        let option_len = options[offset + 1] as usize;
        if option_len < 2 || offset + option_len > options.len() {
            return None;
        }
        if option_type == IPCP_OPTION_IP_ADDRESS && option_len == 6 {
            return Some(Ipv4Addr::new(
                options[offset + 2],
                options[offset + 3],
                options[offset + 4],
                options[offset + 5],
            ));
        }
        offset += option_len;
    }
    None
}

fn ppp_protocol(data: &[u8]) -> Result<u16> {
    if data.len() < 2 {
        return Err(OpenfortivpnError::HdlcInvalidFrame);
    }
    Ok(u16::from_be_bytes([data[0], data[1]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn control(protocol: u16, code: u8, identifier: u8, options: &[u8]) -> PppPacket {
        let mut data = Vec::new();
        data.extend_from_slice(&protocol.to_be_bytes());
        data.push(code);
        data.push(identifier);
        data.extend_from_slice(&((PPP_CONTROL_HEADER_LEN + options.len()) as u16).to_be_bytes());
        data.extend_from_slice(options);
        PppPacket::new(data)
    }

    #[test]
    fn start_sends_lcp_configure_request() {
        let mut engine = PppEngine::new();

        engine.start();
        let packets = engine.drain_outgoing();

        assert_eq!(packets.len(), 1);
        assert_eq!(
            &packets[0].data[0..4],
            [0xc0, 0x21, CODE_CONFIGURE_REQUEST, 1]
        );
        assert_eq!(&packets[0].data[6..], [LCP_OPTION_MRU, 4, 0x05, 0x4a]);
    }

    #[test]
    fn acks_peer_lcp_configure_request() {
        let mut engine = PppEngine::new();
        let request = control(
            PROTOCOL_LCP,
            CODE_CONFIGURE_REQUEST,
            7,
            &[LCP_OPTION_MRU, 4, 0x05, 0x4a],
        );

        let events = engine.handle_incoming(&request).unwrap();
        let packets = engine.drain_outgoing();

        assert!(events.is_empty());
        assert_eq!(packets.len(), 2);
        assert_eq!(&packets[0].data[0..4], [0xc0, 0x21, CODE_CONFIGURE_ACK, 7]);
        assert_eq!(&packets[0].data[6..], [LCP_OPTION_MRU, 4, 0x05, 0x4a]);
        assert_eq!(
            &packets[1].data[0..4],
            [0xc0, 0x21, CODE_CONFIGURE_REQUEST, 1]
        );
    }

    #[test]
    fn lcp_ack_starts_ipcp_request() {
        let mut engine = PppEngine::new();
        engine.start();
        engine.drain_outgoing();
        let ack = control(
            PROTOCOL_LCP,
            CODE_CONFIGURE_ACK,
            1,
            &[LCP_OPTION_MRU, 4, 0x05, 0x4a],
        );

        engine.handle_incoming(&ack).unwrap();
        let packets = engine.drain_outgoing();

        assert_eq!(packets.len(), 1);
        assert_eq!(
            &packets[0].data[0..4],
            [0x80, 0x21, CODE_CONFIGURE_REQUEST, 2]
        );
        assert_eq!(
            &packets[0].data[6..],
            [IPCP_OPTION_IP_ADDRESS, 6, 0, 0, 0, 0]
        );
    }

    #[test]
    fn ipcp_nak_updates_requested_ip_and_retries() {
        let mut engine = PppEngine::new();
        engine.start();
        engine.drain_outgoing();
        engine
            .handle_incoming(&control(
                PROTOCOL_LCP,
                CODE_CONFIGURE_ACK,
                1,
                &[LCP_OPTION_MRU, 4, 0x05, 0x4a],
            ))
            .unwrap();
        engine.drain_outgoing();
        let nak = control(
            PROTOCOL_IPCP,
            CODE_CONFIGURE_NAK,
            2,
            &[IPCP_OPTION_IP_ADDRESS, 6, 10, 0, 0, 42],
        );

        engine.handle_incoming(&nak).unwrap();
        let packets = engine.drain_outgoing();

        assert_eq!(packets.len(), 1);
        assert_eq!(
            &packets[0].data[0..4],
            [0x80, 0x21, CODE_CONFIGURE_REQUEST, 3]
        );
        assert_eq!(
            &packets[0].data[6..],
            [IPCP_OPTION_IP_ADDRESS, 6, 10, 0, 0, 42]
        );
    }

    #[test]
    fn ipcp_ack_opens_link() {
        let mut engine = PppEngine::new();
        engine.start();
        engine.drain_outgoing();
        engine
            .handle_incoming(&control(
                PROTOCOL_LCP,
                CODE_CONFIGURE_ACK,
                1,
                &[LCP_OPTION_MRU, 4, 0x05, 0x4a],
            ))
            .unwrap();
        engine.drain_outgoing();
        engine
            .handle_incoming(&control(
                PROTOCOL_IPCP,
                CODE_CONFIGURE_NAK,
                2,
                &[IPCP_OPTION_IP_ADDRESS, 6, 10, 0, 0, 42],
            ))
            .unwrap();
        engine.drain_outgoing();
        let ack = control(
            PROTOCOL_IPCP,
            CODE_CONFIGURE_ACK,
            3,
            &[IPCP_OPTION_IP_ADDRESS, 6, 10, 0, 0, 42],
        );

        let events = engine.handle_incoming(&ack).unwrap();

        assert_eq!(engine.local_ip(), Some(Ipv4Addr::new(10, 0, 0, 42)));
        assert!(engine.is_open());
        assert_eq!(
            events,
            vec![PppEvent::Up {
                local_ip: Ipv4Addr::new(10, 0, 0, 42),
                peer_ip: None,
                dns_servers: Vec::new(),
            }]
        );
    }

    #[test]
    fn echo_request_gets_echo_reply() {
        let mut engine = PppEngine::new();
        let request = control(
            PROTOCOL_LCP,
            CODE_ECHO_REQUEST,
            9,
            &[0, 0, 0, 1, b'p', b'i', b'n', b'g'],
        );

        engine.handle_incoming(&request).unwrap();
        let packets = engine.drain_outgoing();

        assert_eq!(packets.len(), 1);
        assert_eq!(&packets[0].data[0..4], [0xc0, 0x21, CODE_ECHO_REPLY, 9]);
        assert_eq!(&packets[0].data[6..], [0, 0, 0, 0, b'p', b'i', b'n', b'g']);
    }

    #[test]
    fn unsupported_protocol_gets_protocol_reject() {
        let mut engine = PppEngine::new();
        let packet = PppPacket::new([0x80, 0xfd, 0x01, 0x02]);

        engine.handle_incoming(&packet).unwrap();
        let packets = engine.drain_outgoing();

        assert_eq!(packets.len(), 1);
        assert_eq!(&packets[0].data[0..3], [0xc0, 0x21, CODE_PROTOCOL_REJECT]);
        assert_eq!(&packets[0].data[6..], [0x80, 0xfd, 0x01, 0x02]);
    }

    #[test]
    fn extracts_ipv4_payload_from_ppp_packet() {
        let mut engine = PppEngine::new();
        let packet = PppPacket::new([0x00, 0x21, 0x45, 0x00, 0x00, 0x14]);

        let events = engine.handle_incoming(&packet).unwrap();

        assert_eq!(
            events,
            vec![PppEvent::Ipv4Packet(vec![0x45, 0x00, 0x00, 0x14])]
        );
    }

    #[test]
    fn encodes_ipv4_payload_as_ppp_packet() {
        let engine = PppEngine::new();

        let packet = engine
            .encode_ipv4_packet(&[0x45, 0x00, 0x00, 0x14])
            .unwrap();

        assert_eq!(packet.data, [0x00, 0x21, 0x45, 0x00, 0x00, 0x14]);
    }

    #[test]
    fn rejects_non_ipv4_payload() {
        let engine = PppEngine::new();

        assert!(engine.encode_ipv4_packet(&[0x60, 0x00]).is_err());
    }
}
