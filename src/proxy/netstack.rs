use std::collections::VecDeque;
use std::net::Ipv4Addr;

use smoltcp::iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::socket::tcp::State as TcpState;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address};

pub const DEFAULT_PROXY_MTU: usize = 1354;
pub const DEFAULT_TCP_BUFFER_SIZE: usize = 256 * 1024;

pub struct ProxyNetStack<'a> {
    iface: Interface,
    sockets: SocketSet<'a>,
    device: PppDevice,
    next_ephemeral_port: u16,
}

impl<'a> ProxyNetStack<'a> {
    pub fn new(local_ip: Ipv4Addr, peer_ip: Option<Ipv4Addr>, now: Instant) -> Self {
        let mut device = PppDevice::new(DEFAULT_PROXY_MTU);
        let mut config = InterfaceConfig::new(HardwareAddress::Ip);
        config.random_seed = random_seed(local_ip);
        let mut iface = Interface::new(config, &mut device, now);
        iface.update_ip_addrs(|ip_addrs| {
            ip_addrs
                .push(IpCidr::new(to_smoltcp_ip(local_ip), 32))
                .unwrap();
        });
        iface
            .routes_mut()
            .add_default_ipv4_route(to_smoltcp_ipv4(peer_ip.unwrap_or(local_ip)))
            .unwrap();

        Self {
            iface,
            sockets: SocketSet::new(vec![]),
            device,
            next_ephemeral_port: 49152,
        }
    }

    pub fn add_tcp_socket(&mut self) -> SocketHandle {
        let rx = tcp::SocketBuffer::new(vec![0; DEFAULT_TCP_BUFFER_SIZE]);
        let tx = tcp::SocketBuffer::new(vec![0; DEFAULT_TCP_BUFFER_SIZE]);
        self.sockets.add(tcp::Socket::new(rx, tx))
    }

    pub fn connect_tcp(
        &mut self,
        handle: SocketHandle,
        remote: Ipv4Addr,
        port: u16,
    ) -> Result<(), tcp::ConnectError> {
        let local_port = self.next_port();
        let socket = self.sockets.get_mut::<tcp::Socket>(handle);
        socket.connect(
            self.iface.context(),
            (to_smoltcp_ip(remote), port),
            local_port,
        )
    }

    pub fn poll(&mut self, now: Instant) -> bool {
        self.iface.poll(now, &mut self.device, &mut self.sockets)
    }

    pub fn tcp_state(&mut self, handle: SocketHandle) -> TcpState {
        self.sockets.get_mut::<tcp::Socket>(handle).state()
    }

    pub fn tcp_is_established(&mut self, handle: SocketHandle) -> bool {
        self.tcp_state(handle) == TcpState::Established
    }

    pub fn tcp_is_active(&mut self, handle: SocketHandle) -> bool {
        self.sockets.get_mut::<tcp::Socket>(handle).is_active()
    }

    pub fn tcp_can_send(&mut self, handle: SocketHandle) -> bool {
        self.sockets.get_mut::<tcp::Socket>(handle).can_send()
    }

    pub fn tcp_send(&mut self, handle: SocketHandle, data: &[u8]) -> Result<usize, tcp::SendError> {
        self.sockets.get_mut::<tcp::Socket>(handle).send_slice(data)
    }

    pub fn tcp_recv(
        &mut self,
        handle: SocketHandle,
        data: &mut [u8],
    ) -> Result<usize, tcp::RecvError> {
        self.sockets.get_mut::<tcp::Socket>(handle).recv_slice(data)
    }

    pub fn tcp_close(&mut self, handle: SocketHandle) {
        self.sockets.get_mut::<tcp::Socket>(handle).close();
    }

    pub fn remove_tcp_socket(&mut self, handle: SocketHandle) {
        self.sockets.remove(handle);
    }

    pub fn push_rx_ipv4(&mut self, packet: Vec<u8>) {
        self.device.push_rx(packet);
    }

    pub fn pop_tx_ipv4(&mut self) -> Option<Vec<u8>> {
        self.device.pop_tx()
    }

    fn next_port(&mut self) -> u16 {
        let port = self.next_ephemeral_port;
        self.next_ephemeral_port = if self.next_ephemeral_port == 65535 {
            49152
        } else {
            self.next_ephemeral_port + 1
        };
        port
    }
}

fn to_smoltcp_ip(addr: Ipv4Addr) -> IpAddress {
    let [a, b, c, d] = addr.octets();
    IpAddress::v4(a, b, c, d)
}

fn to_smoltcp_ipv4(addr: Ipv4Addr) -> Ipv4Address {
    let [a, b, c, d] = addr.octets();
    Ipv4Address::new(a, b, c, d)
}

fn random_seed(local_ip: Ipv4Addr) -> u64 {
    0x6f70656e66740000u64 | u64::from(u32::from(local_ip))
}

#[derive(Debug, Default)]
pub struct PppDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl PppDevice {
    pub fn new(mtu: usize) -> Self {
        Self {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            mtu,
        }
    }

    pub fn push_rx(&mut self, packet: Vec<u8>) {
        if !packet.is_empty() {
            self.rx.push_back(packet);
        }
    }

    pub fn pop_tx(&mut self) -> Option<Vec<u8>> {
        self.tx.pop_front()
    }

    pub fn rx_len(&self) -> usize {
        self.rx.len()
    }

    pub fn tx_len(&self) -> usize {
        self.tx.len()
    }
}

impl Device for PppDevice {
    type RxToken<'a>
        = PppRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = PppTxToken<'a>
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx.pop_front()?;
        Some((PppRxToken { packet }, PppTxToken { tx: &mut self.tx }))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(PppTxToken { tx: &mut self.tx })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps.max_burst_size = Some(64);
        caps
    }
}

pub struct PppRxToken {
    packet: Vec<u8>,
}

impl RxToken for PppRxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.packet)
    }
}

pub struct PppTxToken<'a> {
    tx: &'a mut VecDeque<Vec<u8>>,
}

impl TxToken for PppTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0; len];
        let result = f(&mut packet);
        if !packet.is_empty() {
            self.tx.push_back(packet);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netstack_creates_tcp_socket_and_connects_by_ipv4() {
        let mut netstack = ProxyNetStack::new(
            "10.33.1.138".parse().unwrap(),
            Some("10.33.1.1".parse().unwrap()),
            Instant::from_millis(0),
        );
        let handle = netstack.add_tcp_socket();

        netstack
            .connect_tcp(handle, "10.10.0.1".parse().unwrap(), 443)
            .unwrap();
        netstack.poll(Instant::from_millis(1));

        assert!(netstack.pop_tx_ipv4().is_some());
    }

    #[test]
    fn device_exposes_ip_medium_and_mtu() {
        let device = PppDevice::new(DEFAULT_PROXY_MTU);
        let caps = device.capabilities();

        assert_eq!(caps.medium, Medium::Ip);
        assert_eq!(caps.max_transmission_unit, DEFAULT_PROXY_MTU);
    }

    #[test]
    fn device_receives_queued_packets() {
        let mut device = PppDevice::new(DEFAULT_PROXY_MTU);
        device.push_rx(vec![0x45, 0x00, 0x00, 0x14]);

        let (rx, _) = device.receive(Instant::from_millis(0)).unwrap();
        let packet = rx.consume(|packet| packet.to_vec());

        assert_eq!(packet, [0x45, 0x00, 0x00, 0x14]);
        assert_eq!(device.rx_len(), 0);
    }

    #[test]
    fn device_queues_transmitted_packets() {
        let mut device = PppDevice::new(DEFAULT_PROXY_MTU);
        let tx = device.transmit(Instant::from_millis(0)).unwrap();

        tx.consume(4, |packet| {
            packet.copy_from_slice(&[0x45, 0x00, 0x00, 0x14])
        });

        assert_eq!(device.tx_len(), 1);
        assert_eq!(device.pop_tx(), Some(vec![0x45, 0x00, 0x00, 0x14]));
    }
}
