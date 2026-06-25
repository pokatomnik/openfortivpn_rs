use std::time::Duration;

use crate::error::Result;
use crate::tls::TlsConnection;
use crate::tunnel::io::{read_tls_packet, write_tls_packet};
use crate::tunnel::packet::PppPacket;

pub struct FortinetTransport {
    stream: TlsConnection,
}

impl FortinetTransport {
    pub fn new(stream: TlsConnection) -> Self {
        Self { stream }
    }

    pub fn read_packet(&mut self) -> Result<PppPacket> {
        read_tls_packet(&mut self.stream)
    }

    pub fn write_packet(&mut self, packet: &PppPacket) -> Result<()> {
        write_tls_packet(&mut self.stream, packet)
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.stream.set_read_timeout(timeout)
    }

    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.stream.set_write_timeout(timeout)
    }

    pub fn into_inner(self) -> TlsConnection {
        self.stream
    }
}
