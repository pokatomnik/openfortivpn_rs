use std::io::{ErrorKind, Read};
use std::time::Duration;

use crate::error::{OpenfortivpnError, Result};
use crate::tls::TlsConnection;
use crate::tunnel::io::write_tls_packet;
use crate::tunnel::packet::{PppPacket, HEADER_LEN};

const HTTP_HEADER_PREFIX: &[u8; HEADER_LEN] = b"HTTP/1";
const READ_BUFFER_SIZE: usize = 16 * 1024;
const MAX_PACKET_BUFFER_SIZE: usize = 1024 * 1024;

pub struct FortinetTransport {
    stream: TlsConnection,
    read_buffer: Vec<u8>,
}

impl FortinetTransport {
    pub fn new(stream: TlsConnection) -> Self {
        Self {
            stream,
            read_buffer: Vec::new(),
        }
    }

    pub fn read_packet(&mut self) -> Result<PppPacket> {
        loop {
            if let Some(packet) = self.try_decode_buffered_packet()? {
                return Ok(packet);
            }

            let mut buf = [0; READ_BUFFER_SIZE];
            match self.stream.read(&mut buf) {
                Ok(0) => {
                    return Err(OpenfortivpnError::Io(std::io::Error::new(
                        ErrorKind::UnexpectedEof,
                        "VPN tunnel closed",
                    )))
                }
                Ok(n) => {
                    self.read_buffer.extend_from_slice(&buf[..n]);
                    if self.read_buffer.len() > MAX_PACKET_BUFFER_SIZE {
                        return Err(OpenfortivpnError::Network(
                            "Fortinet packet buffer exceeded maximum size".to_owned(),
                        ));
                    }
                }
                Err(err) => return Err(OpenfortivpnError::Io(err)),
            }
        }
    }

    fn try_decode_buffered_packet(&mut self) -> Result<Option<PppPacket>> {
        if self.read_buffer.len() < HEADER_LEN {
            return Ok(None);
        }
        if self.read_buffer[..HEADER_LEN] == *HTTP_HEADER_PREFIX {
            return Err(OpenfortivpnError::PermissionDenied);
        }

        let total = u16::from_be_bytes([self.read_buffer[0], self.read_buffer[1]]) as usize;
        if total < HEADER_LEN + 1 {
            return Err(OpenfortivpnError::HdlcInvalidFrame);
        }
        if self.read_buffer.len() < total {
            return Ok(None);
        }

        let frame: Vec<u8> = self.read_buffer.drain(..total).collect();
        Ok(Some(PppPacket::decode_from_tls_frame(&frame)?))
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
