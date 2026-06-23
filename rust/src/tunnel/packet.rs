use std::net::Ipv4Addr;

use crate::error::{OpenfortivpnError, Result};

pub const FORTINET_MAGIC: u16 = 0x5050;
pub const HEADER_LEN: usize = 6;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PppPacket {
    pub data: Vec<u8>,
}

impl PppPacket {
    pub fn new(data: impl Into<Vec<u8>>) -> Self {
        Self { data: data.into() }
    }

    pub fn encode_for_tls(&self) -> Result<Vec<u8>> {
        if self.data.len() > u16::MAX as usize - HEADER_LEN {
            return Err(OpenfortivpnError::HdlcInvalidFrame);
        }

        let total = (HEADER_LEN + self.data.len()) as u16;
        let size = self.data.len() as u16;
        let mut out = Vec::with_capacity(HEADER_LEN + self.data.len());
        out.extend_from_slice(&total.to_be_bytes());
        out.extend_from_slice(&FORTINET_MAGIC.to_be_bytes());
        out.extend_from_slice(&size.to_be_bytes());
        out.extend_from_slice(&self.data);
        Ok(out)
    }

    pub fn decode_from_tls_frame(frame: &[u8]) -> Result<Self> {
        if frame.len() < HEADER_LEN {
            return Err(OpenfortivpnError::HdlcInvalidFrame);
        }

        let total = u16::from_be_bytes([frame[0], frame[1]]) as usize;
        let magic = u16::from_be_bytes([frame[2], frame[3]]);
        let size = u16::from_be_bytes([frame[4], frame[5]]) as usize;

        if magic != FORTINET_MAGIC || total < HEADER_LEN + 1 || total - HEADER_LEN != size {
            return Err(OpenfortivpnError::HdlcInvalidFrame);
        }
        if frame.len() != total {
            return Err(OpenfortivpnError::HdlcInvalidFrame);
        }

        Ok(Self::new(frame[HEADER_LEN..].to_vec()))
    }

    pub fn is_ip_plus_dns(&self) -> bool {
        let p = self.data.as_slice();
        p.len() >= 12 && p[0] == 0x80 && p[1] == 0x21 && p[2] == 0x02 && p[6] == 0x03
    }

    pub fn is_end_negotiation(&self) -> bool {
        let p = self.data.as_slice();
        (p.len() == 6
            && p[0] == 0x80
            && p[1] == 0x21
            && p[2] == 0x01
            && p[4] == 0x00
            && p[5] == 0x04)
            || (p.len() >= 12 && p[0] == 0x80 && p[1] == 0x21 && p[2] == 0x02)
    }

    pub fn ipcp_ipv4_address(&self) -> Option<Ipv4Addr> {
        let p = self.data.as_slice();
        if p.len() < 10 || p[0] != 0x80 || p[1] != 0x21 {
            return None;
        }

        let length = u16::from_be_bytes([p[4], p[5]]) as usize;
        if length < 4 || p.len() < 2 + length {
            return None;
        }

        let mut offset = 6;
        let end = 2 + length;
        while offset + 2 <= end {
            let option_type = p[offset];
            let option_len = p[offset + 1] as usize;
            if option_len < 2 || offset + option_len > end {
                return None;
            }
            if option_type == 0x03 && option_len == 6 {
                return Some(Ipv4Addr::new(
                    p[offset + 2],
                    p[offset + 3],
                    p[offset + 4],
                    p[offset + 5],
                ));
            }
            offset += option_len;
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_tls_packet_header_like_c_code() {
        let packet = PppPacket::new([0x80, 0x21, 0x01]);
        let encoded = packet.encode_for_tls().unwrap();
        assert_eq!(
            encoded,
            [0x00, 0x09, 0x50, 0x50, 0x00, 0x03, 0x80, 0x21, 0x01]
        );
        assert_eq!(PppPacket::decode_from_tls_frame(&encoded).unwrap(), packet);
    }

    #[test]
    fn rejects_bad_magic() {
        let bad = [0x00, 0x07, 0x50, 0x51, 0x00, 0x01, 0x00];
        assert!(PppPacket::decode_from_tls_frame(&bad).is_err());
    }

    #[test]
    fn detects_ipcp_negotiation_packets() {
        assert!(PppPacket::new([0x80, 0x21, 0x01, 0x00, 0x00, 0x04]).is_end_negotiation());
        assert!(PppPacket::new([0x80, 0x21, 0x02, 0, 0, 0, 0x03, 0, 0, 0, 0, 0]).is_ip_plus_dns());
    }

    #[test]
    fn extracts_ipcp_ipv4_address_option() {
        let packet = PppPacket::new([
            0x80, 0x21, // IPCP
            0x02, // Configure-Ack
            0x7a, // Identifier
            0x00, 0x0a, // Length including code/id/length/options
            0x03, 0x06, // IP-Address option
            10, 212, 134, 201,
        ]);

        assert_eq!(
            packet.ipcp_ipv4_address(),
            Some(Ipv4Addr::new(10, 212, 134, 201))
        );
    }
}
