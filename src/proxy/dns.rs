use std::net::Ipv4Addr;

use crate::error::{OpenfortivpnError, Result};

const DNS_TYPE_A: u16 = 1;
const DNS_CLASS_IN: u16 = 1;
const DNS_HEADER_LEN: usize = 12;

pub fn build_tcp_query(id: u16, name: &str) -> Result<Vec<u8>> {
    let mut message = Vec::new();
    message.extend_from_slice(&id.to_be_bytes());
    message.extend_from_slice(&0x0100u16.to_be_bytes()); // recursion desired
    message.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    message.extend_from_slice(&0u16.to_be_bytes()); // ancount
    message.extend_from_slice(&0u16.to_be_bytes()); // nscount
    message.extend_from_slice(&0u16.to_be_bytes()); // arcount
    encode_name(name, &mut message)?;
    message.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
    message.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

    if message.len() > u16::MAX as usize {
        return Err(OpenfortivpnError::Network(format!(
            "DNS query for {name} is too large"
        )));
    }

    let mut framed = Vec::with_capacity(2 + message.len());
    framed.extend_from_slice(&(message.len() as u16).to_be_bytes());
    framed.extend_from_slice(&message);
    Ok(framed)
}

pub fn parse_tcp_response(frame: &[u8], expected_id: u16) -> Result<Vec<Ipv4Addr>> {
    if frame.len() < 2 {
        return Ok(Vec::new());
    }
    let len = u16::from_be_bytes([frame[0], frame[1]]) as usize;
    if frame.len() < 2 + len {
        return Ok(Vec::new());
    }
    parse_message(&frame[2..2 + len], expected_id)
}

fn parse_message(message: &[u8], expected_id: u16) -> Result<Vec<Ipv4Addr>> {
    if message.len() < DNS_HEADER_LEN {
        return Err(OpenfortivpnError::Network("short DNS response".to_owned()));
    }
    let id = u16::from_be_bytes([message[0], message[1]]);
    if id != expected_id {
        return Err(OpenfortivpnError::Network(
            "DNS response id mismatch".to_owned(),
        ));
    }
    let flags = u16::from_be_bytes([message[2], message[3]]);
    if flags & 0x8000 == 0 {
        return Err(OpenfortivpnError::Network(
            "DNS response is not marked as response".to_owned(),
        ));
    }
    let rcode = flags & 0x000f;
    if rcode != 0 {
        return Err(OpenfortivpnError::Network(format!(
            "DNS response returned rcode {rcode}"
        )));
    }

    let qdcount = u16::from_be_bytes([message[4], message[5]]) as usize;
    let ancount = u16::from_be_bytes([message[6], message[7]]) as usize;
    let mut offset = DNS_HEADER_LEN;

    for _ in 0..qdcount {
        offset = skip_name(message, offset)?;
        if offset + 4 > message.len() {
            return Err(OpenfortivpnError::Network(
                "truncated DNS question".to_owned(),
            ));
        }
        offset += 4;
    }

    let mut addrs = Vec::new();
    for _ in 0..ancount {
        offset = skip_name(message, offset)?;
        if offset + 10 > message.len() {
            return Err(OpenfortivpnError::Network(
                "truncated DNS answer".to_owned(),
            ));
        }
        let rr_type = u16::from_be_bytes([message[offset], message[offset + 1]]);
        let class = u16::from_be_bytes([message[offset + 2], message[offset + 3]]);
        let rdlen = u16::from_be_bytes([message[offset + 8], message[offset + 9]]) as usize;
        offset += 10;
        if offset + rdlen > message.len() {
            return Err(OpenfortivpnError::Network("truncated DNS rdata".to_owned()));
        }
        if rr_type == DNS_TYPE_A && class == DNS_CLASS_IN && rdlen == 4 {
            addrs.push(Ipv4Addr::new(
                message[offset],
                message[offset + 1],
                message[offset + 2],
                message[offset + 3],
            ));
        }
        offset += rdlen;
    }

    Ok(addrs)
}

fn encode_name(name: &str, out: &mut Vec<u8>) -> Result<()> {
    let trimmed = name.trim_end_matches('.');
    if trimmed.is_empty() {
        out.push(0);
        return Ok(());
    }
    for label in trimmed.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(OpenfortivpnError::Network(format!(
                "bad DNS label in {name}"
            )));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

fn skip_name(message: &[u8], mut offset: usize) -> Result<usize> {
    let mut jumps = 0;
    loop {
        if offset >= message.len() {
            return Err(OpenfortivpnError::Network("truncated DNS name".to_owned()));
        }
        let len = message[offset];
        if len & 0xc0 == 0xc0 {
            if offset + 1 >= message.len() {
                return Err(OpenfortivpnError::Network(
                    "truncated DNS name pointer".to_owned(),
                ));
            }
            return Ok(offset + 2);
        }
        if len == 0 {
            return Ok(offset + 1);
        }
        if len & 0xc0 != 0 {
            return Err(OpenfortivpnError::Network(
                "unsupported DNS label encoding".to_owned(),
            ));
        }
        offset += 1 + len as usize;
        jumps += 1;
        if jumps > 128 {
            return Err(OpenfortivpnError::Network("DNS name too deep".to_owned()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_tcp_a_query() {
        let query = build_tcp_query(0x1234, "internal.example").unwrap();

        assert_eq!(&query[0..4], [0x00, 0x22, 0x12, 0x34]);
        assert!(query.windows(2).any(|w| w == [0x00, DNS_TYPE_A as u8]));
    }

    #[test]
    fn parses_compressed_a_response() {
        let response = [
            0x00, 0x32, // TCP length
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, b'i',
            b'n', b't', b'e', b'r', b'n', b'a', b'l', 0x07, b'e', b'x', b'a', b'm', b'p', b'l',
            b'e', 0x00, 0x00, 0x01, 0x00, 0x01, // question
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 10, 32, 228, 1,
        ];

        let addrs = parse_tcp_response(&response, 0x1234).unwrap();

        assert_eq!(addrs, [Ipv4Addr::new(10, 32, 228, 1)]);
    }
}
