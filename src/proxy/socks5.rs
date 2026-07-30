use std::io::{Read, Write};
use std::net::Ipv4Addr;

use crate::error::{OpenfortivpnError, Result};

const VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_NO_ACCEPTABLE: u8 = 0xff;
const COMMAND_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const REPLY_SUCCEEDED: u8 = 0x00;
pub const REPLY_GENERAL_FAILURE: u8 = 0x01;
pub const REPLY_HOST_UNREACHABLE: u8 = 0x04;
const REPLY_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const REPLY_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocksConnectRequest {
    pub target: SocksTarget,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocksTarget {
    Ipv4(Ipv4Addr),
    Domain(String),
}

pub fn read_connect_request<R, W>(reader: &mut R, writer: &mut W) -> Result<SocksConnectRequest>
where
    R: Read,
    W: Write,
{
    negotiate_no_auth(reader, writer)?;
    read_connect_command(reader, writer)
}

pub fn write_success<W: Write>(writer: &mut W, bound: Ipv4Addr, port: u16) -> Result<()> {
    let mut response = vec![VERSION, REPLY_SUCCEEDED, 0x00, ATYP_IPV4];
    response.extend_from_slice(&bound.octets());
    response.extend_from_slice(&port.to_be_bytes());
    writer.write_all(&response)?;
    writer.flush()?;
    Ok(())
}

pub fn write_failure<W: Write>(writer: &mut W, reply: u8) -> Result<()> {
    write_error(writer, reply)
}

fn negotiate_no_auth<R, W>(reader: &mut R, writer: &mut W) -> Result<()>
where
    R: Read,
    W: Write,
{
    let mut header = [0; 2];
    reader.read_exact(&mut header)?;
    if header[0] != VERSION {
        return Err(OpenfortivpnError::Network(format!(
            "unsupported SOCKS version {}",
            header[0]
        )));
    }

    let method_count = header[1] as usize;
    let mut methods = vec![0; method_count];
    reader.read_exact(&mut methods)?;

    if methods.contains(&METHOD_NO_AUTH) {
        writer.write_all(&[VERSION, METHOD_NO_AUTH])?;
        writer.flush()?;
        Ok(())
    } else {
        writer.write_all(&[VERSION, METHOD_NO_ACCEPTABLE])?;
        writer.flush()?;
        Err(OpenfortivpnError::Network(
            "SOCKS5 client did not offer no-auth method".to_owned(),
        ))
    }
}

fn read_connect_command<R, W>(reader: &mut R, writer: &mut W) -> Result<SocksConnectRequest>
where
    R: Read,
    W: Write,
{
    let mut header = [0; 4];
    reader.read_exact(&mut header)?;
    if header[0] != VERSION {
        return Err(OpenfortivpnError::Network(format!(
            "unsupported SOCKS request version {}",
            header[0]
        )));
    }
    if header[1] != COMMAND_CONNECT {
        write_error(writer, REPLY_COMMAND_NOT_SUPPORTED)?;
        return Err(OpenfortivpnError::Network(format!(
            "unsupported SOCKS5 command {}",
            header[1]
        )));
    }

    match header[3] {
        ATYP_IPV4 => read_ipv4_connect(reader),
        ATYP_DOMAIN => read_domain_connect(reader),
        ATYP_IPV6 => {
            discard_bytes(reader, 18)?;
            write_error(writer, REPLY_ADDRESS_TYPE_NOT_SUPPORTED)?;
            Err(OpenfortivpnError::Network(
                "SOCKS5 IPv6 requests are not supported in IPv4-only proxy mode".to_owned(),
            ))
        }
        atyp => {
            write_error(writer, REPLY_ADDRESS_TYPE_NOT_SUPPORTED)?;
            Err(OpenfortivpnError::Network(format!(
                "unsupported SOCKS5 address type {atyp}"
            )))
        }
    }
}

fn read_ipv4_connect<R: Read>(reader: &mut R) -> Result<SocksConnectRequest> {
    let mut tail = [0; 6];
    reader.read_exact(&mut tail)?;
    Ok(SocksConnectRequest {
        target: SocksTarget::Ipv4(Ipv4Addr::new(tail[0], tail[1], tail[2], tail[3])),
        port: u16::from_be_bytes([tail[4], tail[5]]),
    })
}

fn read_domain_connect<R: Read>(reader: &mut R) -> Result<SocksConnectRequest> {
    let mut len = [0; 1];
    reader.read_exact(&mut len)?;
    let mut domain = vec![0; len[0] as usize];
    reader.read_exact(&mut domain)?;
    let mut port = [0; 2];
    reader.read_exact(&mut port)?;
    let domain = String::from_utf8(domain).map_err(|_| {
        OpenfortivpnError::Network("SOCKS5 domain target is not valid UTF-8".to_owned())
    })?;
    Ok(SocksConnectRequest {
        target: SocksTarget::Domain(domain),
        port: u16::from_be_bytes(port),
    })
}

fn discard_bytes<R: Read>(reader: &mut R, len: usize) -> Result<()> {
    let mut bytes = vec![0; len];
    reader.read_exact(&mut bytes)?;
    Ok(())
}

fn write_error<W: Write>(writer: &mut W, reply: u8) -> Result<()> {
    writer.write_all(&[VERSION, reply, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])?;
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn reads_ipv4_connect_request() {
        let mut input = Cursor::new(vec![
            0x05, 0x01, 0x00, // greeting: no auth
            0x05, 0x01, 0x00, 0x01, // connect IPv4
            10, 10, 0, 5, 0x01, 0xbb, // 10.10.0.5:443
        ]);
        let mut output = Vec::new();

        let request = read_connect_request(&mut input, &mut output).unwrap();

        assert_eq!(
            request,
            SocksConnectRequest {
                target: SocksTarget::Ipv4(Ipv4Addr::new(10, 10, 0, 5)),
                port: 443,
            }
        );
        assert_eq!(output, [0x05, 0x00]);
    }

    #[test]
    fn reads_domain_connect_request() {
        let mut input = Cursor::new(vec![
            0x05, 0x01, 0x00, // greeting: no auth
            0x05, 0x01, 0x00, 0x03, // connect domain
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x00, 0x50,
        ]);
        let mut output = Vec::new();

        let request = read_connect_request(&mut input, &mut output).unwrap();

        assert_eq!(
            request,
            SocksConnectRequest {
                target: SocksTarget::Domain("example".to_owned()),
                port: 80,
            }
        );
        assert_eq!(output, [0x05, 0x00]);
    }

    #[test]
    fn writes_success_response() {
        let mut output = Vec::new();

        write_success(&mut output, Ipv4Addr::new(127, 0, 0, 1), 1080).unwrap();

        assert_eq!(output, [0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38]);
    }
}
