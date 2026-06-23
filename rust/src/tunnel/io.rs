use std::io::{Read, Write};

use crate::error::{OpenfortivpnError, Result};
use crate::hdlc::{decode as hdlc_decode, find_frame, HdlcCodec};
use crate::tunnel::packet::{PppPacket, HEADER_LEN};

const HTTP_HEADER_PREFIX: &[u8; HEADER_LEN] = b"HTTP/1";
const MAX_PTY_BUFFER: usize = 64 * 1024;

pub fn send_start_tunnel_request<W: Write>(writer: &mut W, cookie: &str) -> Result<()> {
    write!(
        writer,
        "GET /remote/sslvpn-tunnel HTTP/1.1\r\nHost: sslvpn\r\nCookie: {cookie}\r\n\r\n"
    )?;
    writer.flush()?;
    Ok(())
}

pub fn read_tls_packet<R: Read>(reader: &mut R) -> Result<PppPacket> {
    let mut header = [0u8; HEADER_LEN];
    reader.read_exact(&mut header)?;

    if &header == HTTP_HEADER_PREFIX {
        return Err(OpenfortivpnError::PermissionDenied);
    }

    let total = u16::from_be_bytes([header[0], header[1]]) as usize;
    if total < HEADER_LEN + 1 {
        return Err(OpenfortivpnError::HdlcInvalidFrame);
    }

    let mut frame = Vec::with_capacity(total);
    frame.extend_from_slice(&header);
    frame.resize(total, 0);
    reader.read_exact(&mut frame[HEADER_LEN..])?;

    PppPacket::decode_from_tls_frame(&frame)
}

pub fn write_tls_packet<W: Write>(writer: &mut W, packet: &PppPacket) -> Result<()> {
    writer.write_all(&packet.encode_for_tls()?)?;
    writer.flush()?;
    Ok(())
}

pub fn encode_packet_for_pty(codec: &mut HdlcCodec, packet: &PppPacket) -> Vec<u8> {
    codec.encode(&packet.data)
}

#[derive(Debug, Default)]
pub struct PppdPtyDecoder {
    buffer: Vec<u8>,
}

impl PppdPtyDecoder {
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    pub fn push_bytes(&mut self, bytes: &[u8]) -> Result<Vec<PppPacket>> {
        if self.buffer.len() + bytes.len() > MAX_PTY_BUFFER {
            return Err(OpenfortivpnError::Pppd(
                "pppd pty buffer exceeded maximum size".to_owned(),
            ));
        }

        self.buffer.extend_from_slice(bytes);
        let mut packets = Vec::new();
        let mut consumed_until = 0;

        loop {
            let mut frame_start = consumed_until;
            let frame_len = match find_frame(&self.buffer, &mut frame_start) {
                Ok(frame_len) => frame_len,
                Err(OpenfortivpnError::HdlcNoFrameFound) => break,
                Err(err) => return Err(err),
            };
            let frame_end = frame_start + frame_len;
            packets.push(PppPacket::new(hdlc_decode(
                &self.buffer[frame_start..frame_end],
            )?));
            consumed_until = frame_end;
        }

        if consumed_until > 0 {
            self.buffer.drain(..consumed_until);
        }

        Ok(packets)
    }

    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn sends_start_tunnel_request_like_c() {
        let mut out = Vec::new();
        send_start_tunnel_request(&mut out, "SVPNCOOKIE=abc").unwrap();

        assert_eq!(
            String::from_utf8(out).unwrap(),
            "GET /remote/sslvpn-tunnel HTTP/1.1\r\nHost: sslvpn\r\nCookie: SVPNCOOKIE=abc\r\n\r\n"
        );
    }

    #[test]
    fn reads_and_writes_tls_packet() {
        let packet = PppPacket::new([0x80, 0x21, 0x01]);
        let mut out = Vec::new();
        write_tls_packet(&mut out, &packet).unwrap();

        let decoded = read_tls_packet(&mut Cursor::new(out)).unwrap();
        assert_eq!(decoded, packet);
    }

    #[test]
    fn rejects_http_response_in_tunnel_stream() {
        let mut input = Cursor::new(b"HTTP/1.1 403 Forbidden\r\n\r\n".to_vec());

        assert!(matches!(
            read_tls_packet(&mut input),
            Err(OpenfortivpnError::PermissionDenied)
        ));
    }

    #[test]
    fn decodes_multiple_pppd_frames_and_keeps_partial_tail() {
        let mut codec = HdlcCodec::new();
        let first = codec.encode(&[0x80, 0x21, 0x01]);
        let second = codec.encode(&[0x80, 0x21, 0x02]);
        let partial = vec![0x7e, 0xff];

        let mut input = Vec::new();
        input.extend_from_slice(&first);
        input.extend_from_slice(&second);
        input.extend_from_slice(&partial);

        let mut decoder = PppdPtyDecoder::new();
        let packets = decoder.push_bytes(&input).unwrap();

        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].data, [0x80, 0x21, 0x01]);
        assert_eq!(packets[1].data, [0x80, 0x21, 0x02]);
        // The closing flag of the last complete frame is retained as the
        // possible opening flag for the next frame, matching the C loop.
        assert_eq!(decoder.buffered_len(), partial.len() + 1);
    }
}
