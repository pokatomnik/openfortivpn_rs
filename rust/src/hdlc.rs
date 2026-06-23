use crate::error::{OpenfortivpnError, Result};

const FCS_TAB: [u16; 256] = [
    0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf, 0x8c48, 0x9dc1, 0xaf5a, 0xbed3,
    0xca6c, 0xdbe5, 0xe97e, 0xf8f7, 0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
    0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876, 0x2102, 0x308b, 0x0210, 0x1399,
    0x6726, 0x76af, 0x4434, 0x55bd, 0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
    0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c, 0xbdcb, 0xac42, 0x9ed9, 0x8f50,
    0xfbef, 0xea66, 0xd8fd, 0xc974, 0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
    0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3, 0x5285, 0x430c, 0x7197, 0x601e,
    0x14a1, 0x0528, 0x37b3, 0x263a, 0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
    0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9, 0xef4e, 0xfec7, 0xcc5c, 0xddd5,
    0xa96a, 0xb8e3, 0x8a78, 0x9bf1, 0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
    0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70, 0x8408, 0x9581, 0xa71a, 0xb693,
    0xc22c, 0xd3a5, 0xe13e, 0xf0b7, 0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
    0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036, 0x18c1, 0x0948, 0x3bd3, 0x2a5a,
    0x5ee5, 0x4f6c, 0x7df7, 0x6c7e, 0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
    0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd, 0xb58b, 0xa402, 0x9699, 0x8710,
    0xf3af, 0xe226, 0xd0bd, 0xc134, 0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
    0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3, 0x4a44, 0x5bcd, 0x6956, 0x78df,
    0x0c60, 0x1de9, 0x2f72, 0x3efb, 0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
    0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a, 0xe70e, 0xf687, 0xc41c, 0xd595,
    0xa12a, 0xb0a3, 0x8238, 0x93b1, 0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
    0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330, 0x7bc7, 0x6a4e, 0x58d5, 0x495c,
    0x3de3, 0x2c6a, 0x1ef1, 0x0f78,
];

const ADDRESS_CONTROL_CHECKSUM: u16 = 0x3de3;
const GOOD_FINAL_FCS: u16 = 0xf0b8;

#[derive(Debug, Clone)]
pub struct HdlcCodec {
    need_flag_sequence: bool,
}

impl Default for HdlcCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl HdlcCodec {
    pub fn new() -> Self {
        Self {
            need_flag_sequence: true,
        }
    }

    pub fn estimated_encoded_size(packet_len: usize) -> usize {
        9 + 2 * packet_len
    }

    pub fn estimated_decoded_size(frame_len: usize) -> usize {
        frame_len
    }

    pub fn encode(&mut self, packet: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(Self::estimated_encoded_size(packet.len()));

        if self.need_flag_sequence {
            frame.push(0x7e);
        }

        frame.push(0xff);
        frame.push(0x7d);
        frame.push(0x03 ^ 0x20);

        let mut checksum = ADDRESS_CONTROL_CHECKSUM;
        checksum = frame_checksum_16bit(checksum, packet);

        for &byte in packet {
            push_escaped(&mut frame, byte);
        }

        checksum ^= 0xffff;
        push_escaped(&mut frame, (checksum & 0x00ff) as u8);
        push_escaped(&mut frame, (checksum >> 8) as u8);
        frame.push(0x7e);

        self.need_flag_sequence = false;
        frame
    }
}

pub fn find_frame(buffer: &[u8], start: &mut usize) -> Result<usize> {
    let mut s = None;
    let mut e = None;

    for (i, byte) in buffer.iter().enumerate().skip(*start) {
        if *byte == 0x7e {
            s = Some(i + 1);
            break;
        }
    }

    let mut s = s.ok_or(OpenfortivpnError::HdlcNoFrameFound)?;

    while s < buffer.len() && buffer[s] == 0x7e {
        s += 1;
    }

    for (i, byte) in buffer.iter().enumerate().skip(s) {
        if *byte == 0x7e {
            e = Some(i);
            break;
        }
    }

    let e = e.ok_or(OpenfortivpnError::HdlcNoFrameFound)?;
    *start = s;
    Ok(e - s)
}

pub fn decode(frame: &[u8]) -> Result<Vec<u8>> {
    if frame.len() < 5 {
        return Err(OpenfortivpnError::HdlcInvalidFrame);
    }

    let mut start = 0;
    let mut has_address_control_fields = false;
    if frame.len() >= 3 && frame[0] == 0xff && frame[1] == 0x7d && frame[2] == (0x03 ^ 0x20) {
        start = 3;
        has_address_control_fields = true;
    }

    let mut packet = Vec::with_capacity(HdlcCodec::estimated_decoded_size(frame.len()));
    let mut in_escape = false;

    for &raw_byte in &frame[start..] {
        let mut byte = raw_byte;

        if byte == 0x7d {
            if in_escape {
                return Err(OpenfortivpnError::HdlcInvalidFrame);
            }
            in_escape = true;
            continue;
        } else if in_escape {
            byte ^= 0x20;
            in_escape = false;
        } else if in_receiving_accm(byte) {
            continue;
        }

        packet.push(byte);
    }

    if in_escape || packet.len() < 3 {
        return Err(OpenfortivpnError::HdlcInvalidFrame);
    }

    let initial = if has_address_control_fields {
        ADDRESS_CONTROL_CHECKSUM
    } else {
        0xffff
    };
    if frame_checksum_16bit(initial, &packet) != GOOD_FINAL_FCS {
        return Err(OpenfortivpnError::HdlcBadChecksum);
    }

    packet.truncate(packet.len() - 2);
    Ok(packet)
}

fn push_escaped(out: &mut Vec<u8>, byte: u8) {
    if in_sending_accm(byte) {
        out.push(0x7d);
        out.push(byte ^ 0x20);
    } else {
        out.push(byte);
    }
}

fn in_sending_accm(byte: u8) -> bool {
    byte < 0x20 || (byte & 0x7f) == 0x7d || (byte & 0x7f) == 0x7e
}

fn in_receiving_accm(byte: u8) -> bool {
    byte < 0x20
}

fn frame_checksum_16bit(mut sum: u16, seq: &[u8]) -> u16 {
    for &byte in seq {
        sum = (sum >> 8) ^ FCS_TAB[((sum ^ u16::from(byte)) & 0xff) as usize];
    }
    sum
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_round_trip() {
        let packet = [0x80, 0x21, 0x01, 0x7d, 0x7e, 0x00, 0x1f, 0x20, 0xff];
        let mut codec = HdlcCodec::new();
        let frame = codec.encode(&packet);

        assert_eq!(frame.first(), Some(&0x7e));
        assert_eq!(frame.last(), Some(&0x7e));

        let mut start = 0;
        let frame_len = find_frame(&frame, &mut start).unwrap();
        assert_eq!(decode(&frame[start..start + frame_len]).unwrap(), packet);
    }

    #[test]
    fn subsequent_frames_omit_initial_flag() {
        let mut codec = HdlcCodec::new();
        let first = codec.encode(&[0x80, 0x21]);
        let second = codec.encode(&[0x80, 0x21]);

        assert_eq!(first.first(), Some(&0x7e));
        assert_ne!(second.first(), Some(&0x7e));
        assert_eq!(second.last(), Some(&0x7e));
    }

    #[test]
    fn detects_bad_checksum() {
        let mut codec = HdlcCodec::new();
        let mut frame = codec.encode(&[0x80, 0x21, 0x01]);
        let last_data = frame.len() - 2;
        frame[last_data] ^= 0x01;

        let mut start = 0;
        let frame_len = find_frame(&frame, &mut start).unwrap();
        assert!(matches!(
            decode(&frame[start..start + frame_len]),
            Err(OpenfortivpnError::HdlcBadChecksum)
        ));
    }

    #[test]
    fn ignores_empty_frames() {
        let mut codec = HdlcCodec::new();
        let encoded = codec.encode(&[0x80, 0x21]);
        let mut buf = vec![0x7e, 0x7e];
        buf.extend(encoded);

        let mut start = 0;
        let frame_len = find_frame(&buf, &mut start).unwrap();
        assert!(frame_len > 0);
        assert_eq!(
            decode(&buf[start..start + frame_len]).unwrap(),
            [0x80, 0x21]
        );
    }
}
