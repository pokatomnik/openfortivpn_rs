#[cfg(unix)]
mod unix {
    use std::collections::VecDeque;
    use std::fs::File;
    use std::io::{ErrorKind, Read, Write};
    use std::net::Ipv4Addr;
    use std::os::fd::{AsRawFd, BorrowedFd, RawFd};

    use nix::fcntl::{fcntl, FcntlArg, OFlag};
    use nix::poll::{poll, PollFd, PollFlags};

    use crate::error::{OpenfortivpnError, Result};
    use crate::hdlc::HdlcCodec;
    use crate::tls::TlsConnection;
    use crate::tunnel::io::{encode_packet_for_pty, PppdPtyDecoder};
    use crate::tunnel::packet::{PppPacket, FORTINET_MAGIC, HEADER_LEN};

    const IO_BUFFER_SIZE: usize = 4096;

    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    pub struct ForwardStats {
        pub pty_to_tls_packets: u64,
        pub tls_to_pty_packets: u64,
        pub last_ipcp_ipv4: Option<Ipv4Addr>,
    }

    pub fn forward(pty: File, tls: TlsConnection) -> Result<ForwardStats> {
        forward_with_ipcp_callback(pty, tls, |_| {})
    }

    pub fn forward_with_ipcp_callback<F>(
        pty: File,
        tls: TlsConnection,
        on_ipcp_ipv4: F,
    ) -> Result<ForwardStats>
    where
        F: FnMut(Ipv4Addr),
    {
        forward_with_callbacks(pty, tls, on_ipcp_ipv4, || false)
    }

    pub fn forward_with_callbacks<F, S>(
        mut pty: File,
        mut tls: TlsConnection,
        mut on_ipcp_ipv4: F,
        mut should_stop: S,
    ) -> Result<ForwardStats>
    where
        F: FnMut(Ipv4Addr),
        S: FnMut() -> bool,
    {
        set_fd_nonblocking(pty.as_raw_fd())?;
        tls.set_nonblocking(true)?;

        let pty_fd = pty.as_raw_fd();
        let tls_fd = tls.as_raw_fd();
        let mut pty_decoder = PppdPtyDecoder::new();
        let mut hdlc_encoder = HdlcCodec::new();
        let mut tls_decoder = TlsPacketStreamDecoder::new();
        let mut tls_out = WriteQueue::new();
        let mut pty_out = WriteQueue::new();
        let mut stats = ForwardStats::default();

        loop {
            if should_stop() {
                return Ok(stats);
            }

            let mut pty_events = PollFlags::POLLIN;
            if !pty_out.is_empty() {
                pty_events |= PollFlags::POLLOUT;
            }
            let mut tls_events = PollFlags::POLLIN;
            if !tls_out.is_empty() {
                tls_events |= PollFlags::POLLOUT;
            }

            let mut fds = [
                PollFd::new(unsafe { BorrowedFd::borrow_raw(pty_fd) }, pty_events),
                PollFd::new(unsafe { BorrowedFd::borrow_raw(tls_fd) }, tls_events),
            ];
            poll(&mut fds, 200u16)
                .map_err(|err| OpenfortivpnError::Pppd(format!("poll failed: {err}")))?;

            let pty_revents = fds[0].revents().unwrap_or(PollFlags::empty());
            let tls_revents = fds[1].revents().unwrap_or(PollFlags::empty());

            if has_fatal_poll_event(pty_revents) || has_fatal_poll_event(tls_revents) {
                return Ok(stats);
            }

            if pty_revents.contains(PollFlags::POLLIN) {
                read_pty_into_tls_queue(&mut pty, &mut pty_decoder, &mut tls_out, &mut stats)?;
            }
            if tls_revents.contains(PollFlags::POLLIN) {
                read_tls_into_pty_queue(
                    &mut tls,
                    &mut tls_decoder,
                    &mut hdlc_encoder,
                    &mut pty_out,
                    &mut stats,
                    &mut on_ipcp_ipv4,
                )?;
            }
            if pty_revents.contains(PollFlags::POLLOUT) {
                pty_out.write_available(&mut pty)?;
            }
            if tls_revents.contains(PollFlags::POLLOUT) {
                tls_out.write_available(&mut tls)?;
            }
        }
    }

    fn read_pty_into_tls_queue(
        pty: &mut File,
        decoder: &mut PppdPtyDecoder,
        tls_out: &mut WriteQueue,
        stats: &mut ForwardStats,
    ) -> Result<()> {
        let mut buf = [0u8; IO_BUFFER_SIZE];
        loop {
            match pty.read(&mut buf) {
                Ok(0) => return Err(OpenfortivpnError::Pppd("pppd pty closed".to_owned())),
                Ok(n) => {
                    for packet in decoder.push_bytes(&buf[..n])? {
                        tls_out.push(packet.encode_for_tls()?);
                        stats.pty_to_tls_packets += 1;
                    }
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => return Ok(()),
                Err(err) => return Err(err.into()),
            }
        }
    }

    fn read_tls_into_pty_queue(
        tls: &mut TlsConnection,
        decoder: &mut TlsPacketStreamDecoder,
        hdlc_encoder: &mut HdlcCodec,
        pty_out: &mut WriteQueue,
        stats: &mut ForwardStats,
        on_ipcp_ipv4: &mut impl FnMut(Ipv4Addr),
    ) -> Result<()> {
        let mut buf = [0u8; IO_BUFFER_SIZE];
        loop {
            match tls.read(&mut buf) {
                Ok(0) => return Err(OpenfortivpnError::Pppd("TLS tunnel closed".to_owned())),
                Ok(n) => {
                    for packet in decoder.push_bytes(&buf[..n])? {
                        if let Some(addr) = packet.ipcp_ipv4_address() {
                            if stats.last_ipcp_ipv4 != Some(addr) {
                                on_ipcp_ipv4(addr);
                            }
                            stats.last_ipcp_ipv4 = Some(addr);
                        }
                        pty_out.push(encode_packet_for_pty(hdlc_encoder, &packet));
                        stats.tls_to_pty_packets += 1;
                    }
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => return Ok(()),
                Err(err) => return Err(err.into()),
            }
        }
    }

    fn has_fatal_poll_event(events: PollFlags) -> bool {
        events.intersects(PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL)
    }

    fn set_fd_nonblocking(fd: RawFd) -> Result<()> {
        let flags = fcntl(fd, FcntlArg::F_GETFL)
            .map_err(|err| OpenfortivpnError::Pppd(format!("fcntl F_GETFL failed: {err}")))?;
        let flags = OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK;
        fcntl(fd, FcntlArg::F_SETFL(flags))
            .map_err(|err| OpenfortivpnError::Pppd(format!("fcntl F_SETFL failed: {err}")))?;
        Ok(())
    }

    #[derive(Debug, Default)]
    struct WriteQueue {
        chunks: VecDeque<Vec<u8>>,
        offset: usize,
    }

    impl WriteQueue {
        fn new() -> Self {
            Self::default()
        }

        fn push(&mut self, bytes: Vec<u8>) {
            if !bytes.is_empty() {
                self.chunks.push_back(bytes);
            }
        }

        fn is_empty(&self) -> bool {
            self.chunks.is_empty()
        }

        fn write_available<W: Write>(&mut self, writer: &mut W) -> Result<()> {
            while let Some(front) = self.chunks.front() {
                match writer.write(&front[self.offset..]) {
                    Ok(0) => {
                        return Err(OpenfortivpnError::Pppd(
                            "writer returned zero while queue had pending data".to_owned(),
                        ))
                    }
                    Ok(n) => {
                        self.offset += n;
                        if self.offset == front.len() {
                            self.chunks.pop_front();
                            self.offset = 0;
                        }
                    }
                    Err(err) if err.kind() == ErrorKind::WouldBlock => return Ok(()),
                    Err(err) => return Err(err.into()),
                }
            }
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct TlsPacketStreamDecoder {
        buffer: Vec<u8>,
    }

    impl TlsPacketStreamDecoder {
        fn new() -> Self {
            Self::default()
        }

        fn push_bytes(&mut self, bytes: &[u8]) -> Result<Vec<PppPacket>> {
            self.buffer.extend_from_slice(bytes);
            let mut packets = Vec::new();

            loop {
                if self.buffer.len() < HEADER_LEN {
                    break;
                }
                if &self.buffer[..HEADER_LEN] == b"HTTP/1" {
                    return Err(OpenfortivpnError::PermissionDenied);
                }

                let total = u16::from_be_bytes([self.buffer[0], self.buffer[1]]) as usize;
                let magic = u16::from_be_bytes([self.buffer[2], self.buffer[3]]);
                let size = u16::from_be_bytes([self.buffer[4], self.buffer[5]]) as usize;
                if magic != FORTINET_MAGIC || total < HEADER_LEN + 1 || total - HEADER_LEN != size {
                    return Err(OpenfortivpnError::HdlcInvalidFrame);
                }
                if self.buffer.len() < total {
                    break;
                }

                packets.push(PppPacket::decode_from_tls_frame(&self.buffer[..total])?);
                self.buffer.drain(..total);
            }

            Ok(packets)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn write_queue_handles_partial_writes() {
            let mut queue = WriteQueue::new();
            queue.push(vec![1, 2, 3, 4]);
            let mut writer = PartialWriter::new(2);

            queue.write_available(&mut writer).unwrap();

            assert!(queue.is_empty());
            assert_eq!(writer.out, [1, 2, 3, 4]);
        }

        #[test]
        fn tls_packet_stream_decoder_handles_partial_frames() {
            let encoded = PppPacket::new([0x80, 0x21, 0x01]).encode_for_tls().unwrap();
            let mut decoder = TlsPacketStreamDecoder::new();

            assert!(decoder.push_bytes(&encoded[..3]).unwrap().is_empty());
            let packets = decoder.push_bytes(&encoded[3..]).unwrap();

            assert_eq!(packets, [PppPacket::new([0x80, 0x21, 0x01])]);
        }

        struct PartialWriter {
            limit: usize,
            out: Vec<u8>,
        }

        impl PartialWriter {
            fn new(limit: usize) -> Self {
                Self {
                    limit,
                    out: Vec::new(),
                }
            }
        }

        impl Write for PartialWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                let n = self.limit.min(buf.len());
                self.out.extend_from_slice(&buf[..n]);
                Ok(n)
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
    }
}

#[cfg(unix)]
pub use unix::{forward, forward_with_callbacks, forward_with_ipcp_callback, ForwardStats};

#[cfg(not(unix))]
use crate::{
    error::{OpenfortivpnError, Result},
    tls::TlsConnection,
};
#[cfg(not(unix))]
use std::{fs::File, net::Ipv4Addr};

#[cfg(not(unix))]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ForwardStats {
    pub pty_to_tls_packets: u64,
    pub tls_to_pty_packets: u64,
    pub last_ipcp_ipv4: Option<Ipv4Addr>,
}

#[cfg(not(unix))]
pub fn forward(_pty: File, _tls: TlsConnection) -> Result<ForwardStats> {
    Err(OpenfortivpnError::Pppd(
        "tunnel forwarding is only implemented on Unix platforms".to_owned(),
    ))
}

#[cfg(not(unix))]
pub fn forward_with_ipcp_callback<F>(
    _pty: File,
    _tls: TlsConnection,
    _on_ipcp_ipv4: F,
) -> Result<ForwardStats>
where
    F: FnMut(Ipv4Addr),
{
    Err(OpenfortivpnError::Pppd(
        "tunnel forwarding is only implemented on Unix platforms".to_owned(),
    ))
}

#[cfg(not(unix))]
pub fn forward_with_callbacks<F, S>(
    _pty: File,
    _tls: TlsConnection,
    _on_ipcp_ipv4: F,
    _should_stop: S,
) -> Result<ForwardStats>
where
    F: FnMut(Ipv4Addr),
    S: FnMut() -> bool,
{
    Err(OpenfortivpnError::Pppd(
        "tunnel forwarding is only implemented on Unix platforms".to_owned(),
    ))
}
