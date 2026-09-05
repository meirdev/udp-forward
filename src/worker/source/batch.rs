//! Batched receive shared by the sources. One `recvmmsg` fills many buffers,
//! amortizing the syscall over a batch; callers then drain them one datagram at
//! a time.

use std::io::IoSliceMut;
use std::net::{IpAddr, SocketAddr};
use std::ops::Range;
use std::os::fd::RawFd;

use anyhow::{Context, Result};
use nix::sys::socket::{MsgFlags, MultiHeaders, SockaddrStorage, recvmmsg};

// Datagrams received per `recvmmsg`. Larger amortizes the syscall more but
// costs `RECV_BATCH * buffer_size` bytes of receive buffers per source.
const RECV_BATCH: usize = 16;

/// Owns a batch of receive buffers and drains them one at a time, issuing a
/// single `recvmmsg` to refill when the current batch is exhausted.
pub(super) struct BatchedReceiver {
    bufs: Vec<Vec<u8>>,
    headers: MultiHeaders<SockaddrStorage>,
    // (source address, byte length) per datagram in the current batch, parallel
    // to `bufs`.
    filled: Vec<(Option<SockaddrStorage>, usize)>,
    cursor: usize,
}

impl BatchedReceiver {
    pub(super) fn new(buffer_size: usize) -> Self {
        Self {
            bufs: vec![vec![0u8; buffer_size]; RECV_BATCH],
            headers: MultiHeaders::preallocate(RECV_BATCH, None),
            filled: Vec::with_capacity(RECV_BATCH),
            cursor: 0,
        }
    }

    /// Returns the next datagram: the kernel-reported source address (`None`
    /// for AF_PACKET, where the caller parses the source from the packet)
    /// and the received bytes. The slice borrows an internal buffer and is
    /// valid until the next call.
    pub(super) fn next(&mut self, fd: RawFd) -> Result<(Option<SockaddrStorage>, &[u8])> {
        while self.cursor >= self.filled.len() {
            self.refill(fd)?;
        }
        let (addr, len) = self.filled[self.cursor];
        let idx = self.cursor;
        self.cursor += 1;
        Ok((addr, &self.bufs[idx][..len]))
    }

    /// Re-borrows a range of the datagram most recently returned by
    /// [`next`](Self::next). Lets a caller drop the borrow from `next` (e.g. to
    /// loop on a parse failure) and then reacquire just the slice it wants.
    pub(super) fn last_slice(&self, range: Range<usize>) -> &[u8] {
        &self.bufs[self.cursor - 1][range]
    }

    fn refill(&mut self, fd: RawFd) -> Result<()> {
        let mut iovs: Vec<[IoSliceMut<'_>; 1]> = self
            .bufs
            .iter_mut()
            .map(|b| [IoSliceMut::new(b.as_mut_slice())])
            .collect();

        // MSG_WAITFORONE blocks for the first datagram, then takes whatever else
        // is already queued. Without it, recvmmsg would wait for the whole batch
        // and stall a low-rate stream.
        let results = recvmmsg(
            fd,
            &mut self.headers,
            iovs.iter_mut(),
            MsgFlags::MSG_WAITFORONE,
            None,
        )
        .context("recvmmsg")?;

        self.filled.clear();
        for msg in results {
            self.filled.push((msg.address, msg.bytes));
        }
        self.cursor = 0;

        Ok(())
    }
}

/// Converts a kernel-reported source address into a [`SocketAddr`].
pub(super) fn source_addr(addr: Option<SockaddrStorage>) -> Result<SocketAddr> {
    let addr = addr.context("recvmmsg returned no source address")?;
    if let Some(v4) = addr.as_sockaddr_in() {
        Ok(SocketAddr::new(IpAddr::V4(v4.ip()), v4.port()))
    } else if let Some(v6) = addr.as_sockaddr_in6() {
        Ok(SocketAddr::new(IpAddr::V6(v6.ip()), v6.port()))
    } else {
        anyhow::bail!("unexpected source address family")
    }
}
