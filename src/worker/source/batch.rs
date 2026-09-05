//! Batched receive shared by the sources. One `recvmmsg` fills many buffers;
//! callers then read the received datagrams by index.

use std::io::IoSliceMut;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::RawFd;

use anyhow::{Context, Result};
use nix::sys::socket::{MsgFlags, MultiHeaders, SockaddrStorage, recvmmsg};

use crate::worker::packet::BATCH_SIZE;

/// Owns a batch of receive buffers, filled by one `recvmmsg`.
pub(super) struct BatchedReceiver {
    bufs: Vec<Vec<u8>>,
    headers: MultiHeaders<SockaddrStorage>,
    // (source address, byte length) per received datagram, parallel to `bufs`.
    filled: Vec<(Option<SockaddrStorage>, usize)>,
}

impl BatchedReceiver {
    pub(super) fn new(buffer_size: usize) -> Self {
        Self {
            bufs: vec![vec![0u8; buffer_size]; BATCH_SIZE],
            headers: MultiHeaders::preallocate(BATCH_SIZE, None),
            filled: Vec::with_capacity(BATCH_SIZE),
        }
    }

    /// Receives up to `BATCH_SIZE` datagrams with a single `recvmmsg`,
    /// returning the count. `MSG_WAITFORONE` blocks for the first datagram,
    /// then takes whatever else is already queued, so a low-rate stream is
    /// not stalled waiting for a full batch.
    pub(super) fn recv(&mut self, fd: RawFd) -> Result<usize> {
        let mut iovs: Vec<[IoSliceMut<'_>; 1]> = self
            .bufs
            .iter_mut()
            .map(|b| [IoSliceMut::new(b.as_mut_slice())])
            .collect();

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

        Ok(self.filled.len())
    }

    /// The source address and bytes of received datagram `i` (`i` less than the
    /// last [`recv`](Self::recv) return value).
    pub(super) fn get(&self, i: usize) -> (Option<SockaddrStorage>, &[u8]) {
        let (addr, len) = self.filled[i];
        (addr, &self.bufs[i][..len])
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
