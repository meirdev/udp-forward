//! Batched receive shared by the sources. One `recvmmsg` fills many buffers;
//! callers then iterate the received datagrams.

use std::io::IoSliceMut;
use std::net::{IpAddr, SocketAddr, SocketAddrV6};
use std::os::fd::RawFd;

use anyhow::{Context, Result};
use nix::errno::Errno;
use nix::sys::socket::{MsgFlags, MultiHeaders, SockaddrStorage, recvmmsg};

use crate::worker::packet::RECV_BATCH_SIZE;

/// Per-slot metadata recorded by `recvmmsg`, parallel to the receive buffers.
struct Slot {
    addr: Option<SockaddrStorage>,
    len: usize,
    truncated: bool,
}

/// One received datagram, borrowed from the receiver's buffers.
pub(super) struct Received<'a> {
    /// The kernel-reported address: the peer for a UDP socket, the link-layer
    /// (interface) address for an AF_PACKET capture.
    pub(super) addr: Option<SockaddrStorage>,
    pub(super) data: &'a [u8],
    /// The datagram exceeded the receive buffer (`MSG_TRUNC`); `data` is
    /// incomplete and must not be forwarded.
    pub(super) truncated: bool,
}

/// Owns a batch of receive buffers, filled by one `recvmmsg`.
pub(super) struct BatchedReceiver {
    bufs: Vec<Vec<u8>>,
    headers: MultiHeaders<SockaddrStorage>,
    filled: Vec<Slot>,
}

impl BatchedReceiver {
    pub(super) fn new(buffer_size: usize) -> Self {
        Self {
            bufs: vec![vec![0u8; buffer_size]; RECV_BATCH_SIZE],
            headers: MultiHeaders::preallocate(RECV_BATCH_SIZE, None),
            filled: Vec::with_capacity(RECV_BATCH_SIZE),
        }
    }

    /// Receives up to `RECV_BATCH_SIZE` datagrams with a single `recvmmsg` and
    /// returns the count. `MSG_WAITFORONE` blocks for the first datagram, then
    /// takes whatever else is already queued, so a low-rate stream is not
    /// stalled waiting for a full batch.
    pub(super) fn recv(&mut self, fd: RawFd) -> Result<usize> {
        // EINTR is retried. The io-slices are rebuilt per attempt (cheap, and
        // EINTR is rare) so no borrow of the buffers spans loop iterations.
        loop {
            let mut iovs: Vec<[IoSliceMut<'_>; 1]> = self
                .bufs
                .iter_mut()
                .map(|b| [IoSliceMut::new(b.as_mut_slice())])
                .collect();

            match recvmmsg(
                fd,
                &mut self.headers,
                iovs.iter_mut(),
                MsgFlags::MSG_WAITFORONE,
                None,
            ) {
                Ok(results) => {
                    self.filled.clear();
                    for msg in results {
                        self.filled.push(Slot {
                            addr: msg.address,
                            len: msg.bytes,
                            truncated: msg.flags.contains(MsgFlags::MSG_TRUNC),
                        });
                    }
                    return Ok(self.filled.len());
                }
                Err(Errno::EINTR) => continue,
                Err(e) => return Err(e).context("recvmmsg"),
            }
        }
    }

    /// The datagrams of the most recent batch.
    pub(super) fn received(&self) -> impl Iterator<Item = Received<'_>> {
        self.filled.iter().enumerate().map(|(i, slot)| Received {
            addr: slot.addr,
            data: &self.bufs[i][..slot.len],
            truncated: slot.truncated,
        })
    }
}

/// Converts a kernel-reported UDP peer address into a [`SocketAddr`],
/// preserving IPv6 flow info and scope id (needed for link-local peers).
pub(super) fn source_addr(addr: Option<SockaddrStorage>) -> Result<SocketAddr> {
    let addr = addr.context("recvmmsg returned no source address")?;
    if let Some(v4) = addr.as_sockaddr_in() {
        Ok(SocketAddr::new(IpAddr::V4(v4.ip()), v4.port()))
    } else if let Some(v6) = addr.as_sockaddr_in6() {
        Ok(SocketAddr::V6(SocketAddrV6::new(
            v6.ip(),
            v6.port(),
            v6.flowinfo(),
            v6.scope_id(),
        )))
    } else {
        anyhow::bail!("unexpected source address family")
    }
}
