//! Batched send shared by the sinks. One `sendmmsg` delivers many payloads,
//! each to every destination, on a given socket.

use std::io::IoSlice;
use std::net::SocketAddr;
use std::os::fd::RawFd;

use anyhow::{Context, Result};
use nix::sys::socket::{ControlMessage, MsgFlags, MultiHeaders, SockaddrStorage, sendmmsg};

use crate::worker::packet::BATCH_SIZE;

/// Holds the destination addresses and the scratch headers to fan a batch of
/// payloads out to all destinations in one `sendmmsg`. Reused across sends, and
/// across per-source sockets in the spoof sink (the destination set is the same
/// for every source).
pub(super) struct BatchedSender {
    headers: MultiHeaders<SockaddrStorage>,
    dest_addrs: Vec<Option<SockaddrStorage>>,
}

impl BatchedSender {
    pub(super) fn new(destinations: &[SocketAddr]) -> Self {
        let dest_addrs = destinations
            .iter()
            .map(|&addr| Some(SockaddrStorage::from(addr)))
            .collect::<Vec<_>>();
        // A whole receive batch fanned out to every destination.
        let capacity = BATCH_SIZE * destinations.len().max(1);
        Self {
            headers: MultiHeaders::preallocate(capacity, None),
            dest_addrs,
        }
    }

    pub(super) fn destination_count(&self) -> usize {
        self.dest_addrs.len()
    }

    /// Sends every payload to every destination via `fd` in a single
    /// `sendmmsg` (`payloads.len() * destinations` messages).
    pub(super) fn send(&mut self, fd: RawFd, payloads: &[&[u8]]) -> Result<()> {
        if payloads.is_empty() || self.dest_addrs.is_empty() {
            return Ok(());
        }

        let count = payloads.len() * self.dest_addrs.len();
        let mut iovs: Vec<[IoSlice<'_>; 1]> = Vec::with_capacity(count);
        let mut addrs: Vec<Option<SockaddrStorage>> = Vec::with_capacity(count);
        for payload in payloads {
            for addr in &self.dest_addrs {
                iovs.push([IoSlice::new(payload)]);
                addrs.push(*addr);
            }
        }

        let cmsgs: &[ControlMessage] = &[];
        sendmmsg(
            fd,
            &mut self.headers,
            &iovs,
            &addrs,
            cmsgs,
            MsgFlags::empty(),
        )
        .context("sendmmsg")?;

        Ok(())
    }
}
