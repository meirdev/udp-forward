//! Batched send shared by the sinks. One `sendmmsg` delivers a payload to every
//! destination on a given socket in a single syscall.

use std::io::IoSlice;
use std::net::SocketAddr;
use std::os::fd::RawFd;

use anyhow::{Context, Result};
use nix::sys::socket::{ControlMessage, MsgFlags, MultiHeaders, SockaddrStorage, sendmmsg};

/// Holds the destination addresses and the scratch headers needed to fan a
/// single payload out to all of them with one `sendmmsg`. Reused across sends,
/// and across per-source sockets in the spoof sink (the destination set and its
/// count are the same for every source).
pub(super) struct BatchedSender {
    headers: MultiHeaders<SockaddrStorage>,
    addrs: Vec<Option<SockaddrStorage>>,
}

impl BatchedSender {
    pub(super) fn new(destinations: &[SocketAddr]) -> Self {
        let addrs = destinations
            .iter()
            .map(|&addr| Some(SockaddrStorage::from(addr)))
            .collect::<Vec<_>>();
        let headers = MultiHeaders::preallocate(destinations.len(), None);
        Self { headers, addrs }
    }

    pub(super) fn destination_count(&self) -> usize {
        self.addrs.len()
    }

    /// Sends `payload` to every destination via `fd` in a single `sendmmsg`.
    pub(super) fn send_to_all(&mut self, fd: RawFd, payload: &[u8]) -> Result<()> {
        // One message per destination, each pointing at the same payload.
        let iovs: Vec<[IoSlice<'_>; 1]> =
            self.addrs.iter().map(|_| [IoSlice::new(payload)]).collect();
        let cmsgs: &[ControlMessage] = &[];

        sendmmsg(
            fd,
            &mut self.headers,
            &iovs,
            &self.addrs,
            cmsgs,
            MsgFlags::empty(),
        )
        .context("sendmmsg")?;

        Ok(())
    }
}
