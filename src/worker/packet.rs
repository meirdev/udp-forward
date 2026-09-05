//! The unit of work passed from a source to a sink.

use std::net::SocketAddr;

/// Datagrams received per `recvmmsg`. The outgoing message count is this times
/// the number of destinations, and is chunked separately by the sinks.
pub(crate) const RECV_BATCH_SIZE: usize = 16;

/// One received UDP datagram: its original source and payload. The payload
/// borrows the source's receive buffer and is valid until the source produces
/// its next batch.
pub(crate) struct Datagram<'a> {
    pub(crate) src: SocketAddr,
    pub(crate) payload: &'a [u8],
}

/// What happened to a batch handed to a sink.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SendReport {
    /// Messages the kernel accepted.
    pub(crate) sent: usize,
    /// Messages skipped after a non-fatal send error.
    pub(crate) dropped: usize,
}

impl SendReport {
    pub(crate) fn merge(&mut self, other: SendReport) {
        self.sent += other.sent;
        self.dropped += other.dropped;
    }
}
