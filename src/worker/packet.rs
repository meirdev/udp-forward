//! Borrowed datagrams and send outcomes shared by sources, sinks, and workers.

use std::net::SocketAddr;

/// Maximum datagrams per receive call. Sinks chunk output messages separately.
pub(crate) const RECV_BATCH_SIZE: usize = 16;

/// A UDP payload and its original sender. The payload borrows a receive buffer.
pub(crate) struct Datagram<'a> {
    pub(crate) src: SocketAddr,
    pub(crate) payload: &'a [u8],
}

/// Output counts for a completed send operation, counting each destination
/// copy. A fatal send error returns no report, even if earlier messages were
/// sent.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SendReport {
    /// Messages accepted by the local kernel; delivery is not confirmed.
    pub(crate) sent: usize,
    /// Output copies skipped during socket setup or sending.
    /// Excludes receive-side rejection and kernel queue drops.
    pub(crate) dropped: usize,
}

impl SendReport {
    pub(crate) fn merge(&mut self, other: SendReport) {
        self.sent += other.sent;
        self.dropped += other.dropped;
    }
}
