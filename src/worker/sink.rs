//! Sends each input datagram to every configured destination, using the
//! forwarder's address or preserving the original sender.

mod batch;
mod normal;
mod spoof;

use anyhow::Result;
pub(crate) use normal::NormalSink;
pub(crate) use spoof::SpoofSink;

use crate::worker::packet::{Datagram, SendReport};

/// Forwards batches and reports output counts. Recoverable failures are counted
/// as drops; fatal errors stop the worker and return no partial report.
pub(crate) trait PacketSink {
    fn send_batch(&mut self, batch: &[Datagram]) -> Result<SendReport>;
}
