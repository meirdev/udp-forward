//! Packet sinks: how a batch of datagrams is forwarded to the destinations.
//! [`NormalSink`] sends from the forwarder's own address; [`SpoofSink`]
//! preserves each original sender's address via per-source transparent
//! sockets. Both fan the batch out with `sendmmsg`, chunked to the kernel's
//! per-call limit.

mod batch;
mod normal;
mod spoof;

use anyhow::Result;
pub(crate) use normal::NormalSink;
pub(crate) use spoof::SpoofSink;

use crate::worker::packet::{Datagram, SendReport};

/// Where packets go. Per-message send failures are counted in the returned
/// report rather than raised; `Err` is reserved for a fatal socket error that
/// makes the sink unusable.
pub(crate) trait PacketSink {
    fn send_batch(&mut self, batch: &[Datagram]) -> Result<SendReport>;
}
