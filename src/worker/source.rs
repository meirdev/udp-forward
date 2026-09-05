//! Packet sources: how a batch of datagrams is received and each original
//! source recovered. [`NormalSource`] binds a UDP socket; [`SilentSource`]
//! captures at the device layer.

mod batch;
mod normal;
mod silent;

use anyhow::Result;
pub(crate) use normal::NormalSource;
pub(crate) use silent::SilentSource;

use crate::worker::packet::Datagram;

/// Where packets come from: how datagrams are received and each original source
/// recovered. Implementations decide the receive mechanism (a bound UDP socket
/// vs. device-layer capture); callers only see a batch of [`Datagram`]s.
pub(crate) trait PacketSource {
    /// Receives a batch of datagrams with a single `recvmmsg`. The returned
    /// datagrams borrow internal buffers and are valid until the next call.
    fn recv_batch(&mut self) -> Result<Vec<Datagram<'_>>>;
}
