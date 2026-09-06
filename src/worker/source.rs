//! Receives datagrams through a bound UDP socket or an AF_PACKET capture
//! socket.

mod batch;
mod normal;
mod silent;

use anyhow::Result;
pub(crate) use normal::NormalSource;
pub(crate) use silent::SilentSource;

use crate::worker::packet::Datagram;

/// Supplies datagrams with their original sender addresses.
pub(crate) trait PacketSource {
    /// Waits for input and returns accepted datagrams borrowing internal
    /// buffers. The batch can be empty if every received packet was
    /// rejected.
    fn recv_batch(&mut self) -> Result<Vec<Datagram<'_>>>;
}
