//! Packet sources: how a datagram is received and its original source
//! recovered. [`NormalSource`] binds a UDP socket; [`SilentSource`] captures at
//! the device layer.

mod batch;
mod normal;
mod silent;

use std::net::SocketAddr;

use anyhow::Result;
pub(crate) use normal::NormalSource;
pub(crate) use silent::SilentSource;

/// Where packets come from: how a datagram is received and its original source
/// recovered. Implementations decide the receive mechanism (a bound UDP socket
/// vs. device-layer capture); callers only see `(source, payload)`.
pub(crate) trait PacketSource {
    /// Blocks until the next UDP datagram addressed to the listen port is
    /// available, returning its original source and payload. The payload
    /// borrows an internal buffer and is valid until the next call.
    fn next_packet(&mut self) -> Result<(SocketAddr, &[u8])>;
}
