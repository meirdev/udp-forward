//! The unit of work passed from a source to a sink.

use std::net::SocketAddr;

/// Datagrams handled per batch: received per `recvmmsg`, sent per `sendmmsg`.
pub(crate) const BATCH_SIZE: usize = 16;

/// One received UDP datagram: its original source and payload. The payload
/// borrows the source's receive buffer and is valid until the source produces
/// its next batch.
pub(crate) struct Datagram<'a> {
    pub(crate) src: SocketAddr,
    pub(crate) payload: &'a [u8],
}
