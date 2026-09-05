//! Packet sinks: how a payload is forwarded to the destinations. [`NormalSink`]
//! sends from the forwarder's own address; [`SpoofSink`] preserves the original
//! sender's address via per-source transparent sockets.

mod normal;
mod spoof;

use std::net::SocketAddr;

pub(crate) use normal::NormalSink;
use socket2::SockAddr;
pub(crate) use spoof::SpoofSink;

/// Where packets go: how a payload is forwarded to the destinations, either
/// with the forwarder's own address as the source (normal) or with the original
/// sender's address preserved (spoof).
pub(crate) trait PacketSink {
    fn send(&mut self, payload: &[u8], src: SocketAddr);
}

/// A forwarding destination, paired with its pre-converted socket address.
struct Destination {
    addr: SocketAddr,
    sock_addr: SockAddr,
}

fn to_destinations(addrs: &[SocketAddr]) -> Vec<Destination> {
    addrs
        .iter()
        .map(|&addr| Destination {
            addr,
            sock_addr: addr.into(),
        })
        .collect()
}
