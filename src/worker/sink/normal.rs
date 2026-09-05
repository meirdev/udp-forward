//! Normal send: forwards from the forwarder's own address via one shared
//! socket.

use std::net::SocketAddr;

use anyhow::Result;
use socket2::{Domain, Protocol, Socket, Type};

use super::{Destination, PacketSink, to_destinations};

/// Forwards from the forwarder's own address via a single shared socket.
pub(crate) struct NormalSink {
    socket: Socket,
    destinations: Vec<Destination>,
}

impl NormalSink {
    pub(crate) fn new(is_ipv6: bool, destinations: &[SocketAddr], ttl: u8) -> Result<Self> {
        let domain = if is_ipv6 { Domain::IPV6 } else { Domain::IPV4 };
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        if is_ipv6 {
            socket.set_unicast_hops_v6(ttl as u32)?;
        } else {
            socket.set_ttl_v4(ttl as u32)?;
        }
        Ok(Self {
            socket,
            destinations: to_destinations(destinations),
        })
    }
}

impl PacketSink for NormalSink {
    fn send(&mut self, payload: &[u8], _src: SocketAddr) {
        for dest in &self.destinations {
            log::debug!(
                "Forwarding {} bytes to {} (normal)",
                payload.len(),
                dest.addr
            );
            if let Err(e) = self.socket.send_to(payload, &dest.sock_addr) {
                log::error!("Failed to send to {}: {}", dest.addr, e);
            }
        }
    }
}
