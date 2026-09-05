//! Normal send: forwards from the forwarder's own address via one shared
//! socket.

use std::net::SocketAddr;
use std::os::fd::AsRawFd;

use anyhow::Result;
use socket2::{Domain, Protocol, Socket, Type};

use super::PacketSink;
use super::batch::BatchedSender;

/// Forwards from the forwarder's own address via a single shared socket.
pub(crate) struct NormalSink {
    socket: Socket,
    sender: BatchedSender,
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
            sender: BatchedSender::new(destinations),
        })
    }
}

impl PacketSink for NormalSink {
    fn send(&mut self, payload: &[u8], _src: SocketAddr) {
        let fd = self.socket.as_raw_fd();
        log::debug!(
            "Forwarding {} bytes to {} destination(s) (normal)",
            payload.len(),
            self.sender.destination_count()
        );
        if let Err(e) = self.sender.send_to_all(fd, payload) {
            log::error!("Failed to forward {} bytes: {}", payload.len(), e);
        }
    }
}
