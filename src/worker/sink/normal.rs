//! Normal send: forwards from the forwarder's own address via one shared
//! socket.

use std::net::SocketAddr;
use std::os::fd::AsRawFd;

use anyhow::Result;
use socket2::{Domain, Protocol, Socket, Type};

use super::PacketSink;
use super::batch::BatchedSender;
use crate::worker::packet::Datagram;

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
    fn send_batch(&mut self, batch: &[Datagram]) {
        if batch.is_empty() {
            return;
        }
        // All payloads go out the one socket, so the whole batch fans out to
        // every destination in a single sendmmsg.
        let fd = self.socket.as_raw_fd();
        let payloads: Vec<&[u8]> = batch.iter().map(|d| d.payload).collect();
        log::debug!(
            "Forwarding {} datagram(s) to {} destination(s) (normal)",
            batch.len(),
            self.sender.destination_count()
        );
        if let Err(e) = self.sender.send(fd, &payloads) {
            log::error!("Failed to forward batch: {}", e);
        }
    }
}
