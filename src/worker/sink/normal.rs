//! Sends through one UDP socket per worker, using a local source address.

use std::net::SocketAddr;
use std::os::fd::AsRawFd;

use anyhow::Result;
use socket2::{Domain, Protocol, Socket, Type};

use super::PacketSink;
use super::batch::BatchedSender;
use crate::worker::packet::{Datagram, SendReport};

/// A UDP socket and the destination set used for normal forwarding.
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
    fn send_batch(&mut self, batch: &[Datagram]) -> Result<SendReport> {
        if batch.is_empty() {
            return Ok(SendReport::default());
        }
        let payloads: Vec<&[u8]> = batch.iter().map(|d| d.payload).collect();
        self.sender.send(self.socket.as_raw_fd(), &payloads)
    }
}
