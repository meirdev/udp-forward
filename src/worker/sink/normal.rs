//! Sends through one UDP socket per worker, using a local source address.

use std::net::SocketAddr;
use std::os::fd::AsRawFd;

use anyhow::{Context, Result};
use socket2::{Protocol, Socket, Type};

use super::PacketSink;
use super::batch::BatchedSender;
use crate::worker::packet::{Datagram, SendReport};
use crate::worker::socket::domain_for;

/// A UDP socket and the destination set used for normal forwarding.
pub(crate) struct NormalSink {
    socket: Socket,
    sender: BatchedSender,
}

impl NormalSink {
    /// Opens the sending socket. Fails if the TTL cannot be set.
    pub(crate) fn new(destinations: &[SocketAddr], ttl: u8, is_ipv6: bool) -> Result<Self> {
        let socket = Socket::new(domain_for(is_ipv6), Type::DGRAM, Some(Protocol::UDP))
            .context("create sending socket")?;
        if is_ipv6 {
            socket
                .set_unicast_hops_v6(ttl as u32)
                .context("set IPv6 hop limit")?;
        } else {
            socket.set_ttl_v4(ttl as u32).context("set IPv4 TTL")?;
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
