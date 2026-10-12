//! Normal receive: a UDP socket bound to the listen address.

use std::net::SocketAddr;
use std::os::fd::AsRawFd;

use anyhow::{Context, Result};
use socket2::{Protocol, Socket, Type};

use super::PacketSource;
use super::batch::{BatchedReceiver, source_addr};
use crate::worker::packet::Datagram;
use crate::worker::socket::domain_for;

/// A bound UDP socket and its reusable receive buffers.
pub(crate) struct NormalSource {
    socket: Socket,
    rx: BatchedReceiver,
}

impl NormalSource {
    /// Binds `listen` with port reuse so every worker shares the port.
    pub(crate) fn new(listen: SocketAddr, buffer_size: usize) -> Result<Self> {
        let socket = Socket::new(
            domain_for(listen.is_ipv6()),
            Type::DGRAM,
            Some(Protocol::UDP),
        )
        .context("create listen socket")?;
        socket.set_reuse_port(true).context("set SO_REUSEPORT")?;
        socket
            .bind(&listen.into())
            .with_context(|| format!("bind listen address {}", listen))?;
        Ok(Self {
            socket,
            rx: BatchedReceiver::new(buffer_size),
        })
    }
}

impl PacketSource for NormalSource {
    fn recv_batch(&mut self) -> Result<Vec<Datagram<'_>>> {
        let n = self.rx.recv(self.socket.as_raw_fd())?;

        let mut batch = Vec::with_capacity(n);
        for received in self.rx.received() {
            if received.truncated {
                log::debug!(
                    "Dropping datagram truncated to {} bytes (increase --buffer-size)",
                    received.data.len()
                );
                continue;
            }
            match source_addr(received.addr) {
                Ok(src) => batch.push(Datagram {
                    src,
                    payload: received.data,
                }),
                Err(e) => log::debug!("Dropping datagram with unusable source: {}", e),
            }
        }
        Ok(batch)
    }
}
