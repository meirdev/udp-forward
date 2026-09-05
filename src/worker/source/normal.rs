//! Normal receive: a UDP socket bound to the listen address.

use std::net::SocketAddr;
use std::os::fd::AsRawFd;

use anyhow::Result;
use socket2::{Domain, Protocol, Socket, Type};

use super::PacketSource;
use super::batch::{BatchedReceiver, source_addr};
use crate::worker::packet::Datagram;

/// Receives on a UDP socket bound to the listen address.
pub(crate) struct NormalSource {
    socket: Socket,
    rx: BatchedReceiver,
}

impl NormalSource {
    pub(crate) fn new(listen: SocketAddr, buffer_size: usize) -> Result<Self> {
        let domain = if listen.is_ipv6() {
            Domain::IPV6
        } else {
            Domain::IPV4
        };
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_reuse_port(true)?;
        socket.bind(&listen.into())?;
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
