//! Normal receive: a UDP socket bound to the listen address.

use std::net::SocketAddr;
use std::os::fd::AsRawFd;

use anyhow::Result;
use socket2::{Domain, Protocol, Socket, Type};

use super::PacketSource;
use super::batch::{BatchedReceiver, source_addr};

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
    fn next_packet(&mut self) -> Result<(SocketAddr, &[u8])> {
        let fd = self.socket.as_raw_fd();
        let (addr, payload) = self.rx.next(fd)?;
        let src = source_addr(addr)?;
        log::debug!("Received {} bytes from {}", payload.len(), src);
        Ok((src, payload))
    }
}
