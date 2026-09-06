//! Preserves sender IPs and ports with UDP sockets bound to the original
//! sources.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, RawFd};

use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};

use super::PacketSink;
use super::batch::BatchedSender;
use crate::worker::packet::{Datagram, SendReport};

/// A cache of transparent sockets sharing one destination set.
pub(crate) struct SpoofSink {
    // Each socket is bound to its key and retained for the lifetime of this sink.
    cache: HashMap<SocketAddr, Socket>,
    sender: BatchedSender,
    ttl: u8,
}

impl SpoofSink {
    pub(crate) fn new(destinations: &[SocketAddr], ttl: u8, is_ipv6: bool) -> Result<Self> {
        // Fail startup if required socket options cannot be set.
        drop(new_spoof_socket(is_ipv6, ttl)?);

        Ok(Self {
            cache: HashMap::new(),
            sender: BatchedSender::new(destinations),
            ttl,
        })
    }

    /// Gets or creates the socket for `src`; logs setup errors and returns
    /// `None`. The cache owns the returned descriptor.
    fn socket_for(&mut self, src: SocketAddr) -> Option<RawFd> {
        match self.cache.entry(src) {
            Entry::Occupied(entry) => Some(entry.get().as_raw_fd()),
            Entry::Vacant(entry) => match make_spoof_socket(src, self.ttl) {
                Ok(socket) => Some(entry.insert(socket).as_raw_fd()),
                Err(e) => {
                    log::error!("Failed to create spoof socket for source {}: {:#}", src, e);
                    None
                }
            },
        }
    }
}

impl PacketSink for SpoofSink {
    fn send_batch(&mut self, batch: &[Datagram]) -> Result<SendReport> {
        let mut report = SendReport::default();
        if batch.is_empty() {
            return Ok(report);
        }

        // Each source's packets go out its own socket, so group by source and
        // fan each group out to every destination.
        let mut by_source: HashMap<SocketAddr, Vec<&[u8]>> = HashMap::new();
        for d in batch {
            by_source.entry(d.src).or_default().push(d.payload);
        }

        for (src, payloads) in by_source {
            let Some(fd) = self.socket_for(src) else {
                report.dropped += payloads.len() * self.sender.destination_count();
                continue;
            };
            report.merge(self.sender.send(fd, &payloads)?);
        }

        Ok(report)
    }
}

/// Binds a transparent UDP socket to the original sender, including non-local
/// addresses. The kernel supplies packet headers, checksums, and routing.
fn make_spoof_socket(src: SocketAddr, ttl: u8) -> Result<Socket> {
    let sock = new_spoof_socket(src.is_ipv6(), ttl)?;
    sock.bind(&src.into())
        .with_context(|| format!("bind spoof source {}", src))?;
    Ok(sock)
}

/// Configures a transparent socket; binding the original source is separate.
fn new_spoof_socket(is_ipv6: bool, ttl: u8) -> Result<Socket> {
    let domain = if is_ipv6 { Domain::IPV6 } else { Domain::IPV4 };

    let sock =
        Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).context("create spoof socket")?;

    // Permit sharing source ports with sockets that also enable port reuse.
    sock.set_reuse_address(true).context("set SO_REUSEADDR")?;
    sock.set_reuse_port(true).context("set SO_REUSEPORT")?;

    if is_ipv6 {
        set_ipv6_transparent(&sock).context("set IPV6_TRANSPARENT")?;
        sock.set_freebind_v6(true).context("set IPV6_FREEBIND")?;
        sock.set_unicast_hops_v6(ttl as u32)
            .context("set IPv6 hop limit")?;
    } else {
        sock.set_ip_transparent_v4(true)
            .context("set IP_TRANSPARENT")?;
        sock.set_freebind_v4(true).context("set IP_FREEBIND")?;
        sock.set_ttl_v4(ttl as u32).context("set IPv4 TTL")?;
    }

    Ok(sock)
}

/// Sets the IPV6_TRANSPARENT socket option (socket2 only exposes the IPv4
/// variant directly).
fn set_ipv6_transparent(sock: &Socket) -> Result<()> {
    let on: libc::c_int = 1;
    // SAFETY: on is a live integer with the size expected by this option.
    let ret = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_TRANSPARENT,
            &on as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };

    if ret < 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    Ok(())
}
