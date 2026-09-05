//! Spoof send: preserves each original sender's address via per-source
//! transparent sockets (IP_TRANSPARENT / IPV6_TRANSPARENT).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, RawFd};

use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};

use super::PacketSink;
use super::batch::BatchedSender;
use crate::worker::packet::{Datagram, SendReport};

/// Forwards with each original sender's address preserved, via a per-source
/// transparent socket bound to that address (IP_TRANSPARENT /
/// IPV6_TRANSPARENT).
pub(crate) struct SpoofSink {
    // Keyed by original source address; each socket is bound to that address so
    // the kernel emits packets with it as the source.
    cache: HashMap<SocketAddr, Socket>,
    sender: BatchedSender,
    ttl: u8,
}

impl SpoofSink {
    pub(crate) fn new(destinations: &[SocketAddr], ttl: u8, is_ipv6: bool) -> Result<Self> {
        // Verify at startup that we can set the transparent option (needs
        // CAP_NET_ADMIN), so a privilege problem fails fast instead of on every
        // packet's failed socket creation.
        let domain = if is_ipv6 { Domain::IPV6 } else { Domain::IPV4 };
        let probe =
            Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).context("create spoof probe")?;
        if is_ipv6 {
            set_ipv6_transparent(&probe).context("set IPV6_TRANSPARENT (needs CAP_NET_ADMIN)")?;
        } else {
            probe
                .set_ip_transparent_v4(true)
                .context("set IP_TRANSPARENT (needs CAP_NET_ADMIN)")?;
        }
        drop(probe);

        Ok(Self {
            cache: HashMap::new(),
            sender: BatchedSender::new(destinations),
            ttl,
        })
    }

    /// Returns the raw fd of the transparent socket bound to `src`, creating
    /// and caching it on first use. `None` if the socket cannot be created.
    fn socket_for(&mut self, src: SocketAddr) -> Option<RawFd> {
        if !self.cache.contains_key(&src) {
            match make_spoof_socket(src, self.ttl) {
                Ok(sock) => {
                    self.cache.insert(src, sock);
                }
                Err(e) => {
                    log::error!("Failed to create spoof socket for source {}: {}", src, e);
                    return None;
                }
            }
        }
        Some(self.cache[&src].as_raw_fd())
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

/// Creates a UDP socket bound to `src` that is allowed to send from that
/// (possibly non-local) address.
///
/// Setting IP_TRANSPARENT (IPv4) / IPV6_TRANSPARENT (IPv6) lets the socket bind
/// to an address that is not configured on the host, so the kernel emits
/// packets whose source is the original sender. This replaces hand-built raw
/// packets: the kernel fills in the headers, computes checksums, honors routing
/// across real interfaces, and can use transmit offloads. Requires
/// CAP_NET_ADMIN (root).
fn make_spoof_socket(src: SocketAddr, ttl: u8) -> Result<Socket> {
    let domain = if src.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };

    let sock =
        Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).context("create spoof socket")?;

    // Allow multiple sockets on the same source port (e.g. several workers, or a
    // local socket that already holds the port being spoofed).
    sock.set_reuse_address(true).context("set SO_REUSEADDR")?;
    sock.set_reuse_port(true).context("set SO_REUSEPORT")?;

    if src.is_ipv6() {
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

    sock.bind(&src.into())
        .with_context(|| format!("bind spoof source {}", src))?;

    Ok(sock)
}

/// Sets the IPV6_TRANSPARENT socket option (socket2 only exposes the IPv4
/// variant directly).
fn set_ipv6_transparent(sock: &Socket) -> Result<()> {
    let on: libc::c_int = 1;
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
