//! Spoof send: preserves the original sender's address via per-source
//! transparent sockets (IP_TRANSPARENT / IPV6_TRANSPARENT).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;

use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};

use super::{Destination, PacketSink, to_destinations};

/// Forwards with the original sender's address preserved, via a per-source
/// transparent socket bound to that address (IP_TRANSPARENT /
/// IPV6_TRANSPARENT).
pub(crate) struct SpoofSink {
    // Keyed by original source address; each socket is bound to that address so
    // the kernel emits packets with it as the source.
    cache: HashMap<SocketAddr, Socket>,
    destinations: Vec<Destination>,
    ttl: u8,
}

impl SpoofSink {
    pub(crate) fn new(destinations: &[SocketAddr], ttl: u8) -> Self {
        Self {
            cache: HashMap::new(),
            destinations: to_destinations(destinations),
            ttl,
        }
    }
}

impl PacketSink for SpoofSink {
    fn send(&mut self, payload: &[u8], src: SocketAddr) {
        if !self.cache.contains_key(&src) {
            let sock = match make_spoof_socket(src, self.ttl) {
                Ok(sock) => sock,
                Err(e) => {
                    log::error!("Failed to create spoof socket for source {}: {}", src, e);
                    return;
                }
            };
            self.cache.insert(src, sock);
        }

        let sock = &self.cache[&src];
        for dest in &self.destinations {
            log::debug!(
                "Forwarding {} bytes to {} (spoofed source {})",
                payload.len(),
                dest.addr,
                src
            );
            if let Err(e) = sock.send_to(payload, &dest.sock_addr) {
                log::error!("Failed to send spoofed packet to {}: {}", dest.addr, e);
            }
        }
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
        sock.set_unicast_hops_v6(ttl as u32).ok();
    } else {
        sock.set_ip_transparent_v4(true)
            .context("set IP_TRANSPARENT")?;
        sock.set_freebind_v4(true).context("set IP_FREEBIND")?;
        sock.set_ttl_v4(ttl as u32).ok();
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
