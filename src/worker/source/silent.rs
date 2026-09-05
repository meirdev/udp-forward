//! Silent receive: an AF_PACKET capture socket that taps at the device layer,
//! like tcpdump, plus the in-kernel BPF filter and packet parsing it needs.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::os::fd::AsRawFd;

use anyhow::{Context, Result};
use nix::sys::socket::SockaddrStorage;
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::{Ipv4Flags, Ipv4Packet};
use pnet_packet::ipv6::Ipv6Packet;
use pnet_packet::udp::UdpPacket;
use socket2::{Domain, Protocol, Socket, Type};

use super::PacketSource;
use super::batch::BatchedReceiver;
use crate::worker::packet::Datagram;

// Fixed IPv6 header length (no extension headers). libc has no constant for it.
const IPV6_HEADER_LEN: usize = 40;
const UDP_HEADER_LEN: usize = 8;

const SO_ATTACH_FILTER: libc::c_int = 26;

/// Captures at the device layer with an AF_PACKET socket and reconstructs the
/// source from the packet headers. Sees traffic regardless of routing or NAT.
pub(crate) struct SilentSource {
    socket: Socket,
    rx: BatchedReceiver,
    listen: SocketAddr,
}

impl SilentSource {
    pub(crate) fn new(
        listen: SocketAddr,
        interface: Option<&str>,
        buffer_size: usize,
    ) -> Result<Self> {
        // A scoped IPv6 listen address (`[fe80::1%3]`) names an interface; it
        // must agree with `--interface` when both are given.
        if let (SocketAddr::V6(l), Some(iface)) = (listen, interface)
            && l.scope_id() != 0
            && ifindex_of(iface)? != l.scope_id()
        {
            anyhow::bail!(
                "listen address scope %{} does not match --interface {}",
                l.scope_id(),
                iface
            );
        }

        let socket = new_capture_socket(listen.is_ipv6(), interface, listen.port())?;
        Ok(Self {
            socket,
            rx: BatchedReceiver::new(buffer_size),
            listen,
        })
    }
}

impl PacketSource for SilentSource {
    fn recv_batch(&mut self) -> Result<Vec<Datagram<'_>>> {
        // AF_PACKET SOCK_DGRAM delivers each packet starting at the IP header
        // (the link-layer header is stripped in cooked mode). The BPF filter
        // drops non-UDP and wrong-port packets in the kernel; the parser here
        // enforces the listen address, rejects fragments and malformed lengths,
        // and reconstructs the source (the capture address is the interface,
        // not the datagram's sender).
        let n = self.rx.recv(self.socket.as_raw_fd())?;

        let mut batch = Vec::with_capacity(n);
        for received in self.rx.received() {
            if received.truncated {
                log::debug!("Silent: dropping truncated capture (increase --buffer-size)");
                continue;
            }
            let ifindex = capture_ifindex(received.addr);
            if !listen_scope_matches(self.listen, ifindex) {
                continue;
            }
            let Some(mut datagram) = parse_captured_udp(received.data, self.listen) else {
                continue;
            };
            attach_link_local_scope(&mut datagram.src, ifindex);
            batch.push(datagram);
        }
        Ok(batch)
    }
}

/// The interface a datagram was captured on, from its AF_PACKET link address.
fn capture_ifindex(addr: Option<SockaddrStorage>) -> Option<u32> {
    addr.and_then(|a| a.as_link_addr().map(|l| l.ifindex() as u32))
}

/// A scoped IPv6 listen address only accepts datagrams captured on that
/// interface; an unscoped or IPv4 listen address accepts any interface.
fn listen_scope_matches(listen: SocketAddr, capture_ifindex: Option<u32>) -> bool {
    match listen {
        SocketAddr::V6(l) if l.scope_id() != 0 => capture_ifindex == Some(l.scope_id()),
        _ => true,
    }
}

/// A link-local IPv6 source is only meaningful with its interface scope, which
/// the packet itself does not carry; take it from where the packet was
/// captured.
fn attach_link_local_scope(src: &mut SocketAddr, capture_ifindex: Option<u32>) {
    if let SocketAddr::V6(v6) = src
        && is_link_local_v6(*v6.ip())
        && v6.scope_id() == 0
        && let Some(ifindex) = capture_ifindex
    {
        v6.set_scope_id(ifindex);
    }
}

/// Whether an IPv6 address is in the link-local unicast range (fe80::/10).
fn is_link_local_v6(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

/// Creates an AF_PACKET capture socket for silent mode.
///
/// This taps at the device layer, exactly like tcpdump, so packets are seen
/// regardless of routing, netfilter/NAT rules, or forwarding decisions (for
/// example a Docker host that DNATs or forwards the traffic to a container).
/// A raw `IPPROTO_UDP` socket, by contrast, only receives packets the kernel
/// routes for local delivery, which misses that traffic. Requires CAP_NET_RAW
/// (root).
fn new_capture_socket(is_ipv6: bool, interface: Option<&str>, listen_port: u16) -> Result<Socket> {
    let ethertype = if is_ipv6 {
        libc::ETH_P_IPV6
    } else {
        libc::ETH_P_IP
    } as u16;

    // The protocol passed to socket(AF_PACKET, ...) must be the EtherType in
    // network byte order (htons).
    let sock = Socket::new(
        Domain::PACKET,
        Type::DGRAM,
        Some(Protocol::from(ethertype.to_be() as i32)),
    )
    .context("create AF_PACKET capture socket")?;

    // Drop non-matching packets in the kernel. SOCK_DGRAM delivers cooked
    // frames, so the filter (like the read) sees the packet starting at the IP
    // header on every interface type, making these fixed offsets portable.
    if is_ipv6 {
        attach_bpf_filter(&sock, &create_bpf_filter_ipv6(listen_port))?;
    } else {
        attach_bpf_filter(&sock, &create_bpf_filter_ipv4(listen_port))?;
    }

    match interface {
        Some(iface) => {
            // SO_BINDTODEVICE does not restrict packet sockets; bind a
            // sockaddr_ll with the interface index instead.
            bind_to_interface(&sock, ethertype, iface)?;
            log::info!(
                "AF_PACKET capture for UDP port {} on interface {} ({})",
                listen_port,
                iface,
                if is_ipv6 { "IPv6" } else { "IPv4" }
            );
        }
        None => {
            log::info!(
                "AF_PACKET capture for UDP port {} on all interfaces ({})",
                listen_port,
                if is_ipv6 { "IPv6" } else { "IPv4" }
            );
        }
    }

    Ok(sock)
}

/// Resolves an interface name to its index.
fn ifindex_of(iface: &str) -> Result<u32> {
    let cname = std::ffi::CString::new(iface).context("interface name has interior NUL")?;
    let ifindex = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if ifindex == 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("unknown interface {}", iface));
    }
    Ok(ifindex)
}

/// Binds an AF_PACKET socket to a single interface by index, the supported way
/// to restrict a packet socket's capture to one interface.
fn bind_to_interface(sock: &Socket, ethertype: u16, iface: &str) -> Result<()> {
    let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = ethertype.to_be();
    sll.sll_ifindex = ifindex_of(iface)? as i32;

    let ret = unsafe {
        libc::bind(
            sock.as_raw_fd(),
            &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("bind capture to interface {}", iface));
    }

    Ok(())
}

/// The validated IP layer of a captured packet.
struct IpEnvelope {
    header_len: usize,
    /// Length of the IP packet itself; captured bytes beyond it are link-layer
    /// padding and must never be read as payload.
    total: usize,
    src: IpAddr,
    dst: IpAddr,
}

/// Validates an IPv4 header and confirms it carries an unfragmented UDP
/// datagram. Packet sockets do not reassemble fragments: a fragment has a
/// non-zero offset or the More Fragments flag, only its first piece carries a
/// UDP header, and that header's length covers the whole datagram, so
/// forwarding any fragment would emit corrupted data.
fn parse_ipv4(data: &[u8]) -> Option<IpEnvelope> {
    let ip = Ipv4Packet::new(data)?;
    if ip.get_version() != 4 {
        return None;
    }
    let header_len = (ip.get_header_length() as usize) * 4;
    if header_len < 20 {
        return None;
    }
    if ip.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
        return None;
    }
    if ip.get_fragment_offset() != 0 || (ip.get_flags() & Ipv4Flags::MoreFragments) != 0 {
        log::debug!("Silent: dropping IPv4 fragment from {}", ip.get_source());
        return None;
    }
    Some(IpEnvelope {
        header_len,
        total: ip.get_total_length() as usize,
        src: IpAddr::V4(ip.get_source()),
        dst: IpAddr::V4(ip.get_destination()),
    })
}

/// Validates an IPv6 header and confirms UDP follows it directly. Extension
/// headers (including fragments) are not reassembled; such packets are dropped.
fn parse_ipv6(data: &[u8]) -> Option<IpEnvelope> {
    let ip = Ipv6Packet::new(data)?;
    if ip.get_version() != 6 {
        return None;
    }
    if ip.get_next_header() != IpNextHeaderProtocols::Udp {
        return None;
    }
    Some(IpEnvelope {
        header_len: IPV6_HEADER_LEN,
        total: IPV6_HEADER_LEN + ip.get_payload_length() as usize,
        src: IpAddr::V6(ip.get_source()),
        dst: IpAddr::V6(ip.get_destination()),
    })
}

/// Parses a captured IP + UDP packet into a [`Datagram`] when it is a UDP
/// datagram addressed to `listen`. Enforces the listen port always and the
/// listen IP unless it is the wildcard address. Bounds all UDP parsing by the
/// IP-declared length so link-layer padding is never read as payload.
fn parse_captured_udp(data: &[u8], listen: SocketAddr) -> Option<Datagram<'_>> {
    let ip = if listen.is_ipv6() {
        parse_ipv6(data)?
    } else {
        parse_ipv4(data)?
    };

    // The IP packet must hold at least a UDP header and must not claim more
    // bytes than were captured.
    if ip.total < ip.header_len + UDP_HEADER_LEN || ip.total > data.len() {
        return None;
    }

    if !listen.ip().is_unspecified() && ip.dst != listen.ip() {
        return None;
    }

    let udp = UdpPacket::new(&data[ip.header_len..ip.total])?;
    if udp.get_destination() != listen.port() {
        return None;
    }

    // The UDP length covers header + payload and must fit within the IP packet.
    let udp_len = udp.get_length() as usize;
    if udp_len < UDP_HEADER_LEN {
        return None;
    }
    let end = ip.header_len + udp_len;
    if end > ip.total {
        return None;
    }

    Some(Datagram {
        src: SocketAddr::new(ip.src, udp.get_source()),
        payload: &data[ip.header_len + UDP_HEADER_LEN..end],
    })
}

// A classic BPF instruction (struct sock_filter).
#[repr(C)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

// struct sock_fprog: a BPF program (length + pointer to instructions).
#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

fn attach_bpf_filter(socket: &Socket, filter: &[SockFilter]) -> Result<()> {
    let prog = SockFprog {
        len: filter.len() as u16,
        filter: filter.as_ptr(),
    };

    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            SO_ATTACH_FILTER,
            &prog as *const _ as *const libc::c_void,
            std::mem::size_of::<SockFprog>() as libc::socklen_t,
        )
    };

    if ret < 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    Ok(())
}

/// Classic BPF that accepts UDP datagrams with destination `port`, assuming the
/// data starts at the IPv4 header. Valid for AF_PACKET SOCK_DGRAM, which
/// delivers cooked (link-layer-stripped) frames, so this works on any
/// interface.
const fn create_bpf_filter_ipv4(port: u16) -> [SockFilter; 7] {
    [
        // Load byte at offset 9 (IPv4 protocol field).
        SockFilter {
            code: 0x30,
            jt: 0,
            jf: 0,
            k: 9,
        },
        // If protocol != UDP (17), reject.
        SockFilter {
            code: 0x15,
            jt: 0,
            jf: 4,
            k: 17,
        },
        // X = IPv4 header length (4 * (byte0 & 0xf)).
        SockFilter {
            code: 0xb1,
            jt: 0,
            jf: 0,
            k: 0,
        },
        // Load half-word at X+2 (UDP destination port).
        SockFilter {
            code: 0x48,
            jt: 0,
            jf: 0,
            k: 2,
        },
        // If port matches, accept; else reject.
        SockFilter {
            code: 0x15,
            jt: 0,
            jf: 1,
            k: port as u32,
        },
        // Accept (return full packet).
        SockFilter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0xffff,
        },
        // Reject.
        SockFilter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0,
        },
    ]
}

/// Classic BPF that accepts UDP datagrams with destination `port`, assuming the
/// data starts at a 40-byte IPv6 header with no extension headers. Packets with
/// extension headers have a non-UDP next-header value, so they are dropped in
/// the kernel and never delivered (silent mode does not reassemble them).
const fn create_bpf_filter_ipv6(port: u16) -> [SockFilter; 6] {
    [
        // Load byte at offset 6 (IPv6 Next Header field).
        SockFilter {
            code: 0x30,
            jt: 0,
            jf: 0,
            k: 6,
        },
        // If next header != UDP (17), reject.
        SockFilter {
            code: 0x15,
            jt: 0,
            jf: 3,
            k: 17,
        },
        // Load half-word at offset 42 (UDP destination port after the 40-byte
        // IPv6 header).
        SockFilter {
            code: 0x28,
            jt: 0,
            jf: 0,
            k: (IPV6_HEADER_LEN + 2) as u32,
        },
        // If port matches, accept; else reject.
        SockFilter {
            code: 0x15,
            jt: 0,
            jf: 1,
            k: port as u32,
        },
        // Accept.
        SockFilter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0xffff,
        },
        // Reject.
        SockFilter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0,
        },
    ]
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV6};

    use super::*;

    /// Builds an IPv4 + UDP packet (as an AF_PACKET SOCK_DGRAM capture would
    /// deliver it) with the given fragmentation flags/offset word and payload.
    fn ipv4_udp(flags_frag: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let total = 20 + 8 + payload.len();
        let mut p = vec![0u8; total];
        p[0] = 0x45; // version 4, IHL 5
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[6..8].copy_from_slice(&flags_frag.to_be_bytes());
        p[8] = 64; // TTL
        p[9] = 17; // UDP
        p[12..16].copy_from_slice(&[127, 0, 0, 1]);
        p[16..20].copy_from_slice(&[127, 0, 0, 1]);
        p[20..22].copy_from_slice(&1234u16.to_be_bytes()); // src port
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        p[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        p[28..].copy_from_slice(payload);
        p
    }

    fn wildcard(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)
    }

    #[test]
    fn accepts_unfragmented_udp() {
        let pkt = ipv4_udp(0x0000, 4400, b"hello");
        let d = parse_captured_udp(&pkt, wildcard(4400)).expect("should parse");
        assert_eq!(d.src.port(), 1234);
        assert_eq!(d.payload, b"hello");
    }

    #[test]
    fn rejects_first_fragment() {
        // More Fragments flag set (0x2000), offset 0.
        let pkt = ipv4_udp(0x2000, 4400, b"hello");
        assert!(parse_captured_udp(&pkt, wildcard(4400)).is_none());
    }

    #[test]
    fn rejects_later_fragment() {
        // Non-zero fragment offset (2 * 8 bytes).
        let pkt = ipv4_udp(0x0002, 4400, b"hello");
        assert!(parse_captured_udp(&pkt, wildcard(4400)).is_none());
    }

    #[test]
    fn rejects_wrong_port() {
        let pkt = ipv4_udp(0x0000, 9999, b"hello");
        assert!(parse_captured_udp(&pkt, wildcard(4400)).is_none());
    }

    #[test]
    fn enforces_specific_listen_ip() {
        // Packet is addressed to 127.0.0.1 (see `ipv4_udp`).
        let pkt = ipv4_udp(0x0000, 4400, b"hello");
        let matching: SocketAddr = "127.0.0.1:4400".parse().unwrap();
        let other: SocketAddr = "127.0.0.2:4400".parse().unwrap();
        assert!(parse_captured_udp(&pkt, matching).is_some());
        assert!(parse_captured_udp(&pkt, other).is_none());
    }

    #[test]
    fn rejects_declared_length_beyond_capture() {
        // Claim a UDP length longer than the bytes actually present.
        let mut pkt = ipv4_udp(0x0000, 4400, b"hello");
        pkt[24..26].copy_from_slice(&(8 + 100u16).to_be_bytes());
        assert!(parse_captured_udp(&pkt, wildcard(4400)).is_none());
    }

    #[test]
    fn ignores_link_layer_padding() {
        // A short datagram padded to a larger frame: the UDP length claims into
        // the padding, but the IP total length bounds it out.
        let mut pkt = ipv4_udp(0x0000, 4400, b"hi");
        pkt[24..26].copy_from_slice(&(8 + 50u16).to_be_bytes()); // bogus UDP length
        pkt.extend(std::iter::repeat_n(0u8, 50)); // link-layer padding
        assert!(parse_captured_udp(&pkt, wildcard(4400)).is_none());
    }

    #[test]
    fn scoped_listen_requires_matching_capture_interface() {
        let scoped = SocketAddr::V6(SocketAddrV6::new("fe80::1".parse().unwrap(), 5000, 0, 3));
        assert!(listen_scope_matches(scoped, Some(3)));
        assert!(!listen_scope_matches(scoped, Some(4)));
        assert!(!listen_scope_matches(scoped, None));
        // Unscoped and IPv4 listen addresses accept any interface.
        assert!(listen_scope_matches(wildcard(5000), Some(7)));
        assert!(listen_scope_matches(
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 5000, 0, 0)),
            None
        ));
    }

    #[test]
    fn link_local_source_gets_capture_scope() {
        let mut src = SocketAddr::V6(SocketAddrV6::new("fe80::abcd".parse().unwrap(), 1, 0, 0));
        attach_link_local_scope(&mut src, Some(9));
        assert_eq!(
            match src {
                SocketAddr::V6(v6) => v6.scope_id(),
                _ => unreachable!(),
            },
            9
        );

        // A global address is left alone.
        let mut global = SocketAddr::V6(SocketAddrV6::new("2001:db8::1".parse().unwrap(), 1, 0, 0));
        attach_link_local_scope(&mut global, Some(9));
        assert_eq!(
            match global {
                SocketAddr::V6(v6) => v6.scope_id(),
                _ => unreachable!(),
            },
            0
        );
    }
}
