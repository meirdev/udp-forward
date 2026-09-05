//! Silent receive: an AF_PACKET capture socket that taps at the device layer,
//! like tcpdump, plus the in-kernel BPF filter and packet parsing it needs.

use std::net::{IpAddr, SocketAddr};
use std::ops::Range;
use std::os::fd::AsRawFd;

use anyhow::{Context, Result};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::Ipv4Packet;
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
    is_ipv6: bool,
    listen_port: u16,
}

impl SilentSource {
    pub(crate) fn new(
        listen: SocketAddr,
        interface: Option<&str>,
        buffer_size: usize,
    ) -> Result<Self> {
        let is_ipv6 = listen.is_ipv6();
        let socket = new_capture_socket(is_ipv6, interface, listen.port())?;
        Ok(Self {
            socket,
            rx: BatchedReceiver::new(buffer_size),
            is_ipv6,
            listen_port: listen.port(),
        })
    }
}

impl PacketSource for SilentSource {
    fn recv_batch(&mut self) -> Result<Vec<Datagram<'_>>> {
        // AF_PACKET SOCK_DGRAM delivers each packet starting at the IP header
        // (the link-layer header is stripped in cooked mode). The BPF filter
        // drops non-matching packets in the kernel; the parse here is the
        // backstop (and handles the IPv6-extension-header case). The capture
        // address is ignored; the real source is parsed from the packet.
        let fd = self.socket.as_raw_fd();
        let n = self.rx.recv(fd)?;

        let mut batch = Vec::with_capacity(n);
        for i in 0..n {
            let (_addr, data) = self.rx.get(i);
            log::debug!("Silent: captured raw frame of {} bytes", data.len());
            if let Some((src, range)) = parse_captured_udp(data, self.is_ipv6, self.listen_port) {
                let payload = &data[range];
                log::debug!("Received {} bytes from {} (silent)", payload.len(), src);
                batch.push(Datagram { src, payload });
            }
        }
        Ok(batch)
    }
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
            sock.bind_device(Some(iface.as_bytes()))
                .with_context(|| format!("bind capture to interface {}", iface))?;
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

/// Parses a captured IP + UDP packet, returning the sender address and the byte
/// range of the UDP payload within `data` when it is a UDP datagram addressed
/// to `listen_port`.
///
/// A range (rather than a borrowed slice) is returned so the caller can release
/// its borrow of the receive buffer before reacquiring just the payload. The
/// range is bounded by the UDP length field, which strips any link-layer
/// padding (e.g. Ethernet's 60-byte minimum frame). Returns `None` for anything
/// that is not a matching UDP datagram.
fn parse_captured_udp(
    data: &[u8],
    is_ipv6: bool,
    listen_port: u16,
) -> Option<(SocketAddr, Range<usize>)> {
    let (ip_header_len, src_ip) = if is_ipv6 {
        let ip = Ipv6Packet::new(data)?;
        if ip.get_next_header() != IpNextHeaderProtocols::Udp {
            return None;
        }
        // Only UDP directly after the IPv6 header (no extension headers).
        (IPV6_HEADER_LEN, IpAddr::V6(ip.get_source()))
    } else {
        let ip = Ipv4Packet::new(data)?;
        if ip.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
            return None;
        }
        (
            (ip.get_header_length() as usize) * 4,
            IpAddr::V4(ip.get_source()),
        )
    };

    let udp = UdpPacket::new(data.get(ip_header_len..)?)?;
    if udp.get_destination() != listen_port {
        return None;
    }

    let src = SocketAddr::new(src_ip, udp.get_source());
    let payload_start = ip_header_len + UDP_HEADER_LEN;
    let payload_end = (ip_header_len + udp.get_length() as usize).min(data.len());
    if payload_start > payload_end {
        return None;
    }

    Some((src, payload_start..payload_end))
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
/// extension headers are rejected here and fall to the userspace check.
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
