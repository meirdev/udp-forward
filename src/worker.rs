use std::collections::HashMap;
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;

use anyhow::{Context, Result};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::ipv6::Ipv6Packet;
use pnet_packet::udp::UdpPacket;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::cli::Args;

// Fixed IPv6 header length (no extension headers). libc has no constant for it.
const IPV6_HEADER_LEN: usize = 40;
const UDP_HEADER_LEN: usize = 8;

const SO_ATTACH_FILTER: libc::c_int = 26;

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

struct Destination {
    addr: SocketAddr,
    sock_addr: SockAddr,
}

#[derive(Clone, Copy)]
enum IterationMode {
    NormalV4,
    NormalV6,
    SilentV4,
    SilentV6,
}

pub struct Worker {
    recv_socket: Socket,
    send_socket: Socket,
    // Per-source transparent sockets used when spoofing. Keyed by the original
    // source address; each is bound to that address so the kernel emits packets
    // with it as the source (via IP_TRANSPARENT / IPV6_TRANSPARENT).
    spoof_cache: HashMap<SocketAddr, Socket>,
    destinations: Vec<Destination>,
    listen_port: u16,
    mode: IterationMode,
    spoof: bool,
    ttl: u8,
    recv_buf: Vec<MaybeUninit<u8>>,
}

impl Worker {
    pub fn new(args: &Args) -> Result<Self> {
        let listen_port = args.listen.port();
        let is_ipv6 = args.listen.is_ipv6();
        let domain = if is_ipv6 { Domain::IPV6 } else { Domain::IPV4 };

        let recv_socket = if args.silent {
            new_capture_socket(is_ipv6, args.interface.as_deref(), listen_port)?
        } else {
            let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
            sock.set_reuse_port(true)?;
            sock.bind(&args.listen.into())?;
            sock
        };

        let send_socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        if is_ipv6 {
            send_socket.set_unicast_hops_v6(args.ttl as u32)?;
        } else {
            send_socket.set_ttl_v4(args.ttl as u32)?;
        }

        let destinations: Vec<Destination> = args
            .destinations
            .iter()
            .map(|&addr| Destination {
                addr,
                sock_addr: addr.into(),
            })
            .collect();

        let mode = match (args.silent, is_ipv6) {
            (false, false) => IterationMode::NormalV4,
            (false, true) => IterationMode::NormalV6,
            (true, false) => IterationMode::SilentV4,
            (true, true) => IterationMode::SilentV6,
        };

        let recv_buf = vec![MaybeUninit::uninit(); args.buffer_size];

        Ok(Self {
            recv_socket,
            send_socket,
            spoof_cache: HashMap::new(),
            destinations,
            listen_port,
            mode,
            spoof: args.spoof,
            ttl: args.ttl,
            recv_buf,
        })
    }

    pub fn run(mut self) -> Result<()> {
        match self.mode {
            IterationMode::NormalV4 | IterationMode::NormalV6 => self.run_normal_loop(),
            IterationMode::SilentV4 => self.run_silent_loop(false),
            IterationMode::SilentV6 => self.run_silent_loop(true),
        }
    }

    fn run_normal_loop(&mut self) -> Result<()> {
        loop {
            let (len, src_addr) = self.recv_socket.recv_from(&mut self.recv_buf)?;
            let payload =
                unsafe { std::slice::from_raw_parts(self.recv_buf.as_ptr() as *const u8, len) };
            let src: SocketAddr = src_addr.as_socket().context("Invalid source address")?;
            log::debug!("Received {} bytes from {}", len, src);
            self.forward(payload, src);
        }
    }

    fn run_silent_loop(&mut self, is_ipv6: bool) -> Result<()> {
        // AF_PACKET SOCK_DGRAM delivers the packet starting at the IP header
        // (the link-layer header is stripped in cooked mode).
        loop {
            let len = self.recv_socket.recv(&mut self.recv_buf)?;
            // Logged before any userspace filtering: with the BPF attached, only
            // packets that already passed the in-kernel filter reach this point.
            log::debug!("Silent: captured raw frame of {} bytes", len);
            let data =
                unsafe { std::slice::from_raw_parts(self.recv_buf.as_ptr() as *const u8, len) };

            let Some((src, payload)) = parse_captured_udp(data, is_ipv6, self.listen_port) else {
                continue;
            };

            log::debug!("Received {} bytes from {} (silent)", payload.len(), src);
            self.forward(payload, src);
        }
    }

    fn forward(&mut self, payload: &[u8], src: SocketAddr) {
        if self.spoof {
            self.send_spoofed(payload, src);
        } else {
            for i in 0..self.destinations.len() {
                self.send_normal(payload, i);
            }
        }
    }

    fn send_normal(&self, payload: &[u8], dest_idx: usize) {
        let dest = &self.destinations[dest_idx];
        log::debug!(
            "Forwarding {} bytes to {} (normal)",
            payload.len(),
            dest.addr
        );
        if let Err(e) = self.send_socket.send_to(payload, &dest.sock_addr) {
            log::error!("Failed to send to {}: {}", dest.addr, e);
        }
    }

    fn send_spoofed(&mut self, payload: &[u8], src: SocketAddr) {
        if !self.spoof_cache.contains_key(&src) {
            let sock = match make_spoof_socket(src, self.ttl) {
                Ok(sock) => sock,
                Err(e) => {
                    log::error!("Failed to create spoof socket for source {}: {}", src, e);
                    return;
                }
            };
            self.spoof_cache.insert(src, sock);
        }

        let sock = &self.spoof_cache[&src];
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

/// Creates an AF_PACKET capture socket for silent mode.
///
/// This taps at the device layer, exactly like tcpdump, so packets are seen
/// regardless of routing, netfilter/NAT rules, or forwarding decisions (for
/// example a Docker host that DNATs or forwards the traffic to a container).
/// A raw `IPPROTO_UDP` socket, by contrast, only receives packets the kernel
/// routes for local delivery, which misses that traffic. Requires CAP_NET_RAW
/// (root).
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

/// Parses a captured IP + UDP packet, returning the sender address and the UDP
/// payload when it is a UDP datagram addressed to `listen_port`.
///
/// The returned payload is bounded by the UDP length field, which strips any
/// link-layer padding (e.g. Ethernet's 60-byte minimum frame). Returns `None`
/// for anything that is not a matching UDP datagram.
fn parse_captured_udp(data: &[u8], is_ipv6: bool, listen_port: u16) -> Option<(SocketAddr, &[u8])> {
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
    let payload = data.get(payload_start..payload_end)?;

    Some((src, payload))
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
