use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::AsRawFd;

use anyhow::{Context, Result};
use pnet_packet::Packet;
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::{self, Ipv4Packet, MutableIpv4Packet};
use pnet_packet::ipv6::MutableIpv6Packet;
use pnet_packet::udp::{self, MutableUdpPacket, UdpPacket};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::cli::Args;

const SO_ATTACH_FILTER: libc::c_int = 26;

const IP_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const UDP_HEADER_LEN: usize = 8;

// Ethernet protocol for IPv6
const ETH_P_IPV6: u16 = 0x86dd;

#[repr(C)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

#[repr(C)]
struct SockaddrLl {
    sll_family: u16,
    sll_protocol: u16,
    sll_ifindex: i32,
    sll_hatype: u16,
    sll_pkttype: u8,
    sll_halen: u8,
    sll_addr: [u8; 8],
}

const fn create_bpf_filter_udp(port: u16) -> [SockFilter; 4] {
    [
        // Load half-word at offset 2 (UDP destination port)
        SockFilter {
            code: 0x28,
            jt: 0,
            jf: 0,
            k: 2,
        },
        // Jump if port matches
        SockFilter {
            code: 0x15,
            jt: 0,
            jf: 1,
            k: port as u32,
        },
        // Accept packet
        SockFilter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0xffff,
        },
        // Reject packet
        SockFilter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0,
        },
    ]
}

const fn create_bpf_filter_ipv4(port: u16) -> [SockFilter; 7] {
    [
        // Load byte at offset 9 (IP protocol field)
        SockFilter {
            code: 0x30,
            jt: 0,
            jf: 0,
            k: 9,
        },
        // Jump if protocol == 17 (UDP), else reject
        SockFilter {
            code: 0x15,
            jt: 0,
            jf: 4,
            k: 17,
        },
        // Load IP header length into X
        SockFilter {
            code: 0xb1,
            jt: 0,
            jf: 0,
            k: 0,
        },
        // Load half-word at X+2 (UDP destination port)
        SockFilter {
            code: 0x48,
            jt: 0,
            jf: 0,
            k: 2,
        },
        // Jump if port matches
        SockFilter {
            code: 0x15,
            jt: 0,
            jf: 1,
            k: port as u32,
        },
        // Accept packet
        SockFilter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0xffff,
        },
        // Reject packet
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
    raw_send_socket: Option<Socket>,
    packet_socket_v6: Option<Socket>,
    packet_ifindex: i32,
    destinations: Vec<Destination>,
    listen_port: u16,
    mode: IterationMode,
    spoof: bool,
    ttl: u8,
    recv_buf: Vec<MaybeUninit<u8>>,
    send_buf: Vec<u8>,
}

impl Worker {
    pub fn new(args: &Args) -> Result<Self> {
        let listen_port = args.listen.port();
        let is_ipv6 = args.listen.is_ipv6();
        let domain = if is_ipv6 { Domain::IPV6 } else { Domain::IPV4 };

        let recv_socket = if args.silent {
            let sock = Socket::new(domain, Type::RAW, Some(Protocol::UDP))?;
            if is_ipv6 {
                attach_bpf_filter(&sock, &create_bpf_filter_udp(listen_port))?;
            } else {
                attach_bpf_filter(&sock, &create_bpf_filter_ipv4(listen_port))?;
            }
            log::info!(
                "BPF filter attached for UDP port {} ({})",
                listen_port,
                if is_ipv6 { "IPv6" } else { "IPv4" }
            );
            sock
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

        let raw_send_socket = if args.spoof && !is_ipv6 {
            let sock = Socket::new(domain, Type::RAW, Some(Protocol::UDP))?;
            sock.set_header_included_v4(true)?;
            Some(sock)
        } else {
            None
        };

        // For IPv6 spoofing, we need to use AF_PACKET socket
        let (packet_socket_v6, packet_ifindex) = if args.spoof && is_ipv6 {
            let sock = Socket::new(
                Domain::PACKET,
                Type::DGRAM,
                Some(Protocol::from(ETH_P_IPV6 as i32)),
            )?;
            let ifindex = get_loopback_ifindex().unwrap_or(1);
            log::info!(
                "Created AF_PACKET socket for IPv6 spoofing (ifindex={})",
                ifindex
            );
            (Some(sock), ifindex)
        } else {
            (None, 0)
        };

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
        let send_buf = vec![0u8; args.buffer_size];

        Ok(Self {
            recv_socket,
            send_socket,
            raw_send_socket,
            packet_socket_v6,
            packet_ifindex,
            destinations,
            listen_port,
            mode,
            spoof: args.spoof,
            ttl: args.ttl,
            recv_buf,
            send_buf,
        })
    }

    pub fn run(mut self) -> Result<()> {
        match self.mode {
            IterationMode::NormalV4 | IterationMode::NormalV6 => self.run_normal_loop(),
            IterationMode::SilentV4 => self.run_silent_v4_loop(),
            IterationMode::SilentV6 => self.run_silent_v6_loop(),
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

    fn run_silent_v4_loop(&mut self) -> Result<()> {
        // Raw socket returns full IP packet (IP header + UDP header + payload)
        loop {
            let (len, _) = self.recv_socket.recv_from(&mut self.recv_buf)?;
            log::debug!("Silent v4: recv_from returned {} bytes", len);
            let data =
                unsafe { std::slice::from_raw_parts(self.recv_buf.as_ptr() as *const u8, len) };

            let Some(ip_packet) = Ipv4Packet::new(data) else {
                log::debug!("Silent v4: failed to parse IP packet ({} bytes)", len);
                continue;
            };

            let src_ip = ip_packet.get_source();
            let ip_header_len = (ip_packet.get_header_length() as usize) * 4;

            let Some(udp_packet) = UdpPacket::new(&data[ip_header_len..]) else {
                log::debug!("Silent v4: failed to parse UDP packet from {}", src_ip);
                continue;
            };

            if udp_packet.get_destination() != self.listen_port {
                continue;
            }

            let src = SocketAddr::V4(SocketAddrV4::new(src_ip, udp_packet.get_source()));
            log::debug!(
                "Received {} bytes from {} (silent v4)",
                udp_packet.payload().len(),
                src
            );
            self.forward(udp_packet.payload(), src);
        }
    }

    fn run_silent_v6_loop(&mut self) -> Result<()> {
        // Raw socket returns UDP packet without IPv6 header
        loop {
            let (len, src_addr) = self.recv_socket.recv_from(&mut self.recv_buf)?;
            log::debug!("Silent v6: recv_from returned {} bytes", len);
            let data =
                unsafe { std::slice::from_raw_parts(self.recv_buf.as_ptr() as *const u8, len) };

            let src_ip = match src_addr.as_socket_ipv6() {
                Some(addr) => *addr.ip(),
                None => {
                    log::debug!("Silent v6: received non-IPv6 source address");
                    continue;
                }
            };

            let Some(udp_packet) = UdpPacket::new(data) else {
                log::debug!("Silent v6: failed to parse UDP packet ({} bytes)", len);
                continue;
            };

            if udp_packet.get_destination() != self.listen_port {
                continue;
            }

            let src = SocketAddr::V6(SocketAddrV6::new(src_ip, udp_packet.get_source(), 0, 0));
            log::debug!(
                "Received {} bytes from {} (silent v6)",
                udp_packet.payload().len(),
                src
            );
            self.forward(udp_packet.payload(), src);
        }
    }

    fn forward(&mut self, payload: &[u8], src: SocketAddr) {
        for i in 0..self.destinations.len() {
            if self.spoof {
                self.send_spoofed(payload, src, i);
            } else {
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

    fn send_spoofed(&mut self, payload: &[u8], src: SocketAddr, dest_idx: usize) {
        let dest = &self.destinations[dest_idx];

        match (src, dest.addr) {
            (SocketAddr::V4(src_v4), SocketAddr::V4(dest_v4)) => {
                let raw_socket = self.raw_send_socket.as_ref().unwrap();
                let packet_len = build_packet_v4_into(
                    &mut self.send_buf,
                    payload,
                    *src_v4.ip(),
                    src_v4.port(),
                    *dest_v4.ip(),
                    dest_v4.port(),
                    self.ttl,
                );
                if let Err(e) = raw_socket.send_to(&self.send_buf[..packet_len], &dest.sock_addr) {
                    log::error!("Failed to send spoofed packet to {}: {}", dest.addr, e);
                }
            }
            (SocketAddr::V6(src_v6), SocketAddr::V6(dest_v6)) => {
                let sock = self.packet_socket_v6.as_ref().unwrap();
                let packet_len = build_packet_v6_into(
                    &mut self.send_buf,
                    payload,
                    *src_v6.ip(),
                    src_v6.port(),
                    *dest_v6.ip(),
                    dest_v6.port(),
                    self.ttl,
                );

                let sockaddr = SockaddrLl {
                    sll_family: libc::AF_PACKET as u16,
                    sll_protocol: (ETH_P_IPV6 as u16).to_be(),
                    sll_ifindex: self.packet_ifindex,
                    sll_hatype: 0,
                    sll_pkttype: 0,
                    sll_halen: 0,
                    sll_addr: [0; 8],
                };

                let ret = unsafe {
                    libc::sendto(
                        sock.as_raw_fd(),
                        self.send_buf.as_ptr() as *const libc::c_void,
                        packet_len,
                        0,
                        &sockaddr as *const _ as *const libc::sockaddr,
                        std::mem::size_of::<SockaddrLl>() as libc::socklen_t,
                    )
                };

                if ret < 0 {
                    let err = std::io::Error::last_os_error();
                    log::error!(
                        "Failed to send spoofed IPv6 packet to {}: {}",
                        dest.addr,
                        err
                    );
                }
            }
            _ => {
                log::error!("Address family mismatch: src={}, dest={}", src, dest.addr);
            }
        }
    }
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

fn build_packet_v4_into(
    buf: &mut [u8],
    payload: &[u8],
    src_ip: Ipv4Addr,
    src_port: u16,
    dest_ip: Ipv4Addr,
    dest_port: u16,
    ttl: u8,
) -> usize {
    let total_len = IP_HEADER_LEN + UDP_HEADER_LEN + payload.len();

    {
        let mut ip = MutableIpv4Packet::new(&mut buf[..IP_HEADER_LEN]).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length(total_len as u16);
        ip.set_ttl(ttl);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        ip.set_source(src_ip);
        ip.set_destination(dest_ip);
        ip.set_checksum(ipv4::checksum(&ip.to_immutable()));
    }

    buf[IP_HEADER_LEN + UDP_HEADER_LEN..total_len].copy_from_slice(payload);

    {
        let mut udp_pkt = MutableUdpPacket::new(&mut buf[IP_HEADER_LEN..total_len]).unwrap();
        udp_pkt.set_source(src_port);
        udp_pkt.set_destination(dest_port);
        udp_pkt.set_length((UDP_HEADER_LEN + payload.len()) as u16);

        let checksum = udp::ipv4_checksum(&udp_pkt.to_immutable(), &src_ip, &dest_ip);
        udp_pkt.set_checksum(checksum);
    }

    total_len
}

fn build_packet_v6_into(
    buf: &mut [u8],
    payload: &[u8],
    src_ip: Ipv6Addr,
    src_port: u16,
    dest_ip: Ipv6Addr,
    dest_port: u16,
    hop_limit: u8,
) -> usize {
    let udp_len = UDP_HEADER_LEN + payload.len();
    let total_len = IPV6_HEADER_LEN + udp_len;

    {
        let mut ip6 = MutableIpv6Packet::new(&mut buf[..IPV6_HEADER_LEN]).unwrap();
        ip6.set_version(6);
        ip6.set_traffic_class(0);
        ip6.set_flow_label(0);
        ip6.set_payload_length(udp_len as u16);
        ip6.set_next_header(IpNextHeaderProtocols::Udp);
        ip6.set_hop_limit(hop_limit);
        ip6.set_source(src_ip);
        ip6.set_destination(dest_ip);
    }

    buf[IPV6_HEADER_LEN + UDP_HEADER_LEN..total_len].copy_from_slice(payload);

    {
        let mut udp_pkt = MutableUdpPacket::new(&mut buf[IPV6_HEADER_LEN..total_len]).unwrap();
        udp_pkt.set_source(src_port);
        udp_pkt.set_destination(dest_port);
        udp_pkt.set_length(udp_len as u16);

        let checksum = udp::ipv6_checksum(&udp_pkt.to_immutable(), &src_ip, &dest_ip);
        udp_pkt.set_checksum(checksum);
    }

    total_len
}

fn get_loopback_ifindex() -> Option<i32> {
    unsafe {
        let idx = libc::if_nametoindex(b"lo\0".as_ptr() as *const libc::c_char);
        if idx == 0 { None } else { Some(idx as i32) }
    }
}
