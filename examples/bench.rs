//! Loopback load generator and counter for measuring udp-forward.
//!
//! ```text
//! bench send <dest> <packets> <payload_bytes>   # blast, report achieved pps
//! bench recv <bind> <seconds>                  # count arrivals, report pps
//! ```
//!
//! Both sides batch up to 64 messages per syscall. Measure generator and
//! receiver capacity separately before attributing a limit to the forwarder.

use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};

const BATCH: usize = 64;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("send") if args.len() == 5 => {
            let dest: SocketAddr = args[2].parse().expect("dest addr");
            let packets: usize = args[3].parse().expect("packet count");
            let size: usize = args[4].parse().expect("payload bytes");
            send(dest, packets, size);
        }
        Some("recv") if args.len() == 4 => {
            let bind: SocketAddr = args[2].parse().expect("bind addr");
            let secs: u64 = args[3].parse().expect("seconds");
            recv(bind, secs);
        }
        _ => {
            eprintln!("usage: bench send <dest> <packets> <payload_bytes>");
            eprintln!("       bench recv <bind> <seconds>");
            std::process::exit(2);
        }
    }
}

fn send(dest: SocketAddr, packets: usize, size: usize) {
    let domain = if dest.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).expect("socket");
    // SO_REUSEPORT so the forwarder's spoof sink can bind a transparent socket
    // to this sender's source address while this socket still holds it.
    sock.set_reuse_address(true).expect("SO_REUSEADDR");
    sock.set_reuse_port(true).expect("SO_REUSEPORT");
    let bind: SocketAddr = if dest.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    }
    .parse()
    .unwrap();
    sock.bind(&bind.into()).expect("bind sender");
    // Connected socket: the kernel caches the route and sendmmsg needs no
    // per-message address.
    sock.connect(&dest.into()).expect("connect sender");
    let fd = sock.as_raw_fd();

    let payload = vec![0xabu8; size];
    let mut iovecs: Vec<libc::iovec> = (0..BATCH)
        .map(|_| libc::iovec {
            iov_base: payload.as_ptr() as *mut libc::c_void,
            iov_len: size,
        })
        .collect();
    let mut msgs: Vec<libc::mmsghdr> = (0..BATCH)
        .map(|i| {
            let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
            hdr.msg_iov = &mut iovecs[i];
            hdr.msg_iovlen = 1;
            libc::mmsghdr {
                msg_hdr: hdr,
                msg_len: 0,
            }
        })
        .collect();

    let start = Instant::now();
    let mut sent = 0usize;
    let mut calls = 0usize;
    while sent < packets {
        let n = BATCH.min(packets - sent);
        let ret = unsafe { libc::sendmmsg(fd, msgs.as_mut_ptr(), n as libc::c_uint, 0) };
        if ret < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            panic!("sendmmsg: {}", e);
        }
        sent += ret as usize;
        calls += 1;
    }
    let elapsed = start.elapsed().as_secs_f64();
    let pps = sent as f64 / elapsed;
    let mbps = pps * size as f64 * 8.0 / 1e6;
    println!(
        "SEND packets={} bytes={} elapsed={:.3}s pps={:.0} payload_mbit_s={:.0} sendmmsg_calls={}",
        sent, size, elapsed, pps, mbps, calls
    );
}

fn recv(bind: SocketAddr, secs: u64) {
    let domain = if bind.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).expect("socket");
    // Request extra queue space for bursts. Kernel limits may cap this request;
    // a successful call does not guarantee a lossless receiver.
    sock.set_recv_buffer_size(64 << 20).expect("SO_RCVBUF");
    sock.set_read_timeout(Some(Duration::from_millis(250)))
        .expect("SO_RCVTIMEO");
    sock.bind(&bind.into()).expect("bind receiver");
    let fd = sock.as_raw_fd();

    let mut bufs: Vec<Vec<u8>> = vec![vec![0u8; 65535]; BATCH];
    let mut iovecs: Vec<libc::iovec> = bufs
        .iter_mut()
        .map(|b| libc::iovec {
            iov_base: b.as_mut_ptr() as *mut libc::c_void,
            iov_len: b.len(),
        })
        .collect();
    let mut msgs: Vec<libc::mmsghdr> = (0..BATCH)
        .map(|i| {
            let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
            hdr.msg_iov = &mut iovecs[i];
            hdr.msg_iovlen = 1;
            libc::mmsghdr {
                msg_hdr: hdr,
                msg_len: 0,
            }
        })
        .collect();

    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut packets = 0usize;
    let mut bytes = 0usize;
    let mut calls = 0usize;
    let mut first: Option<Instant> = None;
    let mut last: Option<Instant> = None;

    while Instant::now() < deadline {
        let ret = unsafe {
            libc::recvmmsg(
                fd,
                msgs.as_mut_ptr(),
                BATCH as libc::c_uint,
                libc::MSG_WAITFORONE as _,
                std::ptr::null_mut(),
            )
        };
        if ret < 0 {
            let e = io::Error::last_os_error();
            match e.raw_os_error() {
                Some(libc::EINTR) | Some(libc::EAGAIN) => continue,
                _ => panic!("recvmmsg: {}", e),
            }
        }
        let now = Instant::now();
        first.get_or_insert(now);
        last = Some(now);
        calls += 1;
        let n = ret as usize;
        packets += n;
        bytes += msgs[..n].iter().map(|m| m.msg_len as usize).sum::<usize>();
    }

    // Rate over the window in which traffic was actually arriving.
    let window = match (first, last) {
        (Some(f), Some(l)) if l > f => (l - f).as_secs_f64(),
        _ => 0.0,
    };
    let pps = if window > 0.0 {
        packets as f64 / window
    } else {
        0.0
    };
    let avg_batch = if calls > 0 {
        packets as f64 / calls as f64
    } else {
        0.0
    };
    println!(
        "RECV packets={} bytes={} window={:.3}s pps={:.0} recvmmsg_calls={} avg_per_call={:.1}",
        packets, bytes, window, pps, calls, avg_batch
    );
}
