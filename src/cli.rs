use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;

fn parse_nonzero_usize(s: &str) -> Result<usize, String> {
    let value: usize = s.parse().map_err(|e| format!("{}", e))?;
    if value == 0 {
        return Err("must be greater than 0".to_string());
    }
    Ok(value)
}

#[derive(Parser, Debug, Clone)]
#[command(name = "udp-forward")]
#[command(about = "UDP packets forwarder")]
#[command(version)]
pub struct Args {
    /// Address and port to listen on (e.g., 0.0.0.0:5000)
    #[arg(short, long)]
    pub listen: SocketAddr,

    /// Preserve the original sender IP and port
    #[arg(short, long)]
    pub spoof: bool,

    /// Silent mode: sniff packets without binding (allows other programs to use
    /// the port)
    #[arg(short = 'S', long)]
    pub silent: bool,

    /// Restrict silent-mode capture to a single interface (default: all
    /// interfaces).
    #[arg(short = 'i', long, requires = "silent")]
    pub interface: Option<String>,

    /// IPv4 TTL or IPv6 hop limit for outgoing packets
    #[arg(short = 'T', long, default_value_t = 64)]
    pub ttl: u8,

    /// Number of worker threads (silent mode uses one)
    #[arg(short, long, default_value_t = num_cpus::get(), value_parser = parse_nonzero_usize)]
    pub workers: usize,

    /// Bytes per packet buffer (does not set the kernel receive queue size)
    #[arg(short, long, default_value_t = 65536, value_parser = parse_nonzero_usize)]
    pub buffer_size: usize,

    /// Write logs to this file instead of stderr
    #[arg(long)]
    pub logfile: Option<PathBuf>,

    /// Destination addresses to forward packets to
    #[arg(required = true)]
    pub destinations: Vec<SocketAddr>,
}
