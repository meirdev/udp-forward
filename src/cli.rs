use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(name = "udp-forward")]
#[command(about = "UDP packets forwarder")]
#[command(version)]
pub struct Args {
    /// Address and port to listen on (e.g., 0.0.0.0:5000)
    #[arg(short, long)]
    pub listen: SocketAddr,

    /// Spoof source IP (preserve original sender address)
    #[arg(short, long)]
    pub spoof: bool,

    /// Silent mode: sniff packets without binding (allows other programs to use
    /// the port)
    #[arg(short = 'S', long)]
    pub silent: bool,

    /// TTL for outgoing packets
    #[arg(short = 'T', long, default_value_t = 64)]
    pub ttl: u8,

    /// Number of worker threads
    #[arg(short, long, default_value_t = num_cpus::get())]
    pub workers: usize,

    /// Receive buffer size in bytes
    #[arg(short, long, default_value_t = 65536)]
    pub buffer_size: usize,

    /// Fork into background (daemon mode)
    #[arg(short, long)]
    pub fork: bool,

    /// Write PID to file (useful with --fork)
    #[arg(short, long)]
    pub pidfile: Option<PathBuf>,

    /// Destination addresses to forward packets to
    #[arg(required = true)]
    pub destinations: Vec<SocketAddr>,
}
