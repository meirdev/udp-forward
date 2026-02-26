use std::net::SocketAddr;
use std::thread;

use anyhow::{Context, Result};
use clap::Parser;
use nix::unistd::daemon;
use socket2::{Domain, Protocol, Socket, Type};
use udp_forward::cli::Args;
use udp_forward::worker::Worker;

fn is_port_in_use(addr: SocketAddr) -> bool {
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };

    let Ok(sock) = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)) else {
        return false;
    };

    sock.bind(&addr.into()).is_err()
}

fn main() -> Result<()> {
    env_logger::init();

    let args = Args::parse();

    if args.fork {
        daemon(false, false).context("Failed to daemonize")?;
    }

    if let Some(ref pidfile) = args.pidfile {
        let pid = std::process::id();

        std::fs::write(pidfile, pid.to_string())
            .with_context(|| format!("Failed to write PID to {}", pidfile.display()))?;

        log::info!("PID {} written to {}", pid, pidfile.display());
    }

    let is_ipv6 = args.listen.is_ipv6();
    for dest in &args.destinations {
        if dest.is_ipv6() != is_ipv6 {
            anyhow::bail!(
                "All addresses must be same family. Listen is {}, but destination {} is {}",
                if is_ipv6 { "IPv6" } else { "IPv4" },
                dest,
                if dest.is_ipv6() { "IPv6" } else { "IPv4" }
            );
        }
    }

    let workers = if args.silent && args.workers > 1 {
        log::warn!(
            "Silent mode uses raw sockets which don't support multi-threading. \
             Forcing single worker thread (requested: {})",
            args.workers
        );
        1
    } else {
        args.workers
    };

    if !args.silent && is_port_in_use(args.listen) {
        anyhow::bail!("Port {} is already in use", args.listen);
    }

    log::info!("Config: {:?}", args);
    log::info!("Starting {} worker thread(s)", workers);

    let mut handles = Vec::with_capacity(workers);

    for i in 0..workers {
        let args = args.clone();
        let handle = thread::Builder::new()
            .name(format!("worker-{}", i))
            .spawn(move || {
                let worker = match Worker::new(&args) {
                    Ok(w) => w,
                    Err(e) => {
                        log::error!("Failed to create worker {}: {}", i, e);
                        return;
                    }
                };
                if let Err(e) = worker.run() {
                    log::error!("Worker {} error: {}", i, e);
                }
            })?;
        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("Worker thread panicked");
    }

    Ok(())
}
