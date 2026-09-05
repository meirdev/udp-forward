use std::net::SocketAddr;
use std::thread;

use anyhow::{Context, Result};
use clap::Parser;
use nix::unistd::daemon;
use socket2::{Domain, Protocol, Socket, Type};
use udp_forward::cli::Args;
use udp_forward::worker::Worker;

fn init_logger(logfile: Option<&std::path::Path>) -> Result<()> {
    let mut builder = env_logger::Builder::from_default_env();

    if let Some(path) = logfile {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("Failed to open log file {}", path.display()))?;
        builder.target(env_logger::Target::Pipe(Box::new(file)));
    }

    builder.init();
    Ok(())
}

/// Verifies the listen port can be bound before spawning workers, so a
/// conflict fails fast with a clear error. The probe mirrors the workers'
/// SO_REUSEPORT so it does not false-positive against a cooperating
/// udp-forward instance, while still detecting a foreign holder of the port.
fn check_listen_port(addr: SocketAddr) -> Result<()> {
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };

    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
        .context("Failed to create probe socket for port check")?;
    sock.set_reuse_port(true)
        .context("Failed to set SO_REUSEPORT on probe socket")?;

    match sock.bind(&addr.into()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            anyhow::bail!("Port {} is already in use", addr)
        }
        Err(e) => Err(e).with_context(|| format!("Failed to bind {}", addr)),
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    init_logger(args.logfile.as_deref())?;

    if args.fork {
        if args.logfile.is_none() {
            log::warn!("--fork without --logfile: log output will be discarded");
        }
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
            "Silent mode uses a single AF_PACKET capture socket; multiple \
             workers would each receive a copy of every packet. Forcing single \
             worker thread (requested: {})",
            args.workers
        );
        1
    } else {
        args.workers
    };

    if !args.silent {
        check_listen_port(args.listen)?;
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
