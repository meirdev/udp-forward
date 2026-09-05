use std::any::Any;
use std::net::SocketAddr;
use std::panic::{self, AssertUnwindSafe};
use std::sync::mpsc;
use std::thread;

use anyhow::{Context, Result};
use clap::Parser;
use socket2::{Domain, Protocol, Socket, Type};
use udp_forward::cli::Args;
use udp_forward::worker::Worker;

/// Logs go to stderr by default (where a service manager such as systemd
/// collects them); `--logfile` redirects them to a file instead.
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

/// A worker's whole life: initialize, then forward until a fatal error.
fn run_worker(args: &Args) -> Result<()> {
    Worker::new(args)?.run()
}

/// The payload of an unwinding panic, as text.
fn panic_message(payload: Box<dyn Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        s.to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic payload".to_string()
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    init_logger(args.logfile.as_deref())?;

    // Validate the configuration before starting workers so a bad setup fails
    // fast with a clear error and a non-zero exit.
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

    // Each worker sends exactly one termination result, whether initialization
    // failed, forwarding failed, or the worker panicked. `catch_unwind` is used
    // only here, at the thread boundary; ordinary failures stay as `Result`.
    let (tx, rx) = mpsc::channel::<(usize, Result<(), String>)>();
    for id in 0..workers {
        let args = args.clone();
        let tx = tx.clone();
        thread::Builder::new()
            .name(format!("worker-{}", id))
            .spawn(move || {
                let outcome = match panic::catch_unwind(AssertUnwindSafe(|| run_worker(&args))) {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(e)) => Err(format!("{:#}", e)),
                    Err(payload) => Err(format!("panicked: {}", panic_message(payload))),
                };
                let _ = tx.send((id, outcome));
            })?;
    }
    drop(tx);

    // A worker stopping means lost capacity (or a failed start), so the first
    // one ends the process with an error; a service manager can then restart it.
    match rx.recv() {
        Ok((id, Ok(()))) => anyhow::bail!("Worker {} exited unexpectedly", id),
        Ok((id, Err(e))) => anyhow::bail!("Worker {} failed: {}", id, e),
        Err(_) => Ok(()),
    }
}
