use std::any::Any;
use std::sync::mpsc;
use std::{panic, thread};

use anyhow::{Context, Result};
use clap::Parser;
use udp_forward::cli::Args;
use udp_forward::worker::Worker;

/// Configures logging from RUST_LOG, writing to stderr or the requested file.
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

    // Reject mixed address families before any worker binds a socket.
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

    log::info!("Config: {:?}", args);
    log::info!("Starting {} worker thread(s)", workers);

    // Report setup errors, run errors, and unwinding panics through one channel.
    // Keep panic handling at the thread boundary; normal failures use Result.
    let (tx, rx) = mpsc::channel::<(usize, Result<()>)>();
    for id in 0..workers {
        let args = args.clone();
        let tx = tx.clone();
        thread::Builder::new()
            .name(format!("worker-{}", id))
            .spawn(move || {
                let outcome =
                    panic::catch_unwind(|| Worker::new(&args)?.run()).unwrap_or_else(|payload| {
                        Err(anyhow::anyhow!("panicked: {}", panic_message(payload)))
                    });
                let _ = tx.send((id, outcome));
            })?;
    }
    drop(tx);

    // Any worker exit is fatal: do not leave the service running at reduced
    // capacity.
    match rx.recv() {
        Ok((id, Ok(()))) => anyhow::bail!("Worker {} exited unexpectedly", id),
        Ok((id, Err(e))) => Err(e).with_context(|| format!("Worker {} failed", id)),
        Err(_) => anyhow::bail!("All workers exited without reporting an outcome"),
    }
}
