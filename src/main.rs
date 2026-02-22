mod cli;
mod worker;

use std::thread;

use anyhow::{Context, Result};
use clap::Parser;
use cli::Args;
use nix::unistd::daemon;
use worker::Worker;

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

    log::info!("Config: {:?}", args);
    log::info!("Starting {} worker thread(s)", workers);

    let mut handles = Vec::with_capacity(workers);

    for i in 0..workers {
        let args = args.clone();
        let handle = thread::Builder::new()
            .name(format!("worker-{}", i))
            .spawn(move || {
                let worker = Worker::new(&args).expect("Failed to create worker");
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
