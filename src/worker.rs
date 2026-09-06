//! Connects a packet source to a sink and forwards borrowed datagrams in
//! batches. Receive mode (UDP socket or capture) and send mode (normal or
//! spoofed) are selected independently.

mod packet;
mod sink;
mod source;

use anyhow::Result;
use sink::{NormalSink, PacketSink, SpoofSink};
use source::{NormalSource, PacketSource, SilentSource};

use crate::cli::Args;

pub struct Worker {
    source: Box<dyn PacketSource>,
    sink: Box<dyn PacketSink>,
}

impl Worker {
    pub fn new(args: &Args) -> Result<Self> {
        let source: Box<dyn PacketSource> = if args.silent {
            Box::new(SilentSource::new(
                args.listen,
                args.interface.as_deref(),
                args.buffer_size,
            )?)
        } else {
            Box::new(NormalSource::new(args.listen, args.buffer_size)?)
        };

        let sink: Box<dyn PacketSink> = if args.spoof {
            Box::new(SpoofSink::new(
                &args.destinations,
                args.ttl,
                args.listen.is_ipv6(),
            )?)
        } else {
            Box::new(NormalSink::new(
                args.listen.is_ipv6(),
                &args.destinations,
                args.ttl,
            )?)
        };

        Ok(Self { source, sink })
    }

    /// Forwards batches until a source or sink returns an error.
    /// Logs a summary when a completed batch includes dropped output messages.
    pub fn run(mut self) -> Result<()> {
        loop {
            let batch = self.source.recv_batch()?;
            let report = self.sink.send_batch(&batch)?;
            if report.dropped > 0 {
                log::warn!(
                    "batch: {} message(s) sent, {} dropped",
                    report.sent,
                    report.dropped
                );
            }
        }
    }
}
