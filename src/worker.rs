//! A worker wires one [`PacketSource`] (how packets are received) to one
//! [`PacketSink`] (how they are forwarded). The two concerns are independent:
//! receiving normally or silently, and sending normally or spoofed, combine
//! freely. Work flows in batches: one `recvmmsg` fills a batch, one (or a few)
//! `sendmmsg` calls drain it.

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
            Box::new(SpoofSink::new(&args.destinations, args.ttl))
        } else {
            Box::new(NormalSink::new(
                args.listen.is_ipv6(),
                &args.destinations,
                args.ttl,
            )?)
        };

        Ok(Self { source, sink })
    }

    pub fn run(mut self) -> Result<()> {
        loop {
            let batch = self.source.recv_batch()?;
            self.sink.send_batch(&batch);
        }
    }
}
