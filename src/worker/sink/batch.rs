//! Batched send shared by the sinks: fans a batch of payloads out to every
//! destination on a given socket with `sendmmsg`, in chunks of at most
//! `MAX_MSGS_PER_CALL` messages.
//!
//! `libc::sendmmsg` is called directly rather than through nix: nix's result
//! iterator reads a per-message address the send path never initializes, and
//! the raw call returns how many messages were actually accepted, which the
//! retry policy needs.

use std::io;
use std::net::SocketAddr;
use std::os::fd::RawFd;

use anyhow::{Context, Result};
use nix::sys::socket::{SockaddrLike, SockaddrStorage};

use crate::worker::packet::{RECV_BATCH_SIZE, SendReport};

// Linux caps a single sendmmsg at UIO_MAXIOV (1024) messages.
const MAX_MSGS_PER_CALL: usize = 1024;

/// Fans payloads out to a fixed destination set. Reused across sends, and
/// across per-source sockets in the spoof sink (the destination set is the same
/// for every source).
pub(super) struct BatchedSender {
    dests: Vec<SockaddrStorage>,
    // Scratch descriptors for one chunk. They hold raw pointers with no Rust
    // lifetimes, so the allocations persist across calls and are refilled per
    // chunk, bounding memory to one chunk rather than the whole fan-out.
    iovecs: Vec<libc::iovec>,
    msgs: Vec<libc::mmsghdr>,
}

impl BatchedSender {
    pub(super) fn new(destinations: &[SocketAddr]) -> Self {
        let chunk = destinations
            .len()
            .saturating_mul(RECV_BATCH_SIZE)
            .min(MAX_MSGS_PER_CALL);
        Self {
            dests: destinations
                .iter()
                .map(|&addr| SockaddrStorage::from(addr))
                .collect(),
            iovecs: Vec::with_capacity(chunk),
            msgs: Vec::with_capacity(chunk),
        }
    }

    pub(super) fn destination_count(&self) -> usize {
        self.dests.len()
    }

    /// Sends every payload to every destination via `fd`. Message `m` carries
    /// payload `m / destinations` to destination `m % destinations`.
    /// Per-message failures are counted in the report; `Err` means a fatal
    /// socket error.
    pub(super) fn send(&mut self, fd: RawFd, payloads: &[&[u8]]) -> Result<SendReport> {
        let ndests = self.dests.len();
        if payloads.is_empty() || ndests == 0 {
            return Ok(SendReport::default());
        }
        let total = payloads
            .len()
            .checked_mul(ndests)
            .context("outgoing message count overflow")?;

        run_send_loop(total, |next, end| {
            self.build_chunk(payloads, next, end);
            // SAFETY: every header references a live destination, payload, and
            // iovec. None of those allocations move during this synchronous
            // call, and the kernel only writes to the message headers.
            let ret = unsafe {
                libc::sendmmsg(fd, self.msgs.as_mut_ptr(), (end - next) as libc::c_uint, 0)
            };
            if ret < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(ret as usize)
            }
        })
    }

    /// Fills the scratch descriptors for messages `[next, end)`.
    fn build_chunk(&mut self, payloads: &[&[u8]], next: usize, end: usize) {
        let ndests = self.dests.len();

        self.iovecs.clear();
        for m in next..end {
            let payload = payloads[m / ndests];
            self.iovecs.push(libc::iovec {
                iov_base: payload.as_ptr() as *mut libc::c_void,
                iov_len: payload.len(),
            });
        }

        // No more pushes to `iovecs` below, so pointers into it stay valid.
        let iov_base = self.iovecs.as_mut_ptr();
        self.msgs.clear();
        for (k, m) in (next..end).enumerate() {
            let dest = &self.dests[m % ndests];
            // SAFETY: zero is valid for all msghdr fields; unused ancillary
            // data fields remain null/zero.
            let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
            hdr.msg_name = dest.as_ptr() as *mut libc::c_void;
            hdr.msg_namelen = dest.len();
            // SAFETY: one iovec was populated for each message above.
            hdr.msg_iov = unsafe { iov_base.add(k) };
            hdr.msg_iovlen = 1;
            self.msgs.push(libc::mmsghdr {
                msg_hdr: hdr,
                msg_len: 0,
            });
        }
    }
}

/// Drives chunked sends over `total` messages.
///
/// `send_chunk(next, end)` attempts messages `[next, end)` and returns how many
/// the kernel accepted, or the error for the message at `next`. Policy:
/// - `EINTR`: retry the same chunk.
/// - `EBADF` / `ENOTSOCK`: the socket is unusable; return `Err`.
/// - any other error: the message at `next` cannot be sent; skip it.
/// - partial completion: advance past the accepted messages and retry from the
///   next one, so its error (if any) surfaces on the following call. Linux
///   explicitly permits retrying after a partial `sendmmsg`.
fn run_send_loop<F>(total: usize, mut send_chunk: F) -> Result<SendReport>
where
    F: FnMut(usize, usize) -> io::Result<usize>,
{
    let mut report = SendReport::default();
    let mut next = 0;

    while next < total {
        let end = next + (total - next).min(MAX_MSGS_PER_CALL);
        match send_chunk(next, end) {
            Ok(sent) => {
                report.sent += sent;
                next += sent;
                if sent == 0 {
                    // Defensive: the syscall reported nothing accepted without
                    // an error; skip one message so the loop always progresses.
                    report.dropped += 1;
                    next += 1;
                }
            }
            Err(e) => match e.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::EBADF) | Some(libc::ENOTSOCK) => {
                    return Err(e).context("sendmmsg: socket unusable");
                }
                _ => {
                    log::debug!(
                        "sendmmsg: message {}/{} failed: {}; skipping it",
                        next + 1,
                        total,
                        e
                    );
                    report.dropped += 1;
                    next += 1;
                }
            },
        }
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(code: i32) -> io::Error {
        io::Error::from_raw_os_error(code)
    }

    #[test]
    fn full_chunks_do_not_skip_the_next_message() {
        // 16 payloads x 65 destinations = 1040 messages: one full 1024 chunk
        // followed by 16. A fully successful chunk must not drop message 1025.
        let mut calls = Vec::new();
        let report = run_send_loop(1040, |next, end| {
            calls.push((next, end));
            Ok(end - next)
        })
        .unwrap();
        assert_eq!(calls, vec![(0, 1024), (1024, 1040)]);
        assert_eq!(
            report,
            SendReport {
                sent: 1040,
                dropped: 0
            }
        );
    }

    #[test]
    fn exact_chunk_boundaries() {
        for total in [0, 1, 1023, 1024, 1025, 2048] {
            let report = run_send_loop(total, |next, end| Ok(end - next)).unwrap();
            assert_eq!(
                report,
                SendReport {
                    sent: total,
                    dropped: 0
                },
                "total {}",
                total
            );
        }
    }

    #[test]
    fn partial_completion_across_chunks_preserves_every_message() {
        let mut calls = Vec::new();
        let mut accepted = [600, 424, 1].into_iter();
        let report = run_send_loop(1025, |next, end| {
            calls.push((next, end));
            Ok(accepted.next().expect("unexpected extra send"))
        })
        .unwrap();

        assert_eq!(calls, [(0, 1024), (600, 1025), (1024, 1025)]);
        assert_eq!(
            report,
            SendReport {
                sent: 1025,
                dropped: 0
            }
        );
    }

    #[test]
    fn interruption_after_partial_completion_retries_the_same_messages() {
        let mut calls = Vec::new();
        let mut results = [Ok(2), Err(err(libc::EINTR)), Ok(3)].into_iter();
        let report = run_send_loop(5, |next, end| {
            calls.push((next, end));
            results.next().expect("unexpected extra send")
        })
        .unwrap();

        assert_eq!(calls, [(0, 5), (2, 5), (2, 5)]);
        assert_eq!(
            report,
            SendReport {
                sent: 5,
                dropped: 0
            }
        );
    }

    #[test]
    fn partial_send_retries_then_skips_the_offender() {
        // First call accepts 5 of 10; the retry from message 5 reports its
        // error (EACCES); the rest then succeed.
        let mut calls = 0;
        let report = run_send_loop(10, |next, end| {
            calls += 1;
            match calls {
                1 => Ok(5),
                2 => {
                    assert_eq!(next, 5);
                    Err(err(libc::EACCES))
                }
                _ => Ok(end - next),
            }
        })
        .unwrap();
        assert_eq!(
            report,
            SendReport {
                sent: 9,
                dropped: 1
            }
        );
    }

    #[test]
    fn eintr_is_retried_without_dropping() {
        let mut calls = 0;
        let report = run_send_loop(3, |next, end| {
            calls += 1;
            if calls == 1 {
                Err(err(libc::EINTR))
            } else {
                Ok(end - next)
            }
        })
        .unwrap();
        assert_eq!(calls, 2);
        assert_eq!(
            report,
            SendReport {
                sent: 3,
                dropped: 0
            }
        );
    }

    #[test]
    fn fatal_socket_error_is_returned() {
        let result = run_send_loop(3, |_, _| Err(err(libc::EBADF)));
        assert!(result.is_err());
    }

    #[test]
    fn zero_accepted_still_progresses() {
        let mut calls = 0;
        let report = run_send_loop(2, |next, end| {
            calls += 1;
            if calls == 1 { Ok(0) } else { Ok(end - next) }
        })
        .unwrap();
        assert_eq!(
            report,
            SendReport {
                sent: 1,
                dropped: 1
            }
        );
    }
}
