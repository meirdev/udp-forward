# udp-forward

A lightweight UDP forwarder for Linux, written in Rust. Forward packets to one
or more destinations, optionally preserving the original sender's address or
capturing traffic without binding the listening port.

## Build

```bash
cargo build --release
sudo install -m 755 target/release/udp-forward /usr/local/bin/udp-forward
```

## Usage

Listen on port 5000 and forward to one destination:

```bash
udp-forward -l 0.0.0.0:5000 192.168.1.10:6000
```

Add destinations to send a copy of each packet to each address:

```bash
udp-forward -l 0.0.0.0:5000 192.168.1.10:6000 192.168.1.20:6000
```

IPv4 and IPv6 are supported. The listening address and all destinations must
use the same address family. Use `udp-forward --help` for all options, including
worker count, TTL, and packet buffer size.

### Preserve the sender's address

```bash
sudo udp-forward -l 0.0.0.0:5000 --spoof 192.168.1.10:6000
```

The destination sees the original sender's IP and port. Spoofing uses transparent
UDP sockets and requires `CAP_NET_ADMIN`. The network may still drop packets
with a non-local source address.

### Capture without binding

Silent mode lets another program bind to the listening port:

```bash
sudo udp-forward -l 0.0.0.0:5000 --silent 192.168.1.10:6000
```

It captures packets at the device layer using `AF_PACKET` and requires
`CAP_NET_RAW`. Capture uses all interfaces by default; select one with
`--interface`:

```bash
sudo udp-forward -l 0.0.0.0:5000 --silent --interface eth0 192.168.1.10:6000
```

Silent mode uses one worker. It drops IP fragments and does not handle IPv6
extension headers. Combine `--silent` with `--spoof` to preserve sender addresses.

## Logging

Logs go to stderr by default. Set the log level with `RUST_LOG`:

```bash
RUST_LOG=info udp-forward -l 0.0.0.0:5000 192.168.1.10:6000
```

Use `--logfile /path/to/file` to write logs to a file instead.

## Run with systemd

The example unit is in [udp-forward.service](udp-forward.service). It runs the
forwarder in the foreground, restarts it on failure, and sends logs to the journal.

After installing the binary, copy the unit and edit its `ExecStart` line to set
your listening address and destinations:

```bash
sudo install -m 644 udp-forward.service /etc/systemd/system/udp-forward.service
sudo systemctl edit --full udp-forward.service
```

If using `--spoof` or `--silent`, enable the corresponding capabilities in the
unit's `AmbientCapabilities` setting, as shown in its comments.

Start the service and enable it at boot:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now udp-forward
journalctl -u udp-forward -f
```
