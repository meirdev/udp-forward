# udp-forward

A lightweight, multi-threaded UDP packet forwarder written in Rust.

`udp-forward` listens for incoming UDP packets and forwards them to one or more destination addresses. It supports spoofing, silent sniffing mode, configurable TTL, worker threads, and daemonization.

## Examples

### Basic Forwarding

Listen on port 5000 and forward to one destination:

```bash
udp-forward -l 0.0.0.0:5000 192.168.1.10:6000
```

---

### Forward to Multiple Destinations

```bash
udp-forward -l 0.0.0.0:5000 \
  192.168.1.10:6000 \
  192.168.1.20:6000
```

---

### Enable Source Spoofing

```bash
sudo udp-forward -l 0.0.0.0:5000 --spoof 192.168.1.10:6000
```

The destination sees the original sender's address (IP and port) as the source.
Spoofing uses transparent sockets (`IP_TRANSPARENT` / `IPV6_TRANSPARENT`), so the
kernel builds the headers and routes normally across any interface, IPv6
included. This requires `CAP_NET_ADMIN` (run as root). The upstream network path
may still drop packets with a non-local source (BCP38 / uRPF).

---

### Silent Sniff Mode

Allows other programs to bind to the same port:

```bash
sudo udp-forward -l 0.0.0.0:5000 --silent 192.168.1.10:6000
```

Silent mode captures at the device layer with an `AF_PACKET` socket, exactly like
`tcpdump`, so packets are seen regardless of routing, netfilter/NAT, or
forwarding (for example on a Docker host that DNATs the traffic to a container).
This requires `CAP_NET_RAW` (run as root). By default it captures on all
interfaces; restrict it with `--interface`:

```bash
sudo udp-forward -l 0.0.0.0:5000 --silent --interface eth0 192.168.1.10:6000
```

---

### Run as Daemon

```bash
udp-forward -l 0.0.0.0:5000 \
  --fork \
  --pidfile /var/run/udp-forward.pid \
  --logfile /var/log/udp-forward.log \
  192.168.1.10:6000
```

Use `--logfile` together with `--fork`: a daemonized process has its standard
output redirected away, so without it log output is discarded. Log verbosity is
controlled by the `RUST_LOG` environment variable (e.g. `RUST_LOG=info`).
