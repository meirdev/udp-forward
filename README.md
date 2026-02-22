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
udp-forward -l 0.0.0.0:5000 --spoof 192.168.1.10:6000
```

---

### Silent Sniff Mode

Allows other programs to bind to the same port:

```bash
udp-forward -l 0.0.0.0:5000 --silent 192.168.1.10:6000
```

---

### Run as Daemon

```bash
udp-forward -l 0.0.0.0:5000 \
  --fork \
  --pidfile /var/run/udp-forward.pid \
  192.168.1.10:6000
```
