# udp-forward

A lightweight, multi-threaded UDP packet forwarder written in Rust (Linux only).

`udp-forward` listens for incoming UDP packets and forwards them to one or more
destination addresses. It supports source spoofing, a silent sniffing mode,
configurable TTL, and worker threads. Logs go to stderr (controlled by
`RUST_LOG`, e.g. `RUST_LOG=info`), which a service manager such as systemd
collects for you.

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
included. This requires `CAP_NET_ADMIN`. The upstream network path may still
drop packets with a non-local source (BCP38 / uRPF).

---

### Silent Sniff Mode

Allows other programs to bind to the same port:

```bash
sudo udp-forward -l 0.0.0.0:5000 --silent 192.168.1.10:6000
```

Silent mode captures at the device layer with an `AF_PACKET` socket, exactly like
`tcpdump`, so packets are seen regardless of routing, netfilter/NAT, or
forwarding (for example on a Docker host that DNATs the traffic to a container).
This requires `CAP_NET_RAW`. By default it captures on all interfaces; restrict
it with `--interface`:

```bash
sudo udp-forward -l 0.0.0.0:5000 --silent --interface eth0 192.168.1.10:6000
```

Limitations of silent mode: IP fragments are dropped rather than reassembled,
and IPv6 packets with extension headers are not handled.

---

### Run as a Service (systemd)

`udp-forward` runs in the foreground and exits non-zero if it cannot start or if a
worker fails, so let systemd handle backgrounding, restarts, and logging:

```ini
# /etc/systemd/system/udp-forward.service
[Unit]
Description=UDP forwarder
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/udp-forward -l 0.0.0.0:5000 192.168.1.10:6000
Environment=RUST_LOG=info
Restart=on-failure
DynamicUser=yes
# Only needed for --spoof (CAP_NET_ADMIN) and/or --silent (CAP_NET_RAW):
# AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now udp-forward
journalctl -u udp-forward -f
```
