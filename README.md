# 🛡️ PyWall — Advanced Python Stateful Firewall

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![Platform](https://img.shields.io/badge/Platform-Linux-orange?logo=linux)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Portfolio%20Project-purple)

A **production-grade, stateful network firewall** built entirely in Python using `NetfilterQueue` and `Scapy`. Designed to intercept live Linux kernel traffic, inspect packets at every layer, and enforce granular, configurable security policy.

---

## 📋 Table of Contents

- [Architecture Overview](#architecture-overview)
- [How Stateful Tracking Works](#how-stateful-tracking-works)
- [Deep Packet Inspection](#deep-packet-inspection)
- [Features](#features)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration Reference](#configuration-reference)
- [iptables Commands Explained](#iptables-commands-explained)
- [Security Considerations](#security-considerations)

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────┐
│                     Linux Kernel                             │
│   NIC → Netfilter (iptables) → NFQUEUE → Python Userspace   │
└─────────────────────────┬────────────────────────────────────┘
                          │  raw packet bytes
                          ▼
              ┌───────────────────────┐
              │      Firewall         │  ← Orchestrator (config,
              │   (Orchestrator)      │    iptables, lifecycle)
              └──────────┬────────────┘
                         │
              ┌──────────▼────────────┐
              │    PacketHandler      │  ← Rule evaluation engine
              └──┬──────┬──────┬─────┘
                 │      │      │
        ┌────────▼┐  ┌──▼───┐  ┌▼──────────┐
        │ IP      │  │State │  │    DPI     │
        │Blacklist│  │Table │  │  Engine    │
        └─────────┘  └──────┘  └────────────┘
                         │
              ┌──────────▼────────────┐
              │    RateLimiter        │
              └───────────────────────┘
```

Every packet passes through 4 ordered checks. The first failing check drops the packet immediately — no further evaluation.

---

## How Stateful Tracking Works

Most simple firewalls are **stateless** — they treat each packet in isolation. PyWall implements a **TCP state machine** that tracks the full connection lifecycle.

### The TCP Three-Way Handshake

```
Client                    Server
  │──── SYN ────────────►│   State: SYN_SENT
  │◄─── SYN-ACK ─────────│   State: ESTABLISHED (after SYN-ACK verified)
  │──── ACK ────────────►│   State: ESTABLISHED
  │    [data transfer]    │
  │──── FIN/RST ─────────│   State: CLOSED → entry removed
```

### State Table Logic

| Packet Received | Prior State in Table | Decision | Reason |
|----------------|----------------------|----------|--------|
| `SYN`          | None                 | **ALLOW** | New connection — record it |
| `SYN-ACK`      | `SYN_SENT` (reverse) | **ALLOW** | Valid server response |
| `SYN-ACK`      | None                 | **DROP**  | Possible reflection/spoofing |
| `ACK`          | `ESTABLISHED`        | **ALLOW** | Normal data transfer |
| `ACK`          | None                 | **DROP**  | Orphaned ACK — likely forged |
| `FIN` / `RST`  | Any                  | **ALLOW** + cleanup | Graceful teardown |

### Why This Matters

An attacker performing a **SYN flood** sends thousands of `SYN` packets but never completes the handshake. PyWall records each SYN but expired entries are cleaned up automatically. A **spoofed ACK injection** attack — where an attacker injects `ACK` packets to hijack a TCP stream — is blocked because no matching `SYN_SENT` state exists.

---

## Deep Packet Inspection

PyWall's `DPIEngine` performs Layer 7 analysis on raw packet payloads.

### SQL Injection Detection

Inspects HTTP POST/GET payloads for common SQLi patterns:

```
' OR 1=1 --        → Classic authentication bypass
UNION SELECT        → Data exfiltration via UNION
'; DROP TABLE users → Destructive DDL injection
```

### XSS Detection

```
<script>            → Inline script injection
javascript:         → Protocol handler XSS
onerror=            → Event-handler injection
document.cookie     → Session hijacking attempt
```

### Malicious TCP Flag Combinations

| Scan Type   | Flags Set       | Integer | Why it's suspicious |
|-------------|-----------------|---------|---------------------|
| **Null**    | (none)          | `0x00`  | RFC violation — used by Nmap for OS detection |
| **Xmas**    | FIN + PSH + URG | `0x29`  | Named for the "lit up" flags — stealth scan technique |
| **All-set** | All flags       | `0x3F`  | Invalid by design — used for fingerprinting |
| **SYN+RST** | SYN + RST       | `0x06`  | Mutually exclusive flags — crash/confuse stacks |

---

## Features

| Feature | Description |
|---|---|
| ✅ **Stateful TCP tracking** | Full three-way handshake verification with automatic expiry |
| ✅ **Deep Packet Inspection** | SQLi, XSS, and malicious DNS signature matching |
| ✅ **TCP flag analysis** | Null, Xmas, SYN+RST scan detection |
| ✅ **IP Blacklisting** | Instant drop for known-bad IPs |
| ✅ **Rate Limiting** | Per-IP sliding-window throttle |
| ✅ **Port Allowlisting** | Deny-by-default port policy |
| ✅ **Structured Logging** | File + console logs with drop reasons |
| ✅ **Auto iptables cleanup** | SIGINT/SIGTERM handler flushes rules |
| ✅ **YAML configuration** | Fully externalised policy file |
| ✅ **OOP design** | Clean class hierarchy, easy to extend |
| ✅ **Thread-safe state table** | Background cleanup thread with RLock |

---

## Project Structure

```
pywall/
├── firewall.py          # Main application (Firewall, PacketHandler, DPIEngine, StateTable)
├── config.yaml          # Firewall policy configuration
├── iptables_setup.sh    # Helper script to apply/remove iptables rules
├── pywall.log           # Generated at runtime
├── requirements.txt     # Python dependencies
└── README.md
```

---

## Installation

### Prerequisites

- Linux (kernel 2.6.14+ with `NFNETLINK` support)
- Python 3.10+
- Root / sudo access
- `libnetfilter-queue-dev` system package

```bash
# 1. Install system library
sudo apt-get update
sudo apt-get install -y libnetfilter-queue-dev python3-pip

# 2. Clone repo
git clone https://github.com/YOUR_USERNAME/pywall.git
cd pywall

# 3. Install Python dependencies
pip3 install -r requirements.txt
```

**`requirements.txt`**
```
netfilterqueue>=1.1.0
scapy>=2.5.0
PyYAML>=6.0
```

---

## Usage

### Step 1 — Edit your policy

```bash
nano config.yaml
# Set allowed_ports, blacklisted_ips, rate_limit thresholds
```

### Step 2 — Apply iptables rules

```bash
sudo bash iptables_setup.sh apply
```

### Step 3 — Start PyWall

```bash
sudo python3 firewall.py
# or with a custom config path:
sudo python3 firewall.py --config /etc/pywall/config.yaml
```

### Step 4 — Stop (Ctrl+C)

PyWall catches `SIGINT` and automatically:
1. Unbinds from the NFQueue
2. Removes all iptables rules
3. Logs final packet statistics

```
[INFO] PyWall stopped. Goodbye.
[INFO] FINAL STATS
[INFO]   Packets Allowed : 4821
[INFO]   Packets Blocked : 37
[INFO]   State Entries   : 3
```

---

## Configuration Reference

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `queue_num` | int | `0` | NFQueue number (must match `--queue-num`) |
| `allowed_ports` | list | `[22,53,80,443]` | TCP/UDP ports to permit |
| `blacklisted_ips` | list | `[]` | Source IPs to always drop |
| `rate_limit.enabled` | bool | `true` | Enable per-IP rate limiting |
| `rate_limit.max_packets` | int | `100` | Packets allowed per window |
| `rate_limit.window_seconds` | int | `10` | Sliding window duration |
| `dpi.enabled` | bool | `true` | Enable payload inspection |
| `state_table.timeout_seconds` | int | `120` | Idle connection TTL |
| `state_table.cleanup_interval` | int | `30` | Cleanup thread interval |
| `logging.level` | str | `INFO` | `DEBUG`/`INFO`/`WARNING`/`ERROR` |
| `logging.file` | str | `pywall.log` | Log output file |

---

## iptables Commands Explained

When PyWall starts (or when you run `iptables_setup.sh apply`), three rules are inserted:

```bash
# Redirect all incoming packets to NFQUEUE 0
iptables -I INPUT   -j NFQUEUE --queue-num 0

# Redirect all outgoing packets to NFQUEUE 0
iptables -I OUTPUT  -j NFQUEUE --queue-num 0

# Redirect all forwarded packets (routing/NAT) to NFQUEUE 0
iptables -I FORWARD -j NFQUEUE --queue-num 0
```

**`-I` vs `-A`**: `-I` inserts at position 1 (top of chain), ensuring PyWall evaluates packets before any other rules. `-A` appends to the end and is NOT suitable here.

**What happens if PyWall crashes?** Packets remain queued in kernel space and will **stall** — the kernel waits for a userspace verdict. Always run `iptables_setup.sh remove` or use `--queue-bypass` in the iptables rule for a fail-open behaviour during development.

**Fail-open alternative** (for development only):
```bash
iptables -I INPUT -j NFQUEUE --queue-num 0 --queue-bypass
```

---

## Security Considerations

- **Run in a VM first.** Misconfigurations can lock you out of SSH. Test with a VM snapshot or cloud console access.
- **Extend the DPI signatures.** The included signatures are illustrative. For production, consider integrating a rule format like Snort/Suricata signatures.
- **This is not a replacement for a full IDS/IPS.** PyWall is a learning/portfolio tool demonstrating the mechanics of stateful inspection.
- **Logging sensitive payloads.** By design, PyWall logs *reasons* for drops, not the payload content. Avoid logging raw payloads in production — it creates data privacy and disk space concerns.

---

## How to Extend

**Add a new DPI signature:**
```python
# In DPIEngine class
SQLI_SIGNATURES = [
    ...
    b"your new pattern here",
]
```

**Add a new firewall rule:**
```python
# In PacketHandler._evaluate()
if some_condition(pkt):
    return "DROP", "My custom rule triggered"
```

**Block ICMP entirely:**
```python
elif pkt.haslayer(ICMP):
    return "DROP", "ICMP blocked by policy"
```

---

## License

MIT License — free to use, modify, and distribute.

---

*Built as a cybersecurity portfolio project demonstrating stateful packet filtering, deep packet inspection, and Linux kernel network integration.*
