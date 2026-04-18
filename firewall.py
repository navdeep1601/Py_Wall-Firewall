#!/usr/bin/env python3
"""
PyWall - Advanced Stateful Firewall
Author: Security Engineer
Description: A production-ready stateful firewall using NetfilterQueue and Scapy.
             Implements TCP state tracking, DPI, rate limiting, and signature detection.
"""

import os
import sys
import time
import signal
import logging
import threading
import subprocess
import yaml
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime

try:
    from netfilterqueue import NetfilterQueue
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.dns import DNS
    from scapy.packet import Raw
    from scapy.all import conf as scapy_conf
except ImportError as e:
    print(f"[FATAL] Missing dependency: {e}")
    print("Run: pip install netfilterqueue scapy pyyaml")
    sys.exit(1)

# ─────────────────────────────────────────────
#  Logging Setup
# ─────────────────────────────────────────────

def setup_logging(log_file: str = "pywall.log", level: str = "INFO") -> logging.Logger:
    """Configure structured logging to both file and stdout."""
    logger = logging.getLogger("PyWall")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # File handler
    fh = logging.FileHandler(log_file)
    fh.setFormatter(formatter)

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(formatter)

    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger


# ─────────────────────────────────────────────
#  Data Structures
# ─────────────────────────────────────────────

@dataclass
class ConnectionState:
    """Tracks the lifecycle of a TCP connection."""
    state: str          # NEW | SYN_SENT | ESTABLISHED | FIN_WAIT | CLOSED
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    timestamp: float = field(default_factory=time.time)
    packet_count: int = 0

    def is_expired(self, timeout: int = 120) -> bool:
        return (time.time() - self.timestamp) > timeout


@dataclass
class RateLimitEntry:
    """Tracks packet count per source IP within a time window."""
    count: int = 0
    window_start: float = field(default_factory=time.time)


# ─────────────────────────────────────────────
#  Configuration Loader
# ─────────────────────────────────────────────

class Config:
    """Loads and validates firewall rules from config.yaml."""

    DEFAULTS = {
        "allowed_ports": [22, 80, 443, 53],
        "blacklisted_ips": [],
        "rate_limit": {"enabled": True, "max_packets": 100, "window_seconds": 10},
        "dpi": {"enabled": True},
        "logging": {"level": "INFO", "file": "pywall.log"},
        "state_table": {"timeout_seconds": 120, "cleanup_interval": 30},
        "queue_num": 0,
    }

    def __init__(self, config_path: str = "config.yaml"):
        self.path = config_path
        self.data = self._load()

    def _load(self) -> dict:
        if not os.path.exists(self.path):
            print(f"[WARN] Config '{self.path}' not found — using defaults.")
            return self.DEFAULTS.copy()
        with open(self.path, "r") as f:
            loaded = yaml.safe_load(f) or {}
        # Deep merge with defaults
        merged = self.DEFAULTS.copy()
        merged.update(loaded)
        return merged

    def get(self, key, default=None):
        return self.data.get(key, default)


# ─────────────────────────────────────────────
#  Deep Packet Inspection Engine
# ─────────────────────────────────────────────

class DPIEngine:
    """
    Performs layer-7 payload inspection.
    Detects SQLi, XSS, malicious DNS queries, and dangerous TCP flag combos.
    """

    # Common SQL Injection patterns
    SQLI_SIGNATURES = [
        b"' OR 1=1",
        b"' OR '1'='1",
        b"1' OR '1'='1",
        b"' --",
        b"'; DROP TABLE",
        b"UNION SELECT",
        b"' OR 1=1--",
        b"admin'--",
        b"1 OR 1=1",
    ]

    # XSS patterns
    XSS_SIGNATURES = [
        b"<script>",
        b"</script>",
        b"javascript:",
        b"onerror=",
        b"onload=",
        b"<iframe",
        b"alert(",
        b"document.cookie",
    ]

    # Suspicious DNS hostnames (C2 / malware domains)
    MALICIOUS_DOMAINS = [
        "malware.example.com",
        "c2server.evil",
        "phishing-site.net",
    ]

    # Dangerous TCP flag combinations
    # Null scan: no flags set (flags == 0)
    # Xmas scan: FIN + PSH + URG
    DANGEROUS_FLAG_COMBOS = {
        0x00: "Null Scan (no flags)",
        0x29: "Xmas Scan (FIN+PSH+URG)",
        0x3F: "All Flags Set",
        0x06: "SYN+RST (invalid)",
    }

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def inspect(self, pkt: IP) -> Optional[str]:
        """
        Inspect packet payload and flags.
        Returns a reason string if the packet should be blocked, else None.
        """
        try:
            if pkt.haslayer(TCP):
                reason = self._check_tcp_flags(pkt[TCP])
                if reason:
                    return reason

            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)
                reason = self._check_signatures(payload)
                if reason:
                    return reason

            if pkt.haslayer(DNS):
                reason = self._check_dns(pkt[DNS])
                if reason:
                    return reason

        except Exception as e:
            self.logger.debug(f"DPI exception (non-fatal): {e}")

        return None

    def _check_tcp_flags(self, tcp_layer: TCP) -> Optional[str]:
        flags = int(tcp_layer.flags)
        if flags in self.DANGEROUS_FLAG_COMBOS:
            return f"Suspicious TCP flags: {self.DANGEROUS_FLAG_COMBOS[flags]}"
        return None

    def _check_signatures(self, payload: bytes) -> Optional[str]:
        payload_upper = payload.upper()

        for sig in self.SQLI_SIGNATURES:
            if sig.upper() in payload_upper:
                return f"SQL Injection signature detected: {sig.decode(errors='replace')}"

        for sig in self.XSS_SIGNATURES:
            if sig.upper() in payload_upper:
                return f"XSS signature detected: {sig.decode(errors='replace')}"

        return None

    def _check_dns(self, dns_layer: DNS) -> Optional[str]:
        try:
            if dns_layer.qd:
                qname = dns_layer.qd.qname.decode(errors="replace").rstrip(".")
                for domain in self.MALICIOUS_DOMAINS:
                    if domain in qname:
                        return f"Malicious DNS query: {qname}"
        except Exception:
            pass
        return None


# ─────────────────────────────────────────────
#  State Table (Connection Tracker)
# ─────────────────────────────────────────────

class StateTable:
    """
    Thread-safe TCP connection state machine.

    States:
      SYN_SENT     → SYN packet seen, waiting for SYN-ACK
      ESTABLISHED  → Full handshake completed
      CLOSED       → Connection terminated

    Enforcement:
      - ACK packets without a prior SYN record are DROPPED (blocks spoofed ACKs)
      - Expired entries are purged periodically
    """

    def __init__(self, timeout: int = 120, cleanup_interval: int = 30,
                 logger: Optional[logging.Logger] = None):
        self._table: dict[tuple, ConnectionState] = {}
        self._lock = threading.RLock()
        self.timeout = timeout
        self.logger = logger or logging.getLogger("PyWall.StateTable")

        # Start background cleanup thread
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            args=(cleanup_interval,),
            daemon=True,
            name="StateTableCleaner"
        )
        self._cleanup_thread.start()

    def _make_key(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> tuple:
        return (src_ip, dst_ip, src_port, dst_port)

    def _reverse_key(self, key: tuple) -> tuple:
        src_ip, dst_ip, src_port, dst_port = key
        return (dst_ip, src_ip, dst_port, src_port)

    def process(self, src_ip: str, dst_ip: str, src_port: int,
                dst_port: int, flags: int) -> tuple[bool, str]:
        """
        Evaluate a TCP packet against the state table.

        Returns:
            (allow: bool, reason: str)
        """
        key = self._make_key(src_ip, dst_ip, src_port, dst_port)
        rev_key = self._reverse_key(key)

        SYN  = 0x02
        ACK  = 0x10
        FIN  = 0x01
        RST  = 0x04
        SYN_ACK = SYN | ACK

        with self._lock:
            # ── SYN: New connection initiated ──
            if flags & SYN and not (flags & ACK):
                state = ConnectionState(
                    state="SYN_SENT",
                    src_ip=src_ip, dst_ip=dst_ip,
                    src_port=src_port, dst_port=dst_port
                )
                self._table[key] = state
                return True, "NEW connection (SYN recorded)"

            # ── SYN-ACK: Server responding to handshake ──
            if (flags & SYN_ACK) == SYN_ACK:
                if rev_key in self._table and self._table[rev_key].state == "SYN_SENT":
                    self._table[rev_key].state = "ESTABLISHED"
                    return True, "Handshake SYN-ACK accepted"
                return False, "SYN-ACK without prior SYN (possible spoofing)"

            # ── RST or FIN: Tear down ──
            if flags & (RST | FIN):
                for k in (key, rev_key):
                    if k in self._table:
                        del self._table[k]
                return True, "Connection teardown (RST/FIN)"

            # ── ACK: Must belong to an ESTABLISHED connection ──
            if flags & ACK:
                for k in (key, rev_key):
                    if k in self._table:
                        entry = self._table[k]
                        if entry.state == "ESTABLISHED":
                            entry.packet_count += 1
                            entry.timestamp = time.time()
                            return True, "ESTABLISHED connection"
                        elif entry.state == "SYN_SENT":
                            # Complete the handshake
                            entry.state = "ESTABLISHED"
                            return True, "Connection ESTABLISHED"
                return False, "ACK with no matching state (possible spoofed/invalid)"

        return True, "Non-tracked TCP packet"

    def _cleanup_loop(self, interval: int):
        """Periodically remove expired state entries."""
        while True:
            time.sleep(interval)
            with self._lock:
                expired = [k for k, v in self._table.items()
                           if v.is_expired(self.timeout)]
                for k in expired:
                    del self._table[k]
                if expired:
                    self.logger.debug(f"State table cleanup: removed {len(expired)} expired entries.")

    def stats(self) -> dict:
        with self._lock:
            return {
                "total_tracked": len(self._table),
                "established": sum(1 for v in self._table.values()
                                   if v.state == "ESTABLISHED"),
                "syn_sent": sum(1 for v in self._table.values()
                                if v.state == "SYN_SENT"),
            }


# ─────────────────────────────────────────────
#  Rate Limiter
# ─────────────────────────────────────────────

class RateLimiter:
    """
    Sliding-window rate limiter per source IP.
    Drops packets exceeding max_packets within window_seconds.
    """

    def __init__(self, max_packets: int = 100, window_seconds: int = 10):
        self.max_packets = max_packets
        self.window = window_seconds
        self._buckets: dict[str, RateLimitEntry] = defaultdict(RateLimitEntry)
        self._lock = threading.Lock()

    def is_rate_limited(self, src_ip: str) -> bool:
        with self._lock:
            entry = self._buckets[src_ip]
            now = time.time()
            if (now - entry.window_start) > self.window:
                # Reset window
                entry.count = 1
                entry.window_start = now
                return False
            entry.count += 1
            return entry.count > self.max_packets


# ─────────────────────────────────────────────
#  Packet Handler
# ─────────────────────────────────────────────

class PacketHandler:
    """
    Core NetfilterQueue callback.
    Applies all firewall checks in order:
      1. IP Blacklist
      2. Rate Limiting
      3. Port Allowlist
      4. TCP State Tracking
      5. Deep Packet Inspection
    """

    def __init__(self, config: Config, logger: logging.Logger,
                 state_table: StateTable, dpi: DPIEngine, rate_limiter: RateLimiter):
        self.config = config
        self.logger = logger
        self.state_table = state_table
        self.dpi = dpi
        self.rate_limiter = rate_limiter

        self.blacklisted_ips: set = set(config.get("blacklisted_ips", []))
        self.allowed_ports: set = set(config.get("allowed_ports", [80, 443, 22, 53]))
        self.dpi_enabled: bool = config.get("dpi", {}).get("enabled", True)
        self.rate_limit_enabled: bool = config.get("rate_limit", {}).get("enabled", True)

        # Counters
        self.packets_allowed = 0
        self.packets_blocked = 0

    def handle(self, nfq_packet) -> None:
        """Main callback — called per packet by NetfilterQueue."""
        try:
            raw = nfq_packet.get_payload()
            pkt = IP(raw)

            verdict, reason = self._evaluate(pkt)

            if verdict == "ACCEPT":
                nfq_packet.accept()
                self.packets_allowed += 1
            else:
                nfq_packet.drop()
                self.packets_blocked += 1
                self._log_drop(pkt, reason)

        except Exception as e:
            self.logger.warning(f"Malformed packet — accepting by default. Error: {e}")
            try:
                nfq_packet.accept()
            except Exception:
                pass

    def _evaluate(self, pkt: IP) -> tuple[str, str]:
        """
        Run all firewall rules. Returns ('ACCEPT'|'DROP', reason).
        Short-circuits on first DROP condition.
        """
        src_ip = pkt.src
        dst_ip = pkt.dst

        # ── 1. IP Blacklist ──
        if src_ip in self.blacklisted_ips:
            return "DROP", f"Blacklisted source IP: {src_ip}"

        # ── 2. Rate Limiting ──
        if self.rate_limit_enabled and self.rate_limiter.is_rate_limited(src_ip):
            return "DROP", f"Rate limit exceeded for {src_ip}"

        # ── 3. Protocol-specific checks ──
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]

            # Port check
            if tcp.dport not in self.allowed_ports:
                return "DROP", f"Port {tcp.dport} not in allowlist"

            # State table check
            allow, state_reason = self.state_table.process(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=tcp.sport,
                dst_port=tcp.dport,
                flags=int(tcp.flags)
            )
            if not allow:
                return "DROP", f"State violation: {state_reason}"

        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            if udp.dport not in self.allowed_ports:
                return "DROP", f"UDP port {udp.dport} not in allowlist"

        elif pkt.haslayer(ICMP):
            # Allow ICMP echo by default, block others if desired
            pass

        # ── 4. Deep Packet Inspection ──
        if self.dpi_enabled:
            dpi_reason = self.dpi.inspect(pkt)
            if dpi_reason:
                return "DROP", f"DPI: {dpi_reason}"

        return "ACCEPT", "Passed all rules"

    def _log_drop(self, pkt: IP, reason: str) -> None:
        proto = "UNKNOWN"
        src_port = dst_port = "N/A"

        if pkt.haslayer(TCP):
            proto = "TCP"
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            proto = "UDP"
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
        elif pkt.haslayer(ICMP):
            proto = "ICMP"

        self.logger.warning(
            f"DROPPED | SRC={pkt.src}:{src_port} DST={pkt.dst}:{dst_port} "
            f"PROTO={proto} | REASON: {reason}"
        )

    def stats(self) -> dict:
        return {
            "packets_allowed": self.packets_allowed,
            "packets_blocked": self.packets_blocked,
        }


# ─────────────────────────────────────────────
#  Firewall Orchestrator
# ─────────────────────────────────────────────

class Firewall:
    """
    Top-level orchestrator.
    Manages iptables setup/teardown, component wiring, and the NFQ run loop.
    """

    IPTABLES_RULES = [
        ["iptables", "-I", "INPUT",   "-j", "NFQUEUE", "--queue-num", "0"],
        ["iptables", "-I", "OUTPUT",  "-j", "NFQUEUE", "--queue-num", "0"],
        ["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"],
    ]

    def __init__(self, config_path: str = "config.yaml"):
        self.config = Config(config_path)
        self.logger = setup_logging(
            log_file=self.config.get("logging", {}).get("file", "pywall.log"),
            level=self.config.get("logging", {}).get("level", "INFO")
        )
        self.queue_num = self.config.get("queue_num", 0)
        self._running = False
        self._nfq = NetfilterQueue()
        self._stats_thread: Optional[threading.Thread] = None

        # Wire components
        state_cfg = self.config.get("state_table", {})
        self.state_table = StateTable(
            timeout=state_cfg.get("timeout_seconds", 120),
            cleanup_interval=state_cfg.get("cleanup_interval", 30),
            logger=self.logger
        )
        self.dpi = DPIEngine(logger=self.logger)
        rl_cfg = self.config.get("rate_limit", {})
        self.rate_limiter = RateLimiter(
            max_packets=rl_cfg.get("max_packets", 100),
            window_seconds=rl_cfg.get("window_seconds", 10)
        )
        self.handler = PacketHandler(
            config=self.config,
            logger=self.logger,
            state_table=self.state_table,
            dpi=self.dpi,
            rate_limiter=self.rate_limiter
        )

        # Register signal handlers
        signal.signal(signal.SIGINT,  self._handle_shutdown)
        signal.signal(signal.SIGTERM, self._handle_shutdown)

    # ── iptables Management ──────────────────

    def _apply_iptables(self) -> None:
        self.logger.info("Applying iptables rules...")
        for rule in self.IPTABLES_RULES:
            rule[-1] = str(self.queue_num)
            try:
                subprocess.run(rule, check=True, capture_output=True)
                self.logger.info(f"Rule applied: {' '.join(rule)}")
            except subprocess.CalledProcessError as e:
                self.logger.error(f"iptables error: {e.stderr.decode().strip()}")

    def _flush_iptables(self) -> None:
        self.logger.info("Flushing iptables NFQUEUE rules...")
        flush_cmds = [
            ["iptables", "-D", "INPUT",   "-j", "NFQUEUE", "--queue-num", str(self.queue_num)],
            ["iptables", "-D", "OUTPUT",  "-j", "NFQUEUE", "--queue-num", str(self.queue_num)],
            ["iptables", "-D", "FORWARD", "-j", "NFQUEUE", "--queue-num", str(self.queue_num)],
        ]
        for cmd in flush_cmds:
            try:
                subprocess.run(cmd, check=True, capture_output=True)
            except subprocess.CalledProcessError:
                pass  # Rule may not exist — safe to ignore
        self.logger.info("iptables rules removed.")

    # ── Lifecycle ────────────────────────────

    def start(self) -> None:
        if os.geteuid() != 0:
            print("[FATAL] PyWall must be run as root.")
            sys.exit(1)

        self.logger.info("=" * 60)
        self.logger.info("PyWall Advanced Stateful Firewall — Starting")
        self.logger.info(f"Queue: {self.queue_num} | Config: {self.config.path}")
        self.logger.info("=" * 60)

        self._apply_iptables()
        self._running = True

        # Periodic stats logging
        self._stats_thread = threading.Thread(
            target=self._stats_loop, daemon=True, name="StatsReporter"
        )
        self._stats_thread.start()

        self.logger.info("Binding to NFQUEUE... (press Ctrl+C to stop)")
        try:
            self._nfq.bind(self.queue_num, self.handler.handle)
            self._nfq.run()
        except Exception as e:
            if self._running:
                self.logger.error(f"NFQueue error: {e}")
        finally:
            self._shutdown()

    def _handle_shutdown(self, signum, frame) -> None:
        self.logger.info(f"Signal {signum} received — shutting down gracefully...")
        self._running = False
        try:
            self._nfq.unbind()
        except Exception:
            pass

    def _shutdown(self) -> None:
        self._flush_iptables()
        self._print_final_stats()
        self.logger.info("PyWall stopped. Goodbye.")

    def _stats_loop(self) -> None:
        while self._running:
            time.sleep(30)
            if self._running:
                h = self.handler.stats()
                s = self.state_table.stats()
                self.logger.info(
                    f"[STATS] Allowed={h['packets_allowed']} Blocked={h['packets_blocked']} "
                    f"| Tracked={s['total_tracked']} "
                    f"(ESTAB={s['established']} SYN={s['syn_sent']})"
                )

    def _print_final_stats(self) -> None:
        h = self.handler.stats()
        s = self.state_table.stats()
        self.logger.info("─" * 60)
        self.logger.info("FINAL STATS")
        self.logger.info(f"  Packets Allowed : {h['packets_allowed']}")
        self.logger.info(f"  Packets Blocked : {h['packets_blocked']}")
        self.logger.info(f"  State Entries   : {s['total_tracked']}")
        self.logger.info("─" * 60)


# ─────────────────────────────────────────────
#  Entry Point
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="PyWall — Advanced Python Stateful Firewall",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 firewall.py
  sudo python3 firewall.py --config /etc/pywall/config.yaml
        """
    )
    parser.add_argument(
        "--config", default="config.yaml",
        help="Path to configuration YAML file (default: config.yaml)"
    )
    args = parser.parse_args()

    fw = Firewall(config_path=args.config)
    fw.start()
