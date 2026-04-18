#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
#  PyWall — iptables Helper Script
#  Usage:
#    sudo bash iptables_setup.sh apply    # Route traffic to PyWall
#    sudo bash iptables_setup.sh remove   # Restore normal routing
#    sudo bash iptables_setup.sh status   # Show current rules
# ──────────────────────────────────────────────────────────────

QUEUE_NUM=0
set -e

check_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] This script must be run as root."
    exit 1
  fi
}

apply_rules() {
  echo "[*] Applying iptables NFQUEUE rules (queue $QUEUE_NUM)..."

  # Insert at top of each chain so PyWall sees every packet first.
  iptables -I INPUT   -j NFQUEUE --queue-num $QUEUE_NUM
  iptables -I OUTPUT  -j NFQUEUE --queue-num $QUEUE_NUM
  iptables -I FORWARD -j NFQUEUE --queue-num $QUEUE_NUM

  echo "[+] Rules applied."
  echo ""
  echo "    Chain  INPUT   → NFQUEUE $QUEUE_NUM"
  echo "    Chain  OUTPUT  → NFQUEUE $QUEUE_NUM"
  echo "    Chain  FORWARD → NFQUEUE $QUEUE_NUM"
  echo ""
  echo "[!] Start PyWall NOW or traffic will be queued and stall:"
  echo "    sudo python3 firewall.py"
}

remove_rules() {
  echo "[*] Removing iptables NFQUEUE rules..."

  iptables -D INPUT   -j NFQUEUE --queue-num $QUEUE_NUM 2>/dev/null || true
  iptables -D OUTPUT  -j NFQUEUE --queue-num $QUEUE_NUM 2>/dev/null || true
  iptables -D FORWARD -j NFQUEUE --queue-num $QUEUE_NUM 2>/dev/null || true

  echo "[+] Rules removed. Normal routing restored."
}

show_status() {
  echo "[*] Current iptables rules:"
  echo ""
  iptables -L INPUT   -n -v --line-numbers | grep -E "(NFQUEUE|num)"
  iptables -L OUTPUT  -n -v --line-numbers | grep -E "(NFQUEUE|num)"
  iptables -L FORWARD -n -v --line-numbers | grep -E "(NFQUEUE|num)"
}

check_root

case "$1" in
  apply)   apply_rules  ;;
  remove)  remove_rules ;;
  status)  show_status  ;;
  *)
    echo "Usage: $0 {apply|remove|status}"
    exit 1
    ;;
esac
