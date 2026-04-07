#!/usr/bin/env python3
"""
Tailscale Kill Switch for macOS

A firewall-based kill switch that ensures all traffic routes through your
Tailscale exit node. If the Tailscale connection drops, non-essential
traffic is blocked to prevent IP leaks.

Uses macOS's built-in pf (Packet Filter) firewall — no dependencies beyond
the standard library.

Usage:
    sudo python3 killswitch.py enable      # Activate kill switch
    sudo python3 killswitch.py disable     # Deactivate kill switch
    sudo python3 killswitch.py status      # Show current state
    sudo python3 killswitch.py monitor     # Daemon mode: auto-toggle on VPN drop
    sudo python3 killswitch.py test        # Diagnostic and leak test

Requirements:
    - macOS (uses pfctl)
    - Tailscale installed with CLI available
    - Root privileges (sudo)
"""

from __future__ import annotations

import subprocess
import sys
import json
import time
import signal
import os
import shutil
import logging
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Rules written here — /etc/pf.conf is NEVER modified
PF_RULES_PATH = Path("/tmp/killswitch.pf.conf")
PF_SYSTEM_CONF = Path("/etc/pf.conf")
STATE_FILE = Path("/tmp/tailscale_killswitch.state")
LOG_FILE = Path("/tmp/tailscale_killswitch.log")

MONITOR_INTERVAL = 5

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stderr),
        logging.FileHandler(LOG_FILE),
    ],
)
log = logging.getLogger("killswitch")

# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

class TailscaleStatus(Enum):
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    EXIT_NODE_ACTIVE = "exit_node_active"
    NO_EXIT_NODE = "no_exit_node"
    NOT_RUNNING = "not_running"


@dataclass
class TSInfo:
    """Parsed Tailscale status."""
    status: TailscaleStatus
    exit_node_ip: str | None = None
    tailscale_ip: str | None = None
    interface: str | None = None
    vpn_peer_ip: str | None = None
    derp_ips: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Shell helpers
# ---------------------------------------------------------------------------

def run(cmd: list[str], check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
    log.debug(f"Running: {' '.join(cmd)}")
    return subprocess.run(cmd, capture_output=capture, text=True, check=check)


def require_root():
    if os.geteuid() != 0:
        print("Error: This tool requires root privileges. Run with sudo.")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Tailscale introspection
# ---------------------------------------------------------------------------

def get_tailscale_bin() -> str:
    for candidate in [
        "/usr/local/bin/tailscale",
        "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
    ]:
        if Path(candidate).exists():
            return candidate
    ts = shutil.which("tailscale")
    if ts:
        return ts
    print("Error: Cannot find tailscale CLI. Is Tailscale installed?")
    sys.exit(1)


def detect_vpn_peer_ip() -> str | None:
    """
    Detect the VPN peer's public IP from the routing table.

    When Tailscale uses an exit node, it creates a host route (UGSH/UGSc)
    to the exit node's real public IP. This is the IP we must allow through
    the firewall so the WireGuard tunnel stays up.
    """
    try:
        result = run(["netstat", "-rn", "-f", "inet"], check=False)
        if result.returncode != 0:
            return None

        for line in result.stdout.splitlines():
            if "UGSH" not in line and "UGSc" not in line:
                continue
            parts = line.split()
            if not parts:
                continue
            dest = parts[0]
            try:
                import ipaddress
                addr = ipaddress.ip_address(dest)
                if isinstance(addr, ipaddress.IPv4Address) and not addr.is_private:
                    return str(addr)
            except ValueError:
                continue
    except Exception:
        pass
    return None


def resolve_derp_ips() -> list[str]:
    """Resolve Tailscale DERP relay and control plane IPs."""
    ips = set()
    ts = get_tailscale_bin()

    try:
        result = run([ts, "debug", "derp-map"], check=False)
        if result.returncode == 0:
            try:
                derp_data = json.loads(result.stdout)
                for _rid, region in derp_data.get("Regions", {}).items():
                    for node in region.get("Nodes", []):
                        if "IPv4" in node:
                            ips.add(node["IPv4"])
            except json.JSONDecodeError:
                pass
    except Exception:
        pass

    # Fallback: resolve known DERP hostnames
    if not ips:
        import socket
        for i in list(range(1, 12)) + [14, 16, 17, 18, 19, 20, 21, 24, 25, 26, 27, 28, 29, 30, 31]:
            try:
                for info in socket.getaddrinfo(f"derp{i}.tailscale.com", 443, socket.AF_INET):
                    ips.add(info[4][0])
            except socket.gaierror:
                pass

    # Control plane
    import socket
    for host in ["controlplane.tailscale.com", "login.tailscale.com"]:
        try:
            for info in socket.getaddrinfo(host, 443, socket.AF_INET):
                ips.add(info[4][0])
        except Exception:
            pass

    return sorted(ips)


def get_tailscale_status() -> TSInfo:
    ts = get_tailscale_bin()
    try:
        result = run([ts, "status", "--json"], check=False)
    except FileNotFoundError:
        return TSInfo(status=TailscaleStatus.NOT_RUNNING)

    if result.returncode != 0:
        return TSInfo(status=TailscaleStatus.NOT_RUNNING)

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return TSInfo(status=TailscaleStatus.NOT_RUNNING)

    backend_state = data.get("BackendState", "")
    if backend_state != "Running":
        return TSInfo(status=TailscaleStatus.DISCONNECTED)

    self_status = data.get("Self", {})
    ts_ips = self_status.get("TailscaleIPs", [])
    tailscale_ip = ts_ips[0] if ts_ips else None

    exit_node_ip = None
    peers = data.get("Peer", {})
    for _key, peer in peers.items():
        if peer.get("ExitNode", False):
            peer_ips = peer.get("TailscaleIPs", [])
            exit_node_ip = peer_ips[0] if peer_ips else None
            break

    interface = _detect_ts_interface()
    vpn_peer_ip = detect_vpn_peer_ip()
    derp_ips = resolve_derp_ips()

    if exit_node_ip:
        return TSInfo(
            status=TailscaleStatus.EXIT_NODE_ACTIVE,
            exit_node_ip=exit_node_ip,
            tailscale_ip=tailscale_ip,
            interface=interface,
            vpn_peer_ip=vpn_peer_ip,
            derp_ips=derp_ips,
        )
    else:
        return TSInfo(
            status=TailscaleStatus.NO_EXIT_NODE,
            tailscale_ip=tailscale_ip,
            interface=interface,
            vpn_peer_ip=vpn_peer_ip,
            derp_ips=derp_ips,
        )


def _detect_ts_interface() -> str | None:
    try:
        result = run(["ifconfig"], check=False)
        lines = result.stdout.splitlines()
        current_iface = None
        for line in lines:
            if line and not line[0].isspace() and ":" in line:
                current_iface = line.split(":")[0]
            if current_iface and current_iface.startswith("utun"):
                if "inet 100." in line:
                    return current_iface
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# pf rule generation
# ---------------------------------------------------------------------------

def _build_pf_rules(ts_info: TSInfo) -> str:
    ts_iface = ts_info.interface or "utun0"

    peer_rules = ""
    if ts_info.vpn_peer_ip:
        peer_rules = f"""\
# Allow traffic to VPN peer (keeps the WireGuard tunnel alive)
pass out quick proto udp to {ts_info.vpn_peer_ip} keep state
pass in quick proto udp from {ts_info.vpn_peer_ip} keep state"""
    else:
        peer_rules = """\
# Could not detect VPN peer IP — allowing Tailscale WireGuard port broadly
pass out quick proto udp to any port 41641 keep state
pass in quick proto udp from any port 41641 keep state"""

    # DERP relay rules + STUN (pinned IPs, not blanket 443/3478)
    derp_rules = ""
    if ts_info.derp_ips:
        derp_table = "{ " + ", ".join(ts_info.derp_ips) + " }"
        derp_rules = f"""\
# Tailscale DERP relay and control plane IPs (pinned)
table <tailscale_infra> const {derp_table}
pass out quick proto tcp to <tailscale_infra> port 443 keep state
pass out quick proto udp to <tailscale_infra> port 3478 keep state"""
    else:
        derp_rules = """\
# WARNING: Could not resolve DERP IPs — allowing port 443/3478 broadly as fallback.
pass out quick proto tcp to any port 443 keep state
pass out quick proto udp to any port 3478 keep state"""
        log.warning("Could not resolve DERP IPs — using broad port 443/3478 fallback")

    rules = f"""\
# --------------------------------------------------------------
# Tailscale Kill Switch — generated by killswitch.py
# {time.strftime('%a, %d %b %Y %H:%M:%S %z')}
# Loaded via: pfctl -Fa -f {PF_RULES_PATH}
# Disable:    pfctl -Fa -f {PF_SYSTEM_CONF}
# --------------------------------------------------------------

# Default policy: drop everything, skip loopback
set block-policy drop
set ruleset-optimization basic
set skip on lo0

# Block all traffic by default
block all

# ---- DHCP: keep physical link alive ----
pass quick proto udp from any port 67:68 to any port 67:68 keep state

# ---- ICMP: Required for Path MTU Discovery ----
pass quick proto icmp all keep state

# ---- VPN PEER: allow WireGuard tunnel traffic ----
{peer_rules}

# ---- DERP / CONTROL PLANE / STUN ----
{derp_rules}

# ---- DNS to Tailscale MagicDNS only ----
pass quick proto {{ tcp, udp }} to 100.100.100.100 port 53 keep state

# ---- TAILSCALE TUNNEL: pass everything ----
pass quick on {ts_iface} all
"""
    return rules


def _build_lockdown_rules() -> str:
    """
    Lockdown rules: Tailscale is down, block almost everything.
    Only allows what Tailscale needs to reconnect.
    """
    derp_ips = resolve_derp_ips()
    if derp_ips:
        derp_table = "{ " + ", ".join(derp_ips) + " }"
        derp_rules = f"""\
table <tailscale_infra> const {derp_table}
pass out quick proto tcp to <tailscale_infra> port 443 keep state
pass out quick proto udp to <tailscale_infra> port 3478 keep state"""
    else:
        derp_rules = """\
pass out quick proto tcp to any port 443 keep state
pass out quick proto udp to any port 3478 keep state"""

    rules = f"""\
# --------------------------------------------------------------
# Tailscale Kill Switch — LOCKDOWN MODE
# VPN is disconnected; blocking all non-essential traffic.
# {time.strftime('%a, %d %b %Y %H:%M:%S %z')}
# --------------------------------------------------------------

set block-policy drop
set ruleset-optimization basic
set skip on lo0

block all

# DHCP
pass quick proto udp from any port 67:68 to any port 67:68 keep state

# ICMP
pass quick proto icmp all keep state

# Allow Tailscale WireGuard so it can reconnect
pass out quick proto udp to any port 41641 keep state
pass in quick proto udp from any port 41641 keep state

# Allow Tailscale DERP/control plane/STUN so it can reconnect
{derp_rules}

# DNS to MagicDNS
pass quick proto {{ tcp, udp }} to 100.100.100.100 port 53 keep state
"""
    return rules


# ---------------------------------------------------------------------------
# pf management
# ---------------------------------------------------------------------------

def apply_rules(rules: str) -> bool:
    """Write rules to temp file and atomically flush-and-load."""
    PF_RULES_PATH.write_text(rules)
    log.info(f"Wrote rules to {PF_RULES_PATH}")

    # Enable pf (ignore "already enabled" error)
    result = run(["pfctl", "-e"], check=False)
    if result.returncode != 0 and "already enabled" not in (result.stderr or ""):
        log.error(f"Failed to enable pf: {result.stderr}")
        return False

    # Atomic flush-and-load (no gap where rules are empty)
    result = run(["pfctl", "-Fa", "-f", str(PF_RULES_PATH)], check=False)
    if result.returncode != 0:
        log.error(f"pfctl load failed: {result.stderr}")
        print(f"Error loading rules: {result.stderr}")
        return False

    log.info("Rules applied successfully")
    return True


def restore_system_rules():
    """Restore the system default pf rules. /etc/pf.conf was never touched."""
    run(["pfctl", "-e"], check=False)

    result = run(["pfctl", "-Fa", "-f", str(PF_SYSTEM_CONF)], check=False)
    if result.returncode != 0:
        log.error(f"Failed to restore system rules: {result.stderr}")

    if PF_RULES_PATH.exists():
        PF_RULES_PATH.unlink()
    if STATE_FILE.exists():
        STATE_FILE.unlink()

    log.info("Restored system pf rules")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_enable():
    require_root()
    ts = get_tailscale_status()

    if ts.status == TailscaleStatus.NOT_RUNNING:
        print("⚠  Tailscale is not running. Installing lockdown rules.")
        rules = _build_lockdown_rules()
        apply_rules(rules)
        STATE_FILE.write_text("lockdown")
        return

    if ts.status == TailscaleStatus.DISCONNECTED:
        print("⚠  Tailscale backend is not connected. Installing lockdown rules.")
        rules = _build_lockdown_rules()
        apply_rules(rules)
        STATE_FILE.write_text("lockdown")
        return

    if ts.status == TailscaleStatus.NO_EXIT_NODE:
        print("⚠  Tailscale is running but NO exit node is active.")
        print("   Connect to an exit node first:")
        print("     tailscale set --exit-node=<node>")
        print("   Installing lockdown rules in the meantime.")
        rules = _build_lockdown_rules()
        apply_rules(rules)
        STATE_FILE.write_text("lockdown")
        return

    # Exit node is active
    print(f"✓  Tailscale exit node active: {ts.exit_node_ip}")
    print(f"   Tailscale IP: {ts.tailscale_ip}")
    print(f"   Interface: {ts.interface}")
    if ts.vpn_peer_ip:
        print(f"   VPN peer (real IP): {ts.vpn_peer_ip}")
    else:
        print("   VPN peer: not detected (using port-based fallback)")
    if ts.derp_ips:
        print(f"   DERP/control IPs pinned: {len(ts.derp_ips)} addresses")

    rules = _build_pf_rules(ts)
    if apply_rules(rules):
        STATE_FILE.write_text("active")
        print("✓  Kill switch ENABLED. All traffic must go through Tailscale.")
    else:
        print("✗  Failed to apply rules. Check /tmp/tailscale_killswitch.log")


def cmd_disable():
    require_root()
    restore_system_rules()
    print("✓  Kill switch DISABLED. Normal networking restored.")


def cmd_status():
    ts = get_tailscale_status()

    ks_state = STATE_FILE.read_text().strip() if STATE_FILE.exists() else "unknown"

    pf_enabled = False
    info = run(["pfctl", "-s", "info"], check=False)
    if info.returncode == 0:
        pf_enabled = "Status: Enabled" in info.stdout

    rules_result = run(["pfctl", "-s", "rules"], check=False)
    rules_text = rules_result.stdout or ""

    our_rules = (
        "block drop all" in rules_text
        and "100.100.100.100" in rules_text
        and PF_RULES_PATH.exists()
    )

    print("─── Tailscale Kill Switch Status ───")
    print()

    if pf_enabled and our_rules:
        print(f"  Kill switch:   ✓ ACTIVE ({ks_state})")
    elif pf_enabled:
        print(f"  Kill switch:   INACTIVE (pf enabled with system rules)")
    else:
        print(f"  Kill switch:   INACTIVE (pf disabled)")

    print(f"  Tailscale:     {ts.status.value}")
    if ts.tailscale_ip:
        print(f"  Tailscale IP:  {ts.tailscale_ip}")
    if ts.exit_node_ip:
        print(f"  Exit node:     {ts.exit_node_ip}")
    if ts.interface:
        print(f"  Interface:     {ts.interface}")
    if ts.vpn_peer_ip:
        print(f"  VPN peer:      {ts.vpn_peer_ip}")

    print()

    if pf_enabled:
        print("─── Active pf Rules ───")
        for line in rules_text.splitlines():
            line = line.strip()
            if line and "ALTQ" not in line:
                print(f"  {line}")

        print()
        if info.returncode == 0:
            for line in info.stdout.splitlines():
                if any(w in line.lower() for w in ["match", "block", "pass", "state"]):
                    stripped = line.strip()
                    if stripped:
                        print(f"  {stripped}")


def cmd_test():
    require_root()
    ts = get_tailscale_status()

    print("─── Kill Switch Diagnostics ───")
    print()

    # 1. pf status
    print("1. pf firewall:")
    info = run(["pfctl", "-s", "info"], check=False)
    if info.returncode == 0 and "Status: Enabled" in info.stdout:
        print("   ✓  pf is ENABLED")
    else:
        print("   ✗  pf is DISABLED — kill switch cannot work!")
        print("      Run 'enable' first.")
        return

    # 2. Rules check
    print()
    print("2. Loaded rules:")
    rules = run(["pfctl", "-s", "rules"], check=False)
    if rules.returncode == 0:
        rule_lines = [l.strip() for l in rules.stdout.splitlines()
                      if l.strip() and "ALTQ" not in l]
        has_block_all = any("block drop all" in l for l in rule_lines)
        has_pass_all = any(l.strip() in ("pass all", "pass all flags S/SA")
                          for l in rule_lines)

        print(f"   Rules loaded: {len(rule_lines)}")
        if has_block_all:
            print("   ✓  Has 'block drop all' (default deny)")
        else:
            print("   ✗  MISSING 'block drop all'!")
        if has_pass_all:
            print("   ✗  Has 'pass all' — this overrides all blocks!")
        if PF_RULES_PATH.exists():
            print(f"   ✓  Rules file: {PF_RULES_PATH}")
        else:
            print(f"   ✗  No rules file at {PF_RULES_PATH}")

    # 3. Tailscale
    print()
    print(f"3. Tailscale: {ts.status.value}")
    if ts.interface:
        print(f"   Interface: {ts.interface}")
    if ts.exit_node_ip:
        print(f"   Exit node: {ts.exit_node_ip}")
    if ts.vpn_peer_ip:
        print(f"   VPN peer:  {ts.vpn_peer_ip}")

    # 4. Leak test
    print()
    print("4. Connectivity test:")
    if ts.status == TailscaleStatus.EXIT_NODE_ACTIVE:
        print("   Exit node is ACTIVE — traffic should flow through VPN.")
        result = run(["curl", "-s", "--max-time", "5", "ifconfig.me"], check=False)
        if result.returncode == 0 and result.stdout.strip():
            print(f"   Public IP: {result.stdout.strip()}")
            print("   (Should be your exit node's IP, not your real IP)")
        else:
            print("   Could not reach ifconfig.me")
    else:
        print("   Exit node is NOT active — testing if traffic is blocked...")
        result = run(["curl", "-s", "--max-time", "5", "ifconfig.me"], check=False)
        if result.returncode == 0 and result.stdout.strip():
            print(f"   ⚠  LEAK! Real IP exposed: {result.stdout.strip()}")
        else:
            print("   ✓  Traffic blocked — no internet access (good!)")

    print()


def cmd_monitor():
    require_root()
    print("Starting kill switch monitor...")
    print(f"Checking every {MONITOR_INTERVAL}s. Press Ctrl+C to stop.")
    print()

    def _shutdown(signum, frame):
        print("\nMonitor stopped. Kill switch rules remain active.")
        print("Run 'disable' to restore normal networking.")
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    last_state = None

    while True:
        ts = get_tailscale_status()

        if ts.status == TailscaleStatus.EXIT_NODE_ACTIVE and last_state != "active":
            log.info(f"Exit node active ({ts.exit_node_ip}). Applying VPN rules.")
            rules = _build_pf_rules(ts)
            apply_rules(rules)
            STATE_FILE.write_text("active")
            last_state = "active"
            print(f"  ✓ Exit node UP ({ts.exit_node_ip}) — traffic flowing through VPN")

        elif ts.status != TailscaleStatus.EXIT_NODE_ACTIVE and last_state != "lockdown":
            log.warning(f"Tailscale: {ts.status.value}. LOCKDOWN activated!")
            rules = _build_lockdown_rules()
            apply_rules(rules)
            STATE_FILE.write_text("lockdown")
            last_state = "lockdown"
            print(f"  ⚠ LOCKDOWN — Tailscale is {ts.status.value}, blocking traffic")

        time.sleep(MONITOR_INTERVAL)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

USAGE = """\
Tailscale Kill Switch for macOS

Usage: sudo killswitch <command>

Commands:
  enable    Activate the kill switch (block non-Tailscale traffic)
  disable   Deactivate and restore normal networking
  status    Show current kill switch and Tailscale state
  monitor   Daemon mode — auto-lockdown on VPN drop, auto-restore on reconnect
  test      Diagnostic and leak test
"""


def main():
    if len(sys.argv) < 2:
        print(USAGE)
        sys.exit(1)

    command = sys.argv[1].lower()

    commands = {
        "enable": cmd_enable,
        "disable": cmd_disable,
        "status": cmd_status,
        "monitor": cmd_monitor,
        "test": cmd_test,
    }

    if command in ("-h", "--help", "help"):
        print(USAGE)
        sys.exit(0)

    if command not in commands:
        print(f"Unknown command: {command}")
        print(USAGE)
        sys.exit(1)

    commands[command]()


if __name__ == "__main__":
    main()