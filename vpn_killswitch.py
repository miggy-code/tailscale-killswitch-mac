#!/usr/bin/env python3
"""
VPN Kill Switch for macOS

A firewall-based kill switch that ensures all traffic routes through your
VPN. If the VPN connection drops, non-essential traffic is blocked to
prevent IP leaks.

Supports: Tailscale, WireGuard, OpenVPN, and any macOS Network Extension VPN.

Uses macOS's built-in pf (Packet Filter) firewall — no dependencies beyond
the standard library.

Usage:
    sudo killswitch enable              # Auto-detect VPN and activate
    sudo killswitch enable --ip 1.2.3.4 # Specify VPN peer IP manually
    sudo killswitch disable             # Restore normal networking
    sudo killswitch status              # Show current state
    sudo killswitch monitor             # Daemon: auto-lockdown on VPN drop
    sudo killswitch test                # Diagnostic and leak test

Requirements:
    - macOS (uses pfctl)
    - Active VPN connection (or --ip to specify peer manually)
    - Root privileges (sudo)
"""

from __future__ import annotations

import ipaddress
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

PF_RULES_PATH = Path("/tmp/killswitch.pf.conf")
PF_SYSTEM_CONF = Path("/etc/pf.conf")
STATE_FILE = Path("/tmp/killswitch.state")
LOG_FILE = Path("/tmp/killswitch.log")

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

class VPNStatus(Enum):
    ACTIVE = "active"
    NO_VPN = "no_vpn"
    NO_EXIT_NODE = "no_exit_node"      # Tailscale-specific
    NOT_RUNNING = "not_running"


@dataclass
class VPNInfo:
    """Detected VPN state — works for any VPN, with optional Tailscale extras."""
    status: VPNStatus
    vpn_type: str = "unknown"           # "tailscale", "wireguard", "openvpn", "network_extension"
    vpn_peer_ip: str | None = None      # Real public IP of VPN server
    tunnel_interface: str | None = None  # utun0, utun5, etc.
    # Tailscale-specific (None for other VPNs)
    tailscale_ip: str | None = None
    exit_node_ip: str | None = None
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


def is_valid_vpn_peer(ip_str: str) -> bool:
    """Check if IP is a valid VPN peer: public, routable IPv4."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if not isinstance(addr, ipaddress.IPv4Address):
        return False
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return False
    if addr.is_multicast or addr.is_reserved:
        return False
    if ip_str in ("0.0.0.0", "128.0.0.0", "255.255.255.255"):
        return False
    return True


# ---------------------------------------------------------------------------
# VPN Peer IP Detection (4 methods, like vpnkillswitch Rust)
# ---------------------------------------------------------------------------

def detect_vpn_peer_ip() -> tuple[str | None, str]:
    """
    Detect the VPN peer's public IP. Returns (ip, method).
    Tries multiple detection methods in order of reliability.
    """
    # Method 1: netstat routing table (most reliable, VPN-agnostic)
    ip = _detect_peer_netstat()
    if ip:
        return ip, "netstat"

    # Method 2: WireGuard (wg show)
    ip = _detect_peer_wireguard()
    if ip:
        return ip, "wireguard"

    # Method 3: Tailscale (tailscale status --json)
    ip = _detect_peer_tailscale()
    if ip:
        return ip, "tailscale"

    # Method 4: macOS scutil (Network Extension VPNs)
    ip = _detect_peer_scutil()
    if ip:
        return ip, "scutil"

    return None, "none"


def _detect_peer_netstat() -> str | None:
    """
    Detect VPN peer from routing table.
    Looks for UGSH (Up, Gateway, Static, Host) or UGSc routes —
    these point to the VPN server's public IP.
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
            if is_valid_vpn_peer(dest):
                log.debug(f"Detected VPN peer via netstat: {dest}")
                return dest
    except Exception:
        pass
    return None


def _detect_peer_wireguard() -> str | None:
    """Detect VPN peer from WireGuard (wg show)."""
    wg = shutil.which("wg")
    if not wg:
        return None
    try:
        result = run([wg, "show"], check=False)
        if result.returncode != 0:
            return None
        for line in result.stdout.splitlines():
            trimmed = line.strip()
            if trimmed.startswith("endpoint:"):
                endpoint = trimmed.split(":", 1)[1].strip()
                # Extract IP from "IP:port"
                ip = endpoint.rsplit(":", 1)[0]
                if is_valid_vpn_peer(ip):
                    log.debug(f"Detected VPN peer via WireGuard: {ip}")
                    return ip
    except Exception:
        pass
    return None


def _detect_peer_tailscale() -> str | None:
    """Detect VPN peer from Tailscale exit node's CurAddr."""
    ts = _find_tailscale_bin()
    if not ts:
        return None
    try:
        result = run([ts, "status", "--json"], check=False)
        if result.returncode != 0:
            return None
        data = json.loads(result.stdout)
        peers = data.get("Peer", {})
        for _key, peer in peers.items():
            if peer.get("ExitNode", False):
                cur_addr = peer.get("CurAddr", "")
                if cur_addr:
                    ip = cur_addr.rsplit(":", 1)[0]
                    if is_valid_vpn_peer(ip):
                        log.debug(f"Detected VPN peer via Tailscale CurAddr: {ip}")
                        return ip
    except Exception:
        pass
    return None


def _detect_peer_scutil() -> str | None:
    """Detect VPN peer via macOS Network Extension (scutil --nc)."""
    try:
        result = run(["scutil", "--nc", "list"], check=False)
        if result.returncode != 0:
            return None
        for line in result.stdout.splitlines():
            if "(Connected)" not in line:
                continue
            parts = line.split()
            if len(parts) < 3:
                continue
            uuid = parts[2]
            show = run(["scutil", "--nc", "show", uuid], check=False)
            if show.returncode != 0:
                continue
            for detail_line in show.stdout.splitlines():
                trimmed = detail_line.strip()
                if trimmed.startswith("RemoteAddress :"):
                    ip = trimmed.split(":", 1)[1].strip()
                    if is_valid_vpn_peer(ip):
                        log.debug(f"Detected VPN peer via scutil: {ip}")
                        return ip
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# VPN Tunnel Interface Detection
# ---------------------------------------------------------------------------

def detect_vpn_interfaces() -> list[dict]:
    """
    Detect all active VPN tunnel interfaces (point-to-point utun/tun).
    Returns list of {name, ip, is_tailscale}.
    """
    interfaces = []
    try:
        result = run(["ifconfig"], check=False)
        if result.returncode != 0:
            return interfaces

        current_name = ""
        current_flags = ""

        for line in result.stdout.splitlines():
            if line and not line[0].isspace() and ":" in line:
                current_name = line.split(":")[0]
                current_flags = line
                continue

            if not current_name:
                continue

            # Look for IPv4 on point-to-point interfaces
            trimmed = line.strip()
            if (trimmed.startswith("inet ") and not trimmed.startswith("inet6")
                    and "POINTOPOINT" in current_flags):
                parts = trimmed.split()
                if len(parts) >= 2:
                    ip = parts[1]
                    is_ts = ip.startswith("100.")  # Tailscale CGNAT range
                    interfaces.append({
                        "name": current_name,
                        "ip": ip,
                        "is_tailscale": is_ts,
                    })
    except Exception:
        pass
    return interfaces


# ---------------------------------------------------------------------------
# Tailscale-specific helpers (optional enhancements)
# ---------------------------------------------------------------------------

def _find_tailscale_bin() -> str | None:
    for candidate in [
        "/usr/local/bin/tailscale",
        "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
    ]:
        if Path(candidate).exists():
            return candidate
    return shutil.which("tailscale")


def get_tailscale_info() -> dict:
    """Get Tailscale-specific info (exit node, IPs, DERP). Returns empty dict if not available."""
    ts = _find_tailscale_bin()
    if not ts:
        return {}
    try:
        result = run([ts, "status", "--json"], check=False)
        if result.returncode != 0:
            return {}
        data = json.loads(result.stdout)
    except (json.JSONDecodeError, Exception):
        return {}

    backend = data.get("BackendState", "")
    if backend != "Running":
        return {"running": False}

    info = {"running": True}

    # Our Tailscale IP
    self_status = data.get("Self", {})
    ts_ips = self_status.get("TailscaleIPs", [])
    if ts_ips:
        info["tailscale_ip"] = ts_ips[0]

    # Exit node
    peers = data.get("Peer", {})
    for _key, peer in peers.items():
        if peer.get("ExitNode", False):
            peer_ips = peer.get("TailscaleIPs", [])
            if peer_ips:
                info["exit_node_ip"] = peer_ips[0]
            break

    return info


def resolve_derp_ips() -> list[str]:
    """Resolve Tailscale DERP relay and control plane IPs."""
    ips = set()
    ts = _find_tailscale_bin()

    if ts:
        try:
            result = run([ts, "debug", "derp-map"], check=False)
            if result.returncode == 0:
                derp_data = json.loads(result.stdout)
                for _rid, region in derp_data.get("Regions", {}).items():
                    for node in region.get("Nodes", []):
                        if "IPv4" in node:
                            ips.add(node["IPv4"])
        except Exception:
            pass

    if not ips:
        import socket
        for i in list(range(1, 12)) + [14, 16, 17, 18, 19, 20, 21, 24, 25, 26, 27, 28, 29, 30, 31]:
            try:
                for info in socket.getaddrinfo(f"derp{i}.tailscale.com", 443, socket.AF_INET):
                    ips.add(info[4][0])
            except socket.gaierror:
                pass

    import socket
    for host in ["controlplane.tailscale.com", "login.tailscale.com"]:
        try:
            for info in socket.getaddrinfo(host, 443, socket.AF_INET):
                ips.add(info[4][0])
        except Exception:
            pass

    return sorted(ips)


# ---------------------------------------------------------------------------
# Combined VPN detection
# ---------------------------------------------------------------------------

def detect_vpn(manual_ip: str | None = None) -> VPNInfo:
    """
    Detect VPN state using all available methods.
    If manual_ip is provided, uses that instead of auto-detection.
    """
    # Detect tunnel interfaces
    tunnels = detect_vpn_interfaces()
    tunnel_iface = tunnels[0]["name"] if tunnels else None
    has_tailscale = any(t["is_tailscale"] for t in tunnels)

    # Detect VPN peer IP
    if manual_ip:
        if not is_valid_vpn_peer(manual_ip):
            log.error(f"Provided IP {manual_ip} is not a valid public IPv4 address")
            return VPNInfo(status=VPNStatus.NO_VPN)
        vpn_peer_ip = manual_ip
        detect_method = "manual"
    else:
        vpn_peer_ip, detect_method = detect_vpn_peer_ip()

    # Determine VPN type
    vpn_type = "unknown"
    if detect_method == "wireguard":
        vpn_type = "wireguard"
    elif detect_method == "tailscale" or has_tailscale:
        vpn_type = "tailscale"
    elif detect_method == "scutil":
        vpn_type = "network_extension"
    elif detect_method in ("netstat", "manual"):
        # Could be anything — check for Tailscale
        if has_tailscale:
            vpn_type = "tailscale"
        elif shutil.which("wg"):
            vpn_type = "wireguard"
        else:
            vpn_type = "openvpn"  # best guess

    # Tailscale-specific enrichment
    ts_info = {}
    derp_ips = []
    if vpn_type == "tailscale":
        ts_info = get_tailscale_info()
        if not ts_info.get("running"):
            return VPNInfo(status=VPNStatus.NOT_RUNNING, vpn_type="tailscale")
        if "exit_node_ip" not in ts_info:
            return VPNInfo(
                status=VPNStatus.NO_EXIT_NODE,
                vpn_type="tailscale",
                tailscale_ip=ts_info.get("tailscale_ip"),
                tunnel_interface=tunnel_iface,
            )
        derp_ips = resolve_derp_ips()

    # No tunnel and no peer = no VPN
    if not tunnel_iface and not vpn_peer_ip:
        return VPNInfo(status=VPNStatus.NO_VPN)

    return VPNInfo(
        status=VPNStatus.ACTIVE,
        vpn_type=vpn_type,
        vpn_peer_ip=vpn_peer_ip,
        tunnel_interface=tunnel_iface,
        tailscale_ip=ts_info.get("tailscale_ip"),
        exit_node_ip=ts_info.get("exit_node_ip"),
        derp_ips=derp_ips,
    )


# ---------------------------------------------------------------------------
# pf rule generation
# ---------------------------------------------------------------------------

def _build_pf_rules(vpn: VPNInfo) -> str:
    tunnel = vpn.tunnel_interface or "utun0"

    # VPN peer rule: allow traffic to the VPN server's real IP
    if vpn.vpn_peer_ip:
        peer_rules = f"""\
# Allow traffic to VPN peer ({vpn.vpn_type}: {vpn.vpn_peer_ip})
pass out quick proto udp to {vpn.vpn_peer_ip} keep state
pass in quick proto udp from {vpn.vpn_peer_ip} keep state
# Also allow TCP to peer (some VPNs use TCP fallback)
pass out quick proto tcp to {vpn.vpn_peer_ip} keep state
pass in quick proto tcp from {vpn.vpn_peer_ip} keep state"""
    else:
        peer_rules = """\
# Could not detect VPN peer IP — allowing common VPN ports broadly
pass out quick proto udp to any port 41641 keep state
pass in quick proto udp from any port 41641 keep state
pass out quick proto udp to any port 51820 keep state
pass in quick proto udp from any port 51820 keep state"""

    # Tailscale DERP rules (only if Tailscale)
    derp_rules = ""
    if vpn.vpn_type == "tailscale" and vpn.derp_ips:
        derp_table = "{ " + ", ".join(vpn.derp_ips) + " }"
        derp_rules = f"""\

# Tailscale DERP relay and control plane IPs (pinned)
table <tailscale_infra> const {derp_table}
pass out quick proto tcp to <tailscale_infra> port 443 keep state
# STUN: required for NAT traversal / direct peer connections
pass out quick proto udp to <tailscale_infra> port 3478 keep state"""
    elif vpn.vpn_type == "tailscale":
        derp_rules = """\

# Tailscale DERP fallback (could not pin IPs)
pass out quick proto tcp to any port 443 keep state
pass out quick proto udp to any port 3478 keep state"""

    # Tailscale MagicDNS rule (only if Tailscale)
    dns_rules = ""
    if vpn.vpn_type == "tailscale":
        dns_rules = """\

# DNS to Tailscale MagicDNS
pass quick proto { tcp, udp } to 100.100.100.100 port 53 keep state"""

    rules = f"""\
# --------------------------------------------------------------
# VPN Kill Switch — generated by killswitch.py
# {time.strftime('%a, %d %b %Y %H:%M:%S %z')}
# VPN type: {vpn.vpn_type} | Peer: {vpn.vpn_peer_ip or 'unknown'}
# Tunnel: {tunnel}
# Loaded via: pfctl -Fa -f {PF_RULES_PATH}
# Disable:    pfctl -Fa -f {PF_SYSTEM_CONF}
# --------------------------------------------------------------

set block-policy drop
set ruleset-optimization basic
set skip on lo0

block all

# ---- DHCP: keep physical link alive ----
pass quick proto udp from any port 67:68 to any port 67:68 keep state

# ---- Broadcast (required for some network operations) ----
pass from any to 255.255.255.255 keep state
pass from 255.255.255.255 to any keep state

# ---- ICMP: only types needed for Path MTU Discovery ----
# Type 3 (destination unreachable) includes code 4 (fragmentation needed)
pass quick proto icmp all icmp-type 3 keep state
pass quick proto icmp all icmp-type 11 keep state

# ---- VPN PEER ----
{peer_rules}
{derp_rules}
{dns_rules}

# ---- VPN TUNNEL: pass everything ----
pass quick on {tunnel} all
"""
    return rules


def _build_lockdown_rules(vpn_type: str = "unknown") -> str:
    """
    Lockdown: VPN is down, block almost everything.
    Only allows what's needed to reconnect.
    """
    # Tailscale DERP for reconnection
    derp_rules = ""
    if vpn_type == "tailscale":
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

    dns_rule = ""
    if vpn_type == "tailscale":
        dns_rule = "\n# MagicDNS\npass quick proto { tcp, udp } to 100.100.100.100 port 53 keep state"

    rules = f"""\
# --------------------------------------------------------------
# VPN Kill Switch — LOCKDOWN MODE
# VPN is disconnected; blocking all non-essential traffic.
# {time.strftime('%a, %d %b %Y %H:%M:%S %z')}
# --------------------------------------------------------------

set block-policy drop
set ruleset-optimization basic
set skip on lo0

block all

# DHCP
pass quick proto udp from any port 67:68 to any port 67:68 keep state

# Broadcast
pass from any to 255.255.255.255 keep state

# ICMP (Path MTU Discovery only)
pass quick proto icmp all icmp-type 3 keep state
pass quick proto icmp all icmp-type 11 keep state

# Common VPN ports (allow reconnection)
pass out quick proto udp to any port 41641 keep state
pass in quick proto udp from any port 41641 keep state
pass out quick proto udp to any port 51820 keep state
pass in quick proto udp from any port 51820 keep state
pass out quick proto udp to any port 1194 keep state
pass out quick proto tcp to any port 1194 keep state

{derp_rules}
{dns_rule}
"""
    return rules


# ---------------------------------------------------------------------------
# pf management
# ---------------------------------------------------------------------------

def apply_rules(rules: str) -> bool:
    """Write rules to temp file and atomically flush-and-load."""
    PF_RULES_PATH.write_text(rules)
    log.info(f"Wrote rules to {PF_RULES_PATH}")

    result = run(["pfctl", "-e"], check=False)
    if result.returncode != 0 and "already enabled" not in (result.stderr or ""):
        log.error(f"Failed to enable pf: {result.stderr}")
        return False

    result = run(["pfctl", "-Fa", "-f", str(PF_RULES_PATH)], check=False)
    if result.returncode != 0:
        log.error(f"pfctl load failed: {result.stderr}")
        print(f"Error loading rules: {result.stderr}")
        return False

    log.info("Rules applied successfully")
    return True


def restore_system_rules():
    """Restore the system default pf rules."""
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

def cmd_enable(manual_ip: str | None = None):
    require_root()
    vpn = detect_vpn(manual_ip)

    if vpn.status == VPNStatus.NOT_RUNNING:
        print(f"⚠  {vpn.vpn_type} is not running. Installing lockdown rules.")
        rules = _build_lockdown_rules(vpn.vpn_type)
        apply_rules(rules)
        STATE_FILE.write_text(f"lockdown:{vpn.vpn_type}")
        return

    if vpn.status == VPNStatus.NO_EXIT_NODE:
        print("⚠  Tailscale is running but NO exit node is active.")
        print("   Connect to an exit node first:")
        print("     tailscale set --exit-node=<node>")
        print("   Installing lockdown rules in the meantime.")
        rules = _build_lockdown_rules("tailscale")
        apply_rules(rules)
        STATE_FILE.write_text("lockdown:tailscale")
        return

    if vpn.status == VPNStatus.NO_VPN:
        print("⚠  No active VPN detected.")
        print("   Start your VPN, or specify the peer IP manually:")
        print("     sudo killswitch enable --ip <vpn-server-ip>")
        print("   Installing lockdown rules in the meantime.")
        rules = _build_lockdown_rules()
        apply_rules(rules)
        STATE_FILE.write_text("lockdown:unknown")
        return

    # VPN is active
    print(f"✓  VPN detected: {vpn.vpn_type}")
    print(f"   Tunnel interface: {vpn.tunnel_interface}")
    if vpn.vpn_peer_ip:
        print(f"   VPN peer (real IP): {vpn.vpn_peer_ip}")
    else:
        print("   VPN peer: not detected (using port-based fallback)")
    if vpn.tailscale_ip:
        print(f"   Tailscale IP: {vpn.tailscale_ip}")
    if vpn.exit_node_ip:
        print(f"   Exit node: {vpn.exit_node_ip}")
    if vpn.derp_ips:
        print(f"   DERP/control IPs pinned: {len(vpn.derp_ips)} addresses")

    rules = _build_pf_rules(vpn)
    if apply_rules(rules):
        STATE_FILE.write_text(f"active:{vpn.vpn_type}")
        print(f"✓  Kill switch ENABLED. All traffic must go through {vpn.vpn_type}.")
    else:
        print("✗  Failed to apply rules. Check /tmp/killswitch.log")


def cmd_disable():
    require_root()
    restore_system_rules()
    print("✓  Kill switch DISABLED. Normal networking restored.")


def cmd_status():
    vpn = detect_vpn()

    ks_state = STATE_FILE.read_text().strip() if STATE_FILE.exists() else "inactive"

    pf_enabled = False
    info = run(["pfctl", "-s", "info"], check=False)
    if info.returncode == 0:
        pf_enabled = "Status: Enabled" in info.stdout

    rules_result = run(["pfctl", "-s", "rules"], check=False)
    rules_text = rules_result.stdout or ""

    our_rules = "block drop all" in rules_text and PF_RULES_PATH.exists()

    print("─── VPN Kill Switch Status ───")
    print()

    if pf_enabled and our_rules:
        print(f"  Kill switch:   ✓ ACTIVE ({ks_state})")
    elif pf_enabled:
        print(f"  Kill switch:   INACTIVE (pf enabled with system rules)")
    else:
        print(f"  Kill switch:   INACTIVE (pf disabled)")

    print(f"  VPN status:    {vpn.status.value} ({vpn.vpn_type})")
    if vpn.tunnel_interface:
        print(f"  Tunnel:        {vpn.tunnel_interface}")
    if vpn.vpn_peer_ip:
        print(f"  VPN peer:      {vpn.vpn_peer_ip}")
    if vpn.tailscale_ip:
        print(f"  Tailscale IP:  {vpn.tailscale_ip}")
    if vpn.exit_node_ip:
        print(f"  Exit node:     {vpn.exit_node_ip}")

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
    vpn = detect_vpn()

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

    # 3. VPN detection
    print()
    print(f"3. VPN: {vpn.status.value} ({vpn.vpn_type})")
    if vpn.tunnel_interface:
        print(f"   Tunnel:    {vpn.tunnel_interface}")
    if vpn.vpn_peer_ip:
        print(f"   VPN peer:  {vpn.vpn_peer_ip}")
    if vpn.exit_node_ip:
        print(f"   Exit node: {vpn.exit_node_ip}")

    # 4. Leak test
    print()
    print("4. Connectivity test:")
    if vpn.status == VPNStatus.ACTIVE:
        print("   VPN is ACTIVE — traffic should flow through tunnel.")
        result = run(["curl", "-s", "--max-time", "5", "ifconfig.me"], check=False)
        if result.returncode == 0 and result.stdout.strip():
            print(f"   Public IP: {result.stdout.strip()}")
            print("   (Should be your VPN's IP, not your real IP)")
        else:
            print("   Could not reach ifconfig.me")
    else:
        print("   VPN is NOT active — testing if traffic is blocked...")
        result = run(["curl", "-s", "--max-time", "5", "ifconfig.me"], check=False)
        if result.returncode == 0 and result.stdout.strip():
            print(f"   ⚠  LEAK! Real IP exposed: {result.stdout.strip()}")
        else:
            print("   ✓  Traffic blocked — no internet access (good!)")

    print()


def cmd_monitor(manual_ip: str | None = None):
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
        vpn = detect_vpn(manual_ip)

        if vpn.status == VPNStatus.ACTIVE and last_state != "active":
            log.info(f"VPN active ({vpn.vpn_type}, peer={vpn.vpn_peer_ip}). Applying rules.")
            rules = _build_pf_rules(vpn)
            apply_rules(rules)
            STATE_FILE.write_text(f"active:{vpn.vpn_type}")
            last_state = "active"
            print(f"  ✓ VPN UP ({vpn.vpn_type}) — traffic flowing through tunnel")

        elif vpn.status != VPNStatus.ACTIVE and last_state != "lockdown":
            log.warning(f"VPN: {vpn.status.value}. LOCKDOWN activated!")
            rules = _build_lockdown_rules(vpn.vpn_type)
            apply_rules(rules)
            STATE_FILE.write_text(f"lockdown:{vpn.vpn_type}")
            last_state = "lockdown"
            print(f"  ⚠ LOCKDOWN — VPN is {vpn.status.value}, blocking traffic")

        time.sleep(MONITOR_INTERVAL)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

USAGE = """\
VPN Kill Switch for macOS

Usage: sudo killswitch <command> [options]

Commands:
  enable              Activate the kill switch (auto-detect VPN)
  enable --ip 1.2.3.4 Activate with manual VPN peer IP
  disable             Restore normal networking
  status              Show current state
  monitor             Daemon mode — auto-lockdown on VPN drop
  test                Diagnostic and leak test

Supported VPNs: Tailscale, WireGuard, OpenVPN, macOS Network Extension VPNs
"""


def main():
    if len(sys.argv) < 2:
        print(USAGE)
        sys.exit(1)

    command = sys.argv[1].lower()

    if command in ("-h", "--help", "help"):
        print(USAGE)
        sys.exit(0)

    # Parse --ip flag
    manual_ip = None
    if "--ip" in sys.argv:
        ip_idx = sys.argv.index("--ip")
        if ip_idx + 1 < len(sys.argv):
            manual_ip = sys.argv[ip_idx + 1]
        else:
            print("Error: --ip requires an IP address argument")
            sys.exit(1)

    if command == "enable":
        cmd_enable(manual_ip)
    elif command == "disable":
        cmd_disable()
    elif command == "status":
        cmd_status()
    elif command == "monitor":
        cmd_monitor(manual_ip)
    elif command == "test":
        cmd_test()
    else:
        print(f"Unknown command: {command}")
        print(USAGE)
        sys.exit(1)


if __name__ == "__main__":
    main()