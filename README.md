# VPN Kill Switch for macOS

A firewall-based kill switch that ensures all traffic routes exclusively through your VPN. If the VPN connection drops, non-essential traffic is immediately blocked to prevent IP address leaks.

**Supports:** Tailscale, WireGuard, OpenVPN, and macOS Network Extension VPNs.

Features zero dependencies beyond the Python standard library. It utilizes macOS's built-in `pf` (Packet Filter) firewall.

## Features
- **Auto-Detection:** Automatically detects your active VPN tunnel interface and peer IP.
- **Fail-Safe:** Drops internet access if the VPN connection goes down.
- **Multiple VPN Support:** Works seamlessly with Tailscale, WireGuard, OpenVPN, and others.
- **No Third-Party Dependencies:** Uses standard Python libraries and native macOS tools.
- **Daemon Mode:** Continuously monitors the connection to toggle the kill switch dynamically.

## Installation / Packaging

Since this tool only relies on the Python standard library, you do not need `pip` to install dependencies. You can simply make it executable and move it to your system's PATH.

```bash
# Make the script executable
chmod +x vpn_killswitch.py

# Move to a directory in your PATH (e.g., /usr/local/bin/)
sudo cp vpn_killswitch.py /usr/local/bin/killswitch
```

*Alternatively, if you want to bundle it into a standalone binary so that users don't need to invoke it with a Python interpreter manually, you could use PyInstaller:*
```bash
pip install pyinstaller
pyinstaller --onefile vpn_killswitch.py
sudo mv dist/vpn_killswitch /usr/local/bin/killswitch
```

## Usage

*Note: Since this manipulates firewall rules (`pfctl`), it requires root privileges (`sudo`).*

```bash
sudo killswitch enable              # Auto-detect VPN and activate
sudo killswitch enable --ip 1.2.3.4 # Specify VPN peer IP manually
sudo killswitch disable             # Restore normal networking
sudo killswitch status              # Show current state
sudo killswitch monitor             # Daemon: auto-lockdown on VPN drop
sudo killswitch test                # Diagnostic and leak test
```

## How It Works

1. **Detection:** When you run `enable`, the script uses a cascade of methods (`netstat`, `wg show`, `scutil`, Tailscale CLI) to detect your VPN peer's real public IP, and identifying the created `utun` interface.
2. **Rule Generation:** Based on your VPN type, it dynamically generates `pf` (Packet Filter) rules. These rules:
   - Block all outgoing and incoming traffic by default.
   - Allow DHCP and ICMP (for Path MTU discovery).
   - Allow traffic securely to the active VPN peer IP/port.
   - Rout all existing `utun` traffic directly.
3. **Application:** Applies the firewall rules transparently without permanently altering your baseline `/etc/pf.conf`. When `disable` is triggered, it flushes the temporary rules and resets back to system defaults.

## License

See the [LICENSE](LICENSE) file for more information.
