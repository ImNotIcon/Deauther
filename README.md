# Deauther
Deauths clients from a target Wi‑Fi AP using aircrack‑ng, with channel tracking that follows AP channel hopping. Designed for authorized testing and lab environments. Works well alongside Evil Twin captive portal workflows (e.g., airgeddon) for reliable deauth.

## Prerequisites
- Linux with a monitor‑capable wireless adapter
- `bash`
- `iw`, `ip` (iproute2), `awk`, `ps`, `setsid`, `pkill`, `grep`, `stdbuf`
- aircrack‑ng suite: `airodump-ng`, `aireplay-ng`
- Root privileges (or equivalent) to enable monitor mode and run aircrack‑ng tools

## Install (run as `deauther` from any directory)
Pick one of these:

### System-wide (recommended)
```bash
chmod +x deauther.sh
sudo install -m 755 deauther.sh /usr/local/bin/deauther
```

### User-only (no sudo for install)
```bash
chmod +x deauther.sh
mkdir -p ~/.local/bin
ln -sf "$(pwd)/deauther.sh" ~/.local/bin/deauther
export PATH="$HOME/.local/bin:$PATH"
```
If `deauther` is still not found, add this line to your shell config (`~/.bashrc` or `~/.zshrc`) and restart your shell:
```bash
export PATH="$HOME/.local/bin:$PATH"
```
Note: running `airodump-ng`/`aireplay-ng` typically still requires `sudo` or elevated privileges, even if the script is installed per-user.

## Uninstall
### System-wide
```bash
sudo rm -f /usr/local/bin/deauther
```

### User-only
```bash
rm -f ~/.local/bin/deauther
```

## Usage
```bash
sudo deauther -bssid AA:BB:CC:DD:EE:FF -i wlan1
sudo deauther -ssid "MyWiFi"
sudo deauther -ssid "MyWiFi" -stopfile "/tmp/stop*now.txt"
```

## Options
```
-bssid     Target AP BSSID (MAC), e.g., AA:BB:CC:DD:EE:FF
-ssid      Target AP SSID (ESSID), e.g., MyWiFi
-i         Monitor-capable interface (optional)
-stopfile  A file path or wildcard (globs supported); if any match exists, the program exits cleanly
-h         Show help
```

## Notes
- The script will attempt to switch the interface to monitor mode if needed.
- Use only on networks you own or have explicit permission to test.
- Many Wi‑Fi cards do not support extended 2.4GHz channels (often 12–14), depending on region and driver.
- If a target channel cannot be set (driver/adapter limitation), the script skips deauth for that round and falls back to channel 11.

## Troubleshooting
- `Interface not found`: Verify the interface name with `ip link` and pass `-i`.
- `Monitor mode verification failed`: Ensure the adapter supports monitor mode and try `sudo`.
- `Missing command`: Install `aircrack-ng` and `iw` from your distro packages.

## Evil Twin / airgeddon Integration
For Evil Twin captive portal workflows (e.g., airgeddon), use `-stopfile` to stop deauth after the portal captures credentials. The deauth adapter must be different from the adapter running AP mode. If the target has both 2.4GHz and 5GHz networks, you typically need two Wi‑Fi adapters to deauth both bands.

Example:
```bash
sudo deauther -bssid AA:BB:CC:DD:EE:FF -i wlan1 -stopfile /root/evil_twin_captive_portal_password-*
```

## Security and Safety
- Running this will disrupt wireless connectivity for the target AP and its clients.
- Ensure you have explicit permission before use.

## Legal
This tool is intended for authorized security testing and education. You are responsible for complying with local laws and regulations.

## License
MIT License. See `LICENSE`.

## Contributing
See `CONTRIBUTING.md` for guidelines. Bug reports and small fixes are welcome.
