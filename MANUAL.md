# WifiBear TUI Manual

This document covers the interactive terminal interface, its views, keyboard controls, and configuration options.

## Starting the TUI

```bash
sudo ./wifibear                       # auto-detect interface
sudo ./wifibear -i wlan0              # specify interface
sudo ./wifibear -i wlan0 -v 2         # verbose mode
```

WifiBear launches a full-screen terminal interface with three main views: Scan, Attack, and Results.

---

## Views

### Scan View

The default view. Displays discovered WiFi networks in a live-updating table.

```
┌─ WifiBear                                    wlan0 │ Ch: 6 │ Targets: 5 │ 45s ─┐
│                                                                                  │
│  #    ESSID                  BSSID               CH  ENC    PWR  SIG  WPS  CLI   │
│  ─    ─────                  ─────               ──  ───    ───  ───  ───  ───   │
│  1    HomeNetwork            AA:BB:CC:DD:EE:01    6  WPA2   -45  ████ Yes  3     │
│  2    CoffeeShop_5G          AA:BB:CC:DD:EE:02   36  WPA2   -52  ███░ No   1     │
│  3    OldRouter              AA:BB:CC:DD:EE:03   11  WEP    -61  ██░░ No   0     │
│  4    <hidden>               AA:BB:CC:DD:EE:04    1  WPA2   -70  █░░░ Yes  2     │
│  5    OpenWiFi               AA:BB:CC:DD:EE:05    6  Open   -73  █░░░ No   5     │
│                                                                                  │
├──────────────────────────────────────────────────────────────────────────────────┤
│  [Enter] Attack  [a] Attack all  [r] Results  [?] Help  [q] Quit                │
└──────────────────────────────────────────────────────────────────────────────────┘
```

**Columns:**

| Column | Description |
|--------|-------------|
| # | Target index |
| ESSID | Network name (`<hidden>` if broadcast SSID is empty) |
| BSSID | Access point MAC address |
| CH | WiFi channel |
| ENC | Encryption: WPA2 (green), WPA (yellow), WEP (red), Open (gray) |
| PWR | Signal strength in dBm (less negative = stronger) |
| SIG | Visual signal bar (4 levels based on dBm) |
| WPS | Whether WPS is enabled (green Yes / No) |
| CLI | Number of associated clients |

**Signal bar levels:**

| dBm Range | Bars | Quality |
|-----------|------|---------|
| -50 or better | `████` | Excellent |
| -51 to -60 | `███░` | Good |
| -61 to -70 | `██░░` | Fair |
| -71 to -80 | `█░░░` | Weak |
| Below -80 | `░░░░` | Very weak |

Targets are sorted by signal strength (strongest first). The table updates every second as new beacons are received.

### Attack View

Shown when an attack is in progress. Displays the target details, attack chain progress, and live statistics.

```
┌─ WifiBear                          Attacking: HomeNetwork (WPA2) ───────────────┐
│                                                                                  │
│  Target:  HomeNetwork (AA:BB:CC:DD:EE:01) Ch 6  -45dBm  WPA2                   │
│  Clients: 3 connected                                                            │
│                                                                                  │
│  Attack Chain:                                                                   │
│  [-] PMKID Capture .......... Failed: AP not vulnerable (8s)                     │
│  [>] WPA Handshake Capture .. Deauthing clients                                  │
│  [ ] Dictionary Crack ....... Waiting                                            │
│                                                                                  │
├──────────────────────────────────────────────────────────────────────────────────┤
│  [s] Skip  [Esc] Back  [q] Quit                                                 │
└──────────────────────────────────────────────────────────────────────────────────┘
```

**Status icons:**

| Icon | Meaning |
|------|---------|
| `[ ]` | Waiting (not yet started) |
| `[>]` | In progress (blue) |
| `[+]` | Completed successfully (green) |
| `[-]` | Failed (red) |

### Results View

Shows all previously cracked networks from the results file.

```
┌─ WifiBear ──────────────────────────────────────────────────────────────────────┐
│                                                                                  │
│  Cracked Networks                                                                │
│                                                                                  │
│  ESSID                  BSSID               ENC    KEY                  ATTACK   │
│  HomeNetwork            AA:BB:CC:DD:EE:01   WPA2   mysecretpass123      WPA HS   │
│  CoffeeShop             AA:BB:CC:DD:EE:02   WPA2   coffee2024           PMKID    │
│                                                                                  │
├──────────────────────────────────────────────────────────────────────────────────┤
│  [Esc] Back                                                                      │
└──────────────────────────────────────────────────────────────────────────────────┘
```

### Help View

Accessed with `?`. Shows all keyboard shortcuts.

---

## Keyboard Shortcuts

### Global (all views)

| Key | Action |
|-----|--------|
| `q` | Quit with safe cleanup (restores interface to managed mode) |
| `Ctrl+C` | Quit with safe cleanup |
| `?` | Toggle help overlay |
| `r` | Switch to results view |
| `Esc` | Go back to scan view |

### Scan View

| Key | Action |
|-----|--------|
| `j` / `Down` | Move cursor down |
| `k` / `Up` | Move cursor up |
| `Space` | Toggle target selection |
| `Enter` | Attack the target under the cursor |
| `a` | Attack all visible targets sequentially |

### Attack View

| Key | Action |
|-----|--------|
| `s` | Skip current attack, return to scan view |
| `Esc` | Return to scan view |

---

## Attack Modes

### Automatic (default)

Select a target and press `Enter`. WifiBear runs the appropriate attack chain based on the encryption type:

**WPA/WPA2 targets:**
1. PMKID capture (30s, skipped if hcxdumptool unavailable)
2. 4-way handshake capture with deauthentication
3. Dictionary crack against captured handshake

**WEP targets** (requires aircrack-ng):
1. ARP replay
2. Fragmentation / ChopChop
3. Key recovery

**Open networks:**
No attack needed — no encryption.

### Pillage Mode

```bash
sudo ./wifibear --pillage
```

Attacks every discovered target automatically, one after another. No user interaction required after launch.

### Targeted Mode

```bash
sudo ./wifibear --bssid AA:BB:CC:DD:EE:FF
sudo ./wifibear --essid "TargetNetwork"
```

Scans until the specified target is found, then automatically begins the attack chain.

### Attack-Specific Modes

```bash
sudo ./wifibear --wpa-only          # skip WPS and WEP
sudo ./wifibear --wps-only          # only try WPS attacks
sudo ./wifibear --no-pmkid          # skip PMKID, go straight to handshake
```

---

## Configuration Defaults

All values can be overridden with CLI flags.

| Parameter | Default | Flag |
|-----------|---------|------|
| Scan timeout | 30s | `--scan-timeout` |
| Handshake capture timeout | 8m 20s | `--hs-timeout` |
| Deauth interval | 15s | `--deauth-interval` |
| Deauth frame count | 5 per round | `--deauth-count` |
| PMKID capture timeout | 30s | `--pmkid-timeout` |
| MAC randomization | enabled | `--mac-randomize` |
| Wordlist | /usr/share/wordlists/rockyou.txt | `--wordlist` |
| Results file | ./wifibear-results.json | `--output` |
| Handshake directory | ./handshakes/ | `--hs-dir` |
| Verbosity | 1 | `--verbose` |

---

## Output Files

### Results (JSON)

Cracked networks are persisted to `wifibear-results.json`:

```json
[
  {
    "bssid": "AA:BB:CC:DD:EE:01",
    "essid": "HomeNetwork",
    "key": "mysecretpass123",
    "encryption": "WPA2",
    "attack_type": "WPA Handshake",
    "handshake_file": "./handshakes/hs_HomeNetwork_AA:BB:CC:DD:EE:01.cap",
    "timestamp": "2025-03-15T14:30:00Z"
  }
]
```

Results are deduplicated by BSSID. If the same network is cracked again, the entry is updated.

View stored results at any time:

```bash
./wifibear cracked
```

### Handshake Captures

Captured handshakes are saved as standard pcap files in the handshake directory:

```
./handshakes/
  hs_HomeNetwork_AA:BB:CC:DD:EE:01.cap
  capture_CoffeeShop_20250315-143000.cap
```

These are standard pcap files compatible with aircrack-ng, hashcat, wireshark, and any other tool that reads pcap.

Validate a capture file:

```bash
./wifibear check ./handshakes/capture.cap AA:BB:CC:DD:EE:FF
```

### Session State

WifiBear saves a session file (`.wifibear-session.json`) tracking which targets have been attempted. This enables resuming after interruption.

---

## Verbosity Levels

| Level | Flag | Output |
|-------|------|--------|
| 0 | `-v 0` | Errors only |
| 1 | `-v 1` | Normal operation (default) |
| 2 | `-v 2` | Show tool commands being executed |
| 3 | `-v 3` | Show raw tool output |

---

## Subcommands

These work on any platform (including macOS) and do not require root or a WiFi adapter.

### `wifibear cracked`

Display all previously cracked networks from the results file.

```bash
./wifibear cracked
./wifibear cracked -o /path/to/custom-results.json
```

### `wifibear check <cap-file> <bssid>`

Validate whether a pcap capture file contains a usable WPA handshake.

```bash
./wifibear check ./handshakes/capture.cap AA:BB:CC:DD:EE:FF
```

Uses the native gopacket EAPOL parser. If tshark is installed, it is used as an additional validator.

### `wifibear deps`

Show which external tools are installed and what capabilities they enable.

```bash
./wifibear deps
```

```
 [+] iw               0.9.0      /usr/sbin/iw
 [+] ip               6.1.0      /usr/sbin/ip
 [-] aircrack-ng      --         (optional) -- WEP cracking
 [+] reaver           1.6.6      /usr/bin/reaver
 [-] bully            --         (optional) -- WPS fallback
 [+] hcxdumptool      6.2.7      /usr/bin/hcxdumptool
 [+] hashcat          6.2.6      /usr/bin/hashcat
 [+] tshark           4.0.6      /usr/bin/tshark
 [-] macchanger       --         (optional) -- MAC randomization fallback
```

---

## Recommended WiFi Adapters

WifiBear works with any adapter that supports monitor mode and packet injection on Linux. Popular choices:

- **Alfa AWUS036ACH** — dual-band, rtl8812au driver
- **Alfa AWUS036ACHM** — dual-band, mt7610u driver
- **Alfa AWUS036NHA** — 2.4GHz, ath9k_htc driver (best kernel support)
- **TP-Link TL-WN722N v1** — 2.4GHz, ath9k_htc driver

Check if your adapter supports injection:

```bash
sudo aireplay-ng --test wlan0
```

---

## Troubleshooting

**"no wireless interfaces found"**
Your WiFi adapter is not detected. Check `ip link` and ensure the driver is loaded.

**"set monitor mode: operation not supported"**
Your adapter or driver does not support monitor mode. Use a compatible adapter.

**"open pcap: permission denied"**
Run as root: `sudo ./wifibear`

**Handshake captured but no key found**
The passphrase is not in your wordlist. Try a larger wordlist or use hashcat with GPU acceleration on the saved .cap file.

**PMKID attack skipped**
Install hcxdumptool and hashcat: `sudo apt install hcxtools hashcat`
