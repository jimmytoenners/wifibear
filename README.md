# WifiBear

Fast, single-binary WiFi security auditing tool written in Go.

WifiBear scans for wireless networks, captures WPA handshakes, and cracks passwords — all from one 6 MB executable with **zero third-party tool dependencies** for core functionality. No Python, no aircrack-ng, no pip install.

```
__      ___  __ _ ___
\ \    / (_)/ _(_) _ ) ___ __ _ _ _
 \ \/\/ /| |  _| | _ \/ -_) _` | '_|
  \_/\_/ |_|_| |_|___/\___\__,_|_|
```

## Features

| Feature | Implementation | External Tool Needed? |
|---------|---------------|----------------------|
| Network scanning | Native (gopacket 802.11) | No |
| Monitor mode | Native (`ip`/`iw`) | No |
| Channel hopping | Native | No |
| Deauthentication | Native frame injection | No |
| WPA handshake capture | Native pcap writer | No |
| WPA dictionary cracking | Native PBKDF2 (all CPU cores) | No |
| Handshake validation | Native EAPOL parser | No |
| MAC randomization | Native (`ip link`) | No |
| PMKID capture | hcxdumptool | Yes (optional) |
| PMKID cracking | hashcat | Yes (optional) |
| WPS Pixie-Dust | reaver or bully | Yes (optional) |
| WPS PIN brute-force | reaver or bully | Yes (optional) |
| WEP attacks | aircrack-ng suite | Yes (optional) |
| GPU-accelerated cracking | hashcat | Yes (optional) |

## Quick Start

```bash
# On Kali Linux / Parrot OS / any Linux with a monitor-mode WiFi adapter:
sudo ./wifibear

# Target a specific network:
sudo ./wifibear --bssid AA:BB:CC:DD:EE:FF

# Attack everything automatically:
sudo ./wifibear --pillage --wordlist /usr/share/wordlists/rockyou.txt

# View previously cracked networks:
./wifibear cracked

# Check what tools are available:
./wifibear deps
```

## Requirements

**Required** (standard on every Linux distro):
- `iw` — wireless interface configuration
- `ip` — network interface management
- `libpcap` — packet capture library (linked at compile time)
- A WiFi adapter that supports **monitor mode** and **packet injection**

**Optional** (enables additional attack vectors):
- `hcxdumptool` + `hcxpcaptool` + `hashcat` — PMKID attacks
- `reaver` or `bully` — WPS attacks
- `aircrack-ng` + `aireplay-ng` — WEP attacks
- `tshark` — additional handshake validation
- `macchanger` — MAC randomization fallback

## Building from Source

```bash
git clone https://github.com/wifibear/wifibear.git
cd wifibear
make build
sudo ./wifibear
```

**Build requirements**: Go 1.21+, libpcap-dev

```bash
# Debian/Ubuntu/Kali:
sudo apt install golang libpcap-dev

# Build for current platform:
make build

# Install system-wide:
sudo make install
```

## Platform Support

| Platform | WiFi Attacks | Utility Commands |
|----------|-------------|-----------------|
| Linux (Kali, Parrot, Ubuntu) | Full support | Full support |
| macOS | Not supported | `cracked`, `check`, `deps` work |
| Windows | Not supported | Not supported |

WiFi packet injection requires Linux with a compatible wireless chipset. On macOS, subcommands like `wifibear cracked` and `wifibear deps` work for managing results and checking tools.

---

## Architecture

### How It Works

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  TUI         │────▶│  Attack      │────▶│  Results     │
│  (bubbletea) │     │  Orchestrator│     │  Store       │
└──────┬───────┘     └──────┬───────┘     └──────────────┘
       │                    │
       ▼                    ▼
┌──────────────┐     ┌──────────────┐
│  Scanner     │     │  Injector    │
│  (gopacket)  │     │  (gopacket)  │
└──────┬───────┘     └──────┬───────┘
       │                    │
       ▼                    ▼
┌─────────────────────────────────────┐
│  Monitor-mode WiFi adapter          │
│  (via iw/ip + libpcap)             │
└─────────────────────────────────────┘
```

1. **Interface Manager** enables monitor mode using standard `ip`/`iw` commands
2. **Scanner** opens a pcap handle and passively parses 802.11 beacons, probes, and data frames
3. **Channel Hopper** cycles through WiFi channels in a background goroutine
4. **TUI** renders discovered targets in a live-updating table
5. **Attack Orchestrator** sequences attacks by priority: PMKID → WPA Handshake → WEP
6. **Injector** constructs and transmits raw deauth frames via `pcap.WritePacketData()`
7. **Capture Writer** records packets to a pcap file while monitoring for EAPOL handshakes in real time
8. **Native Cracker** runs parallel PBKDF2-SHA1 across all CPU cores to test passphrases

### Project Structure

```
wifibear/
├── main.go                          Entry point
├── cmd/
│   └── root.go                      CLI commands, flags, orchestration
│
├── internal/
│   ├── config/config.go             All configurable parameters
│   │
│   ├── iface/
│   │   ├── manager.go               Interface selection, monitor mode, MAC
│   │   ├── platform_linux.go         Linux: ip/iw monitor mode, /sys/class/net
│   │   ├── platform_darwin.go        macOS: networksetup detection, graceful errors
│   │   └── channel.go               Channel hopping goroutine
│   │
│   ├── scan/
│   │   ├── scanner.go               Passive 802.11 scanner (gopacket)
│   │   ├── capture.go               Targeted pcap writer with live EAPOL tracking
│   │   ├── parser.go                Airodump CSV parser, target filtering
│   │   └── target.go                Thread-safe target database
│   │
│   ├── attack/
│   │   ├── attack.go                Attack interface, orchestrator, sequencing
│   │   ├── inject.go                Raw 802.11 frame construction + pcap injection
│   │   ├── deauth.go                Deauthentication via native injection
│   │   ├── wpa.go                   WPA handshake capture + crack orchestration
│   │   ├── crack.go                 Native parallel WPA dictionary cracker
│   │   └── pmkid.go                 PMKID capture + crack (external tools)
│   │
│   ├── handshake/
│   │   ├── capture.go               EAPOL 4-way handshake extraction from pcap
│   │   └── validate.go              Multi-backend handshake validation
│   │
│   ├── tools/
│   │   ├── tool.go                  Dependency checker framework
│   │   ├── deps_linux.go            Linux required tools (iw, ip)
│   │   ├── deps_darwin.go           macOS (no required tools)
│   │   ├── process.go               Subprocess lifecycle with process groups
│   │   ├── hashcat.go               hashcat + hcxdumptool + hcxpcaptool
│   │   ├── reaver.go                WPS via reaver
│   │   ├── bully.go                 WPS via bully
│   │   ├── tshark.go                Handshake validation via tshark
│   │   ├── macchanger.go            MAC randomization fallback
│   │   ├── aircrack.go              WEP/WPA cracking (legacy)
│   │   ├── aireplay.go              WEP replay attacks (legacy)
│   │   ├── airmon.go                Monitor mode (legacy, unused)
│   │   └── airodump.go              Scanning (legacy, unused)
│   │
│   ├── result/
│   │   ├── result.go                CrackResult data types
│   │   └── store.go                 JSON persistence with deduplication
│   │
│   └── session/session.go           Session state for resume capability
│
├── pkg/wifi/
│   ├── types.go                     EncryptionType, CipherType, Target, Client
│   ├── eapol.go                     EAPOL key frame parser, handshake state machine
│   └── crypto.go                    PBKDF2-SHA1, PMK/PTK derivation, MIC verification
│
└── ui/
    ├── app.go                       Bubble Tea model, views, keyboard handling
    └── styles.go                    Lipgloss styles, signal bars, encryption colors
```

### Attack Chain

When you select a WPA/WPA2 target, WifiBear runs attacks in priority order:

```
1. PMKID Capture (if hcxdumptool available)
   └─ Fast, no client needed, 30s timeout
   └─ Crack with hashcat if captured

2. WPA 4-Way Handshake Capture (native)
   └─ Open pcap capture on target channel
   └─ Send deauth frames every 15s to force reconnections
   └─ Monitor EAPOL frames in real time
   └─ Stop when M1+M2 captured (complete handshake)

3. Dictionary Crack (native)
   └─ PBKDF2-SHA1 with 4096 iterations per passphrase
   └─ Parallel across all CPU cores via goroutines
   └─ ~200-400 keys/sec per core (comparable to aircrack-ng)
```

### Native 802.11 Injection

WifiBear constructs deauthentication frames using gopacket's layer serialization, the same approach used by [bettercap](https://github.com/bettercap/bettercap):

```
RadioTap Header → Dot11 (addr1/addr2/addr3, type=Deauth) → Dot11MgmtDeauthentication (reason)
```

Frames are injected directly via `pcap.Handle.WritePacketData()`, which calls `pcap_sendpacket()` in libpcap. This works on any monitor-mode interface that supports injection — it's a kernel-level capability, not an aircrack-ng feature.

### Passive Scanning

The scanner opens a pcap handle on the monitor interface and parses raw 802.11 frames:

- **Beacons** → ESSID, BSSID, channel, encryption type, WPS status
- **Probe Responses** → hidden network ESSID recovery
- **Data frames** → client discovery, traffic counting
- **RSN Information Elements** → WPA2/WPA3/SAE cipher detection
- **Vendor IEs** → WPA v1, WPS detection

All parsing happens in Go — no external scanner process.

### WPA Cracking Internals

The native cracker in `pkg/wifi/crypto.go` implements the full WPA key derivation:

1. **PMK** = PBKDF2-SHA1(passphrase, SSID, 4096 iterations, 32 bytes)
2. **PTK** = PRF-512(PMK, "Pairwise key expansion", min(AA,SPA) || max(AA,SPA) || min(ANonce,SNonce) || max(ANonce,SNonce))
3. **KCK** = PTK[0:16]
4. **MIC** = HMAC-SHA1(KCK, EAPOL frame with zeroed MIC field)
5. Compare computed MIC against captured MIC from M2

The cracker distributes passphrases across `runtime.NumCPU()` goroutines. Each worker independently computes the full PMK→PTK→MIC chain and checks against the captured handshake.

### Concurrency Model

```
Goroutine: Channel Hopper     ─── sets channel every 250ms
Goroutine: Packet Capture      ─── reads frames from pcap handle
Goroutine: TUI Renderer        ─── updates display every 1s
Goroutine: Attack Runner       ─── executes attack chain
Goroutine: Signal Handler      ─── catches SIGINT/SIGTERM for cleanup
Goroutine: Crack Worker × N    ─── parallel PBKDF2 (one per CPU core)
```

All communication uses Go channels. The target database uses `sync.RWMutex` for concurrent read/write access between the scanner and TUI goroutines.

---

## CLI Reference

```
Usage:
  wifibear [flags]
  wifibear [command]

Commands:
  cracked     Show previously cracked networks
  check       Check a capture file for valid handshakes
  deps        Check tool dependencies

Flags:
  -i, --interface string     Wireless interface to use
  -w, --wordlist string      Path to wordlist (default: /usr/share/wordlists/rockyou.txt)
  -v, --verbose int          Verbosity 0-3 (default: 1)
  -o, --output string        Results file (default: ./wifibear-results.json)
      --bssid string         Target specific BSSID
      --essid string         Target specific ESSID
      --scan-timeout duration  Scan duration (default: 30s)
      --pillage              Attack all targets automatically
      --wpa-only             Only WPA attacks
      --wps-only             Only WPS attacks
      --wep-only             Only WEP attacks
      --no-pmkid             Skip PMKID attacks
      --no-wps               Skip WPS attacks
      --hs-timeout duration  Handshake capture timeout (default: 8m20s)
      --deauth-interval duration  Deauth interval (default: 15s)
      --deauth-count int     Deauth frames per round (default: 5)
      --pmkid-timeout duration  PMKID capture timeout (default: 30s)
      --mac-randomize        Randomize MAC address (default: true)
      --hs-dir string        Handshake output directory (default: ./handshakes/)
```

See [MANUAL.md](MANUAL.md) for full TUI documentation.

---

## Legal

WifiBear is intended for authorized security testing and educational purposes only. Only use this tool on networks you own or have explicit written permission to test. Unauthorized access to computer networks is illegal.

## License

Copyright 2025 Jimmy Tønners

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full text.

Third-party dependency licenses are listed in [NOTICE](NOTICE).
