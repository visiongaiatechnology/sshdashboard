# 🖥️ VGT SSH Dashboard — Terminal Intelligence HUD

[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Version](https://img.shields.io/badge/Version-3.1.0--diamond--vgt-brightgreen?style=for-the-badge)](#)
[![Status](https://img.shields.io/badge/Status-DIAMOND_VGT-purple?style=for-the-badge)](#)
[![Target](https://img.shields.io/badge/Target-Linux-FCC624?style=for-the-badge&logo=linux)](#)
[![Go](https://img.shields.io/badge/Go-1.20+-00ADD8?style=for-the-badge&logo=go)](#)
[![Build](https://img.shields.io/badge/Build-go_build_.-00ADD8?style=for-the-badge)](#)
[![Modes](https://img.shields.io/badge/Modes-MOTD_%2B_Live--TUI-blue?style=for-the-badge)](#-dual-mode)
[![VGT](https://img.shields.io/badge/VGT-VisionGaia_Technology-red?style=for-the-badge)](https://visiongaiatechnology.de)

> *"Know your server. The moment you log in."*
> *MIT License — Use freely, modify freely.*

---

## ⚠️ DISCLAIMER: EXPERIMENTAL R&D PROJECT

This project is a **Proof of Concept (PoC)** and part of ongoing research and development at VisionGaia Technology. It is **not** a certified or production-ready product.

**Use at your own risk.** The software may contain security vulnerabilities, bugs, or unexpected behavior.

Found a vulnerability or have an improvement? **Open an issue or contact us.**

---

## SSHDash — Live TUI
<img width="672" height="418" alt="{2E0B2ABD-68DB-4C97-AF87-4BA8091F608A}" src="https://github.com/user-attachments/assets/79aacf95-57d8-4e38-81ec-14db647471ad" />

## SSHDash — MOTD Snapshot
<img width="655" height="382" alt="{3F38A5A4-D39B-4C27-8A05-FDBC778237D5}" src="https://github.com/user-attachments/assets/78bcc3d2-3d68-490d-80cb-4dee5c5c2175" />

---

## 🔍 What is VGT SSH Dashboard?

A **compiled Go binary** that renders a full **Tactical Intelligence HUD directly in your terminal** — either as a hardened MOTD login banner or as a live interactive TUI dashboard with tabs, charts and mouse support.

```
Old Bash MOTD:                        VGT SSH Dashboard 3.1:
→ Sequential execution                → 5 concurrent collectors (goroutines)
→ Subshell overhead                   → Direct syscalls (Sysinfo, Statfs, Uname)
→ External tool dependency            → Pure Go — no bash, awk, grep required
→ No input sanitization               → CWE-150 hardened output sanitization
→ PATH hijacking risk                 → Absolute binary paths (CWE-426)
→ No timeout enforcement              → Bounded collection, atomic state swap
→ MOTD-only                           → MOTD + Live TUI (tabs, mouse, scroll)
→ ANSI 256 colors                     → 24-bit Truecolor + gradients
→ Progress bars                       → Braille waveforms, sparklines, heatmaps
```

---

## ⚡ Dual Mode

| Mode | Trigger | Description |
|---|---|---|
| **MOTD** | `sshdash --motd` or non-TTY | Hardened login banner — static snapshot, exits immediately |
| **Live TUI** | `sshdash` in a real TTY | Interactive dashboard — alternate screen, raw mode, 1s refresh |

The binary detects context automatically. A non-interactive SSH session (e.g. `ssh user@host` piped to a script) always triggers MOTD mode — no raw terminal takeover.

---

## 🏛️ Architecture

```
main()
  ├── --motd | non-TTY
  │     └── collectAllMetrics → RenderMOTD → exit
  │
  └── TTY Live Engine
        ├── ListenInput     (typed events, paste isolation, mouse SGR)
        ├── collectAllMetrics (scratch buffer → wg.Wait() → atomic swap)
        └── RenderTUI       (tabs, mouse, scroll, 1s tick)

Module Tree:
  sshdash/
  ├── main.go
  ├── collectors/
  │   ├── system.go     ← CPU, RAM, Disk, Uptime, Kernel
  │   ├── network.go    ← Local IP, Public IP (cached), Throughput
  │   ├── security.go   ← fail2ban, Sessions, Open Ports
  │   ├── docker.go     ← Docker socket, container list
  │   └── process.go    ← Top RAM processes
  ├── tui/
  │   ├── engine.go     ← Alternate screen, raw termios, double-buffer
  │   ├── events.go     ← Key/mouse event parser
  │   ├── frame.go      ← Render loop, tab dispatch
  │   ├── chrome.go     ← Border, header, footer chrome
  │   ├── tab_system.go ← SYSTEM tab
  │   ├── tab_security.go ← SECURITY tab
  │   ├── tab_docker.go ← DOCKER tab
  │   ├── tab_daemons.go ← DAEMONS tab
  │   └── motd.go       ← MOTD renderer
  ├── types/
  │   └── state.go      ← FullState + Snapshot
  └── utils/
      ├── sanitize.go   ← CWE-150 output hardening
      ├── colors.go     ← 24-bit truecolor + gradients
      ├── graph.go      ← Braille waveform, sparklines, heatmap
      └── layout.go     ← Terminal geometry helpers
```

### Collectors (5 parallel goroutines)

| Collector | Method |
|---|---|
| **Uptime / Load** | `syscall.Sysinfo` — direct kernel struct |
| **Kernel / OS** | `syscall.Uname` + `/etc/os-release` |
| **Memory** | `/proc/meminfo` — line-by-line scanner |
| **Disk** | `syscall.Statfs("/")` |
| **Local IP** | UDP dial to `1.1.1.1:80` — reads local addr |
| **Public IP** | DNS TXT `whoami.cloudflare` — 15-min cache, not shown in MOTD |
| **fail2ban** | Last 64KB of `/var/log/fail2ban.log` — bounded read |
| **Services** | `/bin/systemctl is-active --quiet <name>` |
| **Logins / Sessions** | `/usr/bin/last -a -w -n 10` |
| **Docker** | Docker socket — container list |
| **Processes** | Top RAM consumers |

### Concurrency Model

Old (3.0): shared state + 850ms deadline, graceful partial render.

New (3.1): scratch buffer → `wg.Wait()` → **atomic state swap** — no torn writes, no partial state visible in render.

---

## 🖥️ Live TUI — Tabs & Controls

### Tabs

| Tab | Key | Content |
|---|---|---|
| **SYSTEM** | `1` | CPU Braille waveform + heatmap, RAM/Disk gauges, network throughput graph, uptime |
| **SECURITY** | `2` | fail2ban ban count + event log, active sessions, open ports |
| **DOCKER** | `3` | Docker socket container list, status, image names |
| **DAEMONS** | `4` | Service status dots, daemon health overview |

### Keyboard Controls

| Key | Action |
|---|---|
| `1` `2` `3` `4` | Switch tab |
| `h` `l` or `←` `→` | Previous / next tab |
| `j` `k` or `↑` `↓` | Scroll up / down |
| `r` | Force refresh |
| `q` | Quit — restores terminal |

### Mouse

| Action | Effect |
|---|---|
| Click tab header | Switch to tab |
| Scroll wheel | Scroll current tab content |

---

## 📊 MOTD — What it Shows

The MOTD is intentionally **hardened** — less raw intel visible to every login user:

```
▊  ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
▊    VISIONGAIA TECHNOLOGY  //  OMEGA PROTOCOL
▊    NODE: hostname  SYS: Ubuntu 22.04 LTS
▊  ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄

▊  SYSTEM MATRIX  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▊   CPU Load : 0.12, 0.08, 0.05 [4 Cores]  Up: 12d 4h
▊   RAM      : [████████████············] 3.2G / 8.0G
▊   Disk     : [████████················] 42.0G / 220.0G

▊  SERVICES  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▊   [●] fail2ban  [●] nginx  [●] mysql  [○] redis

▊  SECURITY  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▊   IDS: 247 attackers blocked        IP: 192.168.1.10
▊  ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
```

**Intentionally excluded from MOTD (vs. v3.0):**
- Individual attacker IPs — detail only in Live TUI Security tab
- Last login / auth details — available in Live TUI
- Public IP — 15-min cached, never in static MOTD banner

---

## 📊 v3.0 → v3.1 — What Changed

| Feature | v3.0 APEX | v3.1 Diamond |
|---|---|---|
| **Codebase** | Single file `sshdashboard.go` | Module tree: `collectors/` `tui/` `types/` `utils/` |
| **Binary** | `go build -o vgt-hud sshdashboard.go` | `go build -o sshdash .` |
| **Modes** | MOTD only | MOTD (`--motd`) + Live TUI (TTY auto-detect) |
| **Collectors** | 3 goroutines (System, Network, Security) | 5 (+ Docker, Process) |
| **UI** | Single scroll-print, no raw mode | Alternate screen, raw termios, double-buffer |
| **Colors** | ANSI 256 (`38;5;…`) | 24-bit Truecolor + gradients |
| **Charts** | Progress bars | Braille waveform, sparklines, core heatmap, dual RX/TX |
| **Tabs** | — | SYSTEM / SECURITY / DOCKER / DAEMONS |
| **Input** | None | Typed events, paste isolation, mouse SGR, no AppState race |
| **Concurrency** | Shared state + 850ms deadline | Scratch buffer → `wg.Wait()` → atomic swap |
| **Public IP** | Every run: DNS Cloudflare | 15-min cache; not shown in MOTD |
| **MOTD content** | Bans + IPs + last auth + public IP | Hardened: load/RAM/disk, daemon dots, ban count, local IP |
| **Security model** | Sanitize + absolute paths | + IsRoot check, snapshot isolation, bounded Docker/JSON, tests |
| **Go requirement** | 1.21 (README) | 1.20+ (`go.mod`) |
| **Version string** | `3.0 APEX` | `3.1.0-diamond-vgt` |

---

## 🔒 Security Design

| Hardening | Detail |
|---|---|
| **CWE-150 — Terminal Injection** | `sanitizeStr()` and `sanitizeIP()` on all external data before output |
| **CWE-426 — PATH Hijacking** | Absolute paths hardcoded: `/bin/systemctl`, `/usr/bin/last` |
| **Atomic State Swap** | Scratch buffer + `wg.Wait()` → atomic swap — no torn write visible in render |
| **Snapshot Isolation** | `IsRoot` check; no raw ANSI in state struct |
| **Bounded I/O** | fail2ban log: last 64KB only. Docker/JSON: bounded parse |
| **Public IP Cache** | 15-min in-memory cache — no DNS call per login |
| **MOTD Intel Reduction** | No individual attack IPs, no last-login details, no public IP in banner |
| **Paste Isolation** | Paste events isolated from typed input — no bracket paste injection |
| **No `clear`** | Scrollback buffer preserved — admin history never wiped |
| **Test Suite** | `go test ./...` — collectors, sanitize, layout, atomic swap |

---

## 🚀 Installation

### Requirements

```bash
# Go 1.20+ required
apt install golang-go   # Ubuntu/Debian
# or: https://go.dev/dl/
```

### Step 0 — Remove Old Version (if upgrading from 3.0)

```bash
# Remove old MOTD hook
sudo rm -f /etc/update-motd.d/99-vgt-dashboard

# Remove old binary
sudo rm -f /usr/local/bin/vgt-hud
sudo rm -f /usr/local/bin/sshdash   # if partially installed before

# Verify clean
grep -r 'vgt-hud\|sshdashboard\|99-vgt' /etc/update-motd.d /etc/profile.d 2>/dev/null || echo "clean"
ls -la /usr/local/bin/vgt-hud /usr/local/bin/sshdash 2>/dev/null || echo "binaries gone"
```

### Step 1 — Build

```bash
git clone https://github.com/visiongaiatechnology/sshdashboard
cd sshdashboard

# Run tests first
go test ./...

# Build optimized binary
go build -ldflags="-s -w" -o sshdash .

# Verify
./sshdash --version
./sshdash --motd      # static snapshot, works non-interactively
```

**Cross-compile from Windows/macOS:**
```bash
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o sshdash .
# ARM server: GOARCH=arm64
```

### Step 2 — Install Binary

```bash
sudo install -o root -g root -m 755 sshdash /usr/local/bin/sshdash
```

### Step 3 — Register as MOTD

> **Important:** use `--motd` flag. Without it, the binary attempts to start the Live TUI — which fails in a non-interactive MOTD context.

```bash
sudo tee /etc/update-motd.d/99-vgt-dashboard >/dev/null <<'EOF'
#!/bin/sh
# Non-interactive MOTD snapshot — no raw mode, no mouse
exec /usr/local/bin/sshdash --motd
EOF
sudo chmod 755 /etc/update-motd.d/99-vgt-dashboard
```

**Optional — disable default Ubuntu MOTD scripts:**
```bash
sudo chmod -x /etc/update-motd.d/*
sudo chmod +x /etc/update-motd.d/99-vgt-dashboard
```

**Restore Ubuntu defaults later if needed:**
```bash
sudo chmod +x /etc/update-motd.d/00-header \
              /etc/update-motd.d/10-help-text \
              /etc/update-motd.d/50-motd-news \
              /etc/update-motd.d/90-updates-available 2>/dev/null
```

### Step 4 — Verify

```bash
# Test MOTD output
sudo run-parts /etc/update-motd.d/

# Or open a new SSH session — banner appears immediately
```

### Step 5 — Live TUI (Optional)

The Live TUI runs interactively after login — not as MOTD.

```bash
# Launch from shell after login
sshdash

# Optional alias
echo 'alias hud=sshdash' | sudo tee /etc/profile.d/sshdash-alias.sh
sudo chmod 644 /etc/profile.d/sshdash-alias.sh
```

> **Permissions note:** fail2ban log and some Docker sockets require root or group membership. The MOTD runs as root via `update-motd` (typical). The Live TUI as a regular user shows less security detail — expected behavior.

---

## ✅ Migration Checklist (v3.0 → v3.1)

```
[ ] Old MOTD script 99-vgt-dashboard removed
[ ] Old binary /usr/local/bin/vgt-hud removed
[ ] New module built: go build -ldflags="-s -w" -o sshdash .
[ ] Installed to /usr/local/bin/sshdash
[ ] New MOTD: exec /usr/local/bin/sshdash --motd  (--motd flag required)
[ ] sudo run-parts / verified via new SSH login
[ ] Live TUI manually tested (resize, tabs, q restores terminal)
```

---

## ⚙️ Requirements & Compatibility

| Requirement | Detail |
|---|---|
| **OS** | Linux (Ubuntu 22.04+ / Debian 11+ recommended) |
| **Go** | 1.20+ |
| **Build tag** | `//go:build linux` — Linux only |
| **Root access** | Required for fail2ban log read and MOTD installation |
| **Docker** | Optional — Docker collector skipped if socket unavailable |
| **Network** | Optional — DNS lookup cached 15 min, hard-bounded |

---

## 💰 Support the Project

[![Donate via PayPal](https://img.shields.io/badge/Donate-PayPal-00457C?style=for-the-badge&logo=paypal)](https://www.paypal.com/paypalme/dergoldenelotus)

| Method | Address |
|---|---|
| **PayPal** | [paypal.me/dergoldenelotus](https://www.paypal.com/paypalme/dergoldenelotus) |
| **Bitcoin** | `bc1q3ue5gq822tddmkdrek79adlkm36fatat3lz0dm` |
| **ETH / USDT (ERC-20)** | `0xD37DEfb09e07bD775EaaE9ccDaFE3a5b2348Fe85` |

---

## 🔗 VGT Ecosystem

| Tool | Type | Purpose |
|---|---|---|
| 🖥️ **VGT SSH Dashboard** | **Terminal HUD** | System intelligence on every SSH login — you are here |
| ⚡ **[VGT Auto-Punisher](https://github.com/visiongaiatechnology/vgt-auto-punisher)** | **IDS** | L4+L7 Hybrid IDS — attackers terminated before they knock |
| 🌐 **[VGT Global Threat Sync](https://github.com/visiongaiatechnology/vgt-global-threat-sync)** | **Preventive** | Daily threat feed — block known attackers before arrival |
| ⚔️ **[VGT Sentinel](https://github.com/visiongaiatechnology/sentinelcom)** | **WAF / IDS** | Zero-Trust WordPress Security Suite |
| 🔥 **[VGT Windows Firewall Burner](https://github.com/visiongaiatechnology/vgt-windows-burner)** | **Windows** | 280,000+ APT IPs in native Windows Firewall |

---

## 🤝 Contributing

Pull requests are welcome. Tested configurations and compatibility reports for other distros are especially appreciated.

Licensed under **MIT** — use freely, modify freely.

---

## 🏢 Built by VisionGaia Technology

[![VGT](https://img.shields.io/badge/VGT-VisionGaia_Technology-red?style=for-the-badge)](https://visiongaiatechnology.de)

VisionGaia Technology builds enterprise-grade security infrastructure — engineered to the DIAMANT VGT SUPREME standard.

> *"The first thing you see when you log in should tell you everything. Not a blank screen."*

---

*VGT SSH Dashboard v3.1.0-diamond-vgt — Terminal Intelligence HUD // MOTD + Live TUI // 5 Collectors // Braille Charts // Atomic State Swap // Hardened MOTD // Modular Go // MIT License*
