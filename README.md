# 🖥️ VGT SSH Dashboard — Terminal Intelligence HUD

[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Version](https://img.shields.io/badge/Version-3.0_APEX-brightgreen?style=for-the-badge)](#)
[![Target](https://img.shields.io/badge/Target-Linux-FCC624?style=for-the-badge&logo=linux)](#)
[![Language](https://img.shields.io/badge/Language-Go-00ADD8?style=for-the-badge&logo=go)](#)
[![Architecture](https://img.shields.io/badge/Architecture-Concurrent_Goroutines-00ADD8?style=for-the-badge)](#)
[![VGT](https://img.shields.io/badge/VGT-VisionGaia_Technology-red?style=for-the-badge)](https://visiongaiatechnology.de)

> *"Know your server. The moment you log in."*
> *MIT License — Use freely, modify freely.*

---

## ⚠️ DISCLAIMER: EXPERIMENTAL R&D PROJECT

This project is a **Proof of Concept (PoC)** and part of ongoing research and development at
VisionGaia Technology. It is **not** a certified or production-ready product.

**Use at your own risk.** The software may contain security vulnerabilities, bugs, or
unexpected behavior. It may break your environment if misconfigured or used improperly.

**Do not deploy in critical production environments** unless you have thoroughly audited
the code and understand the implications. For enterprise-grade, verified protection,
we recommend established and officially certified solutions.

Found a vulnerability or have an improvement? **Open an issue or contact us.**

---

## 🔍 What is VGT SSH Dashboard?

A **compiled Go binary** that renders a full **Tactical Intelligence HUD directly in your terminal on every SSH login** — concurrent data extraction, kernel-level syscalls, zero external dependencies beyond the Go standard library.

```
Old Bash MOTD:                      VGT SSH Dashboard Go Edition:
→ Sequential execution              → Concurrent goroutines (3 parallel engines)
→ Subshell overhead                 → Direct syscalls (Sysinfo, Statfs, Uname)
→ External tool dependency          → Pure Go — no bash, awk, grep required
→ No input sanitization             → CWE-150 hardened output sanitization
→ PATH hijacking risk               → Absolute binary paths (CWE-426)
→ No timeout enforcement            → 850ms global context deadline
```

---

## 💎 What it shows

```
▊  ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
▊    VISIONGAIA TECHNOLOGY  //  OMEGA PROTOCOL
▊    NODE: HOSTNAME  AUTH: ROOT  SYS: Ubuntu 22.04 LTS
▊  ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄

▊  TACTICAL INTEL  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▊   IDS Status : 247 attackers blocked (fail2ban)
▊     ▶ DROP  185.220.101.47 via sshd [03:12]
▊     ▶ DROP  94.102.49.193  via sshd [07:44]
▊   Last Auth :
▊     ▶ GRANT root from 1.2.3.4  -> still logged in
▊     ▶ GRANT deploy from 10.0.0.5 -> Wed Apr 9

▊  SYSTEM MATRIX  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▊   CPU Load   : 0.12, 0.08, 0.05 [4 Cores]  Up: 12d 4h 22m
▊   RAM Target : [████████████············] 3.2G / 8.0G
▊   Disk Mount : [████████················] 42.0G / 220.0G

▊  EDGE NETWORK  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▊   Routing IPs: L: 192.168.1.10  P: 1.2.3.4
▊   Daemons    : [●] fail2ban  [●] nginx  [●] mysql
▊  ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
```

---

## ⚙️ Architecture

```
main()
  │
  ├── getSystemState()   goroutine → syscall.Sysinfo, /proc/meminfo, syscall.Statfs
  ├── getNetworkState()  goroutine → UDP dial (Local IP), DNS TXT whoami.cloudflare (Public IP)
  └── getSecurityState() goroutine → parseFail2BanLog(), exec /usr/bin/last

All three run concurrently with an 850ms global context deadline.
Timeout = graceful render with available data, no hang.
```

| Component | Method |
|---|---|
| **Uptime / Load** | `syscall.Sysinfo` — direct kernel struct |
| **Kernel / OS** | `syscall.Uname` + `/etc/os-release` |
| **Memory** | `/proc/meminfo` — line-by-line scanner |
| **Disk** | `syscall.Statfs("/")` |
| **Local IP** | UDP dial to `1.1.1.1:80` — reads local addr |
| **Public IP** | DNS TXT lookup `whoami.cloudflare` — no HTTP call |
| **fail2ban** | Last 64KB of `/var/log/fail2ban.log` — bounded read |
| **Services** | `/bin/systemctl is-active --quiet <name>` |
| **Logins** | `/usr/bin/last -a -w -n 10` |

---

## 🔒 Security Design

| Hardening | Detail |
|---|---|
| **CWE-150 — Terminal Injection** | `sanitizeStr()` and `sanitizeIP()` applied to all external data before output |
| **CWE-426 — PATH Hijacking** | Absolute paths hardcoded: `/bin/systemctl`, `/usr/bin/last` |
| **Context Deadline** | 850ms global timeout — no infinite hang possible |
| **Bounded I/O** | fail2ban log: last 64KB only — no full-file read on large logs |
| **No `clear`** | Scrollback buffer preserved — admin history never wiped |
| **Regex pre-compiled** | `rxFail2Ban` and `rxLast` compiled once at startup — O(1) per line |

---

## 🚀 Installation

### Requirements

```bash
# Install Go
apt install golang-go
```

### Step 1 — Remove old Bash version (if installed)

```bash
sudo rm /etc/update-motd.d/99-vgt-dashboard
```

### Step 2 — Clone and build

```bash
git clone https://github.com/visiongaiatechnology/sshdashboard
cd sshdashboard

# Build optimized binary (stripped symbols, minimal size)
go build -ldflags="-s -w" -o vgt-hud sshdashboard.go
```

### Step 3 — Install binary

```bash
sudo mv vgt-hud /usr/local/bin/vgt-hud
sudo chown root:root /usr/local/bin/vgt-hud
sudo chmod 755 /usr/local/bin/vgt-hud
```

### Step 4 — Register as MOTD

```bash
# Create MOTD wrapper
echo '#!/bin/bash' | sudo tee /etc/update-motd.d/99-vgt-dashboard
echo '/usr/local/bin/vgt-hud' | sudo tee -a /etc/update-motd.d/99-vgt-dashboard
sudo chmod +x /etc/update-motd.d/99-vgt-dashboard

# Disable default Ubuntu MOTD scripts
sudo chmod -x /etc/update-motd.d/*
sudo chmod +x /etc/update-motd.d/99-vgt-dashboard
```

### Step 5 — Verify

```bash
sudo run-parts /etc/update-motd.d/
```

Or open a new SSH session — the HUD appears immediately.

---

## 🔧 Customization

Open `sshdashboard.go` and edit the branding section:

```go
// Header — replace with your own name/label:
printRail(fmt.Sprintf("  YOURNAME  //  YOUR ENGINE"))

// Footer — replace the credit line:
// Find the footer printRail and update accordingly
```

**Colors** — all ANSI 256 constants at the top of the file:

```go
cRail  = "\033[38;5;39m"   // Cyan rail — left border glyph
cBrand = "\033[38;5;81m"   // Brand color — header
cOk    = "\033[38;5;113m"  // Green — active services
cWarn  = "\033[38;5;220m"  // Yellow — warnings
cCrit  = "\033[38;5;196m"  // Red — critical / bans
cMag   = "\033[38;5;170m"  // Magenta — IPs / highlights
```

After any change, rebuild:

```bash
go build -ldflags="-s -w" -o vgt-hud sshdashboard.go
sudo mv vgt-hud /usr/local/bin/vgt-hud
```

---

## ⚙️ Requirements & Compatibility

| Requirement | Detail |
|---|---|
| **OS** | Linux (Ubuntu 22.04+ / Debian 11+ recommended) |
| **Go** | 1.21+ (`apt install golang-go`) |
| **Build tag** | `//go:build linux` — Linux only |
| **Root access** | Required for fail2ban log read and MOTD installation |
| **Network** | Optional — DNS lookup has 850ms hard deadline |

---

## 💰 Support the Project

[![Donate via PayPal](https://img.shields.io/badge/Donate-PayPal-00457C?style=for-the-badge&logo=paypal)](https://www.paypal.com/paypalme/dergoldenelotus)

| Method | Address |
|---|---|
| **PayPal** | [paypal.me/dergoldenelotus](https://www.paypal.com/paypalme/dergoldenelotus) |
| **Bitcoin** | `bc1q3ue5gq822tddmkdrek79adlkm36fatat3lz0dm` |
| **ETH** | `0xD37DEfb09e07bD775EaaE9ccDaFE3a5b2348Fe85` |
| **USDT (ERC-20)** | `0xD37DEfb09e07bD775EaaE9ccDaFE3a5b2348Fe85` |

---

## 🔗 VGT Ecosystem

| Tool | Type | Purpose |
|---|---|---|
| 🖥️ **VGT SSH Dashboard** | **Terminal HUD** | System intelligence on every SSH login — you are here |
| ⚔️ **[VGT Auto-Punisher](https://github.com/visiongaiatechnology/vgt-auto-punisher)** | **IDS** | L4+L7 Hybrid IDS — attackers terminated before they knock |
| 🌐 **[VGT Global Threat Sync](https://github.com/visiongaiatechnology/vgt-global-threat-sync)** | **Preventive** | Daily threat feed — block known attackers before they arrive |
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

*VGT SSH Dashboard V3 APEX — Terminal Intelligence HUD // sshdashboard.go // Go // MIT License*
