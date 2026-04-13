# 🖥️ VGT SSH Dashboard — Terminal Intelligence HUD

[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Version](https://img.shields.io/badge/Version-2.0_APEX-brightgreen?style=for-the-badge)](#)
[![Target](https://img.shields.io/badge/Target-Ubuntu_%2F_Debian-E95420?style=for-the-badge&logo=ubuntu)](#)
[![Shell](https://img.shields.io/badge/Shell-Bash-black?style=for-the-badge&logo=gnubash)](#)
[![Panels](https://img.shields.io/badge/Panels-aaPanel_%7C_Plesk_%7C_cPanel-blue?style=for-the-badge)](#)
[![VGT](https://img.shields.io/badge/VGT-VisionGaia_Technology-red?style=for-the-badge)](https://visiongaiatechnology.de)

> *"Know your server. The moment you log in."*
> *MIT License — Use freely, modify freely.*

---

> ## ⚠️ EXPERIMENTAL NOTICE
>
> This script is published as **experimental R&D tooling**. It has been tested on Ubuntu/Debian with aaPanel, Plesk and cPanel environments, but behavior on other setups may vary.
>
> **Use at your own risk.** Replacing system MOTD components can affect login behavior. Always test on a non-production system first.

---
## Notice
While the code for VGT SSH Dashboard is an independent development and original work by VisionGaia Technology, we acknowledge that the visual layout and section structure were inspired by the motd project by [EXT IT GmbH](github.com/EXT-IT/motd). We appreciate their contribution to the community's design standards for terminal dashboards. 



## 🔍 What is VGT SSH Dashboard?

A zero-dependency Bash MOTD replacement that renders a full **system intelligence HUD directly in your terminal on every SSH login** — no external tools, no Node.js, no Python. Pure Bash + ANSI.

```
Without VGT SSH Dashboard:          With VGT SSH Dashboard:
→ Blank terminal or Ubuntu MOTD     → Full system HUD on login
→ No security context               → Active sessions, IPs, privileges
→ No resource overview              → RAM/Disk bars, Load, Uptime
→ No threat visibility              → fail2ban bans, recent logins
→ Slow update-motd.d scripts        → Zero-latency kernel extraction
```

---

## 💎 What it shows

```
  ╭────────────────────────────────────────────────────────╮
  │  YOURNAME  • APEX ENGINE HUD                           │
  ╰────────────────────────────────────────────────────────╯

  👤 Logged as:      user@hostname  [sudo]
     Sessions:       2 active (root(1), deploy(1))

  ⚙ OS:             Ubuntu 22.04.3 LTS (kvm)
    Kernel:          5.15.0-91-generic
    Uptime:          up 12 days, 4 hours, 22 minutes
    Load average:    0.12, 0.08, 0.05 [4 cores]

  ⟁ Local IP:       192.168.1.10
    Public IP:       1.2.3.4

  ⚙ Memory:         1.2G used, 6.1G free          / 8.0G
                    ████████████·························

    Disk (/):       42G used, 180G free            / 220G
                    ████████·····························

  ⚙ Services:       [●] fail2ban  [●] aaPanel  [●] Nginx  [●] MySQL
    Updates:        3 package(s) available (1 security)

  ── 🛡 Security Core ──────────────────────────────────────
    fail2ban:       247 IP(s) banned (extracted from logs)
    aaPanel:        running (active node)

  ── 🛡 Recent Threat Bans ─────────────────────────────────
    › 185.220.101.47   sshd         2026-04-09 03:12
    › 94.102.49.193    sshd         2026-04-09 07:44

  ── 👤 Auth Audit Log ─────────────────────────────────────
    › root            pts/0    1.2.3.4    still logged in
    › deploy          pts/1    10.0.0.5   Wed Apr  9 08:01
```

---

## 🆕 V2 APEX — What's new

| Feature | Detail |
|---|---|
| **Multi-Panel Detection** | Auto-detects aaPanel, Plesk and cPanel — no manual config required |
| **Hardened Input Sanitization** | CWE-150 Terminal Escape Injection prevention on all outputs |
| **set -euo pipefail** | Strict error handling — script aborts on unhandled failures |
| **readonly variables** | All constants locked at runtime |
| **Bounded I/O** | fail2ban log read limited to last 10,000 lines — no I/O stall on large logs |
| **POSIX df -P** | Prevents line-break issues on large disk labels |
| **Native /proc reads** | Load and uptime read directly from kernel — no subshell overhead |
| **VGT HUD Style Bars** | `█` fill + `·` empty for better visual contrast |
| **Standalone Server Support** | Graceful fallback if no control panel is detected |

---

## 📡 Data Sources

| Section | Source | Method |
|---|---|---|
| **CPU / Load** | `/proc/loadavg` | Direct kernel read — zero subshell |
| **Uptime** | `/proc/uptime` | Direct kernel read — zero subshell |
| **Memory** | `free -m` | Single invocation |
| **Disk** | `df -hP /` | POSIX mode — no line-break issues |
| **Local IP** | `ip route get 1.1.1.1` | Default route extraction — ignores Docker/virtual bridges |
| **Public IP** | `ifconfig.me` | 500ms hard timeout — shows `Offline` if unreachable |
| **Updates** | `/var/lib/update-notifier/updates-available` | Cache read — no apt invocation |
| **fail2ban** | `/var/log/fail2ban.log` | Last 10,000 lines — bounded I/O |
| **Services** | `systemctl is-active` | No daemon restart triggered |
| **Logins** | `last -a` | Standard auth log |
| **Control Panel** | Directory + systemctl check | Auto-detection: aaPanel, Plesk, cPanel |

---

## 🖥️ Panel Auto-Detection

VGT SSH Dashboard V2 automatically detects your control panel — no configuration needed:

| Panel | Detection method |
|---|---|
| **aaPanel** | `/www/server/panel` directory or `bt` service |
| **Plesk** | `/usr/local/psa` directory or `psa` / `sw-cp-server` service |
| **cPanel** | `/usr/local/cpanel` directory or `cpanel` service |
| **None** | Displays `standalone server (no panel detected)` |

---

## 🚀 Installation

### Step 1 — Download

```bash
git clone https://github.com/visiongaiatechnology/sshdashboard
cd sshdashboard
```

### Step 2 — Install as MOTD

```bash
sudo mv SSHpanel.sh /etc/update-motd.d/99-vgt-dashboard
sudo chown root:root /etc/update-motd.d/99-vgt-dashboard
sudo chmod +x /etc/update-motd.d/99-vgt-dashboard
```

### Step 3 — Disable default Ubuntu MOTD

```bash
sudo chmod -x /etc/update-motd.d/*
sudo chmod +x /etc/update-motd.d/99-vgt-dashboard
```

> This disables the default Ubuntu news/ads/landscape scripts. Your dashboard is now the only thing that runs on login.

### Step 4 — Verify

```bash
sudo run-parts /etc/update-motd.d/
```

Or open a new SSH session — the dashboard appears immediately.

---

## ⚙️ Alternative: profile.d Installation

```bash
sudo nano /etc/profile.d/vgt_motd.sh
# Paste the script content, save

sudo chmod +x /etc/profile.d/vgt_motd.sh
```

> `profile.d` triggers on interactive login shells only. `update-motd.d` is more reliable across SSH client configurations.

---

## 🔧 Customization

### Branding

```bash
# Header — replace with your own name/label:
echo -e "  YOURNAME • YOUR ENGINE HUD"

# Footer — replace the credit line:
echo -e "  Powered by YOURNAME. All inputs tracked."
```

### Colors

All colors are defined as `readonly` ANSI 256 variables at the top of the script:

```bash
c_head="\033[38;5;39m"      # Cyan/Blue — section headers & glyphs
c_green="\033[38;5;113m"    # Status OK — active services
c_red="\033[38;5;196m"      # Critical — Public IP, bans
c_yellow="\033[38;5;220m"   # Warnings — updates, reboot
c_magenta="\033[38;5;170m"  # Highlights — IPs
```

---

## ⚙️ Requirements & Compatibility

| Requirement | Detail |
|---|---|
| **OS** | Ubuntu 22.04+ / Debian 11+ |
| **Shell** | Bash 5.0+ |
| **Root access** | Required for fail2ban log read and MOTD installation |
| **Network** | Optional — `ifconfig.me` has 500ms hard timeout |

---

## 🔒 Security Notes

**Terminal Injection Prevention (CWE-150):**
All external data (IPs, usernames, hostnames) is sanitized through `sanitize_ip()` and `sanitize_str()` before output. Escape sequences in log data cannot affect your terminal.

**fail2ban log access:**
```bash
# Add your user to the adm group for log access without sudo
sudo usermod -aG adm YOUR_USER
```

**Public IP lookup:**
The script calls `ifconfig.me` with a 500ms hard timeout on every login. To disable:
```bash
# Replace this line in the script:
IP_PUBLIC_RAW=$(curl -s --connect-timeout 0.5 --max-time 0.5 https://ifconfig.me/ip 2>/dev/null || echo "Offline")
# With:
IP_PUBLIC_RAW="disabled"
```

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

Pull requests are welcome. Tested configurations and compatibility reports for other distros and panels are especially appreciated.

Licensed under **MIT** — use freely, modify freely.

---

## 🏢 Built by VisionGaia Technology

[![VGT](https://img.shields.io/badge/VGT-VisionGaia_Technology-red?style=for-the-badge)](https://visiongaiatechnology.de)

VisionGaia Technology builds enterprise-grade security infrastructure — engineered to the DIAMANT VGT SUPREME standard.

> *"The first thing you see when you log in should tell you everything. Not a blank screen."*

---

*VGT SSH Dashboard V2 APEX — Terminal Intelligence HUD // SSHpanel.sh // Bash // MIT License*
