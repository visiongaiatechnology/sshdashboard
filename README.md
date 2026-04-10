# 🖥️ VGT SSH Dashboard — Terminal Intelligence HUD

[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Status](https://img.shields.io/badge/Status-EXPERIMENTAL-orange?style=for-the-badge)](#)
[![Target](https://img.shields.io/badge/Target-Ubuntu_%2F_Debian-E95420?style=for-the-badge&logo=ubuntu)](#)
[![aaPanel](https://img.shields.io/badge/aaPanel-Enterprise-blue?style=for-the-badge)](#)
[![Shell](https://img.shields.io/badge/Shell-Bash-black?style=for-the-badge&logo=gnubash)](#)
[![VGT](https://img.shields.io/badge/VGT-VisionGaia_Technology-red?style=for-the-badge)](https://visiongaiatechnology.de)

> *"Know your server. The moment you log in."*
> *MIT License — Use at your own risk.*

---

> ## ⚠️ EXPERIMENTAL NOTICE
>
> This script is published as **experimental R&D tooling**. It has been tested on Ubuntu/Debian with aaPanel Enterprise environments, but behavior on other setups may vary.
>
> **Use at your own risk.** Replacing system MOTD components can affect login behavior. Always test on a non-production system first.

---

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
  ┌────────────────────────────────────────────────────────┐
  │  YOUR SERVER  • ENGINE                                 │
  └────────────────────────────────────────────────────────┘

  Logged as:      user@hostname
  Privileges:     sudo / user
  Sessions:       2 active (root(1), deploy(1))

  OS:             Ubuntu 22.04.3 LTS
  Type:           kvm / Bare Metal
  Kernel:         5.15.0-91-generic
  IP addresses:   192.168.1.10
  Public IP:      1.2.3.4
  Uptime:         up 12 days, 4 hours, 22 minutes
  Load average:   0.12, 0.08, 0.05 (4 cores)

  Memory:         1.2G used, 6.1G available          / 8.0G
                  ████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░

  Disk (/):       42G used, 180G free                / 220G
                  ████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░

  Services:       ● fail2ban   ● aaPanel   ● Nginx   ● MySQL
  Updates:        3 package(s) available (1 security)

  ── Security ──────────────────────────────────────────────
    fail2ban:     247 IP(s) banned (extracted from logs)
    aaPanel:      running (master node)

  ── Banned IPs (last 24h) ─────────────────────────────────
    185.220.101.47   sshd         2026-04-09 03:12
    94.102.49.193    sshd         2026-04-09 07:44

  ── Recent Logins ─────────────────────────────────────────
    root            pts/0    1.2.3.4          still logged in
    deploy          pts/1    10.0.0.5         Wed Apr  9 08:01
```

---

## 📡 Data Sources

| Section | Source | Method |
|---|---|---|
| **CPU / Load** | `/proc/loadavg` | Kernel direct read |
| **Memory** | `free -m` | Zero-latency |
| **Disk** | `df -h /` | Root partition only |
| **Network IP** | `ip route get 1.1.1.1` | Default route extraction (ignores Docker/virtual bridges) |
| **Public IP** | `ifconfig.me` | 500ms timeout — shows `Offline` if unreachable |
| **Updates** | `/var/lib/update-notifier/updates-available` | Cache read — no apt invocation |
| **fail2ban** | `/var/log/fail2ban.log` | Log grep — requires root or `adm` group |
| **Services** | `systemctl is-active` | No daemon restart triggered |
| **Logins** | `last -a` | Standard auth log |

---

## 🚀 Installation

### Step 1 — Download the script

```bash
# Clone the repository
git clone https://github.com/visiongaiatechnology/sshdashboard
cd sshdashboard
```

### Step 2 — Install as MOTD

```bash
# Copy into the MOTD directory
sudo mv aapanel.sh /etc/update-motd.d/99-vgt-dashboard
sudo chown root:root /etc/update-motd.d/99-vgt-dashboard
sudo chmod +x /etc/update-motd.d/99-vgt-dashboard
```

### Step 3 — Disable the default Ubuntu MOTD

The default Ubuntu MOTD runs multiple slow scripts. Disable them to avoid UI collisions and speed up login:

```bash
sudo chmod -x /etc/update-motd.d/*
sudo chmod +x /etc/update-motd.d/99-vgt-dashboard
```

> This disables the default Ubuntu news/ads/landscape scripts. Your VGT Dashboard is now the only thing that runs on login.

### Step 4 — Verify

```bash
# Test the output manually
sudo run-parts /etc/update-motd.d/
```

Or simply open a new SSH session — the dashboard should appear immediately.

---

## ⚙️ Alternative: profile.d Installation

If you prefer not to modify `update-motd.d`:

```bash
sudo nano /etc/profile.d/vgt_motd.sh
# Paste the script content, save

sudo chmod +x /etc/profile.d/vgt_motd.sh
```

> Note: `profile.d` triggers on interactive login shells only. `update-motd.d` is more reliable across SSH client configurations.

---

## 🔧 Customization

Open the script and edit the header section:

```bash
# Line ~55 — replace with your own label:
echo -e "  YOURNAME • YOUR ENGINE"

# Line ~last — replace the footer:
echo -e "  Managed by YOURNAME. All activity is strictly monitored."
```

**Color tweaks** — all colors are defined in the top block as ANSI 256 variables:

```bash
c_head="\033[38;5;39m"      # VGT Cyan/Blue — section headers
c_green="\033[38;5;113m"    # Status OK
c_red="\033[38;5;196m"      # Status Critical / Public IP
c_yellow="\033[38;5;220m"   # Warnings / Updates
c_magenta="\033[38;5;170m"  # IPs / Highlights
```

---

## ⚙️ Requirements & Compatibility

| Requirement | Detail |
|---|---|
| **OS** | Ubuntu 22.04+ / Debian 11+ |
| **Shell** | Bash 5.0+ |
| **Environment** | Tested on aaPanel Enterprise |
| **Root access** | Required for fail2ban log read and MOTD installation |
| **Network** | Optional — `ifconfig.me` lookup has 500ms timeout |

### Service Detection

The dashboard auto-detects these services:

| Service | Check method |
|---|---|
| **fail2ban** | `systemctl is-active` |
| **Nginx** | `systemctl is-active` |
| **aaPanel** (`bt`) | `systemctl is-active` + init.d fallback |
| **MySQL** (`mysqld`) | `systemctl is-active` |

---

## 🔒 Security Notes

**fail2ban log access:**
The script reads `/var/log/fail2ban.log` to extract ban counts and recent IPs. This requires either root execution or membership in the `adm` group:

```bash
# Add your user to the adm group for log access without sudo
sudo usermod -aG adm YOUR_USER
```

**Public IP lookup:**
The script calls `ifconfig.me` with a 500ms timeout on every login. If this is a concern, remove or replace this line:

```bash
# Line to remove/replace:
IP_PUBLIC=$(curl -s -m 0.5 https://ifconfig.me/ip 2>/dev/null || echo "Offline")
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
| ⚔️ **[VGT Auto-Punisher](https://github.com/visiongaiatechnology/vgt-auto-punisher)** | **IDS** | L4+L7 Hybrid Experimental IDS — attackers terminated before they knock |
| 🌐 **[VGT Global Threat Sync](https://github.com/visiongaiatechnology/vgt-global-threat-sync)** | **Preventive** | Daily threat feed — block known attackers before they arrive |
| ⚔️ **[VGT Sentinel](https://github.com/visiongaiatechnology/sentinelcom)** | **WAF / IDS** | Zero-Trust WordPress Security Suite |
| 🔥 **[VGT Windows Firewall Burner](https://github.com/visiongaiatechnology/vgt-windows-burner)** | **Windows** | 280,000+ APT IPs in native Windows Firewall |

---

## 🤝 Contributing

Pull requests are welcome. Tested configurations and compatibility reports for other distros are especially appreciated.

Licensed under **MIT** — use freely, modify freely, use at your own risk.

---

## 🏢 Built by VisionGaia Technology

[![VGT](https://img.shields.io/badge/VGT-VisionGaia_Technology-red?style=for-the-badge)](https://visiongaiatechnology.de)

VisionGaia Technology builds enterprise-grade security infrastructure — engineered to the DIAMANT VGT SUPREME standard.

> *"The first thing you see when you log in should tell you everything. Not a blank screen."*

---

*VGT SSH Dashboard V2 APEX — Terminal Intelligence HUD // Bash // MIT License*
