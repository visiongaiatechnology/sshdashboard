#!/usr/bin/env bash
# ==============================================================================
# VISIONGAIATECHNOLOGY R&D STUFF - TERMINAL DASHBOARD V2 (APEX)
# STATUS: EXPERIMENTAL
# TARGET: Ubuntu / Debian / aaPanel Enterprise Environment
# EXECUTION: Zero-Latency / Deep Kernel & Log Extraction
# ==============================================================================

# ------------------------------------------------------------------------------
# 1. COLOR & UI DEFINITIONS (ANSI 256)
# ------------------------------------------------------------------------------
c_reset="\033[0m"
c_bold="\033[1m"
c_dim="\033[2m"

c_label="\033[38;5;242m"    # Dark Gray
c_val="\033[38;5;253m"      # Light Gray/White
c_head="\033[38;5;39m"      # VGT Cyan/Blue
c_green="\033[38;5;113m"    # Status OK
c_red="\033[38;5;196m"      # Status Crit
c_yellow="\033[38;5;220m"   # Status Warn/Updates
c_magenta="\033[38;5;170m"  # IPs / Highlights
c_bar_bg="\033[38;5;236m"   # Bar Background
c_line="\033[38;5;239m"     # Divider Lines

# ------------------------------------------------------------------------------
# 2. CORE SYSTEM METRICS EXTRACTION
# ------------------------------------------------------------------------------
HOSTNAME=$(hostname -f)
USER_NAME=$(whoami)
PRIVILEGE=$([ "$EUID" -eq 0 ] && echo -e "${c_red}sudo${c_reset}" || echo -e "${c_val}user${c_reset}")

# Sessions parsing
SESSIONS_RAW=$(who)
SESSIONS_COUNT=$(echo "$SESSIONS_RAW" | wc -l)
SESSIONS_LIST=$(echo "$SESSIONS_RAW" | awk '{print $1}' | sort | uniq -c | awk '{print $2"("$1")"}' | paste -sd ", " -)

# OS & Kernel
OS_PRETTY=$(grep -P '^PRETTY_NAME=' /etc/os-release | cut -d= -f2 | tr -d '"')
KERNEL=$(uname -r)
VIRT=$(systemd-detect-virt 2>/dev/null || echo "Bare Metal / Unknown")

# Uptime
UPTIME_SEC=$(awk '{print $1}' /proc/uptime | cut -d. -f1)
UP_D=$((UPTIME_SEC / 86400)); UP_H=$((UPTIME_SEC % 86400 / 3600)); UP_M=$((UPTIME_SEC % 3600 / 60))
UPTIME_STR="${UP_D} days, ${UP_H} hours, ${UP_M} minutes"

# Load & CPU
LOAD_AVG=$(cat /proc/loadavg | awk '{print $1", "$2", "$3}')
CPU_CORES=$(nproc)

# Network
# VGT UPDATE: Extrahiert nur die primäre IP des default-Routings (ignoriert Docker/Virtual Bridges)
IP_LOCAL=$(ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+')
IP_PUBLIC=$(curl -s -m 0.5 https://ifconfig.me/ip 2>/dev/null || echo "Offline")

# Memory & Disk
read -r RAM_TOTAL RAM_USED RAM_FREE RAM_PERCENT <<< $(free -m | awk 'NR==2{printf "%s %s %s %.0f", $2, $3, $7, $3*100/$2}')
RAM_TOTAL_GB=$(awk "BEGIN {printf \"%.1f\", $RAM_TOTAL/1024}")
RAM_USED_GB=$(awk "BEGIN {printf \"%.1f\", $RAM_USED/1024}")
RAM_FREE_GB=$(awk "BEGIN {printf \"%.1f\", $RAM_FREE/1024}")
read -r DISK_SIZE DISK_USED DISK_FREE DISK_PERCENT <<< $(df -h / | awk 'NR==2{print $2, $3, $4, $5}' | sed 's/%//')

# ------------------------------------------------------------------------------
# 3. SECURITY & UPDATES ENGINE
# ------------------------------------------------------------------------------
# Updates Check (Reads Ubuntu cache to prevent latency)
UPDATES_STR="Up to date"
if [ -f /var/lib/update-notifier/updates-available ]; then
    SEC_UPDATES=$(awk '/security updates/ {print $1}' /var/lib/update-notifier/updates-available 2>/dev/null)
    ALL_UPDATES=$(awk '/packages can be updated/ {print $1}' /var/lib/update-notifier/updates-available 2>/dev/null)
    if [ -n "$ALL_UPDATES" ] && [ "$ALL_UPDATES" -gt 0 ]; then
        UPDATES_STR="${ALL_UPDATES} package(s) available (${SEC_UPDATES:-0} security)"
    fi
fi

# Reboot Check
REBOOT_REQ=""
[ -f /var/run/reboot-required ] && REBOOT_REQ="${c_yellow}⚠ System reboot required (kernel ${KERNEL} pending)${c_reset}"

# Services Status (Expanded for Enterprise)
check_service() {
    if systemctl is-active --quiet "$1" 2>/dev/null || /etc/init.d/"$1" status 2>/dev/null | grep -q "running"; then
        echo -e "${c_green}●${c_reset} ${c_val}$2${c_reset}"
    else
        echo -e "${c_red}●${c_reset} ${c_dim}$2${c_reset}"
    fi
}

SVC_FAIL2BAN=$(check_service "fail2ban" "fail2ban")
SVC_NGINX=$(check_service "nginx" "Nginx")
SVC_BT=$(check_service "bt" "aaPanel")
SVC_MYSQL=$(check_service "mysqld" "MySQL")

# Fail2ban Metrics Extraction (Requires root/sudo for log access)
F2B_STATS="${c_dim}no data (requires root)${c_reset}"
if [ -r /var/log/fail2ban.log ]; then
    BANNED_COUNT=$(grep "Ban " /var/log/fail2ban.log | wc -l)
    F2B_STATS="${c_yellow}${BANNED_COUNT} IP(s) banned${c_reset} (extracted from logs)"
fi

# ------------------------------------------------------------------------------
# 4. RENDER ENGINE (UI BUILDER)
# ------------------------------------------------------------------------------
draw_bar() {
    local percent=$1
    local bar_len=40
    local filled=$((percent * bar_len / 100))
    local empty=$((bar_len - filled))
    local bar_color=$c_green
    [ "$percent" -gt 70 ] && bar_color=$c_yellow
    [ "$percent" -gt 85 ] && bar_color=$c_red

    local b_filled=$(printf "%${filled}s" | tr ' ' '█')
    local b_empty=$(printf "%${empty}s" | tr ' ' '░')
    echo -e "${bar_color}${b_filled}${c_bar_bg}${b_empty}${c_reset}"
}

print_row() { printf "  ${c_label}%-15s${c_reset} %b\n" "$1:" "$2"; }

draw_section() {
    local title=$1
    local line_len=$(( 55 - ${#title} ))
    local line_str=$(printf '─%.0s' $(seq 1 $line_len))
    echo -e "  ${c_line}── ${c_head}${title} ${c_line}${line_str}${c_reset}"
}

# ------------------------------------------------------------------------------
# 5. FINAL UI RENDER
# ------------------------------------------------------------------------------
clear
echo ""
echo -e "      ${c_line}┌────────────────────────────────────────────────────────┐${c_reset}"
echo -e "      ${c_line}│${c_reset}  ${c_head}${c_bold}YOURNAME${c_reset} ${c_dim}• YOUR ENGINE${c_reset}               ${c_line}│${c_reset}"
echo -e "      ${c_line}└────────────────────────────────────────────────────────┘${c_reset}"
echo ""

print_row "Logged as" "${c_val}${USER_NAME}@${HOSTNAME}${c_reset}"
print_row "Privileges" "${PRIVILEGE}"
print_row "Sessions" "${c_val}${SESSIONS_COUNT} active (${SESSIONS_LIST})${c_reset}"
echo ""
print_row "OS" "${c_val}${OS_PRETTY}${c_reset}"
print_row "Type" "${c_val}${VIRT}${c_reset}"
print_row "Kernel" "${c_dim}${KERNEL}${c_reset}"
print_row "IP addresses" "${c_magenta}${IP_LOCAL}${c_reset}"
print_row "Public IP" "${c_red}${IP_PUBLIC}${c_reset}"
print_row "Uptime" "${c_val}up ${UPTIME_STR}${c_reset}"
print_row "Load average" "${c_val}${LOAD_AVG} (${CPU_CORES} cores)${c_reset}"
echo ""
printf "  ${c_label}%-15s${c_reset} RAM - %s used, %s available %9s / %s\n" "Memory:" "${RAM_USED_GB}G" "${RAM_FREE_GB}G" "" "${RAM_TOTAL_GB}G"
printf "  %-15s %b\n" "" "$(draw_bar $RAM_PERCENT)"
echo ""
printf "  ${c_label}%-15s${c_reset} %s used, %s free %16s / %s\n" "Disk (/):" "${DISK_USED}" "${DISK_FREE}" "" "${DISK_SIZE}"
printf "  %-15s %b\n" "" "$(draw_bar $DISK_PERCENT)"
echo ""
printf "  ${c_label}%-15s${c_reset} %b   %b   %b   %b\n" "Services:" "$SVC_FAIL2BAN" "$SVC_BT" "$SVC_NGINX" "$SVC_MYSQL"
print_row "Updates" "${c_val}${UPDATES_STR}${c_reset}"
[ -n "$REBOOT_REQ" ] && echo -e "  ${REBOOT_REQ}"
echo ""

# --- SECURITY SECTION ---
draw_section "Security"
printf "    ${c_label}%-13s${c_reset} %b\n" "fail2ban:" "${F2B_STATS}"
printf "    ${c_label}%-13s${c_reset} %b\n" "aaPanel:" "${c_val}running (master node)${c_reset}"
echo ""

# --- BANNED IPS SECTION ---
draw_section "Banned IPs (last 24h)"
if [ -r /var/log/fail2ban.log ]; then
    # Extracts last 4 bans efficiently
    grep "Ban " /var/log/fail2ban.log | tail -n 4 | while read -r date time _ jail ip _; do
        # Format: IP, Jail, Time
        printf "    ${c_red}%-16s${c_reset} ${c_label}%-12s${c_reset} ${c_dim}%s %s${c_reset}\n" "$ip" "$jail" "$date" "${time%,*}"
    done
else
    echo -e "    ${c_dim}Log unreadable. Execute as root or add user to adm group.${c_reset}"
fi
echo ""

# --- RECENT LOGINS SECTION ---
draw_section "Recent Logins"
last -a | head -n 4 | while read -r line; do
    if [[ -n "$line" && ! "$line" == wtmp* ]]; then
        user=$(echo "$line" | awk '{print $1}')
        tty=$(echo "$line" | awk '{print $2}')
        ip=$(echo "$line" | awk '{print $NF}')
        time_data=$(echo "$line" | awk '{print $3, $4, $5, $6, $7, $8}')
        
        # Check if still logged in
        status_color=$c_label
        [[ "$time_data" == *"still logged in"* ]] && status_color=$c_green
        
        printf "    ${c_val}%-15s${c_reset} ${c_dim}%-8s${c_reset} ${c_magenta}%-16s${c_reset} ${status_color}%s${c_reset}\n" "$user" "$tty" "$ip" "$time_data"
    fi
done
echo ""
echo -e "  ${c_dim}Managed by YOURNAME. All activity is strictly monitored.${c_reset}"
echo ""
