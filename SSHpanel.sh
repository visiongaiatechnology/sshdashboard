#!/usr/bin/env bash
# ==============================================================================
# VISIONGAIATECHNOLOGY R&D STUFF - TERMINAL DASHBOARD V2 (APEX)
# STATUS: VGT SUPREME (PLATINUM ARCHITECTURE)
# TARGET: Ubuntu / Debian / aaPanel Enterprise Environment
# EXECUTION: Zero-Latency / Deep Kernel & Log Extraction / Hardened
# ==============================================================================

# --- KERNEL DIRECTIVES & HARDENING ---
set -euo pipefail
export LANG=C
export LC_ALL=C
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# ------------------------------------------------------------------------------
# 1. COLOR & UI DEFINITIONS (ANSI 256) - READONLY
# ------------------------------------------------------------------------------
readonly c_reset="\033[0m"
readonly c_bold="\033[1m"
readonly c_dim="\033[2m"

readonly c_label="\033[38;5;242m"    # Dark Gray
readonly c_val="\033[38;5;253m"      # Light Gray/White
readonly c_head="\033[38;5;39m"      # VGT Cyan/Blue
readonly c_green="\033[38;5;113m"    # Status OK
readonly c_red="\033[38;5;196m"      # Status Crit
readonly c_yellow="\033[38;5;220m"   # Status Warn/Updates
readonly c_magenta="\033[38;5;170m"  # IPs / Highlights
readonly c_bar_bg="\033[38;5;238m"   # Bar Background (Slightly lighter for contrast)
readonly c_line="\033[38;5;237m"     # Divider Lines

# VGT Semantic Glyphs (Fallback safe)
readonly g_sys="⚙"
readonly g_net="⟁"
readonly g_sec="🛡"
readonly g_usr="👤"
readonly g_arr="›"

# ------------------------------------------------------------------------------
# 2. SECURITY SANITIZATION ENGINE
# ------------------------------------------------------------------------------
# Verhindert Terminal Escape Sequence Injection (CWE-150)
sanitize_ip() {
    local input="$1"
    if [[ "$input" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || [[ "$input" =~ ^[a-fA-F0-9:]+$ ]]; then
        echo "$input"
    else
        echo "Invalid/Offline"
    fi
}

sanitize_str() {
    # Erlaubt nur Alphanumerisch, Punkte, Striche, Unterstriche, Doppelpunkte und Spaces
    echo "$1" | tr -dc '[:alnum:] ._:-' | cut -c 1-50
}

# ------------------------------------------------------------------------------
# 3. CORE SYSTEM METRICS EXTRACTION (ZERO-LATENCY)
# ------------------------------------------------------------------------------
readonly HOSTNAME=$(hostname -f 2>/dev/null || echo "unknown")
readonly USER_NAME=$(whoami)
readonly EUID_VAL=$(id -u)

if [ "$EUID_VAL" -eq 0 ]; then
    PRIVILEGE="${c_red}sudo${c_reset}"
else
    PRIVILEGE="${c_val}user${c_reset}"
fi

# Native Read (No Subshells) für Load & Uptime
read -r LOAD1 LOAD5 LOAD15 _ < /proc/loadavg
read -r UPTIME_SEC_RAW _ < /proc/uptime
UPTIME_SEC=${UPTIME_SEC_RAW%.*}
UP_D=$((UPTIME_SEC / 86400))
UP_H=$((UPTIME_SEC % 86400 / 3600))
UP_M=$((UPTIME_SEC % 3600 / 60))
readonly UPTIME_STR="${UP_D} days, ${UP_H} hours, ${UP_M} minutes"
readonly CPU_CORES=$(nproc 2>/dev/null || echo 1)

# OS & Kernel (Optimized Read)
if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_PRETTY="${PRETTY_NAME:-Linux}"
else
    OS_PRETTY="Unknown Linux"
fi
readonly KERNEL=$(uname -r)
VIRT=$(systemd-detect-virt 2>/dev/null || echo "Bare Metal")
readonly VIRT_SAN=$(sanitize_str "$VIRT")

# Memory & Disk (POSIX Konformität -P verhindert Umbrüche)
read -r _ RAM_TOTAL RAM_USED RAM_FREE _ _ < <(free -m | awk 'NR==2')
RAM_PERCENT=$(( RAM_USED * 100 / RAM_TOTAL ))
RAM_TOTAL_GB=$(awk "BEGIN {printf \"%.1f\", $RAM_TOTAL/1024}")
RAM_USED_GB=$(awk "BEGIN {printf \"%.1f\", $RAM_USED/1024}")
RAM_FREE_GB=$(awk "BEGIN {printf \"%.1f\", $RAM_FREE/1024}")

read -r _ DISK_SIZE DISK_USED DISK_FREE DISK_PERCENT_RAW _ < <(df -hP / | awk 'NR==2')
DISK_PERCENT=${DISK_PERCENT_RAW%\%}

# Network (Timeouts enforced at DNS level via curl parameters)
IP_LOCAL_RAW=$(ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+' || echo "127.0.0.1")
readonly IP_LOCAL=$(sanitize_ip "$IP_LOCAL_RAW")
IP_PUBLIC_RAW=$(curl -s --connect-timeout 0.5 --max-time 0.5 https://ifconfig.me/ip 2>/dev/null || echo "Offline")
readonly IP_PUBLIC=$(sanitize_ip "$IP_PUBLIC_RAW")

# Sessions (Sanitized)
SESSIONS_RAW=$(who 2>/dev/null || true)
if [ -n "$SESSIONS_RAW" ]; then
    SESSIONS_COUNT=$(echo "$SESSIONS_RAW" | wc -l)
    SESSIONS_LIST=$(echo "$SESSIONS_RAW" | awk '{print $1}' | tr -dc '[:alnum:]\n' | sort | uniq -c | awk '{print $2"("$1")"}' | paste -sd ", " -)
else
    SESSIONS_COUNT=0
    SESSIONS_LIST="none"
fi

# ------------------------------------------------------------------------------
# 4. SECURITY & UPDATES ENGINE
# ------------------------------------------------------------------------------
UPDATES_STR="Up to date"
if [ -f /var/lib/update-notifier/updates-available ]; then
    SEC_UPDATES=$(grep -Eo '[0-9]+ security' /var/lib/update-notifier/updates-available | awk '{print $1}' || echo 0)
    ALL_UPDATES=$(grep -Eo '[0-9]+ packages' /var/lib/update-notifier/updates-available | awk '{print $1}' || echo 0)
    if [ "$ALL_UPDATES" -gt 0 ]; then
        UPDATES_STR="${ALL_UPDATES} package(s) available (${SEC_UPDATES} security)"
    fi
fi

REBOOT_REQ=""
[ -f /var/run/reboot-required ] && REBOOT_REQ="${c_yellow}⚠ System reboot required (kernel ${KERNEL} pending)${c_reset}"

check_service() {
    local svc="$1"
    local name="$2"
    # VGT FIX: Ersetze grep -q durch grep >/dev/null um SIGPIPE (141) mit pipefail zu verhindern
    if systemctl is-active --quiet "$svc" 2>/dev/null || ( [ -x "/etc/init.d/$svc" ] && "/etc/init.d/$svc" status 2>/dev/null | grep "running" >/dev/null ); then
        echo -e "${c_dim}[${c_green}●${c_dim}]${c_reset} ${c_val}${name}${c_reset}"
    else
        echo -e "${c_dim}[${c_red}●${c_dim}]${c_reset} ${c_dim}${name}${c_reset}"
    fi
}

readonly SVC_FAIL2BAN=$(check_service "fail2ban" "fail2ban")
readonly SVC_NGINX=$(check_service "nginx" "Nginx")
readonly SVC_MYSQL=$(check_service "mysqld" "MySQL")

# Control Panel Zero-Latency Auto-Detection
CP_NAME=""
CP_SVC=""
if [ -d "/www/server/panel" ] || systemctl is-active --quiet bt 2>/dev/null; then
    CP_NAME="aaPanel"
    CP_SVC="bt"
elif [ -d "/usr/local/psa" ] || systemctl is-active --quiet psa 2>/dev/null || systemctl is-active --quiet sw-cp-server 2>/dev/null; then
    CP_NAME="Plesk"
    CP_SVC="psa"
    systemctl is-active --quiet sw-cp-server 2>/dev/null && CP_SVC="sw-cp-server"
elif [ -d "/usr/local/cpanel" ] || systemctl is-active --quiet cpanel 2>/dev/null; then
    CP_NAME="cPanel"
    CP_SVC="cpanel"
fi

if [ -n "$CP_NAME" ]; then
    readonly SVC_CP=$(check_service "$CP_SVC" "$CP_NAME")
else
    # Fallback Design für Standalone Server
    readonly SVC_CP=$(echo -e "${c_dim}[${c_dim}○${c_dim}]${c_reset} ${c_dim}No Panel${c_reset}")
fi

# Fail2ban Metrics Extraction (Bounded I/O)
F2B_STATS="${c_dim}no data (requires root or adm group)${c_reset}"
if [ -r /var/log/fail2ban.log ]; then
    # O(1) Limitierung: Liest maximal die letzten 10000 Zeilen um IO Stalls zu verhindern
    BANNED_COUNT=$(tail -n 10000 /var/log/fail2ban.log | grep -c "Ban " || echo 0)
    if [ "$BANNED_COUNT" -eq 10000 ]; then
        F2B_STATS="${c_yellow}>10000 IP(s) banned${c_reset} (extracted from recent logs)"
    else
        F2B_STATS="${c_yellow}${BANNED_COUNT} IP(s) banned${c_reset} (extracted from recent logs)"
    fi
fi

# ------------------------------------------------------------------------------
# 5. RENDER ENGINE (UI BUILDER)
# ------------------------------------------------------------------------------
draw_bar() {
    local percent=$1
    local bar_len=38
    
    # Sicherstellen, dass percent numerisch ist
    [[ "$percent" =~ ^[0-9]+$ ]] || percent=0
    [ "$percent" -gt 100 ] && percent=100

    local filled=$((percent * bar_len / 100))
    local empty=$((bar_len - filled))
    local bar_color=$c_green
    
    [ "$percent" -gt 70 ] && bar_color=$c_yellow
    [ "$percent" -gt 85 ] && bar_color=$c_red

    local b_filled=""
    local b_empty=""
    # VGT HUD Style: Solid blocks for fill, subtle dots for empty space
    [ $filled -gt 0 ] && b_filled=$(printf "%${filled}s" | tr ' ' '█')
    [ $empty -gt 0 ] && b_empty=$(printf "%${empty}s" | tr ' ' '·')
    
    echo -e "${bar_color}${b_filled}${c_bar_bg}${b_empty}${c_reset}"
}

print_row() { 
    local glyph="$1"
    local label="$2"
    local val="$3"
    printf "  ${c_head}%s${c_reset} ${c_label}%-14s${c_reset} %b\n" "$glyph" "$label:" "$val" 
}

draw_section() {
    local title="$1"
    local glyph="$2"
    local line_len=$(( 52 - ${#title} ))
    [ $line_len -lt 1 ] && line_len=1
    local line_str=$(printf '─%.0s' $(seq 1 $line_len))
    echo -e "  ${c_line}── ${c_head}${glyph} ${title} ${c_line}${line_str}${c_reset}"
}

# ------------------------------------------------------------------------------
# 6. FINAL UI RENDER
# ------------------------------------------------------------------------------
clear
echo ""
echo -e "      ${c_line}╭────────────────────────────────────────────────────────╮${c_reset}"
echo -e "      ${c_line}│${c_reset}  ${c_head}${c_bold}VISIONGAIATECHNOLOGY${c_reset} ${c_dim}• APEX ENGINE HUD${c_reset}      ${c_line}│${c_reset}"
echo -e "      ${c_line}╰────────────────────────────────────────────────────────╯${c_reset}"
echo ""

print_row "$g_usr" "Logged as" "${c_val}${USER_NAME}@${HOSTNAME}${c_reset}  ${c_dim}[${PRIVILEGE}${c_dim}]${c_reset}"
print_row " " "Sessions" "${c_val}${SESSIONS_COUNT} active${c_reset} ${c_dim}(${SESSIONS_LIST})${c_reset}"
echo ""
print_row "$g_sys" "OS" "${c_val}$(sanitize_str "${OS_PRETTY}")${c_reset} ${c_dim}(${VIRT_SAN})${c_reset}"
print_row " " "Kernel" "${c_dim}${KERNEL}${c_reset}"
print_row " " "Uptime" "${c_val}up ${UPTIME_STR}${c_reset}"
print_row " " "Load average" "${c_val}${LOAD1}, ${LOAD5}, ${LOAD15}${c_reset} ${c_dim}[${CPU_CORES} cores]${c_reset}"
echo ""
print_row "$g_net" "Local IP" "${c_magenta}${IP_LOCAL}${c_reset}"
print_row " " "Public IP" "${c_red}${IP_PUBLIC}${c_reset}"
echo ""
printf "  ${c_head}%s${c_reset} ${c_label}%-14s${c_reset} %s used, %s free %8s / %s\n" "$g_sys" "Memory:" "${RAM_USED_GB}G" "${RAM_FREE_GB}G" "" "${RAM_TOTAL_GB}G"
printf "  %-17s %b\n" "" "$(draw_bar "$RAM_PERCENT")"
echo ""
printf "  ${c_head}%s${c_reset} ${c_label}%-14s${c_reset} %s used, %s free %14s / %s\n" "$g_sys" "Disk (/):" "${DISK_USED}" "${DISK_FREE}" "" "${DISK_SIZE}"
printf "  %-17s %b\n" "" "$(draw_bar "$DISK_PERCENT")"
echo ""
printf "  ${c_head}%s${c_reset} ${c_label}%-14s${c_reset} %b  %b  %b  %b\n" "$g_sys" "Services:" "$SVC_FAIL2BAN" "$SVC_CP" "$SVC_NGINX" "$SVC_MYSQL"
print_row " " "Updates" "${c_val}${UPDATES_STR}${c_reset}"
[ -n "$REBOOT_REQ" ] && echo -e "    ${REBOOT_REQ}"
echo ""

# --- SECURITY SECTION ---
draw_section "Security Core" "$g_sec"
printf "    ${c_label}%-13s${c_reset} %b\n" "fail2ban:" "${F2B_STATS}"

if [ -n "$CP_NAME" ]; then
    if systemctl is-active --quiet "$CP_SVC" 2>/dev/null || ( [ -x "/etc/init.d/$CP_SVC" ] && "/etc/init.d/$CP_SVC" status 2>/dev/null | grep -q "running" ); then
        cp_status="${c_val}running (active node)${c_reset}"
    else
        cp_status="${c_dim}inactive/stopped${c_reset}"
    fi
    printf "    ${c_label}%-13s${c_reset} %b\n" "${CP_NAME}:" "${cp_status}"
else
    printf "    ${c_label}%-13s${c_reset} %b\n" "Control Panel:" "${c_dim}standalone server (no panel detected)${c_reset}"
fi
echo ""

# --- BANNED IPS SECTION (SANITIZED) ---
draw_section "Recent Threat Bans" "$g_sec"
if [ -r /var/log/fail2ban.log ]; then
    tail -n 1000 /var/log/fail2ban.log | grep "Ban " | tail -n 4 | while read -r date time _ jail ip _; do
        s_ip=$(sanitize_ip "$ip")
        s_jail=$(sanitize_str "$jail")
        printf "    ${c_dim}${g_arr}${c_reset} ${c_red}%-16s${c_reset} ${c_label}%-12s${c_reset} ${c_dim}%s %s${c_reset}\n" "$s_ip" "$s_jail" "$date" "${time%,*}"
    done
else
    echo -e "    ${c_dim}Log unreadable. Execute as root or add user to adm group.${c_reset}"
fi
echo ""

# --- RECENT LOGINS SECTION (SANITIZED) ---
draw_section "Auth Audit Log" "$g_usr"
# VGT FIX: Nutze nativen -n 4 Parameter von last, um Pipe-Closure und SIGPIPE (141) Crash zu verhindern
last -a -n 4 2>/dev/null | while read -r line; do
    if [[ -n "$line" && ! "$line" == wtmp* ]]; then
        user=$(echo "$line" | awk '{print $1}')
        tty=$(echo "$line" | awk '{print $2}')
        ip=$(echo "$line" | awk '{print $NF}')
        time_data=$(echo "$line" | awk '{print $3, $4, $5, $6, $7, $8}')
        
        s_user=$(sanitize_str "$user")
        s_tty=$(sanitize_str "$tty")
        s_ip=$(sanitize_ip "$ip")
        s_time=$(sanitize_str "$time_data")

        status_color=$c_label
        [[ "$s_time" == *"still logged in"* ]] && status_color=$c_green
        
        printf "    ${c_dim}${g_arr}${c_reset} ${c_val}%-15s${c_reset} ${c_dim}%-8s${c_reset} ${c_magenta}%-16s${c_reset} ${status_color}%s${c_reset}\n" "$s_user" "$s_tty" "$s_ip" "$s_time"
    fi
done
echo ""
echo -e "  ${c_dim}Powered by VISIONGAIATECHNOLOGY OMEGA PROTOCOL. All inputs tracked.${c_reset}"
echo ""
