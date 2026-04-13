#!/usr/bin/env bash
# ==============================================================================
# VISIONGAIATECHNOLOGY - OMEGA PROTOCOL TERMINAL (TACTICAL COMMAND HUD)
# STATUS: DIAMANT VGT SUPREME v4.1
# DESIGN: CYBER-DECK ASYMMETRICAL (VGT EXCLUSIVE)
# KERNEL UPGRADE: I/O Timeouts, Process Sanitization, Pipefail Immunity
# ==============================================================================

# --- KERNEL DIRECTIVES & HARDENING ---
set -euo pipefail
export LANG=C
export LC_ALL=C
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# ------------------------------------------------------------------------------
# 1. COLOR & UI DEFINITIONS (NEON TACTICAL PALETTE)
# ------------------------------------------------------------------------------
readonly c_reset="\033[0m"
readonly c_bold="\033[1m"
readonly c_dim="\033[2m"
readonly c_inv="\033[7m"

readonly c_rail="\033[38;5;39m"
readonly c_brand="\033[38;5;81m"
readonly c_label="\033[38;5;244m"
readonly c_val="\033[38;5;255m"

readonly c_ok="\033[38;5;113m"
readonly c_warn="\033[38;5;220m"
readonly c_crit="\033[38;5;196m"
readonly c_mag="\033[38;5;170m"
readonly c_bar_bg="\033[38;5;235m"

readonly rail_char="▊"
readonly g_arr="▶"

# ------------------------------------------------------------------------------
# 2. SECURITY SANITIZATION ENGINE
# ------------------------------------------------------------------------------
sanitize_ip() {
    [[ "$1" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || [[ "$1" =~ ^[a-fA-F0-9:]+$ ]] && echo "$1" || echo "Offline"
}
sanitize_str() { echo "$1" | tr -dc '[:alnum:] ._:-' | cut -c 1-30; }

# ------------------------------------------------------------------------------
# 3. CORE METRICS EXTRACTION (ZERO-LATENCY KERNEL READS)
# ------------------------------------------------------------------------------
readonly HOSTNAME=$(hostname -s 2>/dev/null || echo "unknown")
readonly USER_NAME=$(whoami)
readonly EUID_VAL=$(id -u)

[ "$EUID_VAL" -eq 0 ] && PRIVILEGE="${c_crit}ROOT-LEVEL${c_reset}" || PRIVILEGE="${c_warn}USER-LEVEL${c_reset}"

read -r LOAD1 LOAD5 LOAD15 _ < /proc/loadavg
LOAD1_INT=${LOAD1%%.*}
[ -z "$LOAD1_INT" ] && LOAD1_INT=0
readonly CPU_CORES=$(nproc 2>/dev/null || echo 1)

read -r UPTIME_SEC_RAW _ < /proc/uptime
UPTIME_SEC=${UPTIME_SEC_RAW%.*}
readonly UPTIME_STR="$((UPTIME_SEC / 86400))d $((UPTIME_SEC % 86400 / 3600))h $((UPTIME_SEC % 3600 / 60))m"

if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_PRETTY=$(sanitize_str "${PRETTY_NAME:-Linux}")
else
    OS_PRETTY="Unknown Linux"
fi
readonly KERNEL=$(uname -r)
readonly VIRT_SAN=$(sanitize_str "$(systemd-detect-virt 2>/dev/null || echo "Bare Metal")")

read -r _ RAM_TOTAL RAM_USED RAM_FREE _ _ < <(free -m | awk 'NR==2')
RAM_PERCENT=$(( RAM_USED * 100 / RAM_TOTAL ))
RAM_TOT_GB=$(awk "BEGIN {printf \"%.1f\", $RAM_TOTAL/1024}")
RAM_USE_GB=$(awk "BEGIN {printf \"%.1f\", $RAM_USED/1024}")

read -r _ DISK_SIZE DISK_USED DISK_FREE DISK_PERCENT_RAW _ < <(df -hP / | awk 'NR==2')
DISK_PERCENT=${DISK_PERCENT_RAW%\%}

# VGT FIX: O(1) Sanitization des Prozessnamens gegen CWE-150 (prctl ANSI Escapes)
read -r TOP_CMD_RAW TOP_CPU < <(ps -eo comm,pcpu --sort=-pcpu | awk 'NR==2{print $1, $2}')
readonly TOP_CMD=$(sanitize_str "$TOP_CMD_RAW")

IFACE=$(ip -4 route get 1.1.1.1 2>/dev/null | grep -Po '(?<=dev )(\S+)' | head -n1 || echo "")
if [ -n "$IFACE" ] && [ -f "/sys/class/net/$IFACE/statistics/rx_bytes" ]; then
    RX_B=$(cat "/sys/class/net/$IFACE/statistics/rx_bytes")
    TX_B=$(cat "/sys/class/net/$IFACE/statistics/tx_bytes")
    RX_GB=$(awk "BEGIN {printf \"%.2f\", $RX_B/1073741824}")
    TX_GB=$(awk "BEGIN {printf \"%.2f\", $TX_B/1073741824}")
    NET_TRAFFIC="${c_mag}↓ ${RX_GB} GB ${c_dim}|${c_mag} ↑ ${TX_GB} GB${c_reset}"
else
    NET_TRAFFIC="${c_dim}Offline / Unknown Interface${c_reset}"
fi

IP_LOCAL=$(sanitize_ip "$(ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+' || echo "127.0.0.1")")
IP_PUBLIC=$(sanitize_ip "$(curl -s --connect-timeout 0.5 --max-time 0.5 https://ifconfig.me/ip 2>/dev/null || echo "Offline")")

# ------------------------------------------------------------------------------
# 4. SECURITY & THREAT INTELLIGENCE
# ------------------------------------------------------------------------------
SEC_UPDATES=0; ALL_UPDATES=0
if [ -f /var/lib/update-notifier/updates-available ]; then
    SEC_UPDATES=$(grep -Eo '[0-9]+ security' /var/lib/update-notifier/updates-available | awk '{print $1}' || echo 0)
    ALL_UPDATES=$(grep -Eo '[0-9]+ packages' /var/lib/update-notifier/updates-available | awk '{print $1}' || echo 0)
fi

# VGT FIX: Hard Timeout (0.5s) um I/O Blocks durch hängenden D-Bus zu verhindern
check_service() {
    if timeout 0.5s systemctl is-active --quiet "$1" 2>/dev/null || ( [ -x "/etc/init.d/$1" ] && timeout 0.5s "/etc/init.d/$1" status 2>/dev/null | grep "running" >/dev/null ); then
        echo -e "${c_dim}[${c_ok}●${c_dim}]${c_reset} ${c_val}$2${c_reset}"
    else
        echo -e "${c_dim}[${c_crit}○${c_dim}]${c_reset} ${c_dim}$2${c_reset}"
    fi
}

readonly SVC_F2B=$(check_service "fail2ban" "f2b")
readonly SVC_NGX=$(check_service "nginx" "Nginx")
readonly SVC_MYS=$(check_service "mysqld" "MySQL")

CP_NAME="NoPanel"; CP_SVC=""
if [ -d "/www/server/panel" ] || timeout 0.5s systemctl is-active --quiet bt 2>/dev/null; then CP_NAME="aaPanel"; CP_SVC="bt"
elif [ -d "/usr/local/psa" ] || timeout 0.5s systemctl is-active --quiet psa 2>/dev/null || timeout 0.5s systemctl is-active --quiet sw-cp-server 2>/dev/null; then CP_NAME="Plesk"; CP_SVC="psa"; timeout 0.5s systemctl is-active --quiet sw-cp-server 2>/dev/null && CP_SVC="sw-cp-server"
elif [ -d "/usr/local/cpanel" ] || timeout 0.5s systemctl is-active --quiet cpanel 2>/dev/null; then CP_NAME="cPanel"; CP_SVC="cpanel"
fi
[ -n "$CP_SVC" ] && SVC_CP=$(check_service "$CP_SVC" "$CP_NAME") || SVC_CP="${c_dim}[○] NoPanel${c_reset}"

# VGT FIX: awk statt grep -c verhindert malformed 0\n0 Integer durch pipefail
BANNED_COUNT=0
[ -r /var/log/fail2ban.log ] && BANNED_COUNT=$(tail -n 10000 /var/log/fail2ban.log | awk '/Ban /{c++} END{print c+0}')

THREAT_LVL="${c_inv}${c_ok} THREAT: LOW ${c_reset}"
if [ "$BANNED_COUNT" -gt 50 ] || [ "$ALL_UPDATES" -gt 20 ] || [ "$LOAD1_INT" -ge "$CPU_CORES" ]; then
    THREAT_LVL="${c_inv}${c_warn} THREAT: ELEVATED ${c_reset}"
fi
if [ "$BANNED_COUNT" -gt 500 ] || [ "$SEC_UPDATES" -gt 5 ] || [ "$LOAD1_INT" -ge $((CPU_CORES * 2)) ]; then
    THREAT_LVL="${c_inv}${c_crit} THREAT: CRITICAL ${c_reset}"
fi

# ------------------------------------------------------------------------------
# 5. RENDER ENGINE
# ------------------------------------------------------------------------------
echo_rail() { echo -e "${c_rail}${rail_char}${c_reset} $1"; }

draw_bar() {
    local p=$1; local l=24
    [[ "$p" =~ ^[0-9]+$ ]] || p=0; [ "$p" -gt 100 ] && p=100
    local f=$((p * l / 100)); local e=$((l - f))
    local c=$c_ok; [ "$p" -gt 70 ] && c=$c_warn; [ "$p" -gt 85 ] && c=$c_crit
    local bf=""; local be=""
    [ $f -gt 0 ] && for ((i=0; i<f; i++)); do bf="${bf}█"; done
    [ $e -gt 0 ] && for ((i=0; i<e; i++)); do be="${be}·"; done
    echo -e "${c}${bf}${c_bar_bg}${be}${c_reset}"
}

# ------------------------------------------------------------------------------
# 6. FINAL UI RENDER
# ------------------------------------------------------------------------------
# VGT FIX: Kein `clear` mehr. Schützt den Admin-Scrollback. Nur visuelle Trennung.
echo ""
echo ""
echo -e "${c_rail}${rail_char}${c_brand} ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀${c_reset}"
echo -e "${c_rail}${rail_char}${c_reset}  ${c_bold}${c_val}VISIONGAIA TECHNOLOGY${c_reset}  ${c_dim}//${c_reset}  ${c_brand}OMEGA PROTOCOL${c_reset}"
echo -e "${c_rail}${rail_char}${c_reset}  ${c_label}NODE:${c_reset} ${c_val}${HOSTNAME^^}${c_reset}  ${c_label}AUTH:${c_reset} ${PRIVILEGE}  ${c_label}SYS:${c_reset} ${c_val}${OS_PRETTY}${c_reset}"
echo -e "${c_rail}${rail_char}${c_brand} ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄${c_reset}"
echo_rail ""

echo_rail "${c_bold}${c_val}TACTICAL INTEL${c_reset}  ${c_dim}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${c_reset}"
echo_rail " ${THREAT_LVL}   ${c_label}Updates:${c_reset} ${c_val}${ALL_UPDATES}${c_reset} ${c_dim}(${c_crit}${SEC_UPDATES} sec${c_dim})${c_reset}"
echo_rail " ${c_label}IDS Status :${c_reset} ${c_warn}${BANNED_COUNT} attackers blocked${c_reset} (fail2ban)"

if [ -r /var/log/fail2ban.log ]; then
    tail -n 1000 /var/log/fail2ban.log | grep "Ban " | tail -n 2 | sed -nE 's/^([0-9]{4}-[0-9]{2}-[0-9]{2}) ([0-9]{2}:[0-9]{2}:[0-9]{2}).*\[([a-zA-Z0-9_-]+)\] Ban ([0-9a-fA-F:\.]+).*$/\1 \2 \3 \4/p' | while read -r d t j i; do
        echo_rail "   ${c_crit}${g_arr} DROP${c_reset}  ${c_val}$(sanitize_ip "$i")${c_reset} ${c_dim}via ${j} [${t}]${c_reset}"
    done
else
    echo_rail "   ${c_dim}Log access restricted or unreadable.${c_reset}"
fi

echo_rail " ${c_label}Last Auth  :${c_reset}"
# VGT FIX: Hard Timeout (1s) schützt vor wtmp-Exhaustion bei korrupten Logs
timeout 1s last -a -n 3 2>/dev/null | while read -r line; do
    if [[ -n "$line" && ! "$line" == wtmp* ]]; then
        u=$(sanitize_str "$(echo "$line" | awk '{print $1}')")
        i=$(sanitize_ip "$(echo "$line" | awk '{print $NF}')")
        t=$(sanitize_str "$(echo "$line" | awk '{print $3, $4, $5, $6, $7, $8}')")
        c=$c_dim; [[ "$t" == *"still logged"* ]] && c=$c_ok
        echo_rail "   ${c_brand}${g_arr} GRANT${c_reset} ${c_val}${u}${c_reset} ${c_dim}from${c_reset} ${c_val}${i}${c_reset} ${c_dim}->${c_reset} ${c}${t}${c_reset}"
    fi
done
echo_rail ""

echo_rail "${c_bold}${c_val}SYSTEM MATRIX${c_reset}   ${c_dim}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${c_reset}"
echo_rail " ${c_label}CPU Load   :${c_reset} ${c_val}${LOAD1}, ${LOAD5}, ${LOAD15}${c_reset} ${c_dim}[${CPU_CORES} Cores]${c_reset}  ${c_label}Up:${c_reset} ${c_val}${UPTIME_STR}${c_reset}"
echo_rail " ${c_label}Top Process:${c_reset} ${c_crit}${TOP_CMD}${c_reset} ${c_dim}(${TOP_CPU}%)${c_reset}"
echo_rail " ${c_label}RAM Target :${c_reset} [$(draw_bar "$RAM_PERCENT")] ${c_val}${RAM_USE_GB}G${c_reset}${c_dim} / ${RAM_TOT_GB}G${c_reset}"
echo_rail " ${c_label}Disk Mount :${c_reset} [$(draw_bar "$DISK_PERCENT")] ${c_val}${DISK_USED}${c_reset}${c_dim} / ${DISK_SIZE}${c_reset}"
echo_rail ""

echo_rail "${c_bold}${c_val}EDGE NETWORK${c_reset}    ${c_dim}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${c_reset}"
echo_rail " ${c_label}Routing IPs:${c_reset} ${c_dim}L:${c_reset} ${c_val}${IP_LOCAL}${c_reset}  ${c_dim}P:${c_reset} ${c_val}${IP_PUBLIC}${c_reset}"
echo_rail " ${c_label}Traffic I/O:${c_reset} ${NET_TRAFFIC} ${c_dim}(${IFACE:-unknown})${c_reset}"
echo_rail " ${c_label}Daemons    :${c_reset} $SVC_F2B  $SVC_CP  $SVC_NGX  $SVC_MYS"
echo_rail ""
echo -e "${c_rail}▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀${c_reset}"
echo ""
