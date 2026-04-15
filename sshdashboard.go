//go:build linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// --- 1. VGT SUPREME UI TOKENS (ANSI 256 / TRUECOLOR METRICS) ---
const (
	cReset   = "\033[0m"
	cBold    = "\033[1m"
	cDim     = "\033[38;5;240m"
	cText    = "\033[38;5;250m"
	cPrimary = "\033[38;5;39m"  // VGT Azure
	cSec     = "\033[38;5;87m"  // VGT Cyan
	cAlert   = "\033[38;5;196m" // Critical Red
	cWarn    = "\033[38;5;214m" // Warning Orange
	cSafe    = "\033[38;5;112m" // System Green
	cDarkBg  = "\033[38;5;234m" // Deep Slate

	gSys = "◈"
	gNet = "⟁"
	gSec = "✇"
	gUsr = "⎈"
	gArr = "⟩"
)

// --- 2. ARCHITECTURE & STATE MEMORY ---
type SystemState struct {
	HostName    string
	UserName    string
	Privilege   string
	Uptime      string
	Load        string
	Cores       int
	OS          string
	Kernel      string
	RAMUsedGB   float64
	RAMTotalGB  float64
	RAMPercent  int
	DiskUsedGB  float64
	DiskTotalGB float64
	DiskPercent int
}

type NetworkState struct {
	LocalIP  string
	PublicIP string
}

type SecurityState struct {
	SvcFail2Ban  bool
	SvcNginx     bool
	SvcMySQL     bool
	BannedCount  int
	RecentBans   []BanEntry
	LogReadable  bool
	RecentLogins []LoginEntry
}

type BanEntry struct {
	Date string
	Time string
	Jail string
	IP   string
}

type LoginEntry struct {
	User   string
	TTY    string
	IP     string
	Time   string
	Active bool
}

// O(1) Regex Compilation
var (
	rxFail2Ban = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})[^\[]*\[([a-zA-Z0-9_-]+)\]\s+Ban\s+([0-9a-fA-F:\.]+)`)
	rxLast     = regexp.MustCompile(`^([a-zA-Z0-9_-]+)\s+([a-zA-Z0-9/_-]+)\s+(.*?)\s+([0-9a-fA-F:\.]+)\s*$`)
)

// Absolute Path Definitions (CWE-426 PATH Hijacking Prevention)
const (
	cmdLast      = "/usr/bin/last"
	cmdSystemctl = "/bin/systemctl"
)

// --- 3. HARDENED KERNEL & MEMORY SANITIZATION ---

// b2s: Safe zero-allocation string casting with guaranteed bounds checking to prevent OOB Panic.
func b2s(b []int8) string {
	if len(b) == 0 {
		return ""
	}
	max := len(b)
	n := 0
	for ; n < max && b[n] != 0; n++ {
	}
	if n == 0 {
		return ""
	}
	return unsafe.String((*byte)(unsafe.Pointer(&b[0])), n)
}

func sanitizeIP(input string) string {
	if ip := net.ParseIP(strings.TrimSpace(input)); ip != nil {
		return ip.String()
	}
	return "UNKNOWN_HOST"
}

func sanitizeStr(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '.' || c == '_' || c == ':' || c == '-' || c == ' ' || c == '/' || c == '(' || c == ')' {
			b.WriteByte(c)
		}
	}
	if b.Len() > 64 {
		return b.String()[:64]
	}
	return b.String()
}

// fastParseUint: Zero-allocation, reflection-free integer parsing for /proc/meminfo
func fastParseUint(s string) uint64 {
	var n uint64
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			n = n*10 + uint64(s[i]-'0')
		}
	}
	return n
}

func getTermWidth() int {
	ws := &struct{ Row, Col, Xpixel, Ypixel uint16 }{}
	retCode, _, _ := syscall.Syscall(syscall.SYS_IOCTL, uintptr(syscall.Stdout), uintptr(syscall.TIOCGWINSZ), uintptr(unsafe.Pointer(ws)))
	if int(retCode) == -1 || ws.Col == 0 {
		return 80
	}
	return int(ws.Col)
}

// --- 4. CONCURRENT EXTRACTION ENGINES ---

func getSystemState(ctx context.Context, wg *sync.WaitGroup, state *SystemState) {
	defer wg.Done()

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	state.HostName = sanitizeStr(hostname)

	if u, err := user.Current(); err == nil {
		state.UserName = sanitizeStr(u.Username)
		if u.Uid == "0" {
			state.Privilege = cAlert + "ROOT" + cReset
		} else {
			state.Privilege = cSec + "USER" + cReset
		}
	}

	var info syscall.Sysinfo_t
	if err := syscall.Sysinfo(&info); err == nil {
		upD := info.Uptime / 86400
		upH := (info.Uptime % 86400) / 3600
		upM := (info.Uptime % 3600) / 60
		state.Uptime = fmt.Sprintf("%dd %dh %dm", upD, upH, upM)
		state.Load = fmt.Sprintf("%.2f, %.2f, %.2f", float64(info.Loads[0])/65536.0, float64(info.Loads[1])/65536.0, float64(info.Loads[2])/65536.0)
	}
	state.Cores = runtime.NumCPU()

	var uts syscall.Utsname
	if err := syscall.Uname(&uts); err == nil {
		state.Kernel = sanitizeStr(b2s(uts.Release[:]))
	}

	state.OS = "Linux"
	func() {
		f, err := os.Open("/etc/os-release")
		if err != nil {
			return
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				state.OS = sanitizeStr(strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`))
				break
			}
		}
	}()

	func() {
		f, err := os.Open("/proc/meminfo")
		if err != nil {
			return
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		var memTotal, memAvail uint64
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "MemTotal:") {
				memTotal = fastParseUint(line)
			} else if strings.HasPrefix(line, "MemAvailable:") {
				memAvail = fastParseUint(line)
			}
			if memTotal > 0 && memAvail > 0 {
				break
			}
		}
		state.RAMTotalGB = float64(memTotal) / 1024 / 1024
		usedMem := memTotal - memAvail
		state.RAMUsedGB = float64(usedMem) / 1024 / 1024
		if memTotal > 0 {
			state.RAMPercent = int((float64(usedMem) / float64(memTotal)) * 100)
		} else {
			state.RAMPercent = 0
			state.RAMTotalGB = 0.1 // NaN Prevention
		}
	}()

	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err == nil {
		total := stat.Blocks * uint64(stat.Bsize)
		free := stat.Bavail * uint64(stat.Bsize)
		used := total - free
		state.DiskTotalGB = float64(total) / 1024 / 1024 / 1024
		state.DiskUsedGB = float64(used) / 1024 / 1024 / 1024
		if total > 0 {
			state.DiskPercent = int((float64(used) / float64(total)) * 100)
		} else {
			state.DiskPercent = 0
			state.DiskTotalGB = 0.1 // NaN Prevention
		}
	}
}

func getNetworkState(ctx context.Context, wg *sync.WaitGroup, state *NetworkState) {
	defer wg.Done()
	var netWg sync.WaitGroup
	netWg.Add(2)

	go func() {
		defer netWg.Done()
		var d net.Dialer
		conn, err := d.DialContext(ctx, "udp", "1.1.1.1:80")
		if err == nil {
			defer conn.Close()
			state.LocalIP = conn.LocalAddr().(*net.UDPAddr).IP.String()
		} else {
			state.LocalIP = "127.0.0.1 (OFFLINE)"
		}
	}()

	go func() {
		defer netWg.Done()
		r := &net.Resolver{
			PreferGo: true,
			Dial: func(rCtx context.Context, network, address string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(rCtx, "udp", "1.1.1.1:53")
			},
		}
		txts, err := r.LookupTXT(ctx, "whoami.cloudflare")
		if err == nil && len(txts) > 0 {
			state.PublicIP = sanitizeIP(txts[0])
		} else {
			state.PublicIP = "OFFLINE/UNREACHABLE"
		}
	}()
	netWg.Wait()
}

func parseFail2BanLog(filePath string, state *SecurityState) {
	file, err := os.Open(filePath)
	if err != nil {
		return
	}
	defer file.Close()
	state.LogReadable = true

	stat, _ := file.Stat()
	size := stat.Size()
	var offset int64 = 0
	if size > 65536 {
		offset = size - 65536
	}
	file.Seek(offset, 0)

	var r *bufio.Reader
	if offset > 0 {
		r = bufio.NewReader(file)
		r.ReadString('\n')
	} else {
		r = bufio.NewReader(file)
	}

	scanner := bufio.NewScanner(r)
	// VGT Security: Prevent Scanner DoS Attack (Max 4KB per line, dropping larger lines)
	scanner.Buffer(make([]byte, 4096), 4096)

	for scanner.Scan() {
		line := scanner.Text()
		
		// VGT HÄRTUNG: ReDoS Prevention durch striktes Line-Length Capping
		if len(line) > 512 || len(line) < 40 {
			continue
		}

		if strings.Contains(line, " Ban ") {
			state.BannedCount++
			matches := rxFail2Ban.FindStringSubmatch(line)
			if len(matches) == 5 {
				if len(state.RecentBans) >= 4 {
					state.RecentBans = state.RecentBans[1:]
				}
				state.RecentBans = append(state.RecentBans, BanEntry{
					Date: matches[1], Time: matches[2], Jail: sanitizeStr(matches[3]), IP: sanitizeIP(matches[4]),
				})
			}
		}
	}
}

func getSecurityState(ctx context.Context, wg *sync.WaitGroup, state *SecurityState) {
	defer wg.Done()

	state.SvcFail2Ban = checkService(ctx, "fail2ban")
	state.SvcNginx = checkService(ctx, "nginx")
	state.SvcMySQL = checkService(ctx, "mysqld") || checkService(ctx, "mysql")

	state.LogReadable = false
	parseFail2BanLog("/var/log/fail2ban.log", state)
	if state.LogReadable && state.BannedCount == 0 {
		if stat, err := os.Stat("/var/log/fail2ban.log"); err == nil && stat.Size() < 4096 {
			parseFail2BanLog("/var/log/fail2ban.log.1", state)
		}
	}

	// CWE-426 Fix: Nutzung absoluter Pfade für Binary-Execution
	out, err := exec.CommandContext(ctx, cmdLast, "-a", "-w", "-n", "10").Output()
	if err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(out))
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" || strings.HasPrefix(line, "wtmp") {
				continue
			}
			matches := rxLast.FindStringSubmatch(line)
			if len(matches) == 5 {
				timeStr := sanitizeStr(matches[3])
				state.RecentLogins = append(state.RecentLogins, LoginEntry{
					User:   sanitizeStr(matches[1]),
					TTY:    sanitizeStr(matches[2]),
					Time:   timeStr,
					IP:     sanitizeIP(matches[4]),
					Active: strings.Contains(timeStr, "in"),
				})
				if len(state.RecentLogins) >= 4 {
					break
				}
			}
		}
	}
}

func checkService(ctx context.Context, name string) bool {
	// CWE-426 Fix: Nutzung absoluter Pfade für Binary-Execution
	err := exec.CommandContext(ctx, cmdSystemctl, "is-active", "--quiet", name).Run()
	return err == nil
}

// --- 5. RENDER ENGINE (VGT DIAMOND TIER UI) ---

func drawBar(percent int, maxWidth int) string {
	if percent < 0 {
		percent = 0
	} else if percent > 100 {
		percent = 100
	}

	barLen := maxWidth - 26
	if barLen < 10 {
		barLen = 10
	} else if barLen > 50 {
		barLen = 50
	}

	filled := (percent * barLen) / 100
	empty := barLen - filled

	color := cSafe
	if percent > 75 {
		color = cWarn
	}
	if percent > 90 {
		color = cAlert
	}

	// Sub-pixel aesthetic rendering
	bFilled := strings.Repeat("█", filled)
	bEmpty := strings.Repeat("░", empty)

	return fmt.Sprintf("%s%s%s%s%s", color, bFilled, cDarkBg, bEmpty, cReset)
}

func printRow(glyph, label, val string) {
	fmt.Printf("  %s%s%s %s%-14s%s %s\n", cPrimary, glyph, cReset, cText, label+":", cReset, val)
}

func drawSection(title, glyph string, termWidth int) {
	lineLen := termWidth - len(title) - 10
	if lineLen > 50 {
		lineLen = 50
	} else if lineLen < 5 {
		lineLen = 5
	}
	lineStr := strings.Repeat("─", lineLen)
	fmt.Printf("  %s├─ %s%s %s %s%s%s\n", cDim, cPrimary, glyph, title, cDim, lineStr, cReset)
}

func formatSvc(active bool, name string) string {
	if active {
		return fmt.Sprintf("%s[%s◉%s]%s %s%s%s", cDim, cSafe, cDim, cReset, cText, name, cReset)
	}
	return fmt.Sprintf("%s[%s◌%s]%s %s%s%s", cDim, cAlert, cDim, cReset, cDim, name, cReset)
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 850*time.Millisecond) // Aggressive UI Timeout
	defer cancel()

	termWidth := getTermWidth()

	var wg sync.WaitGroup
	var sys SystemState
	var net NetworkState
	var sec SecurityState

	wg.Add(3)
	go getSystemState(ctx, &wg, &sys)
	go getNetworkState(ctx, &wg, &net)
	go getSecurityState(ctx, &wg, &sec)

	waitChan := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitChan)
	}()

	select {
	case <-waitChan:
	case <-ctx.Done():
	}

	// TUI RENDER TREE
	fmt.Print("\033[H\033[2J\n")

	headLen := 60
	if termWidth < 64 {
		headLen = termWidth - 4
	}
	topBorder := strings.Repeat("━", headLen)

	fmt.Printf("  %s┏%s┓%s\n", cPrimary, topBorder, cReset)
	fmt.Printf("  %s┃%s  %s%sVISIONGAIATECHNOLOGY%s %s// APEX NODE HUD%s  %s┃%s\n", cPrimary, cReset, cSec, cBold, cReset, cDim, cReset, cPrimary, cReset)
	fmt.Printf("  %s┗%s┛%s\n\n", cPrimary, topBorder, cReset)

	printRow(gUsr, "Identity", fmt.Sprintf("%s%s@%s%s  %s[%s%s]%s", cText, sys.UserName, sys.HostName, cReset, cDim, sys.Privilege, cDim, cReset))
	fmt.Println()

	printRow(gSys, "OS Core", fmt.Sprintf("%s%s%s", cText, sys.OS, cReset))
	printRow(" ", "Kernel", fmt.Sprintf("%s%s%s", cDim, sys.Kernel, cReset))
	printRow(" ", "Uptime", fmt.Sprintf("%s%s%s", cSec, sys.Uptime, cReset))
	printRow(" ", "Telemetry", fmt.Sprintf("%s%s%s %s[Cores: %d]%s", cText, sys.Load, cReset, cDim, sys.Cores, cReset))
	fmt.Println()

	printRow(gNet, "Internal IP", fmt.Sprintf("%s%s%s", cSec, net.LocalIP, cReset))
	printRow(" ", "External Node", fmt.Sprintf("%s%s%s", cPrimary, net.PublicIP, cReset))
	fmt.Println()

	fmt.Printf("  %s%s%s %s%-14s%s %.1fG alloc / %.1fG free  %s[%.1fG]%s\n", cPrimary, gSys, cReset, cText, "Memory:", cReset, sys.RAMUsedGB, (sys.RAMTotalGB - sys.RAMUsedGB), cDim, sys.RAMTotalGB, cReset)
	fmt.Printf("  %-17s %s\n\n", "", drawBar(sys.RAMPercent, termWidth))

	fmt.Printf("  %s%s%s %s%-14s%s %.1fG alloc / %.1fG free  %s[%.1fG]%s\n", cPrimary, gSys, cReset, cText, "Storage (/):", cReset, sys.DiskUsedGB, (sys.DiskTotalGB - sys.DiskUsedGB), cDim, sys.DiskTotalGB, cReset)
	fmt.Printf("  %-17s %s\n\n", "", drawBar(sys.DiskPercent, termWidth))

	printRow(gSys, "Daemons", fmt.Sprintf("%s  %s  %s", formatSvc(sec.SvcFail2Ban, "fail2ban"), formatSvc(sec.SvcNginx, "nginx"), formatSvc(sec.SvcMySQL, "mysql")))
	fmt.Println()

	// SEC-OPS SUB-DASHBOARD
	drawSection("Perimeter Defense", gSec, termWidth)
	if sec.LogReadable {
		fmt.Printf("    %s%-13s%s %s%d MALICIOUS ACTORS BLOCKED%s\n\n", cText, "Status:", cReset, cWarn, sec.BannedCount, cReset)
	} else {
		fmt.Printf("    %s%-13s%s %sNO AUDIT DATA (ROOT REQUIRED)%s\n\n", cText, "Status:", cReset, cDim, cReset)
	}

	if len(sec.RecentBans) > 0 {
		for _, ban := range sec.RecentBans {
			fmt.Printf("    %s%s%s %s%-15s%s %s%-12s%s %s%s %s%s\n", cDim, gArr, cReset, cAlert, ban.IP, cReset, cText, string(ban.Jail), cReset, cDim, ban.Date, ban.Time, cReset)
		}
	} else if sec.LogReadable {
		fmt.Printf("    %s[+] Zero network anomalies detected.%s\n", cSafe, cReset)
	}
	fmt.Println()

	drawSection("Access Ledger", gUsr, termWidth)
	if len(sec.RecentLogins) > 0 {
		for _, login := range sec.RecentLogins {
			stCol := cText
			if login.Active {
				stCol = cSafe
			}
			fmt.Printf("    %s%s%s %s%-14s%s %s%-8s%s %s%-15s%s %s%s%s\n", cDim, gArr, cReset, cText, login.User, cReset, cDim, login.TTY, cReset, cSec, login.IP, cReset, stCol, login.Time, cReset)
		}
	} else {
		fmt.Printf("    %s[-] Log buffer void.%s\n", cDim, cReset)
	}

	fmt.Println()
	fmt.Printf("  %s━━ VGT OMEGA PROTOCOL ACTIVE // END OF REPORT ━━%s\n\n", cDim, cReset)
}
