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
// --- 1. VGT SUPREME PANOPTICON PALETTE & UI TOKENS ---
const (
	cReset  = "\033[0m"
	cBold   = "\033[1m"
	cDim    = "\033[38;5;239m" // Deep Grid Dim
	cInv    = "\033[7m"

	cGrid   = "\033[38;5;25m"  // VGT Deep Azure Border
	cBrand  = "\033[38;5;39m"  // VGT Bright Blue
	cLabel  = "\033[38;5;246m"
	cVal    = "\033[38;5;255m"

	cOk     = "\033[38;5;46m"  // Neon Green
	cWarn   = "\033[38;5;214m" // Warning Orange
	cCrit   = "\033[38;5;196m" // Critical Red
	cMag    = "\033[38;5;135m"
	cBarBg  = "\033[38;5;235m" // Empty Bar Bg

	gNode   = "◈"
	gArr    = "›"
	gDot    = "·"
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
			// VGT FIX: Raw String. ANSI-Codes im String zerstören das %-12s Alignment.
			state.Privilege = "ROOT"
		} else {
			state.Privilege = "USER"
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
	scanner.Buffer(make([]byte, 4096), 4096)

	for scanner.Scan() {
		line := scanner.Text()
		
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

	// VGT Multi-Layer Verification: Systemd + Kernel Process Table (KPT)
	state.SvcFail2Ban = checkService(ctx, "fail2ban") || isProcessRunning("fail2ban-server")
	state.SvcNginx = checkService(ctx, "nginx") || isProcessRunning("nginx")
	state.SvcMySQL = checkService(ctx, "mysqld") || checkService(ctx, "mysql") || isProcessRunning("mysqld")

	state.LogReadable = false
	parseFail2BanLog("/var/log/fail2ban.log", state)
	if state.LogReadable && state.BannedCount == 0 {
		if stat, err := os.Stat("/var/log/fail2ban.log"); err == nil && stat.Size() < 4096 {
			parseFail2BanLog("/var/log/fail2ban.log.1", state)
		}
	}

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
	err := exec.CommandContext(ctx, cmdSystemctl, "is-active", "--quiet", name).Run()
	return err == nil
}

// VGT KERNEL DIREKTIVE: Deep Process Table Scanning (KPT-Scan)
// Umgeht Systemd-Illusionen (Docker, Custom Binaries). Zero-Allocation Check.
func isProcessRunning(target string) bool {
	d, err := os.Open("/proc")
	if err != nil {
		return false
	}
	defer d.Close()

	names, err := d.Readdirnames(-1)
	if err != nil {
		return false
	}

	buf := make([]byte, 64)
	for _, pid := range names {
		// Überspringe Nicht-PID-Ordner
		if pid[0] < '0' || pid[0] > '9' {
			continue
		}
		f, err := os.Open("/proc/" + pid + "/comm")
		if err != nil {
			continue
		}
		n, _ := f.Read(buf)
		f.Close()

		if n > 0 {
			// Der Go-Compiler optimiert string(byte_slice) == string zu 0 Heap Allokationen
			if buf[n-1] == '\n' {
				if string(buf[:n-1]) == target {
					return true
				}
			} else {
				if string(buf[:n]) == target {
					return true
				}
			}
		}
	}
	return false
}

// --- 5. SUB-PIXEL TACTICAL RENDER ENGINE ---

// drawBar implementiert 100% Terminal-sicheres Block Rendering
// VGT FIX: Sub-Pixel Zeichen (▏▎▍) entfernt. Verhindert Fallback-Glitches in bestimmten Terminals.
func drawBar(percent int) string {
	if percent < 0 {
		percent = 0
	} else if percent > 100 {
		percent = 100
	}

	barLen := 24 
	filled := (percent * barLen) / 100
	empty := barLen - filled

	color := cOk
	if percent > 70 {
		color = cWarn
	}
	if percent > 85 {
		color = cCrit
	}

	bFilled := strings.Repeat("█", filled)
	bEmpty := strings.Repeat("░", empty)

	return fmt.Sprintf("%s%s%s%s%s", color, bFilled, cDim, bEmpty, cReset)
}

func formatSvc(active bool, name string) string {
	if active {
		return fmt.Sprintf("%s[%s●%s]%s %s%s%s", cDim, cOk, cDim, cReset, cVal, name, cReset)
	}
	return fmt.Sprintf("%s[%s◌%s]%s %s%s%s", cDim, cCrit, cDim, cReset, cDim, name, cReset)
}

func printRow(label, val string) {
	fmt.Printf("%s │ %s %s%-12s%s %s\n", cGrid, cReset, cLabel, label+":", cReset, val)
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 850*time.Millisecond)
	defer cancel()

	termWidth := getTermWidth()
	if termWidth > 100 {
		termWidth = 100 // Cap UI aesthetic spread
	}

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

	// -------------------------------------------------------------------------
	// 6. FINAL UI RENDER (DIAMOND PANOPTICON LAYOUT)
	// -------------------------------------------------------------------------
	
	fmt.Println()
	fmt.Println()

	bLineLen := termWidth - 4
	if bLineLen < 46 {
		bLineLen = 46
	}
	hLine := strings.Repeat("─", bLineLen)
	
	// === HEADER ===
	fmt.Printf("%s ╭%s╮%s\n", cGrid, hLine, cReset)
	fmt.Printf("%s │ %s%s %sVISIONGAIA TECHNOLOGY %s// %sAPEX NODE %s %s\n", 
		cGrid, cBrand, gNode, cBold, cDim, cBrand, strings.Repeat(" ", bLineLen-38), cReset)
	fmt.Printf("%s ├%s┤%s\n", cGrid, hLine, cReset)

	// === IDENTITY ===
	// VGT FIX: Argument-Mismatches korrigiert, ANSI-Padding ausgelagert.
	privColor := cOk
	if sys.Privilege == "ROOT" {
		privColor = cCrit
	}

	fmt.Printf("%s │ %s %sNODE:%s %s%-16s%s %sAUTH:%s %s%-10s%s %sSYS:%s %s%s%s\n", 
		cGrid, cReset, 
		cLabel, cReset, cVal, strings.ToUpper(sys.HostName), cReset, 
		cLabel, cReset, privColor, sys.Privilege, cReset,
		cLabel, cReset, cVal, sys.OS, cReset)
	fmt.Printf("%s ├%s┤%s\n", cGrid, hLine, cReset)

	// === TACTICAL INTEL ===
	fmt.Printf("%s │ %s%sTACTICAL INTEL%s\n", cGrid, cBold, cVal, cReset)
	
	if sec.LogReadable {
		printRow("IDS Status", fmt.Sprintf("%s%d attackers blocked%s (fail2ban)", cWarn, sec.BannedCount, cReset))
	} else {
		printRow("IDS Status", fmt.Sprintf("%sNO AUDIT DATA (ROOT REQUIRED)%s", cDim, cReset))
	}

	if len(sec.RecentBans) > 0 {
		for _, ban := range sec.RecentBans {
			fmt.Printf("%s │ %s   %s%s DROP%s  %s%-15s%s %svia %s [%s]%s\n", 
				cGrid, cReset, cCrit, gArr, cReset, cVal, ban.IP, cReset, cDim, ban.Jail, ban.Time, cReset)
		}
	} else if sec.LogReadable {
		fmt.Printf("%s │ %s   %s%s SECURE%s %sZero network anomalies detected.%s\n", 
			cGrid, cReset, cOk, gArr, cReset, cDim, cReset)
	}

	printRow("Last Auth", "")
	if len(sec.RecentLogins) > 0 {
		for _, login := range sec.RecentLogins {
			c := cDim
			if login.Active {
				c = cOk
			}
			fmt.Printf("%s │ %s   %s%s GRANT%s %s%-10s%s %sfrom%s %s%-15s%s %s%s%s\n", 
				cGrid, cReset, cBrand, gArr, cReset, cVal, login.User, cReset, cDim, cReset, cVal, login.IP, cReset, c, login.Time, cReset)
		}
	} else {
		fmt.Printf("%s │ %s   %s[-] Log buffer void.%s\n", cGrid, cReset, cDim, cReset)
	}
	fmt.Printf("%s ├%s┤%s\n", cGrid, hLine, cReset)

	// === SYSTEM MATRIX ===
	fmt.Printf("%s │ %s%sSYSTEM MATRIX%s\n", cGrid, cBold, cVal, cReset)
	printRow("CPU Load", fmt.Sprintf("%s%s%s %s[%d Cores]%s  %sUp:%s %s%s%s", 
		cVal, sys.Load, cReset, cDim, sys.Cores, cReset, cLabel, cReset, cVal, sys.Uptime, cReset))
	
	// VGT FIX: Mathematisches Alignment der Storage/RAM Zahlen (mit %6.1fG für saubere Abstände)
	printRow("RAM Target", fmt.Sprintf("[%s] %s%5.1fG%s%s / %6.1fG%s", 
		drawBar(sys.RAMPercent), cVal, sys.RAMUsedGB, cReset, cDim, sys.RAMTotalGB, cReset))
	printRow("Disk Mount", fmt.Sprintf("[%s] %s%5.1fG%s%s / %6.1fG%s", 
		drawBar(sys.DiskPercent), cVal, sys.DiskUsedGB, cReset, cDim, sys.DiskTotalGB, cReset))
	fmt.Printf("%s ├%s┤%s\n", cGrid, hLine, cReset)

	// === EDGE NETWORK ===
	fmt.Printf("%s │ %s%sEDGE NETWORK%s\n", cGrid, cBold, cVal, cReset)
	printRow("Routing", fmt.Sprintf("%sL:%s %s%-15s%s  %sP:%s %s%s%s", 
		cDim, cReset, cVal, net.LocalIP, cReset, cDim, cReset, cVal, net.PublicIP, cReset))
	printRow("Daemons", fmt.Sprintf("%s  %s  %s", 
		formatSvc(sec.SvcFail2Ban, "fail2ban"), formatSvc(sec.SvcNginx, "nginx"), formatSvc(sec.SvcMySQL, "mysql")))
	
	// === FOOTER ===
	fmt.Printf("%s ╰%s╯%s\n\n", cGrid, hLine, cReset)
}
