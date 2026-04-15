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

// --- 1. NEON TACTICAL PALETTE & UI TOKENS ---
const (
	cReset  = "\033[0m"
	cBold   = "\033[1m"
	cDim    = "\033[2m"
	cInv    = "\033[7m"

	cRail   = "\033[38;5;39m"
	cBrand  = "\033[38;5;81m"
	cLabel  = "\033[38;5;244m"
	cVal    = "\033[38;5;255m"

	cOk     = "\033[38;5;113m"
	cWarn   = "\033[38;5;220m"
	cCrit   = "\033[38;5;196m"
	cMag    = "\033[38;5;170m"
	cBarBg  = "\033[38;5;235m"

	gRail   = "▊"
	gArr    = "▶"
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
			state.Privilege = cCrit + "ROOT" + cReset
		} else {
			state.Privilege = cOk + "USER" + cReset
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

// --- 5. TACTICAL RENDER ENGINE ---

func printRail(text string) {
	fmt.Printf("%s%s%s %s\n", cRail, gRail, cReset, text)
}

func drawBar(percent int) string {
	if percent < 0 {
		percent = 0
	} else if percent > 100 {
		percent = 100
	}

	barLen := 24 // Fixed length for Tactical UI
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
	bEmpty := strings.Repeat("·", empty)

	return fmt.Sprintf("%s%s%s%s%s", color, bFilled, cBarBg, bEmpty, cReset)
}

func formatSvc(active bool, name string) string {
	if active {
		return fmt.Sprintf("%s[%s●%s]%s %s%s%s", cDim, cOk, cDim, cReset, cVal, name, cReset)
	}
	return fmt.Sprintf("%s[%s◌%s]%s %s%s%s", cDim, cCrit, cDim, cReset, cDim, name, cReset)
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
	// 6. FINAL UI RENDER (NEON TACTICAL LAYOUT)
	// -------------------------------------------------------------------------
	
	// VGT FIX: Kein `clear`. Schützt den Admin-Scrollback. Nur visuelle Trennung.
	fmt.Println()
	fmt.Println()

	bLineLen := termWidth - 4
	if bLineLen < 40 {
		bLineLen = 40
	}

	// HEADER
	printRail(fmt.Sprintf("%s %s", cBrand, strings.Repeat("▀", bLineLen)+cReset))
	printRail(fmt.Sprintf("  %s%sVISIONGAIA TECHNOLOGY%s  %s//%s  %sOMEGA PROTOCOL%s", cBold, cVal, cReset, cDim, cReset, cBrand, cReset))
	printRail(fmt.Sprintf("  %sNODE:%s %s%s%s  %sAUTH:%s %s  %sSYS:%s %s%s%s", 
		cLabel, cReset, cVal, strings.ToUpper(sys.HostName), cReset, 
		cLabel, cReset, sys.Privilege, 
		cLabel, cReset, cVal, sys.OS, cReset))
	printRail(fmt.Sprintf("%s %s", cBrand, strings.Repeat("▄", bLineLen)+cReset))
	printRail("")

	// TACTICAL INTEL
	sep := strings.Repeat("━", 50)
	printRail(fmt.Sprintf("%s%sTACTICAL INTEL%s  %s%s%s", cBold, cVal, cReset, cDim, sep, cReset))
	
	if sec.LogReadable {
		printRail(fmt.Sprintf(" %sIDS Status :%s %s%d attackers blocked%s (fail2ban)", cLabel, cReset, cWarn, sec.BannedCount, cReset))
	} else {
		printRail(fmt.Sprintf(" %sIDS Status :%s %sNO AUDIT DATA (ROOT REQUIRED)%s", cLabel, cReset, cDim, cReset))
	}

	if len(sec.RecentBans) > 0 {
		for _, ban := range sec.RecentBans {
			printRail(fmt.Sprintf("   %s%s DROP%s  %s%s%s %svia %s [%s]%s", cCrit, gArr, cReset, cVal, ban.IP, cReset, cDim, ban.Jail, ban.Time, cReset))
		}
	} else if sec.LogReadable {
		printRail(fmt.Sprintf("   %s%s SECURE%s %sZero network anomalies detected.%s", cOk, gArr, cReset, cDim, cReset))
	}

	printRail(fmt.Sprintf(" %sLast Auth  :%s", cLabel, cReset))
	if len(sec.RecentLogins) > 0 {
		for _, login := range sec.RecentLogins {
			c := cDim
			if login.Active {
				c = cOk
			}
			printRail(fmt.Sprintf("   %s%s GRANT%s %s%s%s %sfrom%s %s%s%s %s->%s %s%s%s", 
				cBrand, gArr, cReset, cVal, login.User, cReset, cDim, cReset, cVal, login.IP, cReset, cDim, cReset, c, login.Time, cReset))
		}
	} else {
		printRail(fmt.Sprintf("   %s[-] Log buffer void.%s", cDim, cReset))
	}
	printRail("")

	// SYSTEM MATRIX
	printRail(fmt.Sprintf("%s%sSYSTEM MATRIX%s   %s%s%s", cBold, cVal, cReset, cDim, sep, cReset))
	printRail(fmt.Sprintf(" %sCPU Load   :%s %s%s%s %s[%d Cores]%s  %sUp:%s %s%s%s", 
		cLabel, cReset, cVal, sys.Load, cReset, cDim, sys.Cores, cReset, cLabel, cReset, cVal, sys.Uptime, cReset))
	printRail(fmt.Sprintf(" %sRAM Target :%s [%s] %s%.1fG%s%s / %.1fG%s", 
		cLabel, cReset, drawBar(sys.RAMPercent), cVal, sys.RAMUsedGB, cReset, cDim, sys.RAMTotalGB, cReset))
	printRail(fmt.Sprintf(" %sDisk Mount :%s [%s] %s%.1fG%s%s / %.1fG%s", 
		cLabel, cReset, drawBar(sys.DiskPercent), cVal, sys.DiskUsedGB, cReset, cDim, sys.DiskTotalGB, cReset))
	printRail("")

	// EDGE NETWORK
	printRail(fmt.Sprintf("%s%sEDGE NETWORK%s    %s%s%s", cBold, cVal, cReset, cDim, sep, cReset))
	printRail(fmt.Sprintf(" %sRouting IPs:%s %sL:%s %s%s%s  %sP:%s %s%s%s", 
		cLabel, cReset, cDim, cReset, cVal, net.LocalIP, cReset, cDim, cReset, cVal, net.PublicIP, cReset))
	printRail(fmt.Sprintf(" %sDaemons    :%s %s  %s  %s", 
		cLabel, cReset, formatSvc(sec.SvcFail2Ban, "fail2ban"), formatSvc(sec.SvcNginx, "nginx"), formatSvc(sec.SvcMySQL, "mysql")))
	printRail("")
	
	// FOOTER
	printRail(fmt.Sprintf("%s▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀%s", cRail, cReset))
	fmt.Println()
}
