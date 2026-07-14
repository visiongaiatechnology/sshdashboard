// STATUS: DIAMANT VGT SUPREME
//go:build linux

package collectors

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"sshdash/types"
	"sshdash/utils"
)

var (
	rxFail2Ban = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})[^\[]*\[([a-zA-Z0-9_-]+)\]\s+Ban\s+([0-9a-fA-F:\.]+)`)
	rxLast     = regexp.MustCompile(`^([a-zA-Z0-9_-]+)\s+([a-zA-Z0-9/_-]+)\s+(.*?)\s+([0-9a-fA-F:\.]+)\s*$`)
)

func GetSecurityState(ctx context.Context, wg *sync.WaitGroup, state *types.SecurityState) {
	defer wg.Done()

	// 1. Dual-Layer Verification: Systemd + KPT Deep Scan
	state.SvcFail2Ban = checkService(ctx, "fail2ban") || IsProcessRunning("fail2ban-server")
	state.SvcNginx = checkService(ctx, "nginx") || IsProcessRunning("nginx")
	state.SvcMySQL = checkService(ctx, "mysqld") || checkService(ctx, "mysql") || IsProcessRunning("mysqld")
	state.SvcUFW = checkService(ctx, "ufw") || IsProcessRunning("ufw")

	// 2. Fail2ban Tail Inspection
	state.LogReadable = false
	parseFail2BanLog("/var/log/fail2ban.log", state)
	if state.LogReadable && state.BannedCount == 0 {
		if stat, err := os.Stat("/var/log/fail2ban.log"); err == nil && stat.Size() < 4096 {
			parseFail2BanLog("/var/log/fail2ban.log.1", state)
		}
	}

	// 3. Wtmp Authentication Audit with Bounded Output Buffer (Max 128KB)
	cmdL := exec.CommandContext(ctx, utils.CmdLast, "-a", "-w", "-n", "8")
	outL, err := readBoundedCommandOutput(cmdL, 128*1024)
	if err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(outL))
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" || strings.HasPrefix(line, "wtmp") || strings.HasPrefix(line, "reboot") {
				continue
			}
			matches := rxLast.FindStringSubmatch(line)
			if len(matches) == 5 {
				timeStr := utils.SanitizeStr(matches[3])
				state.RecentLogins = append(state.RecentLogins, types.LoginEntry{
					User:   utils.SanitizeStr(matches[1]),
					TTY:    utils.SanitizeStr(matches[2]),
					Time:   timeStr,
					IP:     utils.SanitizeIP(matches[4]),
					Active: strings.Contains(timeStr, "in"),
				})
				if len(state.RecentLogins) >= 5 {
					break
				}
			}
		}
	}

	// 4. Active SSH User Sessions Inspection (Max 128KB)
	cmdW := exec.CommandContext(ctx, utils.CmdW, "-h")
	outW, err := readBoundedCommandOutput(cmdW, 128*1024)
	if err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(outW))
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 4 {
				userStr := utils.SanitizeStr(fields[0])
				ttyStr := utils.SanitizeStr(fields[1])
				fromStr := utils.SanitizeIP(fields[2])
				idleStr := "0s"
				if len(fields) >= 5 {
					idleStr = utils.SanitizeStr(fields[4])
				}
				whatStr := ""
				if len(fields) >= 7 {
					whatStr = utils.SanitizeStr(strings.Join(fields[6:], " "))
				}

				state.ActiveSessions = append(state.ActiveSessions, types.ActiveSessionEntry{
					User: userStr,
					TTY:  ttyStr,
					From: fromStr,
					Idle: idleStr,
					What: whatStr,
				})
			}
		}
	}
}

func readBoundedCommandOutput(cmd *exec.Cmd, maxBytes int64) ([]byte, error) {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	limitReader := io.LimitReader(stdout, maxBytes)
	out, err := io.ReadAll(limitReader)

	// Ensure process resource reclamation without blocking caller
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		<-done
	}

	return out, err
}

func parseFail2BanLog(filePath string, state *types.SecurityState) {
	file, err := os.Open(filePath)
	if err != nil {
		return
	}
	defer file.Close()
	state.LogReadable = true

	stat, err := file.Stat()
	if err != nil {
		return
	}

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
				if len(state.RecentBans) >= 5 {
					state.RecentBans = state.RecentBans[1:]
				}
				state.RecentBans = append(state.RecentBans, types.BanEntry{
					Date: utils.SanitizeStr(matches[1]),
					Time: utils.SanitizeStr(matches[2]),
					Jail: utils.SanitizeStr(matches[3]),
					IP:   utils.SanitizeIP(matches[4]),
				})
			}
		}
	}
}

func checkService(ctx context.Context, name string) bool {
	cleanName := utils.SanitizeStr(name)
	err := exec.CommandContext(ctx, utils.CmdSystemctl, "is-active", "--quiet", cleanName).Run()
	return err == nil
}

func IsProcessRunning(target string) bool {
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
		if len(pid) == 0 || pid[0] < '0' || pid[0] > '9' {
			continue
		}
		f, err := os.Open("/proc/" + pid + "/comm")
		if err != nil {
			continue
		}
		n, _ := f.Read(buf)
		f.Close()

		if n > 0 {
			comm := string(buf[:n])
			if buf[n-1] == '\n' {
				comm = string(buf[:n-1])
			}
			if comm == target {
				return true
			}
		}
	}
	return false
}
