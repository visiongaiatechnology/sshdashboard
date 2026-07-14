// STATUS: DIAMANT VGT SUPREME
//go:build linux

package collectors

import (
	"bufio"
	"context"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"

	"sshdash/types"
	"sshdash/utils"
)

func GetProcessState(ctx context.Context, wg *sync.WaitGroup, state *types.ProcessState) {
	defer wg.Done()

	d, err := os.Open("/proc")
	if err != nil {
		return
	}
	defer d.Close()

	names, err := d.Readdirnames(-1)
	if err != nil {
		return
	}

	var procs []types.ProcessEntry
	var ramTotalMB float64 = 1024.0

	if f, err := os.Open("/proc/meminfo"); err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "MemTotal:") {
				parsed := utils.FastParseUint(line)
				if parsed > 0 {
					ramTotalMB = float64(parsed) / 1024.0
				}
				break
			}
		}
		f.Close()
	}

	scannedCount := 0
	for _, pidStr := range names {
		// Stop scanning if excessive PIDs present to prevent CPU starvation
		if scannedCount > 4096 {
			break
		}

		if len(pidStr) == 0 || pidStr[0] < '0' || pidStr[0] > '9' {
			continue
		}

		pid, err := strconv.Atoi(pidStr)
		if err != nil || pid <= 0 {
			continue
		}

		scannedCount++

		procName := "unknown"
		if commBytes, err := os.ReadFile("/proc/" + pidStr + "/comm"); err == nil {
			procName = utils.SanitizeStr(strings.TrimSpace(string(commBytes)))
		}

		var rssKB float64
		if fStatus, err := os.Open("/proc/" + pidStr + "/status"); err == nil {
			scanner := bufio.NewScanner(fStatus)
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(line, "VmRSS:") {
					rssKB = float64(utils.FastParseUint(line))
					break
				}
			}
			fStatus.Close()
		}

		memMB := rssKB / 1024.0
		memPerc := (memMB / ramTotalMB) * 100.0

		if memMB < 1.0 {
			continue
		}

		procs = append(procs, types.ProcessEntry{
			PID:     pid,
			Name:    procName,
			MemMB:   memMB,
			MemPerc: memPerc,
		})
	}

	sort.Slice(procs, func(i, j int) bool {
		return procs[i].MemMB > procs[j].MemMB
	})

	if len(procs) > 6 {
		state.TopRAM = procs[:6]
	} else {
		state.TopRAM = procs
	}
}
