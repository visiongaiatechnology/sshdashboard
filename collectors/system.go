// STATUS: DIAMANT VGT SUPREME
//go:build linux

package collectors

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/user"
	"runtime"
	"strings"
	"sync"
	"syscall"

	"sshdash/types"
	"sshdash/utils"
)

type cpuTimeSample struct {
	user    uint64
	nice    uint64
	system  uint64
	idle    uint64
	iowait  uint64
	irq     uint64
	softirq uint64
	steal   uint64
}

func (c cpuTimeSample) total() uint64 {
	return c.user + c.nice + c.system + c.idle + c.iowait + c.irq + c.softirq + c.steal
}

func (c cpuTimeSample) active() uint64 {
	tot := c.total()
	unactive := c.idle + c.iowait
	if tot < unactive {
		return 0
	}
	return tot - unactive
}

var (
	cpuMutex      sync.Mutex
	prevCpuTicks  map[int]cpuTimeSample
	prevDiskRead  uint64
	prevDiskWrite uint64
)

func init() {
	prevCpuTicks = make(map[int]cpuTimeSample)
}

func GetSystemState(ctx context.Context, wg *sync.WaitGroup, state *types.SystemState) {
	defer wg.Done()

	// 1. Hostname & Privilege Execution
	if hostname, err := os.Hostname(); err == nil {
		state.HostName = utils.SanitizeStr(hostname)
	} else {
		state.HostName = "unknown-host"
	}

	state.IsRoot = (os.Geteuid() == 0)
	if u, err := user.Current(); err == nil {
		state.UserName = utils.SanitizeStr(u.Username)
	} else {
		state.UserName = "unknown"
	}

	// 2. Sysinfo Uptime & Load Averages
	var info syscall.Sysinfo_t
	if err := syscall.Sysinfo(&info); err == nil {
		upD := info.Uptime / 86400
		upH := (info.Uptime % 86400) / 3600
		upM := (info.Uptime % 3600) / 60
		state.Uptime = fmt.Sprintf("%dd %dh %dm", upD, upH, upM)

		state.Load1 = float64(info.Loads[0]) / 65536.0
		state.Load5 = float64(info.Loads[1]) / 65536.0
		state.Load15 = float64(info.Loads[2]) / 65536.0
		state.Load = fmt.Sprintf("%.2f, %.2f, %.2f", state.Load1, state.Load5, state.Load15)
	}
	state.Cores = runtime.NumCPU()

	// 3. Kernel & OS Info
	var uts syscall.Utsname
	if err := syscall.Uname(&uts); err == nil {
		state.Kernel = utils.SanitizeStr(utils.B2s(uts.Release[:]))
	}

	state.OS = "Linux"
	if f, err := os.Open("/etc/os-release"); err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				state.OS = utils.SanitizeStr(strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`))
				break
			}
		}
		f.Close()
	}

	// 4. Per-Core CPU & Memory Operations
	readCPUCoreUsage(state)
	readMemInfo(state)

	// 5. Disk Mount Statistics
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err == nil {
		total := stat.Blocks * uint64(stat.Bsize)
		free := stat.Bavail * uint64(stat.Bsize)
		if total >= free {
			used := total - free
			state.DiskTotalGB = float64(total) / 1024 / 1024 / 1024
			state.DiskUsedGB = float64(used) / 1024 / 1024 / 1024
			if total > 0 {
				state.DiskPercent = int((float64(used) / float64(total)) * 100)
			} else {
				state.DiskPercent = 0
				state.DiskTotalGB = 0.1
			}
		}
	}

	readDiskIO(state)
}

func readCPUCoreUsage(state *types.SystemState) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	coreSamples := make(map[int]cpuTimeSample)
	var overallSample cpuTimeSample

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "cpu ") { // Overall CPU line
			fmt.Sscanf(line, "cpu %d %d %d %d %d %d %d %d",
				&overallSample.user, &overallSample.nice, &overallSample.system, &overallSample.idle, &overallSample.iowait, &overallSample.irq, &overallSample.softirq, &overallSample.steal)
		} else if strings.HasPrefix(line, "cpu") && len(line) > 3 && line[3] >= '0' && line[3] <= '9' {
			var coreID int
			var s cpuTimeSample
			n, _ := fmt.Sscanf(line, "cpu%d %d %d %d %d %d %d %d %d",
				&coreID, &s.user, &s.nice, &s.system, &s.idle, &s.iowait, &s.irq, &s.softirq, &s.steal)
			if n >= 5 {
				coreSamples[coreID] = s
			}
		}
	}

	cpuMutex.Lock()
	defer cpuMutex.Unlock()

	usages := make([]float64, state.Cores)
	var overallUsage float64

	for coreID, curr := range coreSamples {
		if coreID < state.Cores {
			if prev, exists := prevCpuTicks[coreID]; exists {
				totalDelta := float64(curr.total() - prev.total())
				activeDelta := float64(curr.active() - prev.active())
				if totalDelta > 0 {
					calc := (activeDelta / totalDelta) * 100.0
					if calc < 0 {
						calc = 0
					} else if calc > 100 {
						calc = 100
					}
					usages[coreID] = calc
					overallUsage += calc
				}
			}
			prevCpuTicks[coreID] = curr
		}
	}

	if state.Cores > 0 {
		overallUsage = overallUsage / float64(state.Cores)
	}

	state.CoreUsage = usages

	// Record global load history for Braille timeline plot (60 samples ≈ 1 min @1Hz)
	state.CPUPercent = overallUsage
	state.GlobalLoadHistory = utils.AppendHistory(state.GlobalLoadHistory, overallUsage, 60)

	if len(state.CoreHistory) < state.Cores {
		state.CoreHistory = make([][]float64, state.Cores)
	}

	for i := 0; i < state.Cores; i++ {
		u := 0.0
		if i < len(usages) {
			u = usages[i]
		}
		state.CoreHistory[i] = utils.AppendHistory(state.CoreHistory[i], u, 24)
	}
}

func readMemInfo(state *types.SystemState) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var memTotal, memAvail, swapTotal, swapFree uint64

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			memTotal = utils.FastParseUint(line)
		} else if strings.HasPrefix(line, "MemAvailable:") {
			memAvail = utils.FastParseUint(line)
		} else if strings.HasPrefix(line, "SwapTotal:") {
			swapTotal = utils.FastParseUint(line)
		} else if strings.HasPrefix(line, "SwapFree:") {
			swapFree = utils.FastParseUint(line)
		}
	}

	state.RAMTotalGB = float64(memTotal) / 1024 / 1024
	if memTotal >= memAvail {
		usedMem := memTotal - memAvail
		state.RAMUsedGB = float64(usedMem) / 1024 / 1024
		if memTotal > 0 {
			state.RAMPercent = int((float64(usedMem) / float64(memTotal)) * 100)
		}
	}

	state.SwapTotalGB = float64(swapTotal) / 1024 / 1024
	if swapTotal >= swapFree {
		usedSwap := swapTotal - swapFree
		state.SwapUsedGB = float64(usedSwap) / 1024 / 1024
		if swapTotal > 0 {
			state.SwapPercent = int((float64(usedSwap) / float64(swapTotal)) * 100)
		}
	}
}

func readDiskIO(state *types.SystemState) {
	f, err := os.Open("/proc/diskstats")
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var totalReadSectors, totalWriteSectors uint64

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 14 {
			devName := fields[2]
			if strings.HasPrefix(devName, "sd") || strings.HasPrefix(devName, "vd") || strings.HasPrefix(devName, "nvme") {
				if !strings.Contains(devName, "p") && len(devName) <= 7 {
					readSectors := utils.FastParseUint(fields[5])
					writeSectors := utils.FastParseUint(fields[9])
					totalReadSectors += readSectors
					totalWriteSectors += writeSectors
				}
			}
		}
	}

	if prevDiskRead > 0 && totalReadSectors >= prevDiskRead {
		readDeltaKB := float64(totalReadSectors-prevDiskRead) * 0.5
		writeDeltaKB := float64(totalWriteSectors-prevDiskWrite) * 0.5
		state.DiskReadKBps = readDeltaKB
		state.DiskWriteKBps = writeDeltaKB
	}
	prevDiskRead = totalReadSectors
	prevDiskWrite = totalWriteSectors
}
