// STATUS: DIAMANT VGT SUPREME
//go:build linux

package collectors

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"sshdash/types"
	"sshdash/utils"
)

var (
	netMutex       sync.Mutex
	prevNetBytes   map[string][2]uint64
	lastNetTime    time.Time
	pubIPMutex     sync.Mutex
	cachedPublicIP string
	lastPubIPTime  time.Time
)

func init() {
	prevNetBytes = make(map[string][2]uint64)
	lastNetTime = time.Now()
}

func GetNetworkState(ctx context.Context, wg *sync.WaitGroup, state *types.NetworkState) {
	defer wg.Done()

	var netWg sync.WaitGroup
	netWg.Add(3)

	var localIP, publicIP string

	// 1. Local Routing IP
	go func() {
		defer netWg.Done()
		var d net.Dialer
		conn, err := d.DialContext(ctx, "udp", "1.1.1.1:80")
		if err == nil {
			defer conn.Close()
			localIP = utils.SanitizeIP(conn.LocalAddr().(*net.UDPAddr).IP.String())
		} else {
			localIP = "127.0.0.1"
		}
	}()

	// 2. Cloudflare Egress Public IP Discovery (Cached 15m to eliminate 1Hz DNS noise & egress leaks)
	go func() {
		defer netWg.Done()

		pubIPMutex.Lock()
		if cachedPublicIP != "" && time.Since(lastPubIPTime) < 15*time.Minute {
			publicIP = cachedPublicIP
			pubIPMutex.Unlock()
			return
		}
		pubIPMutex.Unlock()

		r := &net.Resolver{
			PreferGo: true,
			Dial: func(rCtx context.Context, network, address string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(rCtx, "udp", "1.1.1.1:53")
			},
		}
		txts, err := r.LookupTXT(ctx, "whoami.cloudflare")

		pubIPMutex.Lock()
		defer pubIPMutex.Unlock()
		if err == nil && len(txts) > 0 {
			cachedPublicIP = utils.SanitizeIP(txts[0])
			lastPubIPTime = time.Now()
		} else if cachedPublicIP == "" {
			cachedPublicIP = "0.0.0.0"
		}
		publicIP = cachedPublicIP
	}()

	// 3. Interface Speed & Socket Port Audit
	go func() {
		defer netWg.Done()
		readNetDev(state)
		scanOpenPorts(state)
	}()

	netWg.Wait()

	state.LocalIP = localIP
	state.PublicIP = publicIP
}

func readNetDev(state *types.NetworkState) {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return
	}
	defer f.Close()

	now := time.Now()
	netMutex.Lock()
	timeDelta := now.Sub(lastNetTime).Seconds()
	if timeDelta <= 0 {
		timeDelta = 1.0
	}
	lastNetTime = now

	scanner := bufio.NewScanner(f)
	var interfaces []types.NetworkInterfaceState

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.Contains(line, ":") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		ifName := utils.SanitizeStr(strings.TrimSpace(parts[0]))
		if ifName == "lo" || strings.HasPrefix(ifName, "docker") || strings.HasPrefix(ifName, "veth") {
			continue
		}

		fields := strings.Fields(parts[1])
		if len(fields) >= 10 {
			rxBytes := utils.FastParseUint(fields[0])
			txBytes := utils.FastParseUint(fields[8])

			var rxSpeed, txSpeed float64
			if prev, exists := prevNetBytes[ifName]; exists {
				if rxBytes >= prev[0] {
					rxSpeed = float64(rxBytes-prev[0]) / timeDelta
				}
				if txBytes >= prev[1] {
					txSpeed = float64(txBytes-prev[1]) / timeDelta
				}
			}
			prevNetBytes[ifName] = [2]uint64{rxBytes, txBytes}

			interfaces = append(interfaces, types.NetworkInterfaceState{
				Name:       ifName,
				RxBytes:    rxBytes,
				TxBytes:    txBytes,
				RxSpeedBps: rxSpeed,
				TxSpeedBps: txSpeed,
			})
		}
	}
	// Aggregate throughput for dual braille timeline
	var totalRx, totalTx float64
	for _, iface := range interfaces {
		totalRx += iface.RxSpeedBps
		totalTx += iface.TxSpeedBps
	}
	state.TotalRxBps = totalRx
	state.TotalTxBps = totalTx
	state.RxHistory = utils.AppendHistory(state.RxHistory, totalRx, 60)
	state.TxHistory = utils.AppendHistory(state.TxHistory, totalTx, 60)

	netMutex.Unlock()

	state.Interfaces = interfaces
}

func scanOpenPorts(state *types.NetworkState) {
	var openPorts []types.OpenPort

	parseNetSockets := func(path string, proto string) {
		f, err := os.Open(path)
		if err != nil {
			return
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		scanner.Scan() // skip header line

		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 10 {
				localAddrHex := fields[1]
				stHex := fields[3]

				if (proto == "TCP" && stHex == "0A") || (proto == "UDP" && stHex == "07") {
					parts := strings.Split(localAddrHex, ":")
					if len(parts) == 2 {
						port, err := strconv.ParseInt(parts[1], 16, 32)
						if err == nil && port > 0 && port <= 65535 {
							addrIP := parseHexIP(parts[0])

							openPorts = append(openPorts, types.OpenPort{
								Protocol: proto,
								Port:     int(port),
								Address:  addrIP,
							})
						}
					}
				}
			}
		}
	}

	parseNetSockets("/proc/net/tcp", "TCP")
	parseNetSockets("/proc/net/tcp6", "TCP6")
	parseNetSockets("/proc/net/udp", "UDP")

	if len(openPorts) > 8 {
		openPorts = openPorts[:8]
	}

	state.OpenPorts = openPorts
}

func parseHexIP(hexStr string) string {
	if len(hexStr) == 8 {
		b0, _ := strconv.ParseUint(hexStr[6:8], 16, 8)
		b1, _ := strconv.ParseUint(hexStr[4:6], 16, 8)
		b2, _ := strconv.ParseUint(hexStr[2:4], 16, 8)
		b3, _ := strconv.ParseUint(hexStr[0:2], 16, 8)
		return fmt.Sprintf("%d.%d.%d.%d", b0, b1, b2, b3)
	}
	return "0.0.0.0"
}
