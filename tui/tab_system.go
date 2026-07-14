// STATUS: DIAMANT VGT SUPREME
//go:build linux

package tui

import (
	"fmt"

	"sshdash/types"
	"sshdash/utils"
)

// renderTabSystem — dual-pane SYSTEM matrix: waveform + heat/gauges + edge net.
// Isolated domain module: only reads System + Network slices.
func renderTabSystem(full *types.FullState, contentW int) []string {
	sys := &full.System
	net := &full.Network
	var out []string

	out = append(out, utils.SectionHeader("SYSTEM MATRIX", contentW))

	// Dual column: left = CPU waveform, right = gauges + heatmap
	leftW := (contentW * 58) / 100
	if leftW < 28 {
		leftW = 28
	}

	chartW := leftW - 4
	if chartW < 20 {
		chartW = 20
	}
	chartH := 4
	if contentW < 70 {
		chartH = 3
	}

	var left []string
	left = append(left, fmt.Sprintf("%sCPU Load%s  %s%s%s  %s[%d cores]%s",
		utils.CLabel, utils.CReset, utils.CVal, utils.SanitizeStr(sys.Load), utils.CReset,
		utils.CDim, sys.Cores, utils.CReset))

	if len(sys.GlobalLoadHistory) > 0 {
		braille := utils.PlotBrailleGraph(sys.GlobalLoadHistory, chartW, chartH, 100.0)
		left = append(left, fmt.Sprintf("%s╭%s╮%s", utils.CLabel, padTitle("Realtime CPU · Braille 8×", chartW), utils.CReset))
		for _, line := range braille {
			left = append(left, fmt.Sprintf("%s│%s%s%s│%s", utils.CLabel, utils.CReset, utils.PadVisible(line, chartW), utils.CLabel, utils.CReset))
		}
		left = append(left, fmt.Sprintf("%s╰%s╯%s", utils.CLabel, utils.BoxH+repeatBox(chartW-1), utils.CReset))
		// Sparkline strip under graph
		left = append(left, fmt.Sprintf(" %s∑%s %s", utils.CDim, utils.CReset,
			utils.DrawSparklineFixed(sys.GlobalLoadHistory, chartW-2, 100.0)))
	} else {
		left = append(left, utils.CDim+"  [acquiring CPU samples…] "+utils.CReset)
	}

	// Right column: resource gauges + core heatmap
	gaugeW := contentW - leftW - 6
	if gaugeW < 16 {
		gaugeW = 16
	}
	barW := gaugeW - 14
	if barW < 8 {
		barW = 8
	}
	if barW > 28 {
		barW = 28
	}

	var right []string
	right = append(right, utils.DrawGauge("RAM", sys.RAMPercent, barW))
	right = append(right, fmt.Sprintf("  %s%.1fG%s%s / %.1fG%s",
		utils.CVal, sys.RAMUsedGB, utils.CReset, utils.CDim, sys.RAMTotalGB, utils.CReset))
	if sys.SwapTotalGB > 0.01 {
		right = append(right, utils.DrawGauge("SWAP", sys.SwapPercent, barW))
	}
	right = append(right, utils.DrawGauge("DISK", sys.DiskPercent, barW))
	right = append(right, fmt.Sprintf("  %s%.1fG%s%s / %.1fG%s",
		utils.CVal, sys.DiskUsedGB, utils.CReset, utils.CDim, sys.DiskTotalGB, utils.CReset))

	if sys.DiskReadKBps > 0 || sys.DiskWriteKBps > 0 {
		right = append(right, fmt.Sprintf("%sI/O%s  %s↓ %.1f KB/s%s  %s↑ %.1f KB/s%s",
			utils.CLabel, utils.CReset, utils.COk, sys.DiskReadKBps, utils.CReset,
			utils.CWarn, sys.DiskWriteKBps, utils.CReset))
	}

	right = append(right, fmt.Sprintf("%sCORE HEATMAP%s", utils.CLabel, utils.CReset))
	heatCols := 6
	if gaugeW > 28 {
		heatCols = 8
	}
	right = append(right, utils.DrawCoreHeatmap(sys.CoreUsage, sys.Cores, heatCols)...)

	// Per-core sparklines (top 6)
	if len(sys.CoreHistory) > 0 {
		maxShow := sys.Cores
		if maxShow > 6 {
			maxShow = 6
		}
		for i := 0; i < maxShow; i++ {
			u := 0.0
			if i < len(sys.CoreUsage) {
				u = sys.CoreUsage[i]
			}
			spark := utils.DrawSparkline(sys.CoreHistory[i], 100.0)
			right = append(right, fmt.Sprintf("%sc%d%s %-12s %s%5.1f%%%s",
				utils.CDim, i, utils.CReset, spark, utils.CVal, u, utils.CReset))
		}
	}

	zipped := utils.ZipColumns(left, right, contentW, leftW)
	out = append(out, zipped...)
	out = append(out, "")

	// EDGE NETWORK full width
	out = append(out, utils.SectionHeader("EDGE NETWORK", contentW))
	out = append(out, fmt.Sprintf("%sIP%s  %sLocal%s %s%s%s  %sPublic%s %s%s%s",
		utils.CLabel, utils.CReset,
		utils.CDim, utils.CReset, utils.CVal, displayIP(net.LocalIP), utils.CReset,
		utils.CDim, utils.CReset, utils.CVal, displayIP(net.PublicIP), utils.CReset))

	// Dual RX/TX braille if history present
	if len(net.RxHistory) > 2 || len(net.TxHistory) > 2 {
		netW := contentW - 6
		if netW > 56 {
			netW = 56
		}
		if netW < 20 {
			netW = 20
		}
		maxNet := net.TotalRxBps
		if net.TotalTxBps > maxNet {
			maxNet = net.TotalTxBps
		}
		// scale from history peaks
		for _, v := range net.RxHistory {
			if v > maxNet {
				maxNet = v
			}
		}
		for _, v := range net.TxHistory {
			if v > maxNet {
				maxNet = v
			}
		}
		if maxNet < 1024 {
			maxNet = 1024
		}
		dual := utils.PlotBrailleDual(net.RxHistory, net.TxHistory, netW, 2, maxNet)
		out = append(out, fmt.Sprintf("%sThroughput%s  %s↓ RX%s %s  %s↑ TX%s %s  %s↕ both%s",
			utils.CLabel, utils.CReset,
			utils.COk, utils.CReset, utils.FormatBytesSpeed(net.TotalRxBps),
			utils.CWarn, utils.CReset, utils.FormatBytesSpeed(net.TotalTxBps),
			utils.CMag, utils.CReset))
		for _, line := range dual {
			out = append(out, "  "+line)
		}
	}

	if len(net.Interfaces) > 0 {
		for _, iface := range net.Interfaces {
			name := utils.SanitizeStr(iface.Name)
			rxS := utils.FormatBytesSpeed(iface.RxSpeedBps)
			txS := utils.FormatBytesSpeed(iface.TxSpeedBps)
			out = append(out, fmt.Sprintf("  %s%-10s%s %s↓ %-12s%s %s↑ %-12s%s %sΣ rx %s  tx %s%s",
				utils.CRail, name, utils.CReset,
				utils.COk, rxS, utils.CReset,
				utils.CWarn, txS, utils.CReset,
				utils.CDim, utils.FormatBytes(iface.RxBytes), utils.FormatBytes(iface.TxBytes), utils.CReset))
		}
	} else {
		out = append(out, utils.CDim+"  [-] No active interfaces."+utils.CReset)
	}

	return out
}

// displayIP sanitizes and maps sentinel 0.0.0.0 → OFFLINE for egress discovery failure.
func displayIP(raw string) string {
	ip := utils.SanitizeIP(raw)
	if ip == "0.0.0.0" || ip == "::" || ip == "UNKNOWN_HOST" {
		return "OFFLINE"
	}
	return ip
}

func padTitle(title string, width int) string {
	t := " " + title + " "
	if len(t) >= width {
		return utils.BoxH
	}
	return t + repeatBox(width-len(t))
}

func repeatBox(n int) string {
	if n <= 0 {
		return ""
	}
	b := make([]byte, 0, n*3)
	for i := 0; i < n; i++ {
		b = append(b, []byte(utils.BoxH)...)
	}
	return string(b)
}
