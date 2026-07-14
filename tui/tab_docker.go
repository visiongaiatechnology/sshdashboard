// STATUS: DIAMANT VGT SUPREME
//go:build linux

package tui

import (
	"fmt"

	"sshdash/types"
	"sshdash/utils"
)

// renderTabDocker — container matrix + top memory consumers from /proc.
func renderTabDocker(full *types.FullState, contentW int) []string {
	doc := &full.Docker
	proc := &full.Process
	var out []string

	out = append(out, utils.SectionHeader("DOCKER CONTAINER MATRIX", contentW))

	if !doc.SocketPresent {
		out = append(out, fmt.Sprintf(" %sDocker Daemon%s  %sSocket not found (/var/run/docker.sock)%s",
			utils.CLabel, utils.CReset, utils.CDim, utils.CReset))
		out = append(out, fmt.Sprintf(" %sProcess Probe%s  %s",
			utils.CLabel, utils.CReset, utils.FormatSvc(doc.Installed, "dockerd")))
	} else {
		// Summary bar
		runPct := 0
		if doc.TotalContainers > 0 {
			runPct = (doc.RunningContainers * 100) / doc.TotalContainers
		}
		out = append(out, fmt.Sprintf(" %sContainers%s  %s%d Running%s / %d Total  %s",
			utils.CLabel, utils.CReset,
			utils.COk, doc.RunningContainers, utils.CReset, doc.TotalContainers,
			utils.DrawBar(runPct, 16)))

		if len(doc.Containers) > 0 {
			out = append(out, fmt.Sprintf("  %s%-14s %-16s %-18s %s%s",
				utils.CDim, "ID", "NAME", "IMAGE", "STATUS", utils.CReset))
			for _, c := range doc.Containers {
				statusCol := utils.COk
				if c.State != "running" {
					statusCol = utils.CWarn
				}
				out = append(out, fmt.Sprintf("  %s%-14s%s %s%-16s%s %s%-18s%s %s%s%s",
					utils.CRail, utils.SanitizeStr(c.ID), utils.CReset,
					utils.CVal, utils.SanitizeStr(c.Names), utils.CReset,
					utils.CDim, utils.SanitizeStr(c.Image), utils.CReset,
					statusCol, utils.SanitizeDisplay(c.Status, 28), utils.CReset))
			}
		} else {
			out = append(out, utils.CDim+"  [-] No containers enumerated."+utils.CReset)
		}
	}

	out = append(out, "")
	out = append(out, utils.SectionHeader("TOP MEMORY CONSUMERS (/proc)", contentW))

	if len(proc.TopRAM) > 0 {
		out = append(out, fmt.Sprintf("  %s%-8s %-18s %10s %8s%s",
			utils.CDim, "PID", "PROCESS", "RSS", "%MEM", utils.CReset))
		for _, p := range proc.TopRAM {
			barW := 12
			if contentW < 70 {
				barW = 8
			}
			pct := int(p.MemPerc)
			if pct < 0 {
				pct = 0
			}
			if pct > 100 {
				pct = 100
			}
			out = append(out, fmt.Sprintf("  %s%-8d%s %s%-18s%s %s%8.1f MB%s %s%5.1f%%%s %s",
				utils.CDim, p.PID, utils.CReset,
				utils.CVal, utils.SanitizeStr(p.Name), utils.CReset,
				utils.CMag, p.MemMB, utils.CReset,
				utils.StatusColor(pct), p.MemPerc, utils.CReset,
				utils.DrawBar(pct, barW)))
		}
	} else {
		out = append(out, utils.CDim+"  [-] Process table void."+utils.CReset)
	}

	return out
}
