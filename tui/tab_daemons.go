// STATUS: DIAMANT VGT SUPREME
//go:build linux

package tui

import (
	"fmt"

	"sshdash/types"
	"sshdash/utils"
)

// renderTabDaemons — service status board + host identity card.
func renderTabDaemons(full *types.FullState, contentW int) []string {
	sec := &full.Security
	doc := &full.Docker
	sys := &full.System
	var out []string

	out = append(out, utils.SectionHeader("SYSTEM DAEMONS & PERIMETER", contentW))

	type svcRow struct {
		label string
		ok    bool
		role  string
	}
	rows := []svcRow{
		{"Fail2Ban IDS", sec.SvcFail2Ban, "Intrusion prevention"},
		{"Nginx Web", sec.SvcNginx, "Edge HTTP reverse proxy"},
		{"MySQL Engine", sec.SvcMySQL, "Relational datastore"},
		{"UFW Firewall", sec.SvcUFW, "Host packet filter"},
		{"Docker Engine", doc.Installed, "Container runtime"},
	}

	leftW := (contentW * 50) / 100
	if leftW < 28 {
		leftW = contentW
	}

	var left, right []string
	for i, r := range rows {
		line := formatDaemonCard(r.label, r.ok, r.role)
		if contentW >= 72 && i >= (len(rows)+1)/2 {
			right = append(right, line)
		} else if contentW >= 72 {
			left = append(left, line)
		} else {
			out = append(out, "  "+line)
		}
	}
	if contentW >= 72 {
		out = append(out, utils.ZipColumns(left, right, contentW, leftW)...)
	}

	out = append(out, "")
	out = append(out, utils.SectionHeader("HOST IDENTITY", contentW))

	idBody := []string{
		fmt.Sprintf("%sKernel%s   %s%s%s", utils.CLabel, utils.CReset, utils.CVal, utils.SanitizeStr(sys.Kernel), utils.CReset),
		fmt.Sprintf("%sOS%s       %s%s%s", utils.CLabel, utils.CReset, utils.CVal, utils.SanitizeStr(sys.OS), utils.CReset),
		fmt.Sprintf("%sCores%s    %s%d%s", utils.CLabel, utils.CReset, utils.CVal, sys.Cores, utils.CReset),
		fmt.Sprintf("%sUser%s     %s%s%s  %sPrivilege%s %s",
			utils.CLabel, utils.CReset, utils.CVal, utils.SanitizeStr(sys.UserName), utils.CReset,
			utils.CLabel, utils.CReset, FormatPrivilege(sys.IsRoot)),
		fmt.Sprintf("%sUptime%s   %s%s%s", utils.CLabel, utils.CReset, utils.CVal, utils.SanitizeStr(sys.Uptime), utils.CReset),
		fmt.Sprintf("%sLoad%s     %s%s%s", utils.CLabel, utils.CReset, utils.CVal, utils.SanitizeStr(sys.Load), utils.CReset),
	}
	boxW := contentW
	if boxW > 64 {
		boxW = 64
	}
	out = append(out, utils.PanelBox("NODE CARD", idBody, boxW)...)

	out = append(out, "")
	out = append(out, fmt.Sprintf("%sLegend%s  %s%s ONLINE%s  %s%s OFFLINE%s  %sMouse: click tabs  ·  Wheel: scroll%s",
		utils.CLabel, utils.CReset,
		utils.COk, utils.GDotActive, utils.CReset,
		utils.CCrit, utils.GDotInactive, utils.CReset,
		utils.CDim, utils.CReset))

	return out
}

func formatDaemonCard(label string, ok bool, role string) string {
	dot := utils.GDotInactive
	col := utils.CCrit
	state := "DOWN"
	if ok {
		dot = utils.GDotActive
		col = utils.COk
		state = "UP"
	}
	return fmt.Sprintf("%s%s%s %s%-14s%s %s%-4s%s %s%s%s",
		col, dot, utils.CReset,
		utils.CVal, utils.SanitizeStr(label), utils.CReset,
		col, state, utils.CReset,
		utils.CDim, utils.SanitizeStr(role), utils.CReset)
}
