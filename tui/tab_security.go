// STATUS: DIAMANT VGT SUPREME
//go:build linux

package tui

import (
	"fmt"

	"sshdash/types"
	"sshdash/utils"
)

// renderTabSecurity — intrusion audit, sessions, listening sockets.
// All dynamic fields pass SanitizeStr / SanitizeIP before terminal emission.
func renderTabSecurity(full *types.FullState, contentW int) []string {
	sec := &full.Security
	net := &full.Network
	var out []string

	out = append(out, utils.SectionHeader("SECURITY & INTRUSION AUDIT", contentW))

	// IDS status panel content
	var idsLines []string
	if sec.LogReadable {
		idsLines = append(idsLines, fmt.Sprintf("%sFail2Ban IDS%s  %s%d ban events in log window%s",
			utils.CLabel, utils.CReset, utils.CWarn, sec.BannedCount, utils.CReset))
	} else {
		idsLines = append(idsLines, fmt.Sprintf("%sFail2Ban IDS%s  %sNO AUDIT DATA (ROOT REQUIRED)%s",
			utils.CLabel, utils.CReset, utils.CDim, utils.CReset))
	}

	if len(sec.RecentBans) > 0 {
		idsLines = append(idsLines, fmt.Sprintf("%sRecent Drops%s", utils.CLabel, utils.CReset))
		for _, ban := range sec.RecentBans {
			idsLines = append(idsLines, fmt.Sprintf("  %s%s DROP%s  %s%-15s%s %svia %-10s [%s %s]%s",
				utils.CCrit, utils.GArr, utils.CReset,
				utils.CVal, utils.SanitizeIP(ban.IP), utils.CReset,
				utils.CDim, utils.SanitizeStr(ban.Jail),
				utils.SanitizeStr(ban.Date), utils.SanitizeStr(ban.Time), utils.CReset))
		}
	} else if sec.LogReadable {
		idsLines = append(idsLines, fmt.Sprintf("  %s%s SECURE%s %sZero network anomalies in log window.%s",
			utils.COk, utils.GArr, utils.CReset, utils.CDim, utils.CReset))
	}

	// Service strip
	idsLines = append(idsLines, fmt.Sprintf("%sPerimeter%s  %s  %s  %s  %s",
		utils.CLabel, utils.CReset,
		utils.FormatSvc(sec.SvcFail2Ban, "fail2ban"),
		utils.FormatSvc(sec.SvcUFW, "ufw"),
		utils.FormatSvc(sec.SvcNginx, "nginx"),
		utils.FormatSvc(sec.SvcMySQL, "mysql")))

	leftW := (contentW * 55) / 100
	if leftW < 30 {
		leftW = 30
	}

	var sessLines []string
	sessLines = append(sessLines, fmt.Sprintf("%sActive Sessions%s", utils.CLabel, utils.CReset))
	if len(sec.ActiveSessions) > 0 {
		for _, s := range sec.ActiveSessions {
			sessLines = append(sessLines, fmt.Sprintf("  %s%s%s %s%-10s%s %s←%s %s%-15s%s %sidle %s%s",
				utils.CBrand, utils.GBullet, utils.CReset,
				utils.CVal, utils.SanitizeStr(s.User), utils.CReset,
				utils.CDim, utils.CReset,
				utils.CVal, utils.SanitizeIP(s.From), utils.CReset,
				utils.CDim, utils.SanitizeStr(s.Idle), utils.CReset))
		}
	} else {
		sessLines = append(sessLines, utils.CDim+"  [-] No interactive sessions."+utils.CReset)
	}

	sessLines = append(sessLines, fmt.Sprintf("%sAuth Trail (last)%s", utils.CLabel, utils.CReset))
	if len(sec.RecentLogins) > 0 {
		for _, login := range sec.RecentLogins {
			c := utils.CDim
			tag := "HIST"
			if login.Active {
				c = utils.COk
				tag = "LIVE"
			}
			sessLines = append(sessLines, fmt.Sprintf("  %s%s%s %s%-10s%s %sfrom%s %s%-15s%s %s[%s]%s %s",
				utils.CBrand, utils.GArr, utils.CReset,
				utils.CVal, utils.SanitizeStr(login.User), utils.CReset,
				utils.CDim, utils.CReset,
				utils.CVal, utils.SanitizeIP(login.IP), utils.CReset,
				c, tag, utils.CReset,
				utils.CDim+utils.SanitizeStr(login.Time)+utils.CReset))
		}
	} else {
		sessLines = append(sessLines, utils.CDim+"  [-] Log buffer void."+utils.CReset)
	}

	out = append(out, utils.ZipColumns(idsLines, sessLines, contentW, leftW)...)
	out = append(out, "")

	out = append(out, utils.SectionHeader("OPEN LISTENING SOCKETS (/proc/net)", contentW))
	if len(net.OpenPorts) > 0 {
		// Table header
		out = append(out, fmt.Sprintf("  %s%-6s  %-7s  %s%s", utils.CDim, "PROTO", "PORT", "BIND", utils.CReset))
		for _, p := range net.OpenPorts {
			out = append(out, fmt.Sprintf("  %s%-6s%s  %s%-7d%s  %s%s%s",
				utils.CRail, utils.SanitizeStr(p.Protocol), utils.CReset,
				utils.CVal, p.Port, utils.CReset,
				utils.CDim, utils.SanitizeIP(p.Address), utils.CReset))
		}
	} else {
		out = append(out, utils.CDim+"  [-] Socket table void or non-root context."+utils.CReset)
	}

	return out
}
