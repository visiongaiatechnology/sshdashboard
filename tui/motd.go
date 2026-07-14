// STATUS: DIAMANT VGT SUPREME
//go:build linux

package tui

import (
	"fmt"
	"strings"

	"sshdash/types"
	"sshdash/utils"
)

// RenderMOTD emits a single non-interactive login banner snapshot.
// Privacy Hardened: Suppresses individual user/attacker IP telemetry in non-interactive MOTD mode,
// preventing information leaks to low-privileged SSH users on multi-user systems.
func RenderMOTD(full *types.FullState, termWidth int) {
	f := NewFrame(termWidth, 48)
	cw := f.ContentWidth()
	if cw > 96 {
		cw = 96
	}

	sys := &full.System
	net := &full.Network
	sec := &full.Security

	gradHeader := utils.GradientText(strings.Repeat("▀", cw), [3]uint8{0, 240, 255}, [3]uint8{157, 0, 255})
	f.Add(gradHeader)

	titleText := utils.GradientText("VISIONGAIA TECHNOLOGY  //  OMEGA MOTD PROTOCOL",
		[3]uint8{0, 240, 255}, [3]uint8{0, 255, 135})
	f.Add(fmt.Sprintf("  %s%s%s", utils.CBold, titleText, utils.CReset))

	privStr := FormatPrivilege(sys.IsRoot)

	f.Add(fmt.Sprintf("  %sNODE:%s %s%s%s  %sAUTH:%s %s  %sSYS:%s %s%s%s",
		utils.CLabel, utils.CReset, utils.CVal, strings.ToUpper(utils.SanitizeStr(sys.HostName)), utils.CReset,
		utils.CLabel, utils.CReset, privStr,
		utils.CLabel, utils.CReset, utils.CVal, utils.SanitizeStr(sys.OS), utils.CReset))

	gradFooter := utils.GradientText(strings.Repeat("▄", cw), [3]uint8{157, 0, 255}, [3]uint8{0, 240, 255})
	f.Add(gradFooter)
	f.AddEmpty()

	f.Add(utils.SectionHeader("SYSTEM MATRIX", cw))
	f.Add(fmt.Sprintf(" %sCPU Load   :%s %s%s%s %s[%d Cores]%s  %sUp:%s %s%s%s",
		utils.CLabel, utils.CReset, utils.CVal, utils.SanitizeStr(sys.Load), utils.CReset,
		utils.CDim, sys.Cores, utils.CReset,
		utils.CLabel, utils.CReset, utils.CVal, utils.SanitizeStr(sys.Uptime), utils.CReset))
	f.Add(fmt.Sprintf(" %sRAM Target :%s [%s] %s%.1fG%s%s / %.1fG%s",
		utils.CLabel, utils.CReset, utils.DrawBar(sys.RAMPercent, 22),
		utils.CVal, sys.RAMUsedGB, utils.CReset, utils.CDim, sys.RAMTotalGB, utils.CReset))
	f.Add(fmt.Sprintf(" %sDisk Mount :%s [%s] %s%.1fG%s%s / %.1fG%s",
		utils.CLabel, utils.CReset, utils.DrawBar(sys.DiskPercent, 22),
		utils.CVal, sys.DiskUsedGB, utils.CReset, utils.CDim, sys.DiskTotalGB, utils.CReset))
	f.AddEmpty()

	f.Add(utils.SectionHeader("TACTICAL SECURITY & SERVICES", cw))
	if sec.LogReadable {
		f.Add(fmt.Sprintf(" %sIDS Status :%s %s%d ban events in log window%s (fail2ban)",
			utils.CLabel, utils.CReset, utils.CWarn, sec.BannedCount, utils.CReset))
	} else {
		f.Add(fmt.Sprintf(" %sIDS Status :%s %sNO AUDIT DATA (ROOT REQUIRED)%s",
			utils.CLabel, utils.CReset, utils.CDim, utils.CReset))
	}
	f.Add(fmt.Sprintf(" %sDaemons    :%s %s  %s  %s  %s",
		utils.CLabel, utils.CReset,
		utils.FormatSvc(sec.SvcFail2Ban, "fail2ban"),
		utils.FormatSvc(sec.SvcNginx, "nginx"),
		utils.FormatSvc(sec.SvcMySQL, "mysql"),
		utils.FormatSvc(sec.SvcUFW, "ufw")))
	f.AddEmpty()

	f.Add(utils.SectionHeader("EDGE NETWORK", cw))
	f.Add(fmt.Sprintf(" %sRouting IP :%s %sLocal:%s %s%s%s",
		utils.CLabel, utils.CReset,
		utils.CDim, utils.CReset, utils.CVal, displayIP(net.LocalIP), utils.CReset))
	f.AddEmpty()

	f.Add(gradHeader)
	f.FlushMOTD()
}
