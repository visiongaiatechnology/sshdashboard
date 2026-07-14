// STATUS: DIAMANT VGT SUPREME
//go:build linux

package tui

import (
	"fmt"
	"strings"
	"time"

	"sshdash/types"
	"sshdash/utils"
)

func FormatPrivilege(isRoot bool) string {
	if isRoot {
		return utils.CCrit + "ROOT" + utils.CReset
	}
	return utils.COk + "USER" + utils.CReset
}

// renderHeader paints the cyberpunk gradient masthead + node identity strip.
func renderHeader(f *Frame, sys *types.SystemState, now time.Time) {
	cw := f.ContentWidth()
	gradHeader := utils.GradientText(strings.Repeat("▀", cw), [3]uint8{0, 240, 255}, [3]uint8{157, 0, 255})
	f.Add(gradHeader)

	title := utils.GradientText("SSHDASH Ω  //  VISIONGAIA TACTICAL HUD  //  LIVE ENGINE",
		[3]uint8{0, 240, 255}, [3]uint8{0, 255, 135})
	f.Add(fmt.Sprintf("  %s%s%s", utils.CBold, title, utils.CReset))

	privStr := FormatPrivilege(sys.IsRoot)
	clock := now.Format("15:04:05")
	f.Add(fmt.Sprintf("  %sNODE:%s %s%s%s  %sAUTH:%s %s  %sSYS:%s %s%s%s  %sUP:%s %s%s%s  %sCLK:%s %s%s%s",
		utils.CLabel, utils.CReset, utils.CVal, strings.ToUpper(utils.SanitizeStr(sys.HostName)), utils.CReset,
		utils.CLabel, utils.CReset, privStr,
		utils.CLabel, utils.CReset, utils.CVal, utils.SanitizeStr(sys.OS), utils.CReset,
		utils.CLabel, utils.CReset, utils.CVal, utils.SanitizeStr(sys.Uptime), utils.CReset,
		utils.CLabel, utils.CReset, utils.CRail, clock, utils.CReset))

	gradFooter := utils.GradientText(strings.Repeat("▄", cw), [3]uint8{157, 0, 255}, [3]uint8{0, 240, 255})
	f.Add(gradFooter)
}

// renderTabBar draws clickable tab chrome and records mouse hit regions.
// Hit X coordinates are 1-based screen columns including the rail prefix (~3 cols).
func renderTabBar(f *Frame, app *types.AppState) {
	labels := [types.TabCount]string{
		" [1] SYSTEM ",
		" [2] SECURITY ",
		" [3] DOCKER ",
		" [4] DAEMONS ",
	}

	// Row index: current frame length + 1 (1-based terminal Y after flush home)
	// After flush, line 0 is Y=1. Header is 4 lines → tabs at Y=5 typically.
	tabY := len(f.lines) + 1
	app.TabHitMinY = tabY
	app.TabHitMaxY = tabY

	var b strings.Builder
	b.Grow(256)
	// Visible start after rail: rail glyph + space = 2 cols; frame Add adds rail, so
	// mouse X is absolute screen column. Frame lines are written as "▊ " + content.
	// Absolute X of content start ≈ 3 (1-based: cols 1-2 rail area, content from 3).
	cursorX := 3 // 1-based screen X for start of content

	for i := 0; i < int(types.TabCount); i++ {
		style := utils.CTabInactive
		if app.ActiveTab == types.TabID(i) {
			style = utils.CTabActive
		}
		label := labels[i]
		app.TabHits[i].X0 = cursorX
		app.TabHits[i].X1 = cursorX + len(label) - 1
		cursorX += len(label) + 1
		b.WriteString(style)
		b.WriteString(label)
		b.WriteString(utils.CReset)
		b.WriteByte(' ')
	}

	// Scroll indicator
	if app.ScrollY > 0 {
		b.WriteString(utils.CDim)
		b.WriteString(fmt.Sprintf("  ↕#%d", app.ScrollY))
		b.WriteString(utils.CReset)
	}

	f.Add(b.String())
	f.AddEmpty()
}

// renderFooter paints the inverted help strip.
func renderFooter(f *Frame, full *types.FullState) {
	age := time.Since(full.LastUpdate).Round(time.Millisecond)
	if age < 0 {
		age = 0
	}
	hint := utils.GradientText(
		fmt.Sprintf("🖵 1-4/Click TAB  │  ←→ h/l  │  ↑↓ j/k SCROLL  │  r REFRESH  │  q QUIT  │  Δ %s", age),
		[3]uint8{0, 240, 255}, [3]uint8{0, 255, 135})
	f.Add(fmt.Sprintf("%s %s %s", utils.CInv, hint, utils.CReset))
}

// applyScroll slices body lines by app.ScrollY within remaining viewport budget.
func applyScroll(body []string, scrollY, maxLines int) ([]string, int) {
	if maxLines < 1 {
		maxLines = 1
	}
	if scrollY < 0 {
		scrollY = 0
	}
	if len(body) == 0 {
		return body, 0
	}
	maxScroll := len(body) - maxLines
	if maxScroll < 0 {
		maxScroll = 0
	}
	if scrollY > maxScroll {
		scrollY = maxScroll
	}
	end := scrollY + maxLines
	if end > len(body) {
		end = len(body)
	}
	return body[scrollY:end], scrollY
}
