// STATUS: DIAMANT VGT SUPREME
//go:build linux

package utils

import (
	"fmt"
	"strings"
)

// ZipColumns merges left/right line slices into a dual-pane layout of totalWidth.
// leftW is the left column content width (excluding separator). Gaps pad shorter side.
func ZipColumns(left, right []string, totalWidth int, leftW int) []string {
	if totalWidth < 20 {
		totalWidth = 20
	}
	sepW := 3 // " │ "
	if leftW < 8 {
		leftW = totalWidth / 2
	}
	rightW := totalWidth - leftW - sepW
	if rightW < 8 {
		rightW = 8
		leftW = totalWidth - rightW - sepW
		if leftW < 8 {
			leftW = 8
		}
	}

	n := len(left)
	if len(right) > n {
		n = len(right)
	}
	out := make([]string, n)
	for i := 0; i < n; i++ {
		l := ""
		r := ""
		if i < len(left) {
			l = left[i]
		}
		if i < len(right) {
			r = right[i]
		}
		out[i] = PadVisible(TruncateVisible(l, leftW), leftW) +
			CPanel + " │ " + CReset +
			PadVisible(TruncateVisible(r, rightW), rightW)
	}
	return out
}

// PanelBox wraps content lines in a titled Unicode box of exact width.
func PanelBox(title string, content []string, width int) []string {
	if width < 12 {
		width = 12
	}
	title = SanitizeDisplay(title, 40)
	inner := width - 2
	if inner < 4 {
		inner = 4
	}

	// Top with title inset
	tRunes := []rune(title)
	maxTitle := inner - 4
	if len(tRunes) > maxTitle {
		tRunes = tRunes[:maxTitle]
	}
	titleStr := string(tRunes)
	// ╭─ title ─────╮
	remain := inner - 1 - VisibleWidth(titleStr) - 1
	if remain < 0 {
		remain = 0
	}
	top := CRail + BoxTL + BoxH + CReset + CBold + CVal + " " + titleStr + " " + CReset +
		CRail + strings.Repeat(BoxH, remain) + BoxTR + CReset

	out := make([]string, 0, len(content)+2)
	out = append(out, top)
	for _, line := range content {
		body := PadVisible(TruncateVisible(line, inner), inner)
		out = append(out, CRail+BoxV+CReset+body+CRail+BoxV+CReset)
	}
	bot := CRail + BoxBL + strings.Repeat(BoxH, inner) + BoxBR + CReset
	out = append(out, bot)
	return out
}

// SectionHeader returns a gradient-accent section label line.
func SectionHeader(label string, width int) string {
	label = SanitizeStr(label)
	sepLen := width - VisibleWidth(label) - 4
	if sepLen < 4 {
		sepLen = 4
	}
	sep := GradientText(strings.Repeat("━", sepLen), [3]uint8{0, 240, 255}, [3]uint8{60, 70, 90})
	return fmt.Sprintf("%s%s%s%s  %s", CBold, CVal, label, CReset, sep)
}

// RailPrefix returns the left tactical rail glyph + space (visible width 2).
func RailPrefix() string {
	return CRail + GRail + CReset + " "
}

// ContentWidth computes usable content width given terminal width and rail.
func ContentWidth(termWidth int) int {
	// rail (1) + space (1) + margin
	w := termWidth - 4
	if w < 40 {
		w = 40
	}
	if w > 160 {
		w = 160
	}
	return w
}
