// STATUS: DIAMANT VGT SUPREME
//go:build linux

package utils

import (
	"fmt"
	"strings"
)

// --- 24-BIT TRUECOLOR PALETTE & STYLING TOKENS ---
const (
	CReset = "\033[0m"
	CBold  = "\033[1m"
	CDim   = "\033[2m"
	CInv   = "\033[7m"
	CUnder = "\033[4m"

	// 24-bit Truecolor RGB Primary Colors
	CRail  = "\033[38;2;0;240;255m"   // Neon Cyber Cyan (#00F0FF)
	CBrand = "\033[38;2;157;0;255m"   // Electric Violet (#9D00FF)
	CLabel = "\033[38;2;130;140;160m" // Cool Tactical Gray (#828CA0)
	CVal   = "\033[38;2;255;255;255m" // Pure Obsidian White (#FFFFFF)

	COk    = "\033[38;2;0;255;135m"  // Tactical Emerald (#00FF87)
	CWarn  = "\033[38;2;255;214;0m"  // Amber Gold (#FFD600)
	CCrit  = "\033[38;2;255;0;85m"   // High Alert Crimson (#FF0055)
	CMag   = "\033[38;2;220;0;255m"  // Cyber Magenta (#DC00FF)
	CBarBg = "\033[38;2;30;35;45m"   // Deep Dark Track (#1E232D)
	CPanel = "\033[38;2;40;48;64m"   // Panel border slate
	CMuted = "\033[38;2;70;78;96m"   // Muted grid

	CTabActive   = "\033[48;2;0;240;255m\033[38;2;10;15;20m\033[1m"
	CTabInactive = "\033[48;2;30;35;45m\033[38;2;170;180;200m"
	CTabHover    = "\033[48;2;50;60;80m\033[38;2;0;240;255m"

	// Background fills for panel chrome
	CBgDeep = "\033[48;2;8;10;16m"
	CBgPanel = "\033[48;2;12;16;24m"

	GRail        = "▊"
	GArr         = "▶"
	GDotActive   = "●"
	GDotInactive = "◌"
	GBullet      = "▸"
)

// Box-drawing — single-width Unicode, SSH-safe across modern terminals
const (
	BoxTL     = "╭"
	BoxTR     = "╮"
	BoxBL     = "╰"
	BoxBR     = "╯"
	BoxH      = "─"
	BoxV      = "│"
	BoxTDown  = "┬"
	BoxTUp    = "┴"
	BoxTRight = "├"
	BoxTLeft  = "┤"
	BoxCross  = "┼"
	BoxDH     = "═"
	BoxDV     = "║"
)

// RGB returns a 24-bit Truecolor foreground ANSI string
func RGB(r, g, b uint8) string {
	return fmt.Sprintf("\033[38;2;%d;%d;%dm", r, g, b)
}

// RGBBg returns a 24-bit Truecolor background ANSI string
func RGBBg(r, g, b uint8) string {
	return fmt.Sprintf("\033[48;2;%d;%d;%dm", r, g, b)
}

// GradientText interpolates colors char-by-char across a string
func GradientText(text string, startRGB, endRGB [3]uint8) string {
	runes := []rune(text)
	if len(runes) == 0 {
		return ""
	}
	if len(runes) == 1 {
		return RGB(startRGB[0], startRGB[1], startRGB[2]) + text + CReset
	}

	var builder strings.Builder
	builder.Grow(len(text) * 20)

	total := float64(len(runes) - 1)
	for i, r := range runes {
		ratio := float64(i) / total
		cr := uint8(float64(startRGB[0])*(1.0-ratio) + float64(endRGB[0])*ratio)
		cg := uint8(float64(startRGB[1])*(1.0-ratio) + float64(endRGB[1])*ratio)
		cb := uint8(float64(startRGB[2])*(1.0-ratio) + float64(endRGB[2])*ratio)

		builder.WriteString(RGB(cr, cg, cb))
		builder.WriteRune(r)
	}
	builder.WriteString(CReset)

	return builder.String()
}

// StatusColor maps a 0-100 percent into tactical palette.
func StatusColor(percent int) string {
	if percent > 88 {
		return CCrit
	}
	if percent > 70 {
		return CWarn
	}
	return COk
}

// DrawBar produces high-precision, status-aware progress bars with half-block subpixel edges.
func DrawBar(percent int, width int) string {
	if percent < 0 {
		percent = 0
	} else if percent > 100 {
		percent = 100
	}
	if width <= 0 || width > 100 {
		width = 20
	}

	// Subpixel: each cell is half-filled capable → 2x resolution
	totalHalves := width * 2
	filledHalves := (percent * totalHalves) / 100
	if filledHalves < 0 {
		filledHalves = 0
	} else if filledHalves > totalHalves {
		filledHalves = totalHalves
	}

	color := StatusColor(percent)
	var b strings.Builder
	b.Grow(width*12 + 16)
	b.WriteString(color)

	full := filledHalves / 2
	half := filledHalves % 2
	for i := 0; i < width; i++ {
		if i < full {
			b.WriteRune('█')
		} else if i == full && half == 1 {
			b.WriteRune('▌')
		} else {
			b.WriteString(CBarBg)
			b.WriteRune('·')
			b.WriteString(color)
		}
	}
	b.WriteString(CReset)
	return b.String()
}

// DrawGauge renders a dual-rail vertical-feeling horizontal gauge with percent label.
func DrawGauge(label string, percent int, barWidth int) string {
	label = SanitizeStr(label)
	if barWidth < 8 {
		barWidth = 8
	}
	return fmt.Sprintf("%s%-8s%s %s %s%3d%%%s",
		CLabel, label, CReset, DrawBar(percent, barWidth), StatusColor(percent), percent, CReset)
}

func FormatSvc(active bool, name string) string {
	cleanName := SanitizeStr(name)
	if active {
		return fmt.Sprintf("%s[%s%s%s]%s %s%s%s", CDim, COk, GDotActive, CDim, CReset, CVal, cleanName, CReset)
	}
	return fmt.Sprintf("%s[%s%s%s]%s %s%s%s", CDim, CCrit, GDotInactive, CDim, CReset, CDim, cleanName, CReset)
}

func FormatBytesSpeed(speedBps float64) string {
	if speedBps < 0 {
		speedBps = 0
	}
	if speedBps < 1024 {
		return fmt.Sprintf("%.0f B/s", speedBps)
	} else if speedBps < 1024*1024 {
		return fmt.Sprintf("%.1f KB/s", speedBps/1024)
	} else if speedBps < 1024*1024*1024 {
		return fmt.Sprintf("%.2f MB/s", speedBps/1024/1024)
	}
	return fmt.Sprintf("%.2f GB/s", speedBps/1024/1024/1024)
}

func FormatBytes(n uint64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
		TB = GB * 1024
	)
	switch {
	case n >= TB:
		return fmt.Sprintf("%.2f TB", float64(n)/float64(TB))
	case n >= GB:
		return fmt.Sprintf("%.2f GB", float64(n)/float64(GB))
	case n >= MB:
		return fmt.Sprintf("%.1f MB", float64(n)/float64(MB))
	case n >= KB:
		return fmt.Sprintf("%.1f KB", float64(n)/float64(KB))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
