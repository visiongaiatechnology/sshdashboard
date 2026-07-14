// STATUS: DIAMANT VGT SUPREME
//go:build linux

package tui

import (
	"os"
	"strings"

	"sshdash/utils"
)

// Frame is a double-buffer line compositor. All UI modules append lines;
// a single atomic Write to stdout eliminates flicker over SSH latency.
type Frame struct {
	width  int
	height int
	lines  []string
	maxY   int // soft cap from terminal height
}

// NewFrame allocates a frame for the given terminal geometry.
func NewFrame(width, height int) *Frame {
	if width < 40 {
		width = 40
	}
	if width > 200 {
		width = 200
	}
	if height < 10 {
		height = 10
	}
	if height > 100 {
		height = 100
	}
	return &Frame{
		width:  width,
		height: height,
		lines:  make([]string, 0, height+8),
		maxY:   height,
	}
}

func (f *Frame) Width() int  { return f.width }
func (f *Frame) Height() int { return f.height }
func (f *Frame) Len() int    { return len(f.lines) }

// ContentWidth is the drawable width inside the left rail.
func (f *Frame) ContentWidth() int {
	return utils.ContentWidth(f.width)
}

// Add appends a content line (rail applied). Truncates to content width.
func (f *Frame) Add(text string) {
	cw := f.ContentWidth()
	line := utils.PadVisible(utils.TruncateVisible(text, cw), cw)
	f.lines = append(f.lines, utils.RailPrefix()+line)
}

// AddRaw appends a full-width line without rail (for edge-to-edge bars).
func (f *Frame) AddRaw(text string) {
	line := utils.PadVisible(utils.TruncateVisible(text, f.width), f.width)
	f.lines = append(f.lines, line)
}

// AddEmpty appends a blank railed line.
func (f *Frame) AddEmpty() {
	f.Add("")
}

// AddLines appends multiple content lines.
func (f *Frame) AddLines(lines []string) {
	for _, l := range lines {
		f.Add(l)
	}
}

// AddAll appends pre-railed or content lines via Add.
func (f *Frame) Remaining() int {
	r := f.maxY - len(f.lines) - 1 // reserve footer
	if r < 0 {
		return 0
	}
	return r
}

// Flush writes the complete frame: home cursor, emit lines with EL, clear-below.
// Single Write syscall batch reduces SSH packet chatter / tear.
func (f *Frame) Flush() {
	var b strings.Builder
	// Estimate: ~120 bytes/line avg with truecolor
	b.Grow(len(f.lines)*128 + 32)

	// Cursor home (do NOT full-clear — reduces flash; EL + clear-below handles residue)
	b.WriteString("\033[H")

	limit := len(f.lines)
	if limit > f.maxY {
		limit = f.maxY
	}
	for i := 0; i < limit; i++ {
		b.WriteString(f.lines[i])
		b.WriteString("\033[K\n") // erase to end of line
	}
	// Clear remainder of alternate screen
	b.WriteString("\033[J")

	_, _ = os.Stdout.WriteString(b.String())
}

// FlushMOTD writes without cursor home / clear (scrollable login banner).
func (f *Frame) FlushMOTD() {
	var b strings.Builder
	b.Grow(len(f.lines) * 128)
	for _, line := range f.lines {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	_, _ = os.Stdout.WriteString(b.String())
}
