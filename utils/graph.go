// STATUS: DIAMANT VGT SUPREME
//go:build linux

package utils

import (
	"fmt"
	"math"
	"strings"
)

var sparkBlocks = []rune{' ', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

// heatBlocks: 5-level density for CPU core heatmap cells
var heatBlocks = []rune{'·', '░', '▒', '▓', '█'}

// DrawSparkline renders 1-line block trend charts
func DrawSparkline(series []float64, maxVal float64) string {
	if len(series) == 0 {
		return ""
	}
	if maxVal <= 0 {
		maxVal = 100.0
	}

	var builder strings.Builder
	builder.Grow(len(series) * 4)
	numGlyphs := len(sparkBlocks)

	for _, v := range series {
		if v < 0 {
			v = 0
		}
		ratio := v / maxVal
		if ratio > 1.0 {
			ratio = 1.0
		}
		idx := int(ratio * float64(numGlyphs-1))
		if idx < 0 {
			idx = 0
		} else if idx >= numGlyphs {
			idx = numGlyphs - 1
		}
		if ratio > 0.85 {
			builder.WriteString(CCrit)
		} else if ratio > 0.65 {
			builder.WriteString(CWarn)
		} else {
			builder.WriteString(COk)
		}
		builder.WriteRune(sparkBlocks[idx])
	}
	builder.WriteString(CReset)
	return builder.String()
}

// DrawSparklineFixed resamples series into exactly width columns.
func DrawSparklineFixed(series []float64, width int, maxVal float64) string {
	if width <= 0 {
		return ""
	}
	if maxVal <= 0 {
		maxVal = 100.0
	}
	if len(series) == 0 {
		return CMuted + strings.Repeat("·", width) + CReset
	}
	resampled := make([]float64, width)
	for x := 0; x < width; x++ {
		idx := (x * len(series)) / width
		if idx >= len(series) {
			idx = len(series) - 1
		}
		resampled[x] = series[idx]
	}
	return DrawSparkline(resampled, maxVal)
}

// PlotBrailleGraph renders 2x4 subpixel Unicode Braille charts (U+2800 to U+28FF)
// providing 8x spatial resolution for CPU load & network throughput timeline graphs.
// mode: 0=line (peak dots), 1=filled area under curve.
func PlotBrailleGraph(series []float64, chartWidth, chartHeight int, maxVal float64) []string {
	return PlotBrailleGraphMode(series, chartWidth, chartHeight, maxVal, 1)
}

func PlotBrailleGraphMode(series []float64, chartWidth, chartHeight int, maxVal float64, mode int) []string {
	if chartWidth <= 0 || chartHeight <= 0 {
		return nil
	}
	if maxVal <= 0 {
		maxVal = 100.0
	}

	subWidth := chartWidth * 2
	subHeight := chartHeight * 4

	points := make([]float64, subWidth)
	if len(series) > 0 {
		for x := 0; x < subWidth; x++ {
			idx := (x * len(series)) / subWidth
			if idx >= len(series) {
				idx = len(series) - 1
			}
			points[x] = series[idx]
		}
	}

	grid := make([][]uint8, chartHeight)
	for y := 0; y < chartHeight; y++ {
		grid[y] = make([]uint8, chartWidth)
	}

	dotMask := [2][4]uint8{
		{0x01, 0x02, 0x04, 0x40},
		{0x08, 0x10, 0x20, 0x80},
	}

	for px := 0; px < subWidth; px++ {
		val := points[px]
		if val < 0 {
			val = 0
		}
		norm := val / maxVal
		if norm > 1.0 {
			norm = 1.0
		}

		py := int(math.Round(norm * float64(subHeight-1)))
		if py < 0 {
			py = 0
		} else if py >= subHeight {
			py = subHeight - 1
		}
		pyScreen := (subHeight - 1) - py

		if mode == 1 {
			// Filled area: light all dots from baseline to peak
			for sy := pyScreen; sy < subHeight; sy++ {
				cellX := px / 2
				cellY := sy / 4
				subX := px % 2
				subY := sy % 4
				if cellX < chartWidth && cellY < chartHeight {
					grid[cellY][cellX] |= dotMask[subX][subY]
				}
			}
		} else {
			cellX := px / 2
			cellY := pyScreen / 4
			subX := px % 2
			subY := pyScreen % 4
			if cellX < chartWidth && cellY < chartHeight {
				grid[cellY][cellX] |= dotMask[subX][subY]
			}
		}
	}

	lines := make([]string, chartHeight)
	for y := 0; y < chartHeight; y++ {
		var builder strings.Builder
		builder.Grow(chartWidth * 8)
		for x := 0; x < chartWidth; x++ {
			pattern := grid[y][x]
			r := rune(0x2800 + uint32(pattern))
			heightRatio := float64((chartHeight-1)-y) / float64(maxInt(chartHeight, 1))
			if pattern == 0 {
				builder.WriteString(CMuted)
			} else if heightRatio > 0.8 {
				builder.WriteString(CCrit)
			} else if heightRatio > 0.5 {
				builder.WriteString(CWarn)
			} else {
				builder.WriteString(CRail)
			}
			builder.WriteRune(r)
		}
		builder.WriteString(CReset)
		lines[y] = builder.String()
	}
	return lines
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// PlotBrailleDual overlays two series (e.g. RX/TX) with distinct color channels on shared geometry.
// seriesA uses cyan density, seriesB violet — combined via OR of braille bits, color by dominant.
func PlotBrailleDual(seriesA, seriesB []float64, chartWidth, chartHeight int, maxVal float64) []string {
	if chartWidth <= 0 || chartHeight <= 0 {
		return nil
	}
	if maxVal <= 0 {
		// Auto-scale
		maxVal = 1.0
		for _, v := range seriesA {
			if v > maxVal {
				maxVal = v
			}
		}
		for _, v := range seriesB {
			if v > maxVal {
				maxVal = v
			}
		}
	}

	subWidth := chartWidth * 2
	subHeight := chartHeight * 4
	gridA := make([][]uint8, chartHeight)
	gridB := make([][]uint8, chartHeight)
	for y := 0; y < chartHeight; y++ {
		gridA[y] = make([]uint8, chartWidth)
		gridB[y] = make([]uint8, chartWidth)
	}
	dotMask := [2][4]uint8{
		{0x01, 0x02, 0x04, 0x40},
		{0x08, 0x10, 0x20, 0x80},
	}

	paint := func(series []float64, grid [][]uint8) {
		if len(series) == 0 {
			return
		}
		for px := 0; px < subWidth; px++ {
			idx := (px * len(series)) / subWidth
			if idx >= len(series) {
				idx = len(series) - 1
			}
			val := series[idx]
			if val < 0 {
				val = 0
			}
			norm := val / maxVal
			if norm > 1.0 {
				norm = 1.0
			}
			py := int(math.Round(norm * float64(subHeight-1)))
			if py < 0 {
				py = 0
			} else if py >= subHeight {
				py = subHeight - 1
			}
			pyScreen := (subHeight - 1) - py
			for sy := pyScreen; sy < subHeight; sy++ {
				cellX := px / 2
				cellY := sy / 4
				subX := px % 2
				subY := sy % 4
				if cellX < chartWidth && cellY < chartHeight {
					grid[cellY][cellX] |= dotMask[subX][subY]
				}
			}
		}
	}
	paint(seriesA, gridA)
	paint(seriesB, gridB)

	lines := make([]string, chartHeight)
	for y := 0; y < chartHeight; y++ {
		var b strings.Builder
		b.Grow(chartWidth * 10)
		for x := 0; x < chartWidth; x++ {
			a, bb := gridA[y][x], gridB[y][x]
			combined := a | bb
			r := rune(0x2800 + uint32(combined))
			if combined == 0 {
				b.WriteString(CMuted)
			} else if a != 0 && bb != 0 {
				b.WriteString(CMag)
			} else if a != 0 {
				b.WriteString(COk)
			} else {
				b.WriteString(CWarn)
			}
			b.WriteRune(r)
		}
		b.WriteString(CReset)
		lines[y] = b.String()
	}
	return lines
}

// DrawCoreHeatmap renders a dense per-core heat grid (cols cells wide).
// Returns one or more lines depending on core count.
func DrawCoreHeatmap(usage []float64, cores int, cols int) []string {
	if cores <= 0 {
		cores = len(usage)
	}
	if cores <= 0 {
		return []string{CDim + "[no cores]" + CReset}
	}
	if cols < 4 {
		cols = 4
	}
	if cols > 32 {
		cols = 32
	}

	rows := (cores + cols - 1) / cols
	if rows > 4 {
		rows = 4
		cores = rows * cols
	}

	out := make([]string, 0, rows)
	for row := 0; row < rows; row++ {
		var b strings.Builder
		b.Grow(cols * 24)
		for col := 0; col < cols; col++ {
			idx := row*cols + col
			if idx >= cores {
				b.WriteString(CMuted)
				b.WriteString(" · ")
				b.WriteString(CReset)
				continue
			}
			u := 0.0
			if idx < len(usage) {
				u = usage[idx]
			}
			if u < 0 {
				u = 0
			}
			if u > 100 {
				u = 100
			}
			level := int((u / 100.0) * float64(len(heatBlocks)-1))
			if level < 0 {
				level = 0
			}
			if level >= len(heatBlocks) {
				level = len(heatBlocks) - 1
			}
			if u > 88 {
				b.WriteString(CCrit)
			} else if u > 70 {
				b.WriteString(CWarn)
			} else if u > 30 {
				b.WriteString(CRail)
			} else {
				b.WriteString(COk)
			}
			b.WriteString(fmt.Sprintf("%c%2d", heatBlocks[level], idx))
			b.WriteString(CReset)
			if col < cols-1 {
				b.WriteByte(' ')
			}
		}
		out = append(out, b.String())
	}
	return out
}

// AppendHistory pushes v onto ring buffer maxLen.
func AppendHistory(hist []float64, v float64, maxLen int) []float64 {
	if maxLen <= 0 {
		maxLen = 60
	}
	if len(hist) >= maxLen {
		hist = hist[1:]
	}
	return append(hist, v)
}
