// STATUS: DIAMANT VGT SUPREME
//go:build linux

package utils

import (
	"net"
	"strings"
	"unicode"
	"unicode/utf8"
	"unsafe"
)

// --- ABSOLUTE BINARY PATHS (CWE-426 PATH Hijacking Prevention) ---
const (
	CmdLast      = "/usr/bin/last"
	CmdSystemctl = "/bin/systemctl"
	CmdW         = "/usr/bin/w"
)

// B2s converts a null-terminated int8 slice (such as syscall C-strings) to a Go string
// with 0 allocations, hardened against length boundary overreads.
func B2s(b []int8) string {
	if len(b) == 0 {
		return ""
	}
	maxLen := len(b)
	n := 0
	for ; n < maxLen && b[n] != 0; n++ {
	}
	if n == 0 {
		return ""
	}
	return unsafe.String((*byte)(unsafe.Pointer(&b[0])), n)
}

// SanitizeIP validates and converts raw IP strings to clean IPv4/IPv6 representations,
// blocking malicious hostnames or injected parameters.
func SanitizeIP(input string) string {
	trimmed := strings.TrimSpace(input)
	if len(trimmed) > 45 {
		return "INVALID_IP_LEN"
	}
	if ip := net.ParseIP(trimmed); ip != nil {
		return ip.String()
	}
	return "UNKNOWN_HOST"
}

// SanitizeStr neutralizes VT100/ANSI Control Characters (CWE-150 Terminal Hijacking),
// ensuring raw dynamic user/process data can never issue escape commands to the operator terminal.
// Whitelist: printable ASCII subset safe for tactical HUD labels.
func SanitizeStr(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '.' || c == '_' || c == ':' || c == '-' || c == ' ' || c == '/' ||
			c == '(' || c == ')' || c == '@' || c == '[' || c == ']' || c == '=' ||
			c == '+' || c == '%' || c == ',' {
			b.WriteByte(c)
		}
	}
	res := b.String()
	if len(res) > 64 {
		return res[:64]
	}
	return res
}

// SanitizeDisplay strips ALL C0/C1 controls and ANSI introducers while allowing
// a broader printable set for free-form fields (status strings). Max 96 runes.
func SanitizeDisplay(s string, maxRunes int) string {
	if maxRunes <= 0 || maxRunes > 256 {
		maxRunes = 96
	}
	var b strings.Builder
	b.Grow(len(s))
	count := 0
	for _, r := range s {
		if r == 0x1b || r == 0x9b || r == 0x9d || r == 0x7f {
			continue
		}
		if r < 0x20 {
			continue
		}
		if r >= 0x80 && r < 0xa0 {
			continue
		}
		if !utf8.ValidRune(r) || r == unicode.ReplacementChar {
			continue
		}
		// Block private-use / surrogate
		if r >= 0xD800 && r <= 0xDFFF {
			continue
		}
		b.WriteRune(r)
		count++
		if count >= maxRunes {
			break
		}
	}
	return b.String()
}

// FastParseUint converts ASCII digit strings to uint64 without heap allocation,
// protected against numeric overflow wrap-around.
func FastParseUint(s string) uint64 {
	var n uint64
	const maxUintDiv10 = ^uint64(0) / 10
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			digit := uint64(s[i] - '0')
			if n > maxUintDiv10 {
				return ^uint64(0)
			}
			n = n*10 + digit
		}
	}
	return n
}

// ClampInt bounds v into [lo, hi].
func ClampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// VisibleWidth counts display columns assuming monospaced East-Asian-width=1
// for our glyph set (box/braille/block are single-width). ANSI sequences = 0.
func VisibleWidth(s string) int {
	w := 0
	inEsc := false
	for i := 0; i < len(s); {
		c := s[i]
		if c == 0x1b {
			inEsc = true
			i++
			continue
		}
		if inEsc {
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
				inEsc = false
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			i++
			continue
		}
		w++
		i += size
	}
	return w
}

// TruncateVisible truncates s to at most maxCols visible columns, preserving ANSI reset.
func TruncateVisible(s string, maxCols int) string {
	if maxCols <= 0 {
		return ""
	}
	if VisibleWidth(s) <= maxCols {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	w := 0
	inEsc := false
	for i := 0; i < len(s); {
		c := s[i]
		if c == 0x1b {
			inEsc = true
			b.WriteByte(c)
			i++
			continue
		}
		if inEsc {
			b.WriteByte(c)
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
				inEsc = false
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			i++
			continue
		}
		if w+1 > maxCols {
			break
		}
		b.WriteString(s[i : i+size])
		w++
		i += size
	}
	b.WriteString(CReset)
	return b.String()
}

// PadVisible right-pads with spaces to exactly cols visible width.
func PadVisible(s string, cols int) string {
	vw := VisibleWidth(s)
	if vw >= cols {
		return TruncateVisible(s, cols)
	}
	return s + strings.Repeat(" ", cols-vw)
}
