// STATUS: DIAMANT VGT SUPREME
//go:build linux

package tui

import (
	"os"
	"os/signal"
	"syscall"

	"sshdash/types"
)

// ListenInput is the sole stdin consumer. It emits typed InputEvents only —
// never raw byte slices — so the UI loop cannot be coerced into interpreting
// hostile paste/ANSI as executable sequences beyond our whitelist.
func ListenInput(evChan chan<- types.InputEvent, quitChan chan<- struct{}) {
	buf := make([]byte, 64)
	sigChan := make(chan os.Signal, 4)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGWINCH)

	// Bracketed-paste isolation: while inside paste, drop all key interpretation
	inPaste := false

	go func() {
		defer func() {
			// Ensure quit on goroutine death
			safeCloseQuit(quitChan)
		}()

		for {
			select {
			case sig := <-sigChan:
				if sig == syscall.SIGWINCH {
					w := GetTermWidth()
					h := GetTermHeight()
					select {
					case evChan <- types.InputEvent{Kind: types.EventResize, Width: w, Height: h}:
					default:
					}
				} else {
					safeCloseQuit(quitChan)
					return
				}
			default:
				n, err := os.Stdin.Read(buf)
				if err != nil || n <= 0 {
					continue
				}
				events := decodeInput(buf[:n], &inPaste)
				for _, ev := range events {
					if ev.Kind == types.EventQuit {
						safeCloseQuit(quitChan)
						return
					}
					select {
					case evChan <- ev:
					default:
						// Drop under backpressure — never block input reader
					}
				}
			}
		}
	}()
}

func safeCloseQuit(quitChan chan<- struct{}) {
	defer func() { recover() }()
	close(quitChan)
}

// decodeInput parses a raw stdin chunk into zero or more typed events.
// Supports: ASCII keys, CSI arrows/pages, SGR mouse (ESC [ < ... M/m), bracketed paste.
func decodeInput(data []byte, inPaste *bool) []types.InputEvent {
	var out []types.InputEvent
	i := 0
	for i < len(data) {
		// Bracketed paste start: ESC [ 2 0 0 ~
		if i+5 < len(data) && data[i] == 0x1b && data[i+1] == '[' &&
			data[i+2] == '2' && data[i+3] == '0' && data[i+4] == '0' && data[i+5] == '~' {
			*inPaste = true
			i += 6
			continue
		}
		// Bracketed paste end: ESC [ 2 0 1 ~
		if i+5 < len(data) && data[i] == 0x1b && data[i+1] == '[' &&
			data[i+2] == '2' && data[i+3] == '0' && data[i+4] == '1' && data[i+5] == '~' {
			*inPaste = false
			i += 6
			continue
		}
		if *inPaste {
			// Consume paste payload without interpretation (CWE-150 defense)
			i++
			continue
		}

		b := data[i]

		// ESC sequences
		if b == 0x1b {
			// SGR mouse: ESC [ < b ; x ; y M/m
			if i+2 < len(data) && data[i+1] == '[' && data[i+2] == '<' {
				ev, adv, ok := parseSGRMouse(data[i:])
				if ok {
					if ev.Kind == types.EventMouse && ev.MouseB != types.MouseNone {
						out = append(out, ev)
					}
					i += adv
					continue
				}
			}
			// CSI ...
			if i+2 < len(data) && data[i+1] == '[' {
				ev, adv := parseCSI(data[i:])
				if adv > 0 {
					if ev.Kind != types.EventKey || ev.Key != types.KeyNone {
						out = append(out, ev)
					}
					i += adv
					continue
				}
			}
			i++
			continue
		}

		// Ctrl+C
		if b == 0x03 {
			out = append(out, types.InputEvent{Kind: types.EventQuit})
			i++
			continue
		}

		switch b {
		case 'q', 'Q':
			out = append(out, types.InputEvent{Kind: types.EventQuit})
		case 'r', 'R':
			out = append(out, types.InputEvent{Kind: types.EventKey, Key: types.KeyRefresh})
		case '1':
			out = append(out, types.InputEvent{Kind: types.EventKey, Key: types.KeyTab1})
		case '2':
			out = append(out, types.InputEvent{Kind: types.EventKey, Key: types.KeyTab2})
		case '3':
			out = append(out, types.InputEvent{Kind: types.EventKey, Key: types.KeyTab3})
		case '4':
			out = append(out, types.InputEvent{Kind: types.EventKey, Key: types.KeyTab4})
		case '\t':
			out = append(out, types.InputEvent{Kind: types.EventKey, Key: types.KeyNextTab})
		case 'h', 'H':
			out = append(out, types.InputEvent{Kind: types.EventKey, Key: types.KeyPrevTab})
		case 'l', 'L':
			out = append(out, types.InputEvent{Kind: types.EventKey, Key: types.KeyNextTab})
		case 'j', 'J':
			out = append(out, types.InputEvent{Kind: types.EventKey, Key: types.KeyDown})
		case 'k', 'K':
			out = append(out, types.InputEvent{Kind: types.EventKey, Key: types.KeyUp})
		}
		i++
	}
	return out
}

func parseCSI(data []byte) (types.InputEvent, int) {
	// data[0]=ESC data[1]='['
	if len(data) < 3 {
		return types.InputEvent{}, 0
	}
	// Arrow / special single-letter CSI
	switch data[2] {
	case 'A':
		return types.InputEvent{Kind: types.EventKey, Key: types.KeyUp}, 3
	case 'B':
		return types.InputEvent{Kind: types.EventKey, Key: types.KeyDown}, 3
	case 'C':
		return types.InputEvent{Kind: types.EventKey, Key: types.KeyRight}, 3
	case 'D':
		return types.InputEvent{Kind: types.EventKey, Key: types.KeyLeft}, 3
	case 'Z': // Shift-Tab
		return types.InputEvent{Kind: types.EventKey, Key: types.KeyPrevTab}, 3
	case 'H':
		return types.InputEvent{Kind: types.EventKey, Key: types.KeyHome}, 3
	case 'F':
		return types.InputEvent{Kind: types.EventKey, Key: types.KeyEnd}, 3
	}

	// CSI n ~  form: page up/down 5~ 6~
	j := 2
	num := 0
	for j < len(data) && data[j] >= '0' && data[j] <= '9' {
		num = num*10 + int(data[j]-'0')
		j++
		if j-2 > 4 {
			return types.InputEvent{}, j
		}
	}
	if j < len(data) && data[j] == '~' {
		switch num {
		case 5:
			return types.InputEvent{Kind: types.EventKey, Key: types.KeyPageUp}, j + 1
		case 6:
			return types.InputEvent{Kind: types.EventKey, Key: types.KeyPageDown}, j + 1
		case 1:
			return types.InputEvent{Kind: types.EventKey, Key: types.KeyHome}, j + 1
		case 4:
			return types.InputEvent{Kind: types.EventKey, Key: types.KeyEnd}, j + 1
		default:
			return types.InputEvent{}, j + 1
		}
	}
	// Unknown CSI — consume until letter terminator
	for j < len(data) {
		if (data[j] >= 'a' && data[j] <= 'z') || (data[j] >= 'A' && data[j] <= 'Z') || data[j] == '~' {
			return types.InputEvent{}, j + 1
		}
		j++
		if j > 32 {
			break
		}
	}
	return types.InputEvent{}, j
}

// parseSGRMouse decodes ESC [ < btn ; x ; y M/m
// Coordinates are 1-based. Only press events (M) for left click / wheel are emitted.
func parseSGRMouse(data []byte) (types.InputEvent, int, bool) {
	// Minimum: ESC [ < 0 ; 1 ; 1 M = 9 bytes
	if len(data) < 9 || data[0] != 0x1b || data[1] != '[' || data[2] != '<' {
		return types.InputEvent{}, 0, false
	}
	i := 3
	btn, i, ok := readDec(data, i)
	if !ok || i >= len(data) || data[i] != ';' {
		return types.InputEvent{}, 0, false
	}
	i++
	x, i, ok := readDec(data, i)
	if !ok || i >= len(data) || data[i] != ';' {
		return types.InputEvent{}, 0, false
	}
	i++
	y, i, ok := readDec(data, i)
	if !ok || i >= len(data) {
		return types.InputEvent{}, 0, false
	}
	term := data[i]
	if term != 'M' && term != 'm' {
		return types.InputEvent{}, 0, false
	}
	i++

	// Release (m) ignored except we still advance
	if term == 'm' {
		return types.InputEvent{}, i, true
	}

	// Bounds: reject absurd coordinates (DoS / corrupt stream)
	if x < 1 || x > 500 || y < 1 || y > 200 {
		return types.InputEvent{}, i, true
	}

	ev := types.InputEvent{
		Kind:   types.EventMouse,
		MouseX: x,
		MouseY: y,
	}

	// Motion or drag events have bit 32 set (e.g. 32=left drag, 35=motion without buttons)
	// Absorb as MouseNone / no-op event to prevent drag from being interpreted as left click.
	if (btn & 32) != 0 {
		return types.InputEvent{}, i, true
	}

	switch btn {
	case 0:
		ev.MouseB = types.MouseLeft
	case 64:
		ev.MouseB = types.MouseWheelUp
	case 65:
		ev.MouseB = types.MouseWheelDown
	default:
		// motion / other — absorb, no-op event
		return types.InputEvent{}, i, true
	}
	return ev, i, true
}

func readDec(data []byte, i int) (int, int, bool) {
	if i >= len(data) || data[i] < '0' || data[i] > '9' {
		return 0, i, false
	}
	n := 0
	start := i
	for i < len(data) && data[i] >= '0' && data[i] <= '9' {
		n = n*10 + int(data[i]-'0')
		i++
		if i-start > 4 {
			return 0, i, false
		}
	}
	return n, i, true
}

// ApplyMouseTabHit maps a left-click to a tab if inside chrome hit regions.
func ApplyMouseTabHit(app *types.AppState, x, y int) bool {
	if y < app.TabHitMinY || y > app.TabHitMaxY {
		return false
	}
	for i := 0; i < int(types.TabCount); i++ {
		h := app.TabHits[i]
		if x >= h.X0 && x <= h.X1 {
			app.ActiveTab = types.TabID(i)
			app.ScrollY = 0
			return true
		}
	}
	return false
}
