// STATUS: DIAMANT VGT SUPREME
//go:build linux

package tui

import (
	"testing"

	"sshdash/types"
)

func TestDecodeInputKeys(t *testing.T) {
	inPaste := false

	// ASCII '1' -> KeyTab1
	evs := decodeInput([]byte("1"), &inPaste)
	if len(evs) != 1 || evs[0].Kind != types.EventKey || evs[0].Key != types.KeyTab1 {
		t.Errorf("decodeInput('1') failed: %+v", evs)
	}

	// CSI Up Arrow ESC [ A
	evs = decodeInput([]byte{0x1b, '[', 'A'}, &inPaste)
	if len(evs) != 1 || evs[0].Kind != types.EventKey || evs[0].Key != types.KeyUp {
		t.Errorf("decodeInput(CSI Up) failed: %+v", evs)
	}
}

func TestDecodeInputBracketedPaste(t *testing.T) {
	inPaste := false

	// Start paste + payload + end paste
	pasteData := append([]byte{0x1b, '[', '2', '0', '0', '~'}, []byte("123qR")...)
	pasteData = append(pasteData, []byte{0x1b, '[', '2', '0', '1', '~'}...)

	evs := decodeInput(pasteData, &inPaste)

	// In-paste keys MUST be dropped entirely (0 events generated)
	if len(evs) != 0 {
		t.Errorf("decodeInput(bracketed paste) produced %d events, expected 0", len(evs))
	}
}

func TestParseSGRMouseMotionAndDragIgnored(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"Motion btn 35", []byte("\x1b[<35;10;5M")},
		{"Left Drag btn 32", []byte("\x1b[<32;10;5M")},
		{"Middle Drag btn 33", []byte("\x1b[<33;10;5M")},
		{"Right Drag btn 34", []byte("\x1b[<34;10;5M")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev, adv, ok := parseSGRMouse(tt.data)
			if !ok || adv == 0 {
				t.Fatalf("parseSGRMouse failed to parse stream for %s", tt.name)
			}
			// Motion / drag events must NOT produce MouseLeft click actions
			if ev.MouseB == types.MouseLeft {
				t.Errorf("parseSGRMouse(%s) returned MouseLeft click action! Must be ignored", tt.name)
			}
			if ev.MouseB != types.MouseNone {
				t.Errorf("parseSGRMouse(%s) returned button %v, expected MouseNone", tt.name, ev.MouseB)
			}
		})
	}
}
