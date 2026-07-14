// STATUS: DIAMANT VGT SUPREME
//go:build linux

package tui

import (
	"fmt"
	"os"
	"sync"
	"syscall"
	"unsafe"
)

// TermEngine owns POSIX termios + SSH-compatible capability negotiation.
// Defense: always restore origTermios on DisableRawMode / panic path.
type TermEngine struct {
	mu          sync.Mutex
	origTermios syscall.Termios
	isRaw       bool
	mouseOn     bool
}

// IsTerminalTTY returns true if stdout is connected to an interactive terminal TTY.
func IsTerminalTTY() bool {
	var termios syscall.Termios
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(syscall.Stdout), uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(&termios)))
	return err == 0
}

func GetTermWidth() int {
	ws := &struct{ Row, Col, Xpixel, Ypixel uint16 }{}
	retCode, _, _ := syscall.Syscall(syscall.SYS_IOCTL, uintptr(syscall.Stdout), uintptr(syscall.TIOCGWINSZ), uintptr(unsafe.Pointer(ws)))
	if int(retCode) == -1 || ws.Col == 0 {
		return 80
	}
	w := int(ws.Col)
	if w < 40 {
		return 40
	}
	if w > 200 {
		return 200
	}
	return w
}

func GetTermHeight() int {
	ws := &struct{ Row, Col, Xpixel, Ypixel uint16 }{}
	retCode, _, _ := syscall.Syscall(syscall.SYS_IOCTL, uintptr(syscall.Stdout), uintptr(syscall.TIOCGWINSZ), uintptr(unsafe.Pointer(ws)))
	if int(retCode) == -1 || ws.Row == 0 {
		return 24
	}
	h := int(ws.Row)
	if h < 10 {
		return 10
	}
	if h > 100 {
		return 100
	}
	return h
}

func (t *TermEngine) EnableRawMode() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.isRaw {
		return nil
	}

	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(syscall.Stdin), uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(&t.origTermios)))
	if err != 0 {
		return fmt.Errorf("failed to read termios flags: %v", err)
	}

	raw := t.origTermios
	// Non-canonical, no echo, no extended processing; keep ISIG off so we own signals via Notify
	raw.Lflag &^= syscall.ECHO | syscall.ICANON | syscall.IEXTEN | syscall.ISIG
	raw.Iflag &^= syscall.IXON | syscall.ICRNL | syscall.INPCK | syscall.ISTRIP | syscall.BRKINT
	raw.Cflag |= syscall.CS8
	raw.Cc[syscall.VMIN] = 0
	raw.Cc[syscall.VTIME] = 1 // 100ms poll

	_, _, err = syscall.Syscall(syscall.SYS_IOCTL, uintptr(syscall.Stdin), uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(&raw)))
	if err != 0 {
		return fmt.Errorf("failed to set raw termios: %v", err)
	}

	t.isRaw = true

	// Alternate screen + hide cursor + clear + enable SGR mouse + focus events + bracketed paste
	// Mouse: 1000 click, 1002 drag, 1006 SGR (coordinates > 223 safe), 1015 urxvt fallback not needed
	// Bracketed paste 2004 prevents pasted control sequences from acting as keystrokes mid-stream
	fmt.Fprint(os.Stdout,
		"\033[?1049h"+ // alt screen
			"\033[?25l"+ // hide cursor
			"\033[2J\033[H"+ // clear
			"\033[?1000h"+ // mouse click
			"\033[?1002h"+ // mouse drag (for completeness)
			"\033[?1006h"+ // SGR mouse encoding
			"\033[?2004h", // bracketed paste
	)
	t.mouseOn = true
	return nil
}

func (t *TermEngine) DisableRawMode() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.isRaw {
		return
	}

	// Disable mouse / paste BEFORE restoring primary buffer
	if t.mouseOn {
		fmt.Fprint(os.Stdout,
			"\033[?2004l"+
				"\033[?1006l"+
				"\033[?1002l"+
				"\033[?1000l",
		)
		t.mouseOn = false
	}

	fmt.Fprint(os.Stdout, "\033[?1049l\033[?25h\033[0m")
	syscall.Syscall(syscall.SYS_IOCTL, uintptr(syscall.Stdin), uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(&t.origTermios)))
	t.isRaw = false
}
