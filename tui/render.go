// STATUS: DIAMANT VGT SUPREME
//go:build linux

package tui

import (
	"time"

	"sshdash/types"
)

// RenderTUI composes one full double-buffered frame for the live engine.
// Collectors never write during flush — caller must pass Snapshot() view.
func RenderTUI(full *types.FullState, app *types.AppState) {
	w := app.TerminalWidth
	h := app.TerminalHeight
	if w < 40 {
		w = GetTermWidth()
		app.TerminalWidth = w
	}
	if h < 10 {
		h = GetTermHeight()
		app.TerminalHeight = h
	}

	f := NewFrame(w, h)
	cw := f.ContentWidth()

	renderHeader(f, &full.System, time.Now())
	renderTabBar(f, app)

	// Body budget: total height - header(4) - tabs(2) - footer(1) - margin
	used := f.Len()
	footerReserve := 1
	maxBody := h - used - footerReserve - 1
	if maxBody < 4 {
		maxBody = 4
	}

	var body []string
	switch app.ActiveTab {
	case types.TabSystem:
		body = renderTabSystem(full, cw)
	case types.TabSecurity:
		body = renderTabSecurity(full, cw)
	case types.TabDocker:
		body = renderTabDocker(full, cw)
	case types.TabDaemons:
		body = renderTabDaemons(full, cw)
	default:
		body = renderTabSystem(full, cw)
	}

	visible, clamped := applyScroll(body, app.ScrollY, maxBody)
	app.ScrollY = clamped
	f.AddLines(visible)

	// Fill remaining space so footer stays at bottom-ish without jump artifacts
	for f.Len() < h-footerReserve-1 {
		f.AddEmpty()
	}

	renderFooter(f, full)
	f.Flush()
}

// HandleInput mutates AppState from a typed event. Returns true if refresh metrics requested.
func HandleInput(app *types.AppState, ev types.InputEvent) (needMetrics bool) {
	switch ev.Kind {
	case types.EventResize:
		if ev.Width > 0 && ev.Height > 0 {
			app.TerminalWidth = ev.Width
			app.TerminalHeight = ev.Height
		} else {
			app.TerminalWidth = GetTermWidth()
			app.TerminalHeight = GetTermHeight()
		}
		return false

	case types.EventMouse:
		switch ev.MouseB {
		case types.MouseLeft:
			if ApplyMouseTabHit(app, ev.MouseX, ev.MouseY) {
				return false
			}
		case types.MouseWheelUp:
			if app.ScrollY > 0 {
				app.ScrollY--
			}
		case types.MouseWheelDown:
			app.ScrollY++
		}
		return false

	case types.EventKey:
		switch ev.Key {
		case types.KeyTab1:
			app.ActiveTab = types.TabSystem
			app.ScrollY = 0
		case types.KeyTab2:
			app.ActiveTab = types.TabSecurity
			app.ScrollY = 0
		case types.KeyTab3:
			app.ActiveTab = types.TabDocker
			app.ScrollY = 0
		case types.KeyTab4:
			app.ActiveTab = types.TabDaemons
			app.ScrollY = 0
		case types.KeyNextTab, types.KeyRight:
			app.ActiveTab = (app.ActiveTab + 1) % types.TabCount
			app.ScrollY = 0
		case types.KeyPrevTab, types.KeyLeft:
			app.ActiveTab = (app.ActiveTab + types.TabCount - 1) % types.TabCount
			app.ScrollY = 0
		case types.KeyUp, types.KeyPageUp:
			step := 1
			if ev.Key == types.KeyPageUp {
				step = 5
			}
			app.ScrollY -= step
			if app.ScrollY < 0 {
				app.ScrollY = 0
			}
		case types.KeyDown, types.KeyPageDown:
			step := 1
			if ev.Key == types.KeyPageDown {
				step = 5
			}
			app.ScrollY += step
		case types.KeyHome:
			app.ScrollY = 0
		case types.KeyRefresh:
			return true
		}
	}
	return false
}
