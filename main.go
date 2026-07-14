// STATUS: DIAMANT VGT SUPREME
//go:build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sync"
	"time"

	"sshdash/collectors"
	"sshdash/tui"
	"sshdash/types"
)

const version = "3.1.0-diamond-vgt"

func collectAllMetrics(ctx context.Context, full *types.FullState) {
	// Private local scratch struct to isolate concurrent writes from shared state
	var scratch types.FullState

	// Seed scratch with historical telemetry buffers under short RLock
	full.RLock()
	scratch.System.CoreHistory = cloneCoreHistory(full.System.CoreHistory)
	scratch.System.GlobalLoadHistory = append([]float64(nil), full.System.GlobalLoadHistory...)
	scratch.Network.RxHistory = append([]float64(nil), full.Network.RxHistory...)
	scratch.Network.TxHistory = append([]float64(nil), full.Network.TxHistory...)
	full.RUnlock()

	var wg sync.WaitGroup
	wg.Add(5)

	// Execute collectors targeting ONLY the unshared private scratch buffer
	go collectors.GetSystemState(ctx, &wg, &scratch.System)
	go collectors.GetNetworkState(ctx, &wg, &scratch.Network)
	go collectors.GetSecurityState(ctx, &wg, &scratch.Security)
	go collectors.GetDockerState(ctx, &wg, &scratch.Docker)
	go collectors.GetProcessState(ctx, &wg, &scratch.Process)

	// Always wait for all collectors to conclude — guarantees ZERO goroutine leaks or torn writes
	wg.Wait()

	scratch.LastUpdate = time.Now()

	// Atomic update of shared state under short Lock
	full.Lock()
	full.LastUpdate = scratch.LastUpdate
	full.System = scratch.System
	full.Network = scratch.Network
	full.Security = scratch.Security
	full.Docker = scratch.Docker
	full.Process = scratch.Process
	full.Unlock()
}

func cloneCoreHistory(in [][]float64) [][]float64 {
	if len(in) == 0 {
		return nil
	}
	out := make([][]float64, len(in))
	for i := range in {
		if len(in[i]) > 0 {
			out[i] = append([]float64(nil), in[i]...)
		}
	}
	return out
}

func main() {
	motdFlag := flag.Bool("motd", false, "Render a single MOTD snapshot and exit (for SSH login /etc/profile.d)")
	verFlag := flag.Bool("version", false, "Display SSHDash version and exit")
	flag.BoolVar(motdFlag, "m", false, "Alias for --motd")
	flag.BoolVar(verFlag, "v", false, "Alias for --version")
	flag.Parse()

	if *verFlag {
		fmt.Printf("SSHDash Diamond Tactical SSH Engine v%s (Linux x86_64/ARM64)\n", version)
		os.Exit(0)
	}

	isTTY := tui.IsTerminalTTY()

	app := &types.AppState{
		ActiveTab:      types.TabSystem,
		MotdMode:       *motdFlag || !isTTY,
		Running:        true,
		TerminalWidth:  tui.GetTermWidth(),
		TerminalHeight: tui.GetTermHeight(),
		MouseEnabled:   true,
	}

	var full types.FullState

	// 1. SINGLE SNAPSHOT MOTD MODE (NON-INTERACTIVE OR --motd FLAG)
	if app.MotdMode {
		ctx, cancel := context.WithTimeout(context.Background(), 850*time.Millisecond)
		collectAllMetrics(ctx, &full)
		cancel()
		snap := full.Snapshot()
		tui.RenderMOTD(&snap, app.TerminalWidth)
		os.Exit(0)
	}

	// 2. LIVE INTERACTIVE TUI ENGINE (100% PURE SSH / TTY MODE)
	termEngine := &tui.TermEngine{}

	defer func() {
		termEngine.DisableRawMode()
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "\n[CRITICAL FAULT] SSHDash unhandled panic: %v\nTerminal state restored.\n", r)
			os.Exit(1)
		}
	}()

	if err := termEngine.EnableRawMode(); err != nil {
		fmt.Printf("Error initializing TUI raw mode: %v\nRunning fallback MOTD mode...\n", err)
		ctx, cancel := context.WithTimeout(context.Background(), 850*time.Millisecond)
		collectAllMetrics(ctx, &full)
		cancel()
		snap := full.Snapshot()
		tui.RenderMOTD(&snap, app.TerminalWidth)
		os.Exit(1)
	}

	evChan := make(chan types.InputEvent, 32)
	quitChan := make(chan struct{})

	// ListenInput is 100% side-effect free: emits events into evChan without mutating AppState
	tui.ListenInput(evChan, quitChan)

	ctx, cancel := context.WithTimeout(context.Background(), 850*time.Millisecond)
	collectAllMetrics(ctx, &full)
	cancel()

	snap := full.Snapshot()
	tui.RenderTUI(&snap, app)

	ticker := time.NewTicker(1000 * time.Millisecond)
	defer ticker.Stop()

	for app.Running {
		select {
		case <-quitChan:
			app.Running = false

		case ev := <-evChan:
			needMetrics := tui.HandleInput(app, ev)
			if needMetrics {
				ctx, cancel := context.WithTimeout(context.Background(), 850*time.Millisecond)
				collectAllMetrics(ctx, &full)
				cancel()
			}
			snap := full.Snapshot()
			tui.RenderTUI(&snap, app)

		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 850*time.Millisecond)
			collectAllMetrics(ctx, &full)
			cancel()
			snap := full.Snapshot()
			tui.RenderTUI(&snap, app)
		}
	}
}
