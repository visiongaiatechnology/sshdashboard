// STATUS: DIAMANT VGT SUPREME
//go:build linux

package types

import (
	"sync"
	"time"
)

// Tab Constants
type TabID int

const (
	TabSystem TabID = iota
	TabSecurity
	TabDocker
	TabDaemons
	TabCount
)

// InputEvent is the sanitized, typed event bus payload between termios reader and UI loop.
// No raw bytes reach the render path (CWE-150 / terminal injection isolation).
type InputEvent struct {
	Kind   EventKind
	Key    KeyCode
	MouseX int
	MouseY int
	MouseB MouseButton
	Width  int
	Height int
}

type EventKind uint8

const (
	EventKey EventKind = iota
	EventMouse
	EventResize
	EventQuit
)

type KeyCode uint8

const (
	KeyNone KeyCode = iota
	KeyQuit
	KeyRefresh
	KeyTab1
	KeyTab2
	KeyTab3
	KeyTab4
	KeyNextTab
	KeyPrevTab
	KeyUp
	KeyDown
	KeyLeft
	KeyRight
	KeyPageUp
	KeyPageDown
	KeyHome
	KeyEnd
)

type MouseButton uint8

const (
	MouseNone MouseButton = iota
	MouseLeft
	MouseWheelUp
	MouseWheelDown
)

// --- DATA STRUCTURES (HARDENED MEMORY BOUNDS & HIGH-RES HISTORY) ---

type SystemState struct {
	HostName          string
	UserName          string
	IsRoot            bool
	Uptime            string
	Load              string
	Load1             float64
	Load5             float64
	Load15            float64
	Cores             int
	CoreUsage         []float64
	CoreHistory       [][]float64
	GlobalLoadHistory []float64 // 60-sample high-res buffer for Braille plot
	OS                string
	Kernel            string
	RAMUsedGB         float64
	RAMTotalGB        float64
	RAMPercent        int
	SwapUsedGB        float64
	SwapTotalGB       float64
	SwapPercent       int
	DiskUsedGB        float64
	DiskTotalGB       float64
	DiskPercent       int
	DiskReadKBps      float64
	DiskWriteKBps     float64
	CPUPercent        float64
}

type NetworkInterfaceState struct {
	Name       string
	RxBytes    uint64
	TxBytes    uint64
	RxSpeedBps float64
	TxSpeedBps float64
}

type NetworkState struct {
	LocalIP    string
	PublicIP   string
	Interfaces []NetworkInterfaceState
	OpenPorts  []OpenPort
	RxHistory  []float64 // aggregate RX B/s timeline
	TxHistory  []float64 // aggregate TX B/s timeline
	TotalRxBps float64
	TotalTxBps float64
}

type OpenPort struct {
	Protocol    string
	Port        int
	Address     string
	ProcessName string
	ProcessPID  int
}

type SecurityState struct {
	SvcFail2Ban    bool
	SvcNginx       bool
	SvcMySQL       bool
	SvcUFW         bool
	BannedCount    int
	RecentBans     []BanEntry
	LogReadable    bool
	RecentLogins   []LoginEntry
	ActiveSessions []ActiveSessionEntry
}

type BanEntry struct {
	Date string
	Time string
	Jail string
	IP   string
}

type LoginEntry struct {
	User   string
	TTY    string
	IP     string
	Time   string
	Active bool
}

type ActiveSessionEntry struct {
	User      string
	TTY       string
	From      string
	LoginTime string
	Idle      string
	What      string
}

type DockerState struct {
	Installed         bool
	SocketPresent     bool
	RunningContainers int
	TotalContainers   int
	Containers        []ContainerEntry
}

type ContainerEntry struct {
	ID      string
	Names   string
	Image   string
	Status  string
	State   string
	Created string
}

type ProcessState struct {
	TopCPU []ProcessEntry
	TopRAM []ProcessEntry
}

type ProcessEntry struct {
	PID     int
	Name    string
	User    string
	CPU     float64
	MemMB   float64
	MemPerc float64
}

// FullState is the atomic metrics snapshot. Renderers never hold a live pointer
// into a concurrent collector write — they receive a shallow-cloned view under lock.
type FullState struct {
	mu         sync.RWMutex
	LastUpdate time.Time
	System     SystemState
	Network    NetworkState
	Security   SecurityState
	Docker     DockerState
	Process    ProcessState
}

// Lock / Unlock expose the mutex for the collector pipeline (single writer).
func (f *FullState) Lock()    { f.mu.Lock() }
func (f *FullState) Unlock()  { f.mu.Unlock() }
func (f *FullState) RLock()   { f.mu.RLock() }
func (f *FullState) RUnlock() { f.mu.RUnlock() }

// Snapshot returns a deep-enough copy for lock-free rendering (slices cloned).
func (f *FullState) Snapshot() FullState {
	f.mu.RLock()
	defer f.mu.RUnlock()

	out := FullState{
		LastUpdate: f.LastUpdate,
		System:     f.System,
		Network:    f.Network,
		Security:   f.Security,
		Docker:     f.Docker,
		Process:    f.Process,
	}

	// Slice isolation — prevent renderer from observing mid-append mutations
	out.System.CoreUsage = cloneF64(f.System.CoreUsage)
	out.System.GlobalLoadHistory = cloneF64(f.System.GlobalLoadHistory)
	if n := len(f.System.CoreHistory); n > 0 {
		out.System.CoreHistory = make([][]float64, n)
		for i := range f.System.CoreHistory {
			out.System.CoreHistory[i] = cloneF64(f.System.CoreHistory[i])
		}
	}
	out.Network.Interfaces = append([]NetworkInterfaceState(nil), f.Network.Interfaces...)
	out.Network.OpenPorts = append([]OpenPort(nil), f.Network.OpenPorts...)
	out.Network.RxHistory = cloneF64(f.Network.RxHistory)
	out.Network.TxHistory = cloneF64(f.Network.TxHistory)
	out.Security.RecentBans = append([]BanEntry(nil), f.Security.RecentBans...)
	out.Security.RecentLogins = append([]LoginEntry(nil), f.Security.RecentLogins...)
	out.Security.ActiveSessions = append([]ActiveSessionEntry(nil), f.Security.ActiveSessions...)
	out.Docker.Containers = append([]ContainerEntry(nil), f.Docker.Containers...)
	out.Process.TopRAM = append([]ProcessEntry(nil), f.Process.TopRAM...)
	out.Process.TopCPU = append([]ProcessEntry(nil), f.Process.TopCPU...)
	return out
}

func cloneF64(in []float64) []float64 {
	if len(in) == 0 {
		return nil
	}
	out := make([]float64, len(in))
	copy(out, in)
	return out
}

// AppState holds pure UI state — never mixes collector data.
type AppState struct {
	ActiveTab      TabID
	MotdMode       bool
	Running        bool
	TerminalWidth  int
	TerminalHeight int
	ScrollY        int
	MouseEnabled   bool
	LastTick       time.Time
	// Hit regions for mouse tab clicks (set each frame by chrome renderer)
	TabHitMinY int
	TabHitMaxY int
	TabHits    [TabCount]struct{ X0, X1 int }
}
