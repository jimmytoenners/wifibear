package ui

import (
	"context"
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/wifibear/wifibear/internal/attack"
	"github.com/wifibear/wifibear/internal/config"
	"github.com/wifibear/wifibear/internal/result"
	"github.com/wifibear/wifibear/internal/scan"
	"github.com/wifibear/wifibear/pkg/wifi"
)

// View represents which screen the TUI is showing.
type View int

const (
	ViewScan View = iota
	ViewAttack
	ViewResults
	ViewHelp
)

// App is the main Bubble Tea model.
type App struct {
	cfg          *config.Config
	scanner      *scan.Scanner
	orchestrator *attack.Orchestrator
	store        *result.Store
	ctx          context.Context
	cancel       context.CancelFunc

	view         View
	width        int
	height       int
	scanElapsed  time.Duration
	startTime    time.Time
	monitorIface string
	channel      int

	// Scan view state
	targets     []*wifi.Target
	cursor      int
	selected    map[int]bool

	// Attack view state
	attackTarget  *wifi.Target
	attackStatus  []attackStep
	attackRunning bool
	statusCh      chan attack.StatusUpdate

	// Results
	crackedResults []*result.CrackResult

	err error
}

type attackStep struct {
	name     string
	status   string
	done     bool
	success  bool
	progress float64
}

// Tick messages
type tickMsg time.Time
type scanUpdateMsg struct{}
type attackStatusMsg attack.StatusUpdate
type attackDoneMsg struct {
	result *result.CrackResult
	err    error
}

func NewApp(cfg *config.Config, scanner *scan.Scanner, orchestrator *attack.Orchestrator, store *result.Store, monitorIface string) *App {
	ctx, cancel := context.WithCancel(context.Background())
	return &App{
		cfg:          cfg,
		scanner:      scanner,
		orchestrator: orchestrator,
		store:        store,
		ctx:          ctx,
		cancel:       cancel,
		view:         ViewScan,
		startTime:    time.Now(),
		monitorIface: monitorIface,
		selected:     make(map[int]bool),
		statusCh:     make(chan attack.StatusUpdate, 100),
	}
}

func (a *App) Init() tea.Cmd {
	return tea.Batch(tickCmd(), a.scanUpdateCmd())
}

func (a *App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		a.width = msg.Width
		a.height = msg.Height
		return a, nil

	case tea.KeyMsg:
		return a.handleKey(msg)

	case tickMsg:
		a.scanElapsed = time.Since(a.startTime)
		var cmds []tea.Cmd
		cmds = append(cmds, tickCmd())

		// Check for attack status updates
		if a.attackRunning {
			cmds = append(cmds, a.checkAttackStatus())
		}
		return a, tea.Batch(cmds...)

	case scanUpdateMsg:
		a.targets = a.scanner.DB().Targets()
		return a, a.scanUpdateCmd()

	case attackStatusMsg:
		a.updateAttackStatus(attack.StatusUpdate(msg))
		return a, nil

	case attackDoneMsg:
		a.attackRunning = false
		if msg.result != nil && msg.result.Cracked() {
			a.store.Add(msg.result)
			a.crackedResults = a.store.Cracked()
		}
		if msg.err != nil {
			a.err = msg.err
		}
		return a, nil
	}

	return a, nil
}

func (a *App) View() string {
	switch a.view {
	case ViewScan:
		return a.renderScanView()
	case ViewAttack:
		return a.renderAttackView()
	case ViewResults:
		return a.renderResultsView()
	case ViewHelp:
		return a.renderHelpView()
	default:
		return a.renderScanView()
	}
}

func (a *App) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		a.cancel()
		return a, tea.Quit

	case "?":
		if a.view == ViewHelp {
			a.view = ViewScan
		} else {
			a.view = ViewHelp
		}
		return a, nil

	case "r":
		a.view = ViewResults
		a.crackedResults = a.store.Cracked()
		return a, nil

	case "esc":
		if a.view != ViewScan {
			a.view = ViewScan
		}
		return a, nil
	}

	switch a.view {
	case ViewScan:
		return a.handleScanKey(msg)
	case ViewAttack:
		return a.handleAttackKey(msg)
	}

	return a, nil
}

func (a *App) handleScanKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if a.cursor > 0 {
			a.cursor--
		}
	case "down", "j":
		if a.cursor < len(a.targets)-1 {
			a.cursor++
		}
	case " ":
		a.selected[a.cursor] = !a.selected[a.cursor]
	case "enter":
		if len(a.targets) > 0 {
			return a, a.startAttack(a.targets[a.cursor])
		}
	case "a":
		if len(a.targets) > 0 {
			return a, a.startAttackAll()
		}
	}
	return a, nil
}

func (a *App) handleAttackKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "s":
		a.cancel()
		a.view = ViewScan
		a.ctx, a.cancel = context.WithCancel(context.Background())
	case "esc":
		a.view = ViewScan
	}
	return a, nil
}

func (a *App) startAttack(target *wifi.Target) tea.Cmd {
	a.attackTarget = target
	a.view = ViewAttack
	a.attackRunning = true
	a.err = nil

	chain := a.orchestrator.AttackChainForTarget(target)
	a.attackStatus = make([]attackStep, len(chain))
	for i, name := range chain {
		a.attackStatus[i] = attackStep{name: name, status: "Waiting"}
	}

	return func() tea.Msg {
		res, err := a.orchestrator.AttackTarget(a.ctx, target, a.monitorIface)
		return attackDoneMsg{result: res, err: err}
	}
}

func (a *App) startAttackAll() tea.Cmd {
	if len(a.targets) == 0 {
		return nil
	}
	// Start with first target
	return a.startAttack(a.targets[0])
}

func (a *App) updateAttackStatus(s attack.StatusUpdate) {
	for i := range a.attackStatus {
		if a.attackStatus[i].name == s.Attack {
			a.attackStatus[i].status = s.Message
			a.attackStatus[i].done = s.Done
			a.attackStatus[i].success = s.Success
			a.attackStatus[i].progress = s.Progress
			return
		}
	}
}

func (a *App) checkAttackStatus() tea.Cmd {
	return func() tea.Msg {
		select {
		case s := <-a.statusCh:
			return attackStatusMsg(s)
		default:
			return nil
		}
	}
}

func tickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (a *App) scanUpdateCmd() tea.Cmd {
	return func() tea.Msg {
		time.Sleep(time.Second)
		return scanUpdateMsg{}
	}
}

// Rendering

func (a *App) renderScanView() string {
	s := ""

	// Header
	s += a.renderHeader()
	s += "\n"

	// Target table
	if len(a.targets) == 0 {
		s += "\n" + dimStyle.Render("  Scanning for networks... waiting for beacons") + "\n"
	} else {
		s += a.renderTargetTable()
	}

	s += "\n"

	// Footer
	s += a.renderScanFooter()

	return s
}

func (a *App) renderHeader() string {
	elapsed := a.scanElapsed.Round(time.Second)
	title := bannerStyle.Render("WifiBear")
	status := statusBarStyle.Render(fmt.Sprintf(
		"%s | Ch: %d | Targets: %d | %s",
		a.monitorIface, a.channel, len(a.targets), elapsed,
	))

	gap := ""
	if a.width > 0 {
		titleLen := len("WifiBear")
		statusLen := len(a.monitorIface) + 30
		gapLen := a.width - titleLen - statusLen - 4
		if gapLen > 0 {
			for i := 0; i < gapLen; i++ {
				gap += " "
			}
		}
	}

	return borderStyle.Render(title + gap + status)
}

func (a *App) renderTargetTable() string {
	s := headerStyle.Render(fmt.Sprintf(
		"%-4s %-22s %-19s %3s %-6s %5s %-4s %-4s %s",
		"#", "ESSID", "BSSID", "CH", "ENC", "PWR", "SIG", "WPS", "CLI",
	))
	s += "\n"

	s += dimStyle.Render(fmt.Sprintf(
		"  %-4s %-22s %-19s %3s %-6s %5s %-4s %-4s %s",
		"─", "─────", "─────", "──", "───", "───", "───", "───", "───",
	))
	s += "\n"

	for i, t := range a.targets {
		essid := t.ESSID
		if t.Hidden || essid == "" {
			essid = "<hidden>"
		}
		if len(essid) > 20 {
			essid = essid[:20] + ".."
		}

		wps := " No"
		if t.WPS {
			wps = successStyle.Render("Yes")
		}

		enc := EncryptionColor(t.Encryption.String())
		signal := SignalBar(t.Power)

		line := fmt.Sprintf("  %-4d %-22s %-19s %3d %-6s %5d %s %-4s %d",
			i+1, essid, t.BSSID, t.Channel, enc, t.Power, signal, wps, len(t.Clients))

		if i == a.cursor {
			line = selectedRowStyle.Render(line)
		}

		s += line + "\n"
	}

	return s
}

func (a *App) renderScanFooter() string {
	keys := []struct{ key, desc string }{
		{"Enter", "Attack"},
		{"a", "Attack all"},
		{"r", "Results"},
		{"?", "Help"},
		{"q", "Quit"},
	}

	s := "  "
	for i, k := range keys {
		if i > 0 {
			s += "  "
		}
		s += keyStyle.Render("["+k.key+"]") + " " + helpStyle.Render(k.desc)
	}

	return borderStyle.Render(s)
}

func (a *App) renderAttackView() string {
	s := a.renderHeader() + "\n\n"

	if a.attackTarget != nil {
		t := a.attackTarget
		essid := t.ESSID
		if essid == "" {
			essid = "<hidden>"
		}
		s += infoStyle.Render(fmt.Sprintf(
			"  Target:  %s (%s) Ch %d  %ddBm  %s",
			essid, t.BSSID, t.Channel, t.Power, t.Encryption,
		))
		s += "\n"
		s += dimStyle.Render(fmt.Sprintf("  Clients: %d connected", len(t.Clients)))
		s += "\n\n"
	}

	s += infoStyle.Render("  Attack Chain:") + "\n"
	for _, step := range a.attackStatus {
		icon := waitingStyle.Render("[ ]")
		status := waitingStyle.Render(step.status)

		if step.done && step.success {
			icon = successStyle.Render("[+]")
			status = successStyle.Render(step.status)
		} else if step.done {
			icon = failStyle.Render("[-]")
			status = failStyle.Render(step.status)
		} else if step.status != "Waiting" {
			icon = progressStyle.Render("[>]")
			status = progressStyle.Render(step.status)
		}

		s += fmt.Sprintf("  %s %s ... %s\n", icon, step.name, status)
	}

	if a.err != nil {
		s += "\n" + failStyle.Render(fmt.Sprintf("  Error: %v", a.err)) + "\n"
	}

	s += "\n"
	s += borderStyle.Render(
		"  " + keyStyle.Render("[s]") + " " + helpStyle.Render("Skip") +
			"  " + keyStyle.Render("[Esc]") + " " + helpStyle.Render("Back") +
			"  " + keyStyle.Render("[q]") + " " + helpStyle.Render("Quit"),
	)

	return s
}

func (a *App) renderResultsView() string {
	s := a.renderHeader() + "\n\n"
	s += bannerStyle.Render("  Cracked Networks") + "\n\n"

	if len(a.crackedResults) == 0 {
		s += dimStyle.Render("  No networks cracked yet.") + "\n"
	} else {
		s += headerStyle.Render(fmt.Sprintf("  %-22s %-19s %-6s %-20s %s",
			"ESSID", "BSSID", "ENC", "KEY", "ATTACK"))
		s += "\n"

		for _, r := range a.crackedResults {
			essid := r.ESSID
			if len(essid) > 20 {
				essid = essid[:20] + ".."
			}
			key := r.Key
			if len(key) > 18 {
				key = key[:18] + ".."
			}
			s += fmt.Sprintf("  %-22s %-19s %-6s %-20s %s\n",
				essid, r.BSSID, r.Encryption, successStyle.Render(key), r.AttackType)
		}
	}

	s += "\n"
	s += borderStyle.Render("  " + keyStyle.Render("[Esc]") + " " + helpStyle.Render("Back"))

	return s
}

func (a *App) renderHelpView() string {
	s := a.renderHeader() + "\n\n"
	s += bannerStyle.Render("  Keyboard Shortcuts") + "\n\n"

	help := []struct{ key, desc string }{
		{"j/k or Up/Down", "Navigate targets"},
		{"Space", "Select/deselect target"},
		{"Enter", "Attack selected target"},
		{"a", "Attack all targets"},
		{"r", "View cracked results"},
		{"s", "Skip current attack"},
		{"?", "Toggle help"},
		{"Esc", "Go back"},
		{"q / Ctrl+C", "Quit (safe cleanup)"},
	}

	for _, h := range help {
		s += fmt.Sprintf("  %s  %s\n",
			keyStyle.Render(fmt.Sprintf("%-20s", h.key)),
			helpStyle.Render(h.desc),
		)
	}

	s += "\n"
	s += borderStyle.Render("  " + keyStyle.Render("[Esc]") + " " + helpStyle.Render("Back"))

	return s
}

// SetChannel updates the displayed channel.
func (a *App) SetChannel(ch int) {
	a.channel = ch
}

// Run starts the Bubble Tea program.
func Run(app *App) error {
	p := tea.NewProgram(app, tea.WithAltScreen())
	_, err := p.Run()
	return err
}
