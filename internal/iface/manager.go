package iface

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sync"

	"github.com/wifibear/wifibear/internal/tools"
)

// WirelessInterface represents a WiFi adapter.
type WirelessInterface struct {
	Name      string
	PHY       string
	Driver    string
	Chipset   string
	MAC       net.HardwareAddr
	Mode      string // managed, monitor
	IsMonitor bool
}

// Manager handles wireless interface lifecycle.
// Platform-specific operations are delegated to platform_linux.go / platform_darwin.go.
type Manager struct {
	macchanger *tools.Macchanger

	originalIface string
	monitorIface  string
	originalMAC   net.HardwareAddr
	mu            sync.Mutex
}

func NewManager() *Manager {
	return &Manager{
		macchanger: tools.NewMacchanger(),
	}
}

// DetectInterfaces finds all wireless interfaces on the system.
func (m *Manager) DetectInterfaces() ([]WirelessInterface, error) {
	return detectInterfaces()
}

// SelectInterface picks the best available wireless interface.
func (m *Manager) SelectInterface(preferred string) (*WirelessInterface, error) {
	ifaces, err := m.DetectInterfaces()
	if err != nil {
		return nil, err
	}

	if len(ifaces) == 0 {
		return nil, fmt.Errorf("no wireless interfaces found")
	}

	if preferred != "" {
		for i, iface := range ifaces {
			if iface.Name == preferred {
				return &ifaces[i], nil
			}
		}
		return nil, fmt.Errorf("interface %s not found", preferred)
	}

	for i, iface := range ifaces {
		if !iface.IsMonitor {
			return &ifaces[i], nil
		}
	}

	return &ifaces[0], nil
}

// EnableMonitorMode puts the interface into monitor mode.
func (m *Manager) EnableMonitorMode(ctx context.Context, iface string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.originalIface = iface
	m.originalMAC = readOriginalMAC(iface)

	monIface, err := enableMonitorMode(ctx, iface)
	if err != nil {
		return "", err
	}

	m.monitorIface = monIface
	return monIface, nil
}

// DisableMonitorMode restores the interface to managed mode.
func (m *Manager) DisableMonitorMode(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.monitorIface == "" {
		return nil
	}

	err := disableMonitorMode(ctx, m.monitorIface)
	m.monitorIface = ""
	return err
}

// RandomizeMAC sets a random MAC on the monitor interface.
func (m *Manager) RandomizeMAC(ctx context.Context) (net.HardwareAddr, error) {
	iface := m.monitorIface
	if iface == "" {
		return nil, fmt.Errorf("no monitor interface active")
	}

	mac := tools.GenerateRandomMAC()

	if err := setMAC(ctx, iface, mac); err != nil {
		if m.macchanger.Available() {
			return m.macchanger.Randomize(ctx, iface)
		}
		return nil, err
	}

	return mac, nil
}

// RestoreMAC restores the original MAC address.
func (m *Manager) RestoreMAC(ctx context.Context) error {
	iface := m.monitorIface
	if iface == "" {
		iface = m.originalIface
	}
	if iface == "" || m.originalMAC == nil {
		return nil
	}

	return setMAC(ctx, iface, m.originalMAC)
}

// MonitorInterface returns the current monitor interface name.
func (m *Manager) MonitorInterface() string {
	return m.monitorIface
}

// OriginalInterface returns the original interface name.
func (m *Manager) OriginalInterface() string {
	return m.originalIface
}

// Cleanup restores the interface to its original state.
func (m *Manager) Cleanup(ctx context.Context) {
	_ = m.RestoreMAC(ctx)
	_ = m.DisableMonitorMode(ctx)
}

// IsLinux returns true if running on Linux.
func IsLinux() bool {
	return runtime.GOOS == "linux"
}
