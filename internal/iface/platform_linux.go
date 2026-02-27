//go:build linux

package iface

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/wifibear/wifibear/internal/tools"
)

// Processes known to interfere with monitor mode and packet injection.
var interferingProcesses = []string{
	"NetworkManager",
	"wpa_supplicant",
	"dhclient",
	"dhcpcd",
	"avahi-daemon",
}

func detectInterfaces() ([]WirelessInterface, error) {
	var ifaces []WirelessInterface

	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil, fmt.Errorf("read /sys/class/net: %w", err)
	}

	for _, entry := range entries {
		name := entry.Name()
		wirelessPath := filepath.Join("/sys/class/net", name, "wireless")
		if _, err := os.Stat(wirelessPath); os.IsNotExist(err) {
			phyPath := filepath.Join("/sys/class/net", name, "phy80211")
			if _, err := os.Stat(phyPath); os.IsNotExist(err) {
				continue
			}
		}

		iface := WirelessInterface{Name: name}

		macBytes, err := os.ReadFile(filepath.Join("/sys/class/net", name, "address"))
		if err == nil {
			mac, err := net.ParseMAC(strings.TrimSpace(string(macBytes)))
			if err == nil {
				iface.MAC = mac
			}
		}

		phyLink, err := os.Readlink(filepath.Join("/sys/class/net", name, "phy80211"))
		if err == nil {
			iface.PHY = filepath.Base(phyLink)
		}

		driverLink, err := os.Readlink(filepath.Join("/sys/class/net", name, "device", "driver"))
		if err == nil {
			iface.Driver = filepath.Base(driverLink)
		}

		typeBytes, err := os.ReadFile(filepath.Join("/sys/class/net", name, "type"))
		if err == nil {
			t := strings.TrimSpace(string(typeBytes))
			if t == "803" {
				iface.IsMonitor = true
				iface.Mode = "monitor"
			} else {
				iface.Mode = "managed"
			}
		}

		ifaces = append(ifaces, iface)
	}

	return ifaces, nil
}

func enableMonitorMode(ctx context.Context, iface string) (string, error) {
	// Kill interfering processes
	for _, proc := range interferingProcesses {
		_ = tools.RunSilent(ctx, "systemctl", "stop", proc)
		_ = tools.RunSilent(ctx, "pkill", proc)
	}

	// ip link set <iface> down
	if _, err := tools.RunCapture(ctx, "ip", "link", "set", iface, "down"); err != nil {
		return "", fmt.Errorf("bring interface down: %w", err)
	}

	// iw dev <iface> set type monitor
	if _, err := tools.RunCapture(ctx, "iw", "dev", iface, "set", "type", "monitor"); err != nil {
		if _, err2 := tools.RunCapture(ctx, "iwconfig", iface, "mode", "monitor"); err2 != nil {
			_, _ = tools.RunCapture(ctx, "ip", "link", "set", iface, "up")
			return "", fmt.Errorf("set monitor mode: %w (iwconfig fallback: %w)", err, err2)
		}
	}

	// ip link set <iface> up
	if _, err := tools.RunCapture(ctx, "ip", "link", "set", iface, "up"); err != nil {
		return "", fmt.Errorf("bring interface up: %w", err)
	}

	return iface, nil
}

func disableMonitorMode(ctx context.Context, iface string) error {
	_, _ = tools.RunCapture(ctx, "ip", "link", "set", iface, "down")
	_, _ = tools.RunCapture(ctx, "iw", "dev", iface, "set", "type", "managed")
	_, _ = tools.RunCapture(ctx, "ip", "link", "set", iface, "up")
	_ = tools.RunSilent(ctx, "systemctl", "start", "NetworkManager")
	return nil
}

func setMAC(ctx context.Context, iface string, mac net.HardwareAddr) error {
	_, _ = tools.RunCapture(ctx, "ip", "link", "set", iface, "down")
	_, err := tools.RunCapture(ctx, "ip", "link", "set", iface, "address", mac.String())
	_, _ = tools.RunCapture(ctx, "ip", "link", "set", iface, "up")
	return err
}

func readOriginalMAC(iface string) net.HardwareAddr {
	macBytes, err := os.ReadFile(filepath.Join("/sys/class/net", iface, "address"))
	if err != nil {
		return nil
	}
	mac, _ := net.ParseMAC(strings.TrimSpace(string(macBytes)))
	return mac
}
