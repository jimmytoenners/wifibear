//go:build darwin

package iface

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"

	"github.com/wifibear/wifibear/internal/tools"
)

var macAddrRe = regexp.MustCompile(`ether\s+([0-9a-fA-F:]{17})`)

func detectInterfaces() ([]WirelessInterface, error) {
	// On macOS, use system_profiler or airport to find WiFi interfaces
	// The default WiFi interface is typically en0
	var ifaces []WirelessInterface

	// Try to find interfaces via networksetup
	out, err := tools.RunCapture(context.Background(), "networksetup", "-listallhardwareports")
	if err != nil {
		return nil, fmt.Errorf("list hardware ports: %w", err)
	}

	lines := strings.Split(out, "\n")
	var currentName string
	isWifi := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Hardware Port:") {
			name := strings.TrimPrefix(line, "Hardware Port: ")
			isWifi = strings.Contains(strings.ToLower(name), "wi-fi") ||
				strings.Contains(strings.ToLower(name), "airport")
		}
		if strings.HasPrefix(line, "Device:") && isWifi {
			currentName = strings.TrimSpace(strings.TrimPrefix(line, "Device:"))
			iface := WirelessInterface{
				Name:   currentName,
				Driver: "apple80211",
				Mode:   "managed",
			}

			// Get MAC address
			ifOut, err := exec.Command("ifconfig", currentName).Output()
			if err == nil {
				if match := macAddrRe.FindStringSubmatch(string(ifOut)); len(match) > 1 {
					mac, _ := net.ParseMAC(match[1])
					iface.MAC = mac
				}
			}

			ifaces = append(ifaces, iface)
			isWifi = false
		}
	}

	return ifaces, nil
}

func enableMonitorMode(ctx context.Context, iface string) (string, error) {
	// macOS does not support monitor mode via standard tools on modern hardware.
	// Apple Silicon Macs have no monitor mode support at all.
	// On older Intel Macs with compatible cards, you'd need:
	//   sudo /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport <iface> sniff <channel>
	// But this is extremely limited compared to Linux monitor mode.
	return "", fmt.Errorf("monitor mode is not supported on macOS.\n" +
		"  WiFi packet injection requires Linux with a compatible wireless adapter.\n" +
		"  Recommended: run wifibear on Kali Linux, Parrot OS, or a Raspberry Pi.\n" +
		"  You can still use 'wifibear cracked', 'wifibear check', and 'wifibear deps' on macOS")
}

func disableMonitorMode(ctx context.Context, iface string) error {
	return nil // no-op on macOS
}

func setMAC(ctx context.Context, iface string, mac net.HardwareAddr) error {
	// macOS can change MAC with ifconfig, though it resets on reboot
	_, err := tools.RunCapture(ctx, "ifconfig", iface, "ether", mac.String())
	return err
}

func readOriginalMAC(iface string) net.HardwareAddr {
	out, err := exec.Command("ifconfig", iface).Output()
	if err != nil {
		return nil
	}
	if match := macAddrRe.FindStringSubmatch(string(out)); len(match) > 1 {
		mac, _ := net.ParseMAC(match[1])
		return mac
	}
	return nil
}
