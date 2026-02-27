package tools

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

var monIfaceRe = regexp.MustCompile(`\(monitor mode (?:enabled|vif enabled) on (.+?)\)`)

// AirmonNG wraps airmon-ng for monitor mode management.
type AirmonNG struct {
	tool *ExternalTool
}

func NewAirmonNG() *AirmonNG {
	return &AirmonNG{
		tool: &ExternalTool{Name: "airmon-ng", Required: true},
	}
}

func (a *AirmonNG) Available() bool {
	return a.tool.Exists()
}

// Start enables monitor mode on the given interface.
// Returns the monitor interface name (e.g., "wlan0mon").
func (a *AirmonNG) Start(ctx context.Context, iface string) (string, error) {
	out, err := RunCapture(ctx, "airmon-ng", "start", iface)
	if err != nil {
		return "", fmt.Errorf("airmon-ng start: %w\nOutput: %s", err, out)
	}

	// Try to parse the monitor interface name from output
	if match := monIfaceRe.FindStringSubmatch(out); len(match) > 1 {
		return strings.TrimSpace(match[1]), nil
	}

	// Fallback: assume iface + "mon"
	return iface + "mon", nil
}

// Stop disables monitor mode.
func (a *AirmonNG) Stop(ctx context.Context, iface string) error {
	_, err := RunCapture(ctx, "airmon-ng", "stop", iface)
	return err
}

// CheckKill kills interfering processes.
func (a *AirmonNG) CheckKill(ctx context.Context) error {
	_, err := RunCapture(ctx, "airmon-ng", "check", "kill")
	return err
}

// ListInterfaces returns available wireless interfaces.
func (a *AirmonNG) ListInterfaces(ctx context.Context) ([]string, error) {
	out, err := RunCapture(ctx, "airmon-ng")
	if err != nil {
		return nil, err
	}

	var ifaces []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "PHY") || strings.HasPrefix(line, "Interface") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			ifaces = append(ifaces, fields[1])
		}
	}

	return ifaces, nil
}
