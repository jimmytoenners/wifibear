package tools

import (
	"context"
	"fmt"
	"strconv"
)

// AireplayNG wraps the aireplay-ng binary.
type AireplayNG struct {
	tool *ExternalTool
}

func NewAireplayNG() *AireplayNG {
	return &AireplayNG{
		tool: &ExternalTool{Name: "aireplay-ng", Required: true},
	}
}

func (a *AireplayNG) Available() bool {
	return a.tool.Exists()
}

// Deauth sends deauthentication frames.
// If clientMAC is empty, it broadcasts to all clients.
func (a *AireplayNG) Deauth(ctx context.Context, iface, bssid, clientMAC string, count int) error {
	args := []string{
		"--deauth", strconv.Itoa(count),
		"-a", bssid,
	}
	if clientMAC != "" {
		args = append(args, "-c", clientMAC)
	}
	args = append(args, iface)

	_, err := RunCapture(ctx, "aireplay-ng", args...)
	return err
}

// FakeAuth performs a fake authentication with the AP.
func (a *AireplayNG) FakeAuth(ctx context.Context, iface, bssid, sourceMAC string) error {
	args := []string{
		"--fakeauth", "0",
		"-a", bssid,
		"-h", sourceMAC,
		iface,
	}
	_, err := RunCapture(ctx, "aireplay-ng", args...)
	return err
}

// ARPReplay starts an ARP replay attack (WEP).
func (a *AireplayNG) ARPReplay(ctx context.Context, iface, bssid, sourceMAC string) (*Process, error) {
	return StartProcess(ctx, "aireplay-ng",
		"--arpreplay",
		"-b", bssid,
		"-h", sourceMAC,
		iface,
	)
}

// ChopChop starts a chopchop attack (WEP).
func (a *AireplayNG) ChopChop(ctx context.Context, iface, bssid, sourceMAC string) (*Process, error) {
	return StartProcess(ctx, "aireplay-ng",
		"--chopchop",
		"-b", bssid,
		"-h", sourceMAC,
		iface,
	)
}

// Fragment starts a fragmentation attack (WEP).
func (a *AireplayNG) Fragment(ctx context.Context, iface, bssid, sourceMAC string) (*Process, error) {
	return StartProcess(ctx, "aireplay-ng",
		"--fragment",
		"-b", bssid,
		"-h", sourceMAC,
		iface,
	)
}

// Interactive starts an interactive packet replay attack (WEP p0841).
func (a *AireplayNG) Interactive(ctx context.Context, iface, bssid string, capFile string) (*Process, error) {
	return StartProcess(ctx, "aireplay-ng",
		"--interactive",
		"-b", bssid,
		"-r", capFile,
		iface,
	)
}

// DeauthStream starts a continuous deauth in the background.
func (a *AireplayNG) DeauthStream(ctx context.Context, iface, bssid, clientMAC string, count int) (*Process, error) {
	args := []string{
		"--deauth", strconv.Itoa(count),
		"-a", bssid,
	}
	if clientMAC != "" {
		args = append(args, "-c", clientMAC)
	}
	args = append(args, iface)

	proc, err := StartProcess(ctx, "aireplay-ng", args...)
	if err != nil {
		return nil, fmt.Errorf("aireplay deauth: %w", err)
	}
	return proc, nil
}
