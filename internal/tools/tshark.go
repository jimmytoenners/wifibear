package tools

import (
	"context"
	"strings"
)

// Tshark wraps tshark for handshake validation and WPS detection.
type Tshark struct {
	tool *ExternalTool
}

func NewTshark() *Tshark {
	return &Tshark{
		tool: &ExternalTool{Name: "tshark", Required: false},
	}
}

func (t *Tshark) Available() bool {
	return t.tool.Exists()
}

// HasHandshake checks if a cap file contains a valid WPA handshake.
func (t *Tshark) HasHandshake(ctx context.Context, capFile, bssid string) (bool, error) {
	// Look for EAPOL key frames associated with this BSSID
	out, err := RunCapture(ctx, "tshark",
		"-r", capFile,
		"-Y", "eapol && wlan.bssid == "+bssid,
		"-T", "fields",
		"-e", "eapol.keydes.type",
	)
	if err != nil {
		return false, err
	}

	// Need at least 2 EAPOL frames for a valid handshake
	lines := strings.Split(strings.TrimSpace(out), "\n")
	count := 0
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}

	return count >= 2, nil
}

// CountEAPOLFrames returns the number of EAPOL frames in a capture.
func (t *Tshark) CountEAPOLFrames(ctx context.Context, capFile, bssid string) (int, error) {
	out, err := RunCapture(ctx, "tshark",
		"-r", capFile,
		"-Y", "eapol && wlan.bssid == "+bssid,
		"-T", "fields",
		"-e", "frame.number",
	)
	if err != nil {
		return 0, err
	}

	lines := strings.Split(strings.TrimSpace(out), "\n")
	count := 0
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}
	return count, nil
}

// StripCapture removes non-EAPOL/non-beacon frames from a capture file.
func (t *Tshark) StripCapture(ctx context.Context, inFile, outFile, bssid string) error {
	_, err := RunCapture(ctx, "tshark",
		"-r", inFile,
		"-w", outFile,
		"-Y", "(eapol || wlan.fc.type_subtype == 0x08) && wlan.bssid == "+bssid,
	)
	return err
}

// DetectWPS checks if networks with WPS are visible in a capture.
func (t *Tshark) DetectWPS(ctx context.Context, capFile string) ([]string, error) {
	out, err := RunCapture(ctx, "tshark",
		"-r", capFile,
		"-Y", "wps.wifi_protected_setup_state",
		"-T", "fields",
		"-e", "wlan.bssid",
		"-e", "wps.wifi_protected_setup_state",
	)
	if err != nil {
		return nil, err
	}

	var wpsEnabled []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) >= 2 && strings.Contains(fields[1], "Configured") {
			wpsEnabled = append(wpsEnabled, fields[0])
		}
	}

	return wpsEnabled, nil
}
