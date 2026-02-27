package tools

import (
	"bufio"
	"context"
	"fmt"
	"regexp"
	"strings"
)

var keyFoundRe = regexp.MustCompile(`KEY FOUND!\s*\[\s*(.+?)\s*\]`)

// AircrackNG wraps the aircrack-ng binary.
type AircrackNG struct {
	tool *ExternalTool
}

func NewAircrackNG() *AircrackNG {
	return &AircrackNG{
		tool: &ExternalTool{Name: "aircrack-ng", Required: true},
	}
}

func (a *AircrackNG) Available() bool {
	return a.tool.Exists()
}

// CrackWPA attempts to crack a WPA handshake with a wordlist.
// Returns the key if found, empty string otherwise.
func (a *AircrackNG) CrackWPA(ctx context.Context, capFile, bssid, wordlist string) (string, error) {
	args := []string{
		"-a", "2", // WPA mode
		"-b", bssid,
		"-w", wordlist,
		capFile,
	}

	out, err := RunCapture(ctx, "aircrack-ng", args...)
	if err != nil {
		if strings.Contains(out, "No valid WPA handshakes found") {
			return "", fmt.Errorf("no valid handshake in capture file")
		}
		return "", err
	}

	if match := keyFoundRe.FindStringSubmatch(out); len(match) > 1 {
		return match[1], nil
	}

	return "", fmt.Errorf("key not found")
}

// CrackWEP attempts to crack a WEP key from captured IVs.
func (a *AircrackNG) CrackWEP(ctx context.Context, capFile string) (string, error) {
	args := []string{
		"-a", "1", // WEP mode
		capFile,
	}

	out, err := RunCapture(ctx, "aircrack-ng", args...)
	if err != nil {
		return "", err
	}

	if match := keyFoundRe.FindStringSubmatch(out); len(match) > 1 {
		return match[1], nil
	}

	return "", fmt.Errorf("key not found")
}

// CrackWPAStream starts aircrack-ng in streaming mode for progress tracking.
func (a *AircrackNG) CrackWPAStream(ctx context.Context, capFile, bssid, wordlist string) (*Process, error) {
	return StartProcess(ctx, "aircrack-ng",
		"-a", "2",
		"-b", bssid,
		"-w", wordlist,
		capFile,
	)
}

// ParseOutputStream reads aircrack-ng output and extracts status/results.
func ParseAircrackOutput(scanner *bufio.Scanner) (key string, found bool) {
	for scanner.Scan() {
		line := scanner.Text()
		if match := keyFoundRe.FindStringSubmatch(line); len(match) > 1 {
			return match[1], true
		}
	}
	return "", false
}
