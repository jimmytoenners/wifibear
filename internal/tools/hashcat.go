package tools

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
)

var hashcatKeyRe = regexp.MustCompile(`:([^:]+)$`)

// Hashcat wraps hashcat for PMKID cracking.
type Hashcat struct {
	tool *ExternalTool
}

func NewHashcat() *Hashcat {
	return &Hashcat{
		tool: &ExternalTool{Name: "hashcat", Required: false},
	}
}

func (h *Hashcat) Available() bool {
	return h.tool.Exists()
}

// CrackPMKID attempts to crack a PMKID hash with a wordlist.
func (h *Hashcat) CrackPMKID(ctx context.Context, hashFile, wordlist string) (string, error) {
	potFile := hashFile + ".potfile"
	args := []string{
		"-m", "22000", // WPA-PMKID-PBKDF2
		"-a", "0", // Dictionary attack
		"--potfile-path", potFile,
		"--quiet",
		hashFile,
		wordlist,
	}

	_, _ = RunCapture(ctx, "hashcat", args...)

	// Check potfile for results
	data, err := os.ReadFile(potFile)
	if err != nil {
		return "", fmt.Errorf("key not found")
	}

	content := strings.TrimSpace(string(data))
	if content == "" {
		return "", fmt.Errorf("key not found")
	}

	// Potfile format: hash:password
	lines := strings.Split(content, "\n")
	lastLine := lines[len(lines)-1]
	if match := hashcatKeyRe.FindStringSubmatch(lastLine); len(match) > 1 {
		return match[1], nil
	}

	return "", fmt.Errorf("key not found")
}

// HcxDumpTool wraps hcxdumptool for PMKID capture.
type HcxDumpTool struct {
	tool *ExternalTool
}

func NewHcxDumpTool() *HcxDumpTool {
	return &HcxDumpTool{
		tool: &ExternalTool{Name: "hcxdumptool", Required: false},
	}
}

func (h *HcxDumpTool) Available() bool {
	return h.tool.Exists()
}

// CapturePMKID captures PMKID from a target AP.
func (h *HcxDumpTool) CapturePMKID(ctx context.Context, iface, bssid, outFile string) error {
	// Create filter file with target BSSID
	filterFile, err := os.CreateTemp("", "wifibear-filter-*")
	if err != nil {
		return fmt.Errorf("create filter: %w", err)
	}
	defer os.Remove(filterFile.Name())

	// Write BSSID without colons
	cleanBSSID := strings.ReplaceAll(bssid, ":", "")
	if _, err := filterFile.WriteString(cleanBSSID + "\n"); err != nil {
		filterFile.Close()
		return err
	}
	filterFile.Close()

	args := []string{
		"-i", iface,
		"-o", outFile,
		"--filterlist_ap", filterFile.Name(),
		"--filtermode=2",
		"--enable_status=3",
	}

	_, err = RunCapture(ctx, "hcxdumptool", args...)
	return err
}

// HcxPcapTool wraps hcxpcaptool for converting captures.
type HcxPcapTool struct {
	tool *ExternalTool
}

func NewHcxPcapTool() *HcxPcapTool {
	return &HcxPcapTool{
		tool: &ExternalTool{Name: "hcxpcaptool", Required: false},
	}
}

func (h *HcxPcapTool) Available() bool {
	return h.tool.Exists()
}

// ConvertToHashcat converts a pcapng capture to hashcat 22000 format.
func (h *HcxPcapTool) ConvertToHashcat(ctx context.Context, pcapFile, outFile string) error {
	_, err := RunCapture(ctx, "hcxpcaptool",
		"-z", outFile,
		pcapFile,
	)
	if err != nil {
		return fmt.Errorf("hcxpcaptool: %w", err)
	}

	// Check if output file was created and has content
	info, err := os.Stat(outFile)
	if err != nil || info.Size() == 0 {
		return fmt.Errorf("no PMKID hashes extracted")
	}

	return nil
}
