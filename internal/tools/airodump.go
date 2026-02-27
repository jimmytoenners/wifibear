package tools

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/wifibear/wifibear/pkg/wifi"
)

// AirodumpNG wraps airodump-ng for packet capture.
type AirodumpNG struct {
	tool *ExternalTool
}

func NewAirodumpNG() *AirodumpNG {
	return &AirodumpNG{
		tool: &ExternalTool{Name: "airodump-ng", Required: true},
	}
}

func (a *AirodumpNG) Available() bool {
	return a.tool.Exists()
}

// CaptureSession holds the state of an airodump-ng capture.
type CaptureSession struct {
	proc    *Process
	prefix  string
	tempDir string
}

// StartCapture begins capturing on a specific channel and BSSID.
func (a *AirodumpNG) StartCapture(ctx context.Context, iface, bssid string, channel int, outputPrefix string) (*CaptureSession, error) {
	tempDir, err := os.MkdirTemp("", "wifibear-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}

	prefix := filepath.Join(tempDir, outputPrefix)
	args := []string{
		"--bssid", bssid,
		"--channel", strconv.Itoa(channel),
		"--write", prefix,
		"--output-format", "csv,pcap",
		"--write-interval", "1",
		iface,
	}

	proc, err := StartProcess(ctx, "airodump-ng", args...)
	if err != nil {
		os.RemoveAll(tempDir)
		return nil, fmt.Errorf("start airodump: %w", err)
	}

	return &CaptureSession{
		proc:    proc,
		prefix:  prefix,
		tempDir: tempDir,
	}, nil
}

// StartScan starts a general scan (all channels).
func (a *AirodumpNG) StartScan(ctx context.Context, iface string, band string) (*CaptureSession, error) {
	tempDir, err := os.MkdirTemp("", "wifibear-scan-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}

	prefix := filepath.Join(tempDir, "scan")
	args := []string{
		"--write", prefix,
		"--output-format", "csv",
		"--write-interval", "1",
	}

	if band == "5ghz" {
		args = append(args, "--band", "a")
	} else if band == "both" {
		args = append(args, "--band", "abg")
	}

	args = append(args, iface)

	proc, err := StartProcess(ctx, "airodump-ng", args...)
	if err != nil {
		os.RemoveAll(tempDir)
		return nil, fmt.Errorf("start airodump scan: %w", err)
	}

	return &CaptureSession{
		proc:    proc,
		prefix:  prefix,
		tempDir: tempDir,
	}, nil
}

// CapFile returns the path to the .cap file.
func (cs *CaptureSession) CapFile() string {
	return cs.prefix + "-01.cap"
}

// CSVFile returns the path to the .csv file.
func (cs *CaptureSession) CSVFile() string {
	return cs.prefix + "-01.csv"
}

// Stop terminates the capture session and cleans up.
func (cs *CaptureSession) Stop() {
	if cs.proc != nil {
		_ = cs.proc.Stop()
	}
}

// Cleanup removes temporary files.
func (cs *CaptureSession) Cleanup() {
	os.RemoveAll(cs.tempDir)
}

// Process returns the underlying process.
func (cs *CaptureSession) Process() *Process {
	return cs.proc
}

// ParseCSV parses an airodump-ng CSV file and returns targets and clients.
func ParseAirodumpCSV(path string) ([]*wifi.Target, []*wifi.Client, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	reader := csv.NewReader(f)
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true
	reader.TrimLeadingSpace = true

	var targets []*wifi.Target
	var clients []*wifi.Client
	parsingClients := false

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		if len(record) == 0 {
			continue
		}

		first := strings.TrimSpace(record[0])

		// Detect section headers
		if first == "BSSID" {
			if parsingClients {
				continue
			}
			parsingClients = false
			continue
		}
		if first == "Station MAC" {
			parsingClients = true
			continue
		}
		if first == "" {
			continue
		}

		if parsingClients {
			c := parseClientRecord(record)
			if c != nil {
				clients = append(clients, c)
			}
		} else {
			t := parseTargetRecord(record)
			if t != nil {
				targets = append(targets, t)
			}
		}
	}

	// Associate clients with targets
	for _, c := range clients {
		for _, t := range targets {
			if t.BSSID.String() == c.BSSID.String() {
				t.Clients = append(t.Clients, c)
				break
			}
		}
	}

	return targets, clients, nil
}

func parseTargetRecord(record []string) *wifi.Target {
	if len(record) < 14 {
		return nil
	}

	bssid, err := net.ParseMAC(strings.TrimSpace(record[0]))
	if err != nil {
		return nil
	}

	channel, _ := strconv.Atoi(strings.TrimSpace(record[3]))
	power, _ := strconv.Atoi(strings.TrimSpace(record[8]))
	beacons, _ := strconv.Atoi(strings.TrimSpace(record[6]))
	data, _ := strconv.Atoi(strings.TrimSpace(record[7]))

	essid := strings.TrimSpace(record[13])
	hidden := essid == "" || strings.HasPrefix(essid, "\\x00")

	enc := parseEncryption(strings.TrimSpace(record[5]))
	cipher := parseCipher(strings.TrimSpace(record[6]))

	firstSeen := parseAirodumpTime(strings.TrimSpace(record[1]))
	lastSeen := parseAirodumpTime(strings.TrimSpace(record[2]))

	return &wifi.Target{
		BSSID:       bssid,
		ESSID:       essid,
		Channel:     channel,
		Encryption:  enc,
		Cipher:      cipher,
		Power:       power,
		Hidden:      hidden,
		BeaconCount: beacons,
		DataCount:   data,
		FirstSeen:   firstSeen,
		LastSeen:    lastSeen,
	}
}

func parseClientRecord(record []string) *wifi.Client {
	if len(record) < 6 {
		return nil
	}

	mac, err := net.ParseMAC(strings.TrimSpace(record[0]))
	if err != nil {
		return nil
	}

	bssidStr := strings.TrimSpace(record[5])
	if bssidStr == "(not associated)" || bssidStr == "" {
		return nil
	}

	bssid, err := net.ParseMAC(bssidStr)
	if err != nil {
		return nil
	}

	power, _ := strconv.Atoi(strings.TrimSpace(record[3]))
	packets, _ := strconv.Atoi(strings.TrimSpace(record[4]))

	return &wifi.Client{
		MAC:     mac,
		BSSID:   bssid,
		Power:   power,
		Packets: packets,
	}
}

func parseEncryption(s string) wifi.EncryptionType {
	s = strings.ToUpper(s)
	switch {
	case strings.Contains(s, "WPA2"):
		return wifi.EncWPA2
	case strings.Contains(s, "WPA"):
		return wifi.EncWPA
	case strings.Contains(s, "WEP"):
		return wifi.EncWEP
	case strings.Contains(s, "OPN"):
		return wifi.EncOpen
	default:
		return wifi.EncOpen
	}
}

func parseCipher(s string) wifi.CipherType {
	s = strings.ToUpper(s)
	switch {
	case strings.Contains(s, "CCMP"):
		return wifi.CipherCCMP
	case strings.Contains(s, "TKIP"):
		return wifi.CipherTKIP
	case strings.Contains(s, "WEP"):
		return wifi.CipherWEP
	default:
		return wifi.CipherNone
	}
}

func parseAirodumpTime(s string) time.Time {
	layouts := []string{
		"2006-01-02 15:04:05",
		"2006-01-02 15:04",
	}
	for _, layout := range layouts {
		t, err := time.Parse(layout, s)
		if err == nil {
			return t
		}
	}
	return time.Time{}
}

// FormatTargetTable creates a formatted table of targets for display.
func FormatTargetTable(targets []*wifi.Target) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("  %-4s %-24s %-19s %4s %-6s %5s %-4s %s\n",
		"#", "ESSID", "BSSID", "CH", "ENC", "PWR", "WPS", "CLIENTS"))
	sb.WriteString(fmt.Sprintf("  %-4s %-24s %-19s %4s %-6s %5s %-4s %s\n",
		"─", "─────", "─────", "──", "───", "───", "───", "───────"))

	for i, t := range targets {
		essid := t.ESSID
		if t.Hidden || essid == "" {
			essid = "<hidden>"
		}
		if len(essid) > 22 {
			essid = essid[:22] + ".."
		}

		wps := "No"
		if t.WPS {
			wps = "Yes"
		}

		sb.WriteString(fmt.Sprintf("  %-4d %-24s %-19s %4d %-6s %5d %-4s %d\n",
			i+1, essid, t.BSSID, t.Channel, t.Encryption, t.Power, wps, len(t.Clients)))
	}

	return sb.String()
}
