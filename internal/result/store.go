package result

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// Store persists crack results to a JSON file.
type Store struct {
	path    string
	results []*CrackResult
	mu      sync.RWMutex
}

func NewStore(path string) *Store {
	s := &Store{path: path}
	s.load()
	return s
}

// Add saves a new result, deduplicating by BSSID.
func (s *Store) Add(r *CrackResult) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Deduplicate: replace existing result for same BSSID
	for i, existing := range s.results {
		if existing.BSSID == r.BSSID {
			s.results[i] = r
			s.save()
			return
		}
	}

	s.results = append(s.results, r)
	s.save()
}

// All returns all stored results.
func (s *Store) All() []*CrackResult {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]*CrackResult, len(s.results))
	copy(out, s.results)
	return out
}

// Cracked returns only results with recovered keys.
func (s *Store) Cracked() []*CrackResult {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var cracked []*CrackResult
	for _, r := range s.results {
		if r.Cracked() {
			cracked = append(cracked, r)
		}
	}
	return cracked
}

// FindByBSSID looks up a result by BSSID.
func (s *Store) FindByBSSID(bssid string) *CrackResult {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, r := range s.results {
		if r.BSSID == bssid {
			return r
		}
	}
	return nil
}

// Count returns the total number of results.
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.results)
}

// FormatCracked returns a formatted table of cracked networks.
func (s *Store) FormatCracked() string {
	cracked := s.Cracked()
	if len(cracked) == 0 {
		return "No cracked networks.\n"
	}

	out := fmt.Sprintf("  %-24s %-19s %-8s %-20s %s\n",
		"ESSID", "BSSID", "ENC", "KEY", "ATTACK")
	out += fmt.Sprintf("  %-24s %-19s %-8s %-20s %s\n",
		"─────", "─────", "───", "───", "──────")

	for _, r := range cracked {
		essid := r.ESSID
		if len(essid) > 22 {
			essid = essid[:22] + ".."
		}
		key := r.Key
		if len(key) > 18 {
			key = key[:18] + ".."
		}
		out += fmt.Sprintf("  %-24s %-19s %-8s %-20s %s\n",
			essid, r.BSSID, r.Encryption, key, r.AttackType)
	}

	return out
}

func (s *Store) load() {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return
	}

	var results []*CrackResult
	if err := json.Unmarshal(data, &results); err != nil {
		return
	}
	s.results = results
}

func (s *Store) save() {
	data, err := json.MarshalIndent(s.results, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(s.path, data, 0o644)
}
