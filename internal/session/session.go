package session

import (
	"encoding/json"
	"os"
	"time"
)

// Session tracks the state of a wifibear run for resume capability.
type Session struct {
	ID              string    `json:"id"`
	Interface       string    `json:"interface"`
	MonitorIface    string    `json:"monitor_iface"`
	StartTime       time.Time `json:"start_time"`
	AttackedBSSIDs  []string  `json:"attacked_bssids"`
	SkippedBSSIDs   []string  `json:"skipped_bssids"`
	CrackedBSSIDs   []string  `json:"cracked_bssids"`
	CurrentTarget   string    `json:"current_target,omitempty"`
	path            string
}

const sessionFile = ".wifibear-session.json"

// NewSession creates a new session.
func NewSession(iface string) *Session {
	return &Session{
		ID:        time.Now().Format("20060102-150405"),
		Interface: iface,
		StartTime: time.Now(),
		path:      sessionFile,
	}
}

// Load reads a session from disk.
func Load() (*Session, error) {
	data, err := os.ReadFile(sessionFile)
	if err != nil {
		return nil, err
	}

	var s Session
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	s.path = sessionFile
	return &s, nil
}

// Save writes the session to disk.
func (s *Session) Save() error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0o644)
}

// MarkAttacked records that a BSSID has been attempted.
func (s *Session) MarkAttacked(bssid string) {
	for _, b := range s.AttackedBSSIDs {
		if b == bssid {
			return
		}
	}
	s.AttackedBSSIDs = append(s.AttackedBSSIDs, bssid)
	_ = s.Save()
}

// MarkCracked records that a BSSID was successfully cracked.
func (s *Session) MarkCracked(bssid string) {
	for _, b := range s.CrackedBSSIDs {
		if b == bssid {
			return
		}
	}
	s.CrackedBSSIDs = append(s.CrackedBSSIDs, bssid)
	_ = s.Save()
}

// WasAttacked checks if a BSSID was already attempted.
func (s *Session) WasAttacked(bssid string) bool {
	for _, b := range s.AttackedBSSIDs {
		if b == bssid {
			return true
		}
	}
	return false
}

// Clean removes the session file.
func (s *Session) Clean() {
	os.Remove(s.path)
}
