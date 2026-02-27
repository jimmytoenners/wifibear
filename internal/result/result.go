package result

import (
	"encoding/json"
	"time"
)

// CrackResult holds the outcome of a successful attack.
type CrackResult struct {
	BSSID         string    `json:"bssid"`
	ESSID         string    `json:"essid"`
	Key           string    `json:"key,omitempty"`
	Encryption    string    `json:"encryption"`
	AttackType    string    `json:"attack_type"`
	HandshakeFile string    `json:"handshake_file,omitempty"`
	Duration      Duration  `json:"duration,omitempty"`
	Timestamp     time.Time `json:"timestamp"`
}

// Duration wraps time.Duration for JSON serialization.
type Duration time.Duration

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(dur)
	return nil
}

func (r *CrackResult) Cracked() bool {
	return r.Key != ""
}
