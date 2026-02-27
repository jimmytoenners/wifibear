package scan

import (
	"net"
	"sort"
	"sync"
	"time"

	"github.com/wifibear/wifibear/pkg/wifi"
)

// TargetDB is a thread-safe database of discovered targets.
type TargetDB struct {
	targets map[string]*wifi.Target // keyed by BSSID string
	clients map[string]*wifi.Client // keyed by client MAC string
	mu      sync.RWMutex

	onNewTarget    func(*wifi.Target)
	onTargetUpdate func(*wifi.Target)
}

func NewTargetDB() *TargetDB {
	return &TargetDB{
		targets: make(map[string]*wifi.Target),
		clients: make(map[string]*wifi.Client),
	}
}

// OnNewTarget sets a callback for newly discovered targets.
func (db *TargetDB) OnNewTarget(fn func(*wifi.Target)) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.onNewTarget = fn
}

// OnTargetUpdate sets a callback for updated targets.
func (db *TargetDB) OnTargetUpdate(fn func(*wifi.Target)) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.onTargetUpdate = fn
}

// UpdateTarget adds or updates a target in the database.
func (db *TargetDB) UpdateTarget(bssid net.HardwareAddr, essid string, channel int, power int, enc wifi.EncryptionType, cipher wifi.CipherType, wps bool) {
	db.mu.Lock()
	defer db.mu.Unlock()

	key := bssid.String()
	t, exists := db.targets[key]

	if !exists {
		t = &wifi.Target{
			BSSID:      bssid,
			ESSID:      essid,
			Channel:    channel,
			Power:      power,
			Encryption: enc,
			Cipher:     cipher,
			WPS:        wps,
			FirstSeen:  time.Now(),
			LastSeen:   time.Now(),
			Hidden:     essid == "",
		}
		db.targets[key] = t
		if db.onNewTarget != nil {
			go db.onNewTarget(t)
		}
		return
	}

	// Update existing target
	if essid != "" && t.ESSID == "" {
		t.ESSID = essid
		t.Hidden = false
	}
	if channel != 0 {
		t.Channel = channel
	}
	if power != 0 {
		t.Power = power
	}
	if enc != wifi.EncOpen {
		t.Encryption = enc
	}
	if cipher != wifi.CipherNone {
		t.Cipher = cipher
	}
	if wps {
		t.WPS = true
	}
	t.BeaconCount++
	t.LastSeen = time.Now()

	if db.onTargetUpdate != nil {
		go db.onTargetUpdate(t)
	}
}

// UpdateClient adds or updates a client associated with a BSSID.
func (db *TargetDB) UpdateClient(clientMAC, bssid net.HardwareAddr, power int) {
	db.mu.Lock()
	defer db.mu.Unlock()

	clientKey := clientMAC.String()
	c, exists := db.clients[clientKey]

	if !exists {
		c = &wifi.Client{
			MAC:       clientMAC,
			BSSID:     bssid,
			Power:     power,
			Packets:   1,
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
		}
		db.clients[clientKey] = c
	} else {
		c.Power = power
		c.Packets++
		c.LastSeen = time.Now()
	}

	// Associate client with target
	bssidKey := bssid.String()
	if t, ok := db.targets[bssidKey]; ok {
		found := false
		for _, existing := range t.Clients {
			if existing.MAC.String() == clientKey {
				existing.Power = power
				existing.Packets++
				existing.LastSeen = time.Now()
				found = true
				break
			}
		}
		if !found {
			t.Clients = append(t.Clients, c)
		}
	}
}

// IncrementData increments the data frame count for a target.
func (db *TargetDB) IncrementData(bssid net.HardwareAddr) {
	db.mu.Lock()
	defer db.mu.Unlock()

	key := bssid.String()
	if t, ok := db.targets[key]; ok {
		t.DataCount++
	}
}

// Targets returns all targets sorted by signal strength (strongest first).
func (db *TargetDB) Targets() []*wifi.Target {
	db.mu.RLock()
	defer db.mu.RUnlock()

	targets := make([]*wifi.Target, 0, len(db.targets))
	for _, t := range db.targets {
		targets = append(targets, t)
	}

	sort.Slice(targets, func(i, j int) bool {
		// Higher power (less negative) = stronger signal
		return targets[i].Power > targets[j].Power
	})

	return targets
}

// GetTarget returns a target by BSSID.
func (db *TargetDB) GetTarget(bssid string) *wifi.Target {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return db.targets[bssid]
}

// Count returns the number of targets.
func (db *TargetDB) Count() int {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return len(db.targets)
}
