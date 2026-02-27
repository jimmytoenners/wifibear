package scan

import (
	"github.com/wifibear/wifibear/internal/tools"
	"github.com/wifibear/wifibear/pkg/wifi"
)

// MergeAirodumpTargets merges targets parsed from airodump-ng CSV into the DB.
func (db *TargetDB) MergeAirodumpTargets(csvPath string) error {
	targets, _, err := tools.ParseAirodumpCSV(csvPath)
	if err != nil {
		return err
	}

	for _, t := range targets {
		db.UpdateTarget(
			t.BSSID,
			t.ESSID,
			t.Channel,
			t.Power,
			t.Encryption,
			t.Cipher,
			t.WPS,
		)

		for _, c := range t.Clients {
			db.UpdateClient(c.MAC, c.BSSID, c.Power)
		}
	}

	return nil
}

// FilterTargets applies filters to a target list.
func FilterTargets(targets []*wifi.Target, bssid, essid string, encFilter wifi.EncryptionType, wpsOnly, clientsOnly bool) []*wifi.Target {
	var filtered []*wifi.Target

	for _, t := range targets {
		if bssid != "" && t.BSSID.String() != bssid {
			continue
		}
		if essid != "" && t.ESSID != essid {
			continue
		}
		if encFilter != wifi.EncOpen && t.Encryption != encFilter {
			// EncOpen as filter means "any"
			if encFilter != 0 {
				continue
			}
		}
		if wpsOnly && !t.WPS {
			continue
		}
		if clientsOnly && !t.HasClients() {
			continue
		}

		filtered = append(filtered, t)
	}

	return filtered
}
