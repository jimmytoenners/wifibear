package wifi

import (
	"fmt"
	"net"
	"time"
)

type EncryptionType int

const (
	EncOpen EncryptionType = iota
	EncWEP
	EncWPA
	EncWPA2
	EncWPA3
)

func (e EncryptionType) String() string {
	switch e {
	case EncOpen:
		return "Open"
	case EncWEP:
		return "WEP"
	case EncWPA:
		return "WPA"
	case EncWPA2:
		return "WPA2"
	case EncWPA3:
		return "WPA3"
	default:
		return "Unknown"
	}
}

type CipherType int

const (
	CipherNone CipherType = iota
	CipherWEP
	CipherTKIP
	CipherCCMP
	CipherWRAP
)

func (c CipherType) String() string {
	switch c {
	case CipherNone:
		return "None"
	case CipherWEP:
		return "WEP"
	case CipherTKIP:
		return "TKIP"
	case CipherCCMP:
		return "CCMP"
	case CipherWRAP:
		return "WRAP"
	default:
		return "Unknown"
	}
}

type AuthType int

const (
	AuthOpen AuthType = iota
	AuthPSK
	AuthEnterprise
	AuthSAE
)

func (a AuthType) String() string {
	switch a {
	case AuthOpen:
		return "Open"
	case AuthPSK:
		return "PSK"
	case AuthEnterprise:
		return "Enterprise"
	case AuthSAE:
		return "SAE"
	default:
		return "Unknown"
	}
}

type Target struct {
	BSSID       net.HardwareAddr
	ESSID       string
	Channel     int
	Frequency   int
	Encryption  EncryptionType
	Cipher      CipherType
	Auth        AuthType
	WPS         bool
	Power       int
	Clients     []*Client
	FirstSeen   time.Time
	LastSeen    time.Time
	Hidden      bool
	BeaconCount int
	DataCount   int
}

func (t *Target) String() string {
	essid := t.ESSID
	if t.Hidden || essid == "" {
		essid = "<hidden>"
	}
	return fmt.Sprintf("%s [%s] Ch:%d %s %ddBm", essid, t.BSSID, t.Channel, t.Encryption, t.Power)
}

func (t *Target) HasClients() bool {
	return len(t.Clients) > 0
}

type Client struct {
	MAC       net.HardwareAddr
	BSSID     net.HardwareAddr
	Power     int
	Packets   int
	FirstSeen time.Time
	LastSeen  time.Time
}

func (c *Client) String() string {
	return fmt.Sprintf("%s -> %s (%d pkts)", c.MAC, c.BSSID, c.Packets)
}
