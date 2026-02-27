package config

import (
	"time"
)

type Config struct {
	Interface string
	Wordlist  string
	Band      Band
	Channels  []int

	Scan    ScanConfig
	Attack  AttackConfig
	MAC     MACConfig
	Output  OutputConfig
	Pillage bool
	BSSID   string
	ESSID   string
}

type Band int

const (
	Band2GHz Band = iota
	Band5GHz
	BandBoth
)

type ScanConfig struct {
	Timeout time.Duration
}

type AttackConfig struct {
	WPA   WPAConfig
	PMKID PMKIDConfig
	WPS   WPSConfig
	WEP   WEPConfig

	WPAOnly  bool
	WPSOnly  bool
	WEPOnly  bool
	NoWPS    bool
	NoPMKID  bool
}

type WPAConfig struct {
	HandshakeTimeout time.Duration
	DeauthInterval   time.Duration
	DeauthCount      int
}

type PMKIDConfig struct {
	Timeout time.Duration
}

type WPSConfig struct {
	PixieTimeout time.Duration
	PINTimeout   time.Duration
	MaxFailures  int
	IgnoreLock   bool
}

type WEPConfig struct {
	IVThreshold int
	Timeout     time.Duration
}

type MACConfig struct {
	Randomize       bool
	RotatePerTarget bool
}

type OutputConfig struct {
	ResultsFile   string
	HandshakeDir  string
	Verbose       int
}

func DefaultConfig() *Config {
	return &Config{
		Band:     Band2GHz,
		Wordlist: "/usr/share/wordlists/rockyou.txt",
		Scan: ScanConfig{
			Timeout: 30 * time.Second,
		},
		Attack: AttackConfig{
			WPA: WPAConfig{
				HandshakeTimeout: 500 * time.Second,
				DeauthInterval:   15 * time.Second,
				DeauthCount:      5,
			},
			PMKID: PMKIDConfig{
				Timeout: 30 * time.Second,
			},
			WPS: WPSConfig{
				PixieTimeout: 300 * time.Second,
				PINTimeout:   3600 * time.Second,
				MaxFailures:  100,
			},
			WEP: WEPConfig{
				IVThreshold: 10000,
				Timeout:     600 * time.Second,
			},
		},
		MAC: MACConfig{
			Randomize:       true,
			RotatePerTarget: true,
		},
		Output: OutputConfig{
			ResultsFile:  "./wifibear-results.json",
			HandshakeDir: "./handshakes/",
			Verbose:      1,
		},
	}
}
