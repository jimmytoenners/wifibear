package scan

import (
	"context"
	"fmt"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/wifibear/wifibear/pkg/wifi"
)

// Scanner performs passive 802.11 scanning using gopacket.
type Scanner struct {
	iface    string
	handle   *pcap.Handle
	db       *TargetDB
	verbose  int
}

// NewScanner creates a new passive WiFi scanner.
func NewScanner(iface string, verbose int) *Scanner {
	return &Scanner{
		iface:   iface,
		db:      NewTargetDB(),
		verbose: verbose,
	}
}

// DB returns the underlying target database.
func (s *Scanner) DB() *TargetDB {
	return s.db
}

// Start begins capturing and processing 802.11 frames.
func (s *Scanner) Start(ctx context.Context) error {
	handle, err := pcap.OpenLive(s.iface, 65536, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("open pcap on %s: %w", s.iface, err)
	}
	s.handle = handle

	// Set BPF filter for management frames and EAPOL
	if err := handle.SetBPFFilter("type mgt or ether proto 0x888e"); err != nil {
		if s.verbose > 1 {
			log.Printf("Warning: could not set BPF filter: %v", err)
		}
	}

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	source.NoCopy = true

	go s.processPackets(ctx, source)

	return nil
}

// Stop closes the pcap handle.
func (s *Scanner) Stop() {
	if s.handle != nil {
		s.handle.Close()
	}
}

func (s *Scanner) processPackets(ctx context.Context, source *gopacket.PacketSource) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		packet, err := source.NextPacket()
		if err != nil {
			continue
		}

		s.handlePacket(packet)
	}
}

func (s *Scanner) handlePacket(packet gopacket.Packet) {
	// Extract radiotap info for signal strength
	power := int(-100)
	if rtLayer := packet.Layer(layers.LayerTypeRadioTap); rtLayer != nil {
		rt := rtLayer.(*layers.RadioTap)
		if rt.DBMAntennaSignal != 0 {
			power = int(rt.DBMAntennaSignal)
		}
	}

	dot11Layer := packet.Layer(layers.LayerTypeDot11)
	if dot11Layer == nil {
		return
	}
	dot11 := dot11Layer.(*layers.Dot11)

	switch dot11.Type {
	case layers.Dot11TypeMgmtBeacon:
		s.handleBeacon(packet, dot11, power)
	case layers.Dot11TypeMgmtProbeResp:
		s.handleProbeResponse(packet, dot11, power)
	case layers.Dot11TypeMgmtProbeReq:
		// Track probe requests for client discovery
	case layers.Dot11TypeData, layers.Dot11TypeDataQOSData:
		s.handleDataFrame(dot11, power)
	}
}

func (s *Scanner) handleBeacon(packet gopacket.Packet, dot11 *layers.Dot11, power int) {
	bssid := dot11.Address3
	if isBroadcast(bssid) {
		return
	}

	var essid string
	var channel int
	var enc wifi.EncryptionType
	var cipher wifi.CipherType
	var wps bool

	// Parse information elements
	for _, layer := range packet.Layers() {
		switch l := layer.(type) {
		case *layers.Dot11InformationElement:
			switch l.ID {
			case layers.Dot11InformationElementIDSSID:
				essid = string(l.Info)
			case layers.Dot11InformationElementIDDSSet:
				if len(l.Info) > 0 {
					channel = int(l.Info[0])
				}
			case layers.Dot11InformationElementIDRSNInfo:
				enc, cipher = parseRSN(l.Info)
			case layers.Dot11InformationElementIDVendor:
				if isWPSElement(l.Info) {
					wps = true
				}
				if enc == wifi.EncOpen {
					e, c := parseWPAVendor(l.Info)
					if e != wifi.EncOpen {
						enc = e
						cipher = c
					}
				}
			}
		}
	}

	// Check for WEP from capability info
	if enc == wifi.EncOpen {
		if mgmt := packet.Layer(layers.LayerTypeDot11MgmtBeacon); mgmt != nil {
			beacon := mgmt.(*layers.Dot11MgmtBeacon)
			if beacon.Flags&0x0010 != 0 { // Privacy bit
				enc = wifi.EncWEP
				cipher = wifi.CipherWEP
			}
		}
	}

	s.db.UpdateTarget(bssid, essid, channel, power, enc, cipher, wps)
}

func (s *Scanner) handleProbeResponse(packet gopacket.Packet, dot11 *layers.Dot11, power int) {
	bssid := dot11.Address3
	if isBroadcast(bssid) {
		return
	}

	var essid string
	var channel int
	var enc wifi.EncryptionType
	var cipher wifi.CipherType

	for _, layer := range packet.Layers() {
		if ie, ok := layer.(*layers.Dot11InformationElement); ok {
			switch ie.ID {
			case layers.Dot11InformationElementIDSSID:
				essid = string(ie.Info)
			case layers.Dot11InformationElementIDDSSet:
				if len(ie.Info) > 0 {
					channel = int(ie.Info[0])
				}
			case layers.Dot11InformationElementIDRSNInfo:
				enc, cipher = parseRSN(ie.Info)
			}
		}
	}

	s.db.UpdateTarget(bssid, essid, channel, power, enc, cipher, false)
}

func (s *Scanner) handleDataFrame(dot11 *layers.Dot11, power int) {
	// Determine BSSID and client from ToDS/FromDS flags
	var bssid, client net.HardwareAddr

	switch {
	case dot11.Flags.ToDS() && !dot11.Flags.FromDS():
		// Client -> AP
		bssid = dot11.Address1
		client = dot11.Address2
	case !dot11.Flags.ToDS() && dot11.Flags.FromDS():
		// AP -> Client
		bssid = dot11.Address2
		client = dot11.Address1
	default:
		return
	}

	if isBroadcast(bssid) || isBroadcast(client) {
		return
	}

	s.db.IncrementData(bssid)
	s.db.UpdateClient(client, bssid, power)
}

// parseRSN extracts encryption and cipher from RSN (WPA2) information element.
func parseRSN(data []byte) (wifi.EncryptionType, wifi.CipherType) {
	if len(data) < 10 {
		return wifi.EncOpen, wifi.CipherNone
	}

	enc := wifi.EncWPA2
	cipher := wifi.CipherCCMP

	// Parse pairwise cipher suite
	if len(data) >= 10 {
		oui := data[6:10]
		switch oui[3] {
		case 2:
			cipher = wifi.CipherTKIP
		case 4:
			cipher = wifi.CipherCCMP
		}
	}

	// Check AKM suite for WPA3/SAE
	if len(data) >= 18 {
		akm := data[14:18]
		if akm[3] == 8 { // SAE
			enc = wifi.EncWPA3
		}
	}

	return enc, cipher
}

// parseWPAVendor extracts WPA (v1) from vendor-specific IE.
func parseWPAVendor(data []byte) (wifi.EncryptionType, wifi.CipherType) {
	// WPA OUI: 00:50:F2:01
	if len(data) < 4 {
		return wifi.EncOpen, wifi.CipherNone
	}
	if data[0] == 0x00 && data[1] == 0x50 && data[2] == 0xF2 && data[3] == 0x01 {
		return wifi.EncWPA, wifi.CipherTKIP
	}
	return wifi.EncOpen, wifi.CipherNone
}

// isWPSElement checks if a vendor IE contains WPS data.
func isWPSElement(data []byte) bool {
	// WPS OUI: 00:50:F2:04
	if len(data) < 4 {
		return false
	}
	return data[0] == 0x00 && data[1] == 0x50 && data[2] == 0xF2 && data[3] == 0x04
}

func isBroadcast(mac net.HardwareAddr) bool {
	if len(mac) != 6 {
		return true
	}
	return mac[0] == 0xff && mac[1] == 0xff && mac[2] == 0xff &&
		mac[3] == 0xff && mac[4] == 0xff && mac[5] == 0xff
}
