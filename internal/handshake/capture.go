package handshake

import (
	"fmt"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/wifibear/wifibear/pkg/wifi"
)

// CaptureState tracks EAPOL frames captured for a BSSID.
type CaptureState struct {
	Handshakes map[string]*wifi.FourWayHandshake // keyed by client MAC
}

func NewCaptureState() *CaptureState {
	return &CaptureState{
		Handshakes: make(map[string]*wifi.FourWayHandshake),
	}
}

// ScanCapFile reads a pcap file and extracts EAPOL handshake frames.
func ScanCapFile(capFile, targetBSSID string) (*CaptureState, error) {
	handle, err := pcap.OpenOffline(capFile)
	if err != nil {
		return nil, fmt.Errorf("open cap file: %w", err)
	}
	defer handle.Close()

	state := NewCaptureState()
	source := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range source.Packets() {
		dot11Layer := packet.Layer(layers.LayerTypeDot11)
		if dot11Layer == nil {
			continue
		}
		dot11 := dot11Layer.(*layers.Dot11)

		// Look for EAPOL frames
		eapolLayer := packet.Layer(layers.LayerTypeEAPOLKey)
		if eapolLayer == nil {
			continue
		}

		// Determine BSSID and client MAC
		bssid, clientMAC := extractAddresses(dot11)
		if bssid == "" {
			continue
		}

		if targetBSSID != "" && bssid != targetBSSID {
			continue
		}

		// Parse EAPOL key frame
		eapolData := eapolLayer.LayerContents()
		if len(eapolData) < 99 {
			continue
		}

		// Get the full EAPOL frame (header + key data)
		var fullEAPOL []byte
		if eapol := packet.Layer(layers.LayerTypeEAPOL); eapol != nil {
			fullEAPOL = append(eapol.LayerContents(), eapol.LayerPayload()...)
		}

		keyFrame, err := wifi.ParseEAPOLKeyFrame(eapolData)
		if err != nil {
			continue
		}

		msgNum := keyFrame.MessageNumber()
		if msgNum == wifi.HandshakeMsgUnknown {
			continue
		}

		// Get or create handshake tracker for this client
		hs, ok := state.Handshakes[clientMAC]
		if !ok {
			hs = wifi.NewFourWayHandshake()
			state.Handshakes[clientMAC] = hs
		}

		hs.AddMessage(msgNum, keyFrame, fullEAPOL)
	}

	return state, nil
}

// HasCompleteHandshake checks if any client has a complete handshake.
func (cs *CaptureState) HasCompleteHandshake() bool {
	for _, hs := range cs.Handshakes {
		if hs.Complete {
			return true
		}
	}
	return false
}

// CompleteHandshakes returns all complete handshakes.
func (cs *CaptureState) CompleteHandshakes() []*wifi.FourWayHandshake {
	var complete []*wifi.FourWayHandshake
	for _, hs := range cs.Handshakes {
		if hs.Complete {
			complete = append(complete, hs)
		}
	}
	return complete
}

// TotalEAPOLFrames returns the total number of EAPOL frames captured.
func (cs *CaptureState) TotalEAPOLFrames() int {
	total := 0
	for _, hs := range cs.Handshakes {
		total += hs.MessageCount()
	}
	return total
}

func extractAddresses(dot11 *layers.Dot11) (bssid, client string) {
	switch {
	case dot11.Flags.ToDS() && !dot11.Flags.FromDS():
		return dot11.Address1.String(), dot11.Address2.String()
	case !dot11.Flags.ToDS() && dot11.Flags.FromDS():
		return dot11.Address2.String(), dot11.Address1.String()
	case !dot11.Flags.ToDS() && !dot11.Flags.FromDS():
		return dot11.Address3.String(), dot11.Address2.String()
	default:
		return "", ""
	}
}

// StripCapture creates a new cap file with only handshake-relevant frames.
func StripCapture(inputFile, outputFile, bssid string) error {
	handle, err := pcap.OpenOffline(inputFile)
	if err != nil {
		return fmt.Errorf("open input: %w", err)
	}
	defer handle.Close()

	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	defer outFile.Close()

	writer := pcapgo.NewWriter(outFile)
	if err := writer.WriteFileHeader(65536, handle.LinkType()); err != nil {
		return fmt.Errorf("write pcap header: %w", err)
	}

	source := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range source.Packets() {
		dot11Layer := packet.Layer(layers.LayerTypeDot11)
		if dot11Layer == nil {
			continue
		}
		dot11 := dot11Layer.(*layers.Dot11)

		// Keep beacons and EAPOL frames for this BSSID
		isBeacon := dot11.Type == layers.Dot11TypeMgmtBeacon
		isEAPOL := packet.Layer(layers.LayerTypeEAPOLKey) != nil

		if !isBeacon && !isEAPOL {
			continue
		}

		b, _ := extractAddresses(dot11)
		if bssid != "" && b != bssid && dot11.Address3.String() != bssid {
			continue
		}

		ci := packet.Metadata().CaptureInfo
		_ = writer.WritePacket(ci, packet.Data())
	}

	return nil
}
