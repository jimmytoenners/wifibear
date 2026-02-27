package scan

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/wifibear/wifibear/pkg/wifi"
)

// CaptureWriter captures packets to a pcap file while monitoring for EAPOL handshakes.
// Replaces airodump-ng for targeted capture during WPA attacks.
type CaptureWriter struct {
	handle   *pcap.Handle
	writer   *pcapgo.Writer
	outFile  *os.File
	capPath  string
	bssid    string
	channel  int
	mu       sync.Mutex

	// Handshake tracking
	handshakes map[string]*wifi.FourWayHandshake
	eapolCount int
	onHandshake func(*wifi.FourWayHandshake)
}

// NewCaptureWriter creates a capture writer focused on a specific BSSID and channel.
func NewCaptureWriter(iface, bssid string, channel int, outputPath string) (*CaptureWriter, error) {
	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("open pcap on %s: %w", iface, err)
	}

	// BPF filter for this BSSID: management frames + EAPOL + data
	filter := fmt.Sprintf("ether host %s or ether proto 0x888e", bssid)
	if err := handle.SetBPFFilter(filter); err != nil {
		// Non-fatal: capture everything if filter fails
		_ = err
	}

	outFile, err := os.Create(outputPath)
	if err != nil {
		handle.Close()
		return nil, fmt.Errorf("create output file: %w", err)
	}

	writer := pcapgo.NewWriter(outFile)
	if err := writer.WriteFileHeader(65536, handle.LinkType()); err != nil {
		outFile.Close()
		handle.Close()
		return nil, fmt.Errorf("write pcap header: %w", err)
	}

	return &CaptureWriter{
		handle:     handle,
		writer:     writer,
		outFile:    outFile,
		capPath:    outputPath,
		bssid:      bssid,
		channel:    channel,
		handshakes: make(map[string]*wifi.FourWayHandshake),
	}, nil
}

// OnHandshake sets a callback for when a complete handshake is captured.
func (cw *CaptureWriter) OnHandshake(fn func(*wifi.FourWayHandshake)) {
	cw.onHandshake = fn
}

// Start begins capturing packets and writing them to the pcap file.
func (cw *CaptureWriter) Start(ctx context.Context) {
	go cw.captureLoop(ctx)
}

// Stop closes the capture.
func (cw *CaptureWriter) Stop() {
	if cw.handle != nil {
		cw.handle.Close()
	}
	if cw.outFile != nil {
		cw.outFile.Close()
	}
}

// CapFile returns the path to the capture file.
func (cw *CaptureWriter) CapFile() string {
	return cw.capPath
}

// HasHandshake returns true if a complete 4-way handshake has been captured.
func (cw *CaptureWriter) HasHandshake() bool {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	for _, hs := range cw.handshakes {
		if hs.Complete {
			return true
		}
	}
	return false
}

// EAPOLCount returns the number of EAPOL frames captured.
func (cw *CaptureWriter) EAPOLCount() int {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	return cw.eapolCount
}

// HandshakeMessageCount returns the best handshake message count across all clients.
func (cw *CaptureWriter) HandshakeMessageCount() int {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	best := 0
	for _, hs := range cw.handshakes {
		c := hs.MessageCount()
		if c > best {
			best = c
		}
	}
	return best
}

func (cw *CaptureWriter) captureLoop(ctx context.Context) {
	source := gopacket.NewPacketSource(cw.handle, cw.handle.LinkType())
	source.NoCopy = true

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

		// Write every packet to the cap file
		ci := gopacket.CaptureInfo{
			Timestamp:     time.Now(),
			CaptureLength: len(packet.Data()),
			Length:        len(packet.Data()),
		}
		cw.mu.Lock()
		_ = cw.writer.WritePacket(ci, packet.Data())
		cw.mu.Unlock()

		// Check for EAPOL frames
		cw.checkEAPOL(packet)
	}
}

func (cw *CaptureWriter) checkEAPOL(packet gopacket.Packet) {
	eapolLayer := packet.Layer(layers.LayerTypeEAPOLKey)
	if eapolLayer == nil {
		return
	}

	dot11Layer := packet.Layer(layers.LayerTypeDot11)
	if dot11Layer == nil {
		return
	}
	dot11 := dot11Layer.(*layers.Dot11)

	// Determine client MAC
	var clientMAC string
	switch {
	case dot11.Flags.ToDS() && !dot11.Flags.FromDS():
		clientMAC = dot11.Address2.String()
	case !dot11.Flags.ToDS() && dot11.Flags.FromDS():
		clientMAC = dot11.Address1.String()
	case !dot11.Flags.ToDS() && !dot11.Flags.FromDS():
		clientMAC = dot11.Address2.String()
	default:
		return
	}

	eapolData := eapolLayer.LayerContents()
	if len(eapolData) < 99 {
		return
	}

	keyFrame, err := wifi.ParseEAPOLKeyFrame(eapolData)
	if err != nil {
		return
	}

	msgNum := keyFrame.MessageNumber()
	if msgNum == wifi.HandshakeMsgUnknown {
		return
	}

	cw.mu.Lock()
	defer cw.mu.Unlock()

	cw.eapolCount++

	hs, ok := cw.handshakes[clientMAC]
	if !ok {
		hs = wifi.NewFourWayHandshake()
		cw.handshakes[clientMAC] = hs
	}

	var rawFrame []byte
	if eapol := packet.Layer(layers.LayerTypeEAPOL); eapol != nil {
		rawFrame = append(eapol.LayerContents(), eapol.LayerPayload()...)
	}

	wasComplete := hs.Complete
	hs.AddMessage(msgNum, keyFrame, rawFrame)

	if hs.Complete && !wasComplete && cw.onHandshake != nil {
		go cw.onHandshake(hs)
	}
}
