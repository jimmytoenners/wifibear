package wifi

import (
	"encoding/binary"
	"fmt"
)

const (
	EAPOLKeyTypeRC4  = 1
	EAPOLKeyTypeAES  = 2
	EAPOLVersion1    = 1
	EAPOLVersion2    = 2
	EAPOLTypeKey     = 3
	EAPOLKeyInfoPairwise = 0x0008
	EAPOLKeyInfoInstall  = 0x0040
	EAPOLKeyInfoACK      = 0x0080
	EAPOLKeyInfoMIC      = 0x0100
	EAPOLKeyInfoSecure   = 0x0200
)

type EAPOLKeyFrame struct {
	Version        uint8
	Type           uint8
	Length         uint16
	DescriptorType uint8
	KeyInfo        uint16
	KeyLength      uint16
	ReplayCounter  uint64
	Nonce          [32]byte
	IV             [16]byte
	RSC            [8]byte
	ID             [8]byte
	MIC            [16]byte
	DataLength     uint16
	Data           []byte
}

type HandshakeMessage int

const (
	HandshakeMsg1 HandshakeMessage = 1
	HandshakeMsg2 HandshakeMessage = 2
	HandshakeMsg3 HandshakeMessage = 3
	HandshakeMsg4 HandshakeMessage = 4
	HandshakeMsgUnknown HandshakeMessage = 0
)

func (h HandshakeMessage) String() string {
	switch h {
	case HandshakeMsg1:
		return "M1"
	case HandshakeMsg2:
		return "M2"
	case HandshakeMsg3:
		return "M3"
	case HandshakeMsg4:
		return "M4"
	default:
		return "Unknown"
	}
}

func ParseEAPOLKeyFrame(data []byte) (*EAPOLKeyFrame, error) {
	if len(data) < 99 {
		return nil, fmt.Errorf("EAPOL key frame too short: %d bytes", len(data))
	}

	frame := &EAPOLKeyFrame{
		Version:        data[0],
		Type:           data[1],
		Length:         binary.BigEndian.Uint16(data[2:4]),
		DescriptorType: data[4],
		KeyInfo:        binary.BigEndian.Uint16(data[5:7]),
		KeyLength:      binary.BigEndian.Uint16(data[7:9]),
		ReplayCounter:  binary.BigEndian.Uint64(data[9:17]),
	}

	copy(frame.Nonce[:], data[17:49])
	copy(frame.IV[:], data[49:65])
	copy(frame.RSC[:], data[65:73])
	copy(frame.ID[:], data[73:81])
	copy(frame.MIC[:], data[81:97])

	frame.DataLength = binary.BigEndian.Uint16(data[97:99])
	if len(data) > 99 {
		frame.Data = data[99:]
	}

	return frame, nil
}

func (f *EAPOLKeyFrame) MessageNumber() HandshakeMessage {
	hasACK := f.KeyInfo&EAPOLKeyInfoACK != 0
	hasMIC := f.KeyInfo&EAPOLKeyInfoMIC != 0
	hasInstall := f.KeyInfo&EAPOLKeyInfoInstall != 0
	hasSecure := f.KeyInfo&EAPOLKeyInfoSecure != 0

	isNonceZero := true
	for _, b := range f.Nonce {
		if b != 0 {
			isNonceZero = false
			break
		}
	}

	switch {
	case hasACK && !hasMIC && !hasInstall:
		return HandshakeMsg1
	case !hasACK && hasMIC && !hasInstall && !isNonceZero:
		return HandshakeMsg2
	case hasACK && hasMIC && hasInstall && hasSecure:
		return HandshakeMsg3
	case !hasACK && hasMIC && !hasInstall && hasSecure && isNonceZero:
		return HandshakeMsg4
	default:
		return HandshakeMsgUnknown
	}
}

type FourWayHandshake struct {
	BSSID    [6]byte
	ClientMAC [6]byte
	Messages [4]*EAPOLKeyFrame
	RawFrames [4][]byte
	Complete bool
}

func NewFourWayHandshake() *FourWayHandshake {
	return &FourWayHandshake{}
}

func (h *FourWayHandshake) AddMessage(msg HandshakeMessage, frame *EAPOLKeyFrame, raw []byte) {
	idx := int(msg) - 1
	if idx < 0 || idx > 3 {
		return
	}
	h.Messages[idx] = frame
	h.RawFrames[idx] = make([]byte, len(raw))
	copy(h.RawFrames[idx], raw)
	h.checkComplete()
}

func (h *FourWayHandshake) checkComplete() {
	// A valid handshake needs at minimum M1+M2 or M2+M3
	// M1 provides ANonce, M2 provides SNonce + MIC
	if h.Messages[0] != nil && h.Messages[1] != nil {
		h.Complete = true
	}
}

func (h *FourWayHandshake) HasMinimumFrames() bool {
	return h.Messages[0] != nil && h.Messages[1] != nil
}

func (h *FourWayHandshake) MessageCount() int {
	count := 0
	for _, m := range h.Messages {
		if m != nil {
			count++
		}
	}
	return count
}

func (h *FourWayHandshake) ANonce() [32]byte {
	if h.Messages[0] != nil {
		return h.Messages[0].Nonce
	}
	return [32]byte{}
}

func (h *FourWayHandshake) SNonce() [32]byte {
	if h.Messages[1] != nil {
		return h.Messages[1].Nonce
	}
	return [32]byte{}
}
