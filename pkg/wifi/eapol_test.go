package wifi

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// buildKeyFrame assembles a minimal 99-byte EAPOL-Key frame (plus optional
// trailing key data) with the given key-info bitmask and nonce.
func buildKeyFrame(keyInfo uint16, nonce [32]byte, keyData []byte) []byte {
	buf := make([]byte, 99+len(keyData))
	buf[0] = EAPOLVersion2
	buf[1] = EAPOLTypeKey
	binary.BigEndian.PutUint16(buf[2:4], uint16(95+len(keyData)))
	buf[4] = EAPOLKeyTypeAES
	binary.BigEndian.PutUint16(buf[5:7], keyInfo)
	binary.BigEndian.PutUint16(buf[7:9], 16)
	binary.BigEndian.PutUint64(buf[9:17], 1)
	copy(buf[17:49], nonce[:])
	binary.BigEndian.PutUint16(buf[97:99], uint16(len(keyData)))
	copy(buf[99:], keyData)
	return buf
}

func TestParseEAPOLKeyFrameTooShort(t *testing.T) {
	if _, err := ParseEAPOLKeyFrame(make([]byte, 98)); err == nil {
		t.Error("expected an error for a frame shorter than 99 bytes, got nil")
	}
}

func TestParseEAPOLKeyFrameFields(t *testing.T) {
	var nonce [32]byte
	for i := range nonce {
		nonce[i] = 0xAB
	}
	keyData := []byte{0xde, 0xad, 0xbe, 0xef}
	raw := buildKeyFrame(0x008a, nonce, keyData)

	f, err := ParseEAPOLKeyFrame(raw)
	if err != nil {
		t.Fatalf("ParseEAPOLKeyFrame: %v", err)
	}
	if f.Version != EAPOLVersion2 {
		t.Errorf("Version = %d, want %d", f.Version, EAPOLVersion2)
	}
	if f.Type != EAPOLTypeKey {
		t.Errorf("Type = %d, want %d", f.Type, EAPOLTypeKey)
	}
	if f.KeyInfo != 0x008a {
		t.Errorf("KeyInfo = %#x, want 0x008a", f.KeyInfo)
	}
	if f.KeyLength != 16 {
		t.Errorf("KeyLength = %d, want 16", f.KeyLength)
	}
	if f.Nonce != nonce {
		t.Error("Nonce was not parsed correctly")
	}
	if !bytes.Equal(f.Data, keyData) {
		t.Errorf("Data = %x, want %x", f.Data, keyData)
	}
}

// TestMessageNumber checks the 4-way-handshake message classifier across all
// four messages plus an unclassifiable frame.
func TestMessageNumber(t *testing.T) {
	var zero [32]byte
	nonzero := zero
	nonzero[0] = 0x01

	tests := []struct {
		name    string
		keyInfo uint16
		nonce   [32]byte
		want    HandshakeMessage
	}{
		{"M1", EAPOLKeyInfoPairwise | EAPOLKeyInfoACK, nonzero, HandshakeMsg1},
		{"M2", EAPOLKeyInfoPairwise | EAPOLKeyInfoMIC, nonzero, HandshakeMsg2},
		{"M3", EAPOLKeyInfoPairwise | EAPOLKeyInfoACK | EAPOLKeyInfoMIC | EAPOLKeyInfoInstall | EAPOLKeyInfoSecure, nonzero, HandshakeMsg3},
		{"M4", EAPOLKeyInfoPairwise | EAPOLKeyInfoMIC | EAPOLKeyInfoSecure, zero, HandshakeMsg4},
		{"Unknown", 0, zero, HandshakeMsgUnknown},
	}
	for _, tt := range tests {
		f := &EAPOLKeyFrame{KeyInfo: tt.keyInfo, Nonce: tt.nonce}
		if got := f.MessageNumber(); got != tt.want {
			t.Errorf("%s: MessageNumber() = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestFourWayHandshake(t *testing.T) {
	hs := NewFourWayHandshake()
	if hs.MessageCount() != 0 || hs.HasMinimumFrames() {
		t.Fatal("a new handshake should hold no frames")
	}

	var aNonce, sNonce [32]byte
	aNonce[0] = 0xA1
	sNonce[0] = 0x5B

	hs.AddMessage(HandshakeMsg1, &EAPOLKeyFrame{Nonce: aNonce}, []byte{0x01})
	if hs.HasMinimumFrames() {
		t.Error("a single frame should not satisfy the minimum")
	}

	hs.AddMessage(HandshakeMsg2, &EAPOLKeyFrame{Nonce: sNonce}, []byte{0x02})
	if hs.MessageCount() != 2 {
		t.Errorf("MessageCount = %d, want 2", hs.MessageCount())
	}
	if !hs.HasMinimumFrames() || !hs.Complete {
		t.Error("M1+M2 should mark the handshake complete")
	}
	if hs.ANonce() != aNonce {
		t.Error("ANonce did not match the M1 nonce")
	}
	if hs.SNonce() != sNonce {
		t.Error("SNonce did not match the M2 nonce")
	}

	// Out-of-range message numbers must be ignored.
	hs.AddMessage(HandshakeMessage(9), &EAPOLKeyFrame{}, []byte{0xff})
	if hs.MessageCount() != 2 {
		t.Errorf("out-of-range AddMessage changed count to %d, want 2", hs.MessageCount())
	}
}
