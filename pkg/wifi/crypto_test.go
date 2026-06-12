package wifi

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestDerivePMKKnownAnswer checks DerivePMK against the published IEEE 802.11i
// WPA-PSK reference vectors (PBKDF2-SHA1, 4096 iterations, 32-byte output).
// These vectors are widely reproduced in hostapd and Wireshark documentation.
func TestDerivePMKKnownAnswer(t *testing.T) {
	tests := []struct {
		passphrase, ssid, wantHex string
	}{
		{"password", "IEEE", "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e"},
		{"ThisIsAPassword", "ThisIsASSID", "0dc0d6eb90555ed6419756b9a15ec3e3209b63df707dd508d14581f8982721af"},
	}
	for _, tt := range tests {
		pmk := DerivePMK(tt.passphrase, tt.ssid)
		if len(pmk) != PMKLength {
			t.Errorf("DerivePMK(%q,%q) length = %d, want %d", tt.passphrase, tt.ssid, len(pmk), PMKLength)
		}
		if got := hex.EncodeToString(pmk); got != tt.wantHex {
			t.Errorf("DerivePMK(%q,%q) = %s, want %s", tt.passphrase, tt.ssid, got, tt.wantHex)
		}
	}
}

// TestDerivePTKCanonicalOrdering verifies that the PTK is derived over
// canonically ordered (min/max) MAC and nonce pairs: swapping the operands
// within each pair must produce an identical PTK, while different inputs must not.
func TestDerivePTKCanonicalOrdering(t *testing.T) {
	pmk := DerivePMK("password", "IEEE")
	a := [6]byte{0x00, 0x0c, 0x29, 0x11, 0x22, 0x33}
	b := [6]byte{0x00, 0x0c, 0x29, 0xaa, 0xbb, 0xcc}
	var nA, nB [32]byte
	for i := range nA {
		nA[i] = byte(i)
		nB[i] = byte(255 - i)
	}

	base := DerivePTK(pmk, a, b, nA, nB)
	if len(base) != PTKLength {
		t.Fatalf("DerivePTK length = %d, want %d", len(base), PTKLength)
	}

	for _, c := range []struct {
		name           string
		aa, spa        [6]byte
		aNonce, sNonce [32]byte
	}{
		{"swap both pairs", b, a, nB, nA},
		{"swap macs only", b, a, nA, nB},
		{"swap nonces only", a, b, nB, nA},
	} {
		if got := DerivePTK(pmk, c.aa, c.spa, c.aNonce, c.sNonce); !bytes.Equal(base, got) {
			t.Errorf("PTK changed after %s; expected invariance", c.name)
		}
	}

	other := [6]byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}
	if bytes.Equal(base, DerivePTK(pmk, a, other, nA, nB)) {
		t.Error("PTK unexpectedly identical for a different peer MAC")
	}
}

func TestComputeMIC(t *testing.T) {
	kck := []byte("0123456789abcdef")
	frame := []byte("eapol-key-frame-bytes")

	mic := ComputeMIC(kck, frame)
	if len(mic) != MICLength {
		t.Fatalf("ComputeMIC length = %d, want %d", len(mic), MICLength)
	}
	if !bytes.Equal(mic, ComputeMIC(kck, frame)) {
		t.Error("ComputeMIC is not deterministic")
	}
	if bytes.Equal(mic, ComputeMIC([]byte("fedcba9876543210"), frame)) {
		t.Error("ComputeMIC produced the same MIC under a different KCK")
	}
}

// TestVerifyPassphraseRoundTrip builds a self-consistent handshake (PMK -> PTK ->
// KCK -> MIC) and confirms the verifier accepts the correct passphrase/MIC and
// rejects an incorrect passphrase and a tampered MIC.
func TestVerifyPassphraseRoundTrip(t *testing.T) {
	const ssid = "TestNet"
	const pass = "correct horse battery staple"

	pmk := DerivePMK(pass, ssid)
	aa := [6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	spa := [6]byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb}
	var aNonce, sNonce [32]byte
	for i := range aNonce {
		aNonce[i] = byte(i * 3)
		sNonce[i] = byte(i * 7)
	}

	ptk := DerivePTK(pmk, aa, spa, aNonce, sNonce)
	kck := ptk[:16]
	eapol := []byte{0x02, 0x03, 0x00, 0x5f, 0x00, 0x8a, 0x00, 0x10}
	mic := ComputeMIC(kck, eapol)

	if !VerifyMIC(pmk, aa, spa, aNonce, sNonce, eapol, mic) {
		t.Error("VerifyMIC rejected a self-consistent MIC")
	}
	if !VerifyPassphrase(pass, ssid, aa, spa, aNonce, sNonce, eapol, mic) {
		t.Error("VerifyPassphrase rejected the correct passphrase")
	}
	if VerifyPassphrase("wrong-passphrase", ssid, aa, spa, aNonce, sNonce, eapol, mic) {
		t.Error("VerifyPassphrase accepted an incorrect passphrase")
	}

	tampered := bytes.Clone(mic)
	tampered[0] ^= 0xff
	if VerifyMIC(pmk, aa, spa, aNonce, sNonce, eapol, tampered) {
		t.Error("VerifyMIC accepted a tampered MIC")
	}
}

func TestMACLess(t *testing.T) {
	lo := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	hi := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x02}
	if !macLess(lo, hi) {
		t.Error("macLess(lo, hi) = false, want true")
	}
	if macLess(hi, lo) {
		t.Error("macLess(hi, lo) = true, want false")
	}
	if macLess(lo, lo) {
		t.Error("macLess(lo, lo) = true, want false")
	}
}

func TestBytesLess(t *testing.T) {
	a := []byte{0x01, 0x02, 0x03}
	b := []byte{0x01, 0x02, 0x04}
	if !bytesLess(a, b) {
		t.Error("bytesLess(a, b) = false, want true")
	}
	if bytesLess(b, a) {
		t.Error("bytesLess(b, a) = true, want false")
	}
	if bytesLess(a, a) {
		t.Error("bytesLess(a, a) = true, want false")
	}
}
