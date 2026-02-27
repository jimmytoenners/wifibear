package wifi

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"math"

	"golang.org/x/crypto/pbkdf2"
)

const (
	PMKLength = 32
	PTKLength = 64
	MICLength = 16
)

// DerivePMK generates the Pairwise Master Key from a passphrase and SSID
// using PBKDF2-SHA1 with 4096 iterations as defined in IEEE 802.11i.
func DerivePMK(passphrase, ssid string) []byte {
	return pbkdf2.Key([]byte(passphrase), []byte(ssid), 4096, PMKLength, sha1.New)
}

// DerivePTK generates the Pairwise Transient Key from the PMK and nonces.
// It uses the PRF-512 function defined in IEEE 802.11i.
func DerivePTK(pmk []byte, aa, spa [6]byte, aNonce, sNonce [32]byte) []byte {
	// Build the data input for PRF: min(AA,SPA) || max(AA,SPA) || min(ANonce,SNonce) || max(ANonce,SNonce)
	var data [76]byte

	if macLess(aa[:], spa[:]) {
		copy(data[0:6], aa[:])
		copy(data[6:12], spa[:])
	} else {
		copy(data[0:6], spa[:])
		copy(data[6:12], aa[:])
	}

	if bytesLess(aNonce[:], sNonce[:]) {
		copy(data[12:44], aNonce[:])
		copy(data[44:76], sNonce[:])
	} else {
		copy(data[12:44], sNonce[:])
		copy(data[44:76], aNonce[:])
	}

	return prf512(pmk, "Pairwise key expansion", data[:])
}

// ComputeMIC calculates the MIC for an EAPOL frame using HMAC-SHA1.
func ComputeMIC(kck, eapolFrame []byte) []byte {
	mac := hmac.New(sha1.New, kck)
	mac.Write(eapolFrame)
	return mac.Sum(nil)[:MICLength]
}

// VerifyMIC checks if a given MIC matches the expected MIC for an EAPOL frame.
func VerifyMIC(pmk []byte, aa, spa [6]byte, aNonce, sNonce [32]byte, eapolFrame []byte, expectedMIC []byte) bool {
	ptk := DerivePTK(pmk, aa, spa, aNonce, sNonce)
	kck := ptk[:16]
	computedMIC := ComputeMIC(kck, eapolFrame)
	return hmac.Equal(computedMIC, expectedMIC)
}

// VerifyPassphrase checks if a passphrase is valid for a given handshake.
func VerifyPassphrase(passphrase, ssid string, aa, spa [6]byte, aNonce, sNonce [32]byte, eapolFrame []byte, expectedMIC []byte) bool {
	pmk := DerivePMK(passphrase, ssid)
	return VerifyMIC(pmk, aa, spa, aNonce, sNonce, eapolFrame, expectedMIC)
}

// prf512 implements the PRF-512 function from IEEE 802.11i.
func prf512(key []byte, label string, data []byte) []byte {
	nIter := int(math.Ceil(float64(PTKLength) / float64(sha1.Size)))
	result := make([]byte, 0, nIter*sha1.Size)

	prefix := append([]byte(label), 0)

	for i := 0; i < nIter; i++ {
		msg := make([]byte, 0, len(prefix)+len(data)+1)
		msg = append(msg, prefix...)
		msg = append(msg, data...)

		var counter [1]byte
		counter[0] = byte(i)
		msg = append(msg, counter[0])

		mac := hmac.New(sha1.New, key)
		mac.Write(msg)
		result = append(result, mac.Sum(nil)...)
	}

	return result[:PTKLength]
}

func macLess(a, b []byte) bool {
	aa := binary.BigEndian.Uint64(append([]byte{0, 0}, a[:6]...))
	bb := binary.BigEndian.Uint64(append([]byte{0, 0}, b[:6]...))
	return aa < bb
}

func bytesLess(a, b []byte) bool {
	for i := range a {
		if a[i] < b[i] {
			return true
		}
		if a[i] > b[i] {
			return false
		}
	}
	return false
}
