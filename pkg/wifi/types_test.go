package wifi

import "testing"

func TestEncryptionTypeString(t *testing.T) {
	tests := []struct {
		enc  EncryptionType
		want string
	}{
		{EncOpen, "Open"},
		{EncWEP, "WEP"},
		{EncWPA, "WPA"},
		{EncWPA2, "WPA2"},
		{EncWPA3, "WPA3"},
		{EncryptionType(99), "Unknown"},
	}
	for _, tt := range tests {
		if got := tt.enc.String(); got != tt.want {
			t.Errorf("EncryptionType(%d).String() = %q, want %q", tt.enc, got, tt.want)
		}
	}
}

func TestCipherTypeString(t *testing.T) {
	tests := []struct {
		c    CipherType
		want string
	}{
		{CipherNone, "None"},
		{CipherWEP, "WEP"},
		{CipherTKIP, "TKIP"},
		{CipherCCMP, "CCMP"},
		{CipherWRAP, "WRAP"},
		{CipherType(42), "Unknown"},
	}
	for _, tt := range tests {
		if got := tt.c.String(); got != tt.want {
			t.Errorf("CipherType(%d).String() = %q, want %q", tt.c, got, tt.want)
		}
	}
}

func TestAuthTypeString(t *testing.T) {
	tests := []struct {
		a    AuthType
		want string
	}{
		{AuthOpen, "Open"},
		{AuthPSK, "PSK"},
		{AuthEnterprise, "Enterprise"},
		{AuthSAE, "SAE"},
		{AuthType(7), "Unknown"},
	}
	for _, tt := range tests {
		if got := tt.a.String(); got != tt.want {
			t.Errorf("AuthType(%d).String() = %q, want %q", tt.a, got, tt.want)
		}
	}
}

func TestHandshakeMessageString(t *testing.T) {
	tests := []struct {
		m    HandshakeMessage
		want string
	}{
		{HandshakeMsg1, "M1"},
		{HandshakeMsg2, "M2"},
		{HandshakeMsg3, "M3"},
		{HandshakeMsg4, "M4"},
		{HandshakeMsgUnknown, "Unknown"},
	}
	for _, tt := range tests {
		if got := tt.m.String(); got != tt.want {
			t.Errorf("HandshakeMessage(%d).String() = %q, want %q", tt.m, got, tt.want)
		}
	}
}
