package handshake

import (
	"context"

	"github.com/wifibear/wifibear/internal/tools"
)

// Validator checks if a capture file contains a valid handshake.
type Validator interface {
	Name() string
	Validate(ctx context.Context, capFile, bssid string) (bool, error)
}

// GopacketValidator uses gopacket to check for EAPOL frames in a capture.
type GopacketValidator struct{}

func NewGopacketValidator() *GopacketValidator {
	return &GopacketValidator{}
}

func (v *GopacketValidator) Name() string {
	return "gopacket"
}

func (v *GopacketValidator) Validate(ctx context.Context, capFile, bssid string) (bool, error) {
	state, err := ScanCapFile(capFile, bssid)
	if err != nil {
		return false, err
	}
	return state.HasCompleteHandshake(), nil
}

// TsharkValidator uses tshark to validate handshakes.
type TsharkValidator struct {
	tshark *tools.Tshark
}

func NewTsharkValidator(tshark *tools.Tshark) *TsharkValidator {
	return &TsharkValidator{tshark: tshark}
}

func (v *TsharkValidator) Name() string {
	return "tshark"
}

func (v *TsharkValidator) Validate(ctx context.Context, capFile, bssid string) (bool, error) {
	return v.tshark.HasHandshake(ctx, capFile, bssid)
}
