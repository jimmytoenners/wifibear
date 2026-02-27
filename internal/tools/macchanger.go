package tools

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"regexp"
)

var macAddrRe = regexp.MustCompile(`([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})`)

// Macchanger wraps the macchanger utility.
type Macchanger struct {
	tool *ExternalTool
}

func NewMacchanger() *Macchanger {
	return &Macchanger{
		tool: &ExternalTool{Name: "macchanger", Required: false},
	}
}

func (m *Macchanger) Available() bool {
	return m.tool.Exists()
}

// Randomize sets a random MAC address on the interface.
func (m *Macchanger) Randomize(ctx context.Context, iface string) (net.HardwareAddr, error) {
	// Bring interface down first
	if err := RunSilent(ctx, "ip", "link", "set", iface, "down"); err != nil {
		return nil, fmt.Errorf("interface down: %w", err)
	}

	out, err := RunCapture(ctx, "macchanger", "-r", iface)

	// Bring interface back up regardless of macchanger result
	_ = RunSilent(ctx, "ip", "link", "set", iface, "up")

	if err != nil {
		return nil, fmt.Errorf("macchanger: %w", err)
	}

	// Parse the new MAC from output
	matches := macAddrRe.FindAllString(out, -1)
	if len(matches) > 0 {
		mac, _ := net.ParseMAC(matches[len(matches)-1])
		return mac, nil
	}

	return nil, fmt.Errorf("could not parse new MAC from output")
}

// SetMAC sets a specific MAC address on the interface.
func (m *Macchanger) SetMAC(ctx context.Context, iface string, mac net.HardwareAddr) error {
	if err := RunSilent(ctx, "ip", "link", "set", iface, "down"); err != nil {
		return fmt.Errorf("interface down: %w", err)
	}

	_, err := RunCapture(ctx, "macchanger", "-m", mac.String(), iface)

	_ = RunSilent(ctx, "ip", "link", "set", iface, "up")

	return err
}

// Restore restores the original hardware MAC.
func (m *Macchanger) Restore(ctx context.Context, iface string) error {
	if err := RunSilent(ctx, "ip", "link", "set", iface, "down"); err != nil {
		return fmt.Errorf("interface down: %w", err)
	}

	_, err := RunCapture(ctx, "macchanger", "-p", iface)

	_ = RunSilent(ctx, "ip", "link", "set", iface, "up")

	return err
}

// GenerateRandomMAC generates a random locally-administered unicast MAC.
func GenerateRandomMAC() net.HardwareAddr {
	mac := make([]byte, 6)
	for i := range mac {
		mac[i] = byte(rand.Intn(256))
	}
	// Set locally administered bit, clear multicast bit
	mac[0] = (mac[0] | 0x02) & 0xfe
	return net.HardwareAddr(mac)
}
