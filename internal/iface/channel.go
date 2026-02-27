package iface

import (
	"context"
	"fmt"
	"time"

	"github.com/wifibear/wifibear/internal/tools"
)

// Standard 2.4 GHz channels
var Channels2GHz = []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}

// Standard 5 GHz channels
var Channels5GHz = []int{
	36, 40, 44, 48, 52, 56, 60, 64,
	100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
	149, 153, 157, 161, 165,
}

// ChannelHopper cycles through WiFi channels on a monitor interface.
type ChannelHopper struct {
	iface    string
	channels []int
	interval time.Duration
	current  int
	stopCh   chan struct{}
}

// NewChannelHopper creates a new channel hopper.
func NewChannelHopper(iface string, channels []int, interval time.Duration) *ChannelHopper {
	if len(channels) == 0 {
		channels = Channels2GHz
	}
	if interval == 0 {
		interval = 250 * time.Millisecond
	}
	return &ChannelHopper{
		iface:    iface,
		channels: channels,
		interval: interval,
		stopCh:   make(chan struct{}),
	}
}

// Start begins channel hopping in a goroutine.
func (ch *ChannelHopper) Start(ctx context.Context) {
	go ch.run(ctx)
}

// Stop halts channel hopping.
func (ch *ChannelHopper) Stop() {
	select {
	case ch.stopCh <- struct{}{}:
	default:
	}
}

// SetChannel locks the hopper to a specific channel.
func (ch *ChannelHopper) SetChannel(ctx context.Context, channel int) error {
	ch.current = channel
	return setChannel(ctx, ch.iface, channel)
}

// Current returns the current channel.
func (ch *ChannelHopper) Current() int {
	return ch.current
}

func (ch *ChannelHopper) run(ctx context.Context) {
	idx := 0
	ticker := time.NewTicker(ch.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ch.stopCh:
			return
		case <-ticker.C:
			channel := ch.channels[idx%len(ch.channels)]
			if err := setChannel(ctx, ch.iface, channel); err == nil {
				ch.current = channel
			}
			idx++
		}
	}
}

func setChannel(ctx context.Context, iface string, channel int) error {
	// Use iwconfig to set channel (most compatible)
	_, err := tools.RunCapture(ctx, "iwconfig", iface, "channel", fmt.Sprintf("%d", channel))
	if err != nil {
		// Fallback to iw
		_, err = tools.RunCapture(ctx, "iw", "dev", iface, "set", "channel", fmt.Sprintf("%d", channel))
	}
	return err
}

// ChannelsForBand returns channel list for the specified band.
func ChannelsForBand(band string) []int {
	switch band {
	case "5ghz":
		return Channels5GHz
	case "both":
		all := make([]int, 0, len(Channels2GHz)+len(Channels5GHz))
		all = append(all, Channels2GHz...)
		all = append(all, Channels5GHz...)
		return all
	default:
		return Channels2GHz
	}
}
