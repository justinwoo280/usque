//go:build windows

package cmd

import (
	"fmt"
	"net"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/internal"
	"golang.zx2c4.com/wireguard/tun"
)

func (t *tunDevice) create() (api.TunnelDevice, error) {
	if t.name == "" {
		t.name = "usque"
	}

	dev, err := tun.CreateTUN(t.name, t.mtu)
	if err != nil {
		return nil, err
	}

	t.name, err = dev.Name()
	if err != nil {
		return nil, err
	}

	if t.ipv4 {
		err = internal.SetIPv4Address(t.name, t.account.IPv4, "255.255.255.255")
		if err != nil {
			return nil, fmt.Errorf("failed to set IPv4 address: %v", err)
		}
		if err := internal.SetIPv4Peer(t.name, derivePeerIPv4Win(t.account.IPv4)); err != nil {
			return nil, fmt.Errorf("failed to set IPv4 peer: %v", err)
		}

		err = internal.SetIPv4MTU(t.name, t.mtu)
		if err != nil {
			return nil, fmt.Errorf("failed to set IPv4 MTU: %v", err)
		}
	}

	if t.ipv6 {
		err = internal.SetIPv6Address(t.name, t.account.IPv6, "128")
		if err != nil {
			return nil, fmt.Errorf("failed to set IPv6 address: %v", err)
		}
		if err := internal.SetIPv6Peer(t.name, "fe80::1"); err != nil {
			return nil, fmt.Errorf("failed to set IPv6 peer: %v", err)
		}

		err = internal.SetIPv6MTU(t.name, t.mtu)
		if err != nil {
			return nil, fmt.Errorf("failed to set IPv6 MTU: %v", err)
		}
	}

	return api.NewNetstackAdapter(dev), nil
}

func derivePeerIPv4Win(localIP string) string {
	ip := net.ParseIP(localIP).To4()
	if ip == nil {
		return "10.0.0.1"
	}
	peer := make(net.IP, 4)
	copy(peer, ip)
	if peer[3] < 255 {
		peer[3]++
	} else {
		peer[3] = 1
	}
	return peer.String()
}
