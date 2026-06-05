//go:build windows

package cmd

import (
	"fmt"
	"net"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"golang.zx2c4.com/wireguard/tun"
)

var longDescription = "Expose Warp as a native TUN device that accepts any IP traffic." +
	" Requires wintun.dll and administrator rights."

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
		err = internal.SetIPv4Address(t.name, config.AppConfig.IPv4, "255.255.255.255")
		if err != nil {
			return nil, fmt.Errorf("failed to set IPv4 address: %v", err)
		}
		if err := internal.SetIPv4Peer(t.name, derivePeerIPv4(config.AppConfig.IPv4)); err != nil {
			return nil, fmt.Errorf("failed to set IPv4 peer: %v", err)
		}

		err = internal.SetIPv4MTU(t.name, t.mtu)
		if err != nil {
			return nil, fmt.Errorf("failed to set IPv4 MTU: %v", err)
		}
	}

	if t.ipv6 {
		err = internal.SetIPv6Address(t.name, config.AppConfig.IPv6, "128")
		if err != nil {
			return nil, fmt.Errorf("failed to set IPv6 address: %v", err)
		}
		if err := internal.SetIPv6Peer(t.name, peerIPv6); err != nil {
			return nil, fmt.Errorf("failed to set IPv6 peer: %v", err)
		}

		err = internal.SetIPv6MTU(t.name, t.mtu)
		if err != nil {
			return nil, fmt.Errorf("failed to set IPv6 MTU: %v", err)
		}
	}

	return api.NewNetstackAdapter(dev), nil
}

const peerIPv6 = "fe80::1"

func derivePeerIPv4(localIP string) string {
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
