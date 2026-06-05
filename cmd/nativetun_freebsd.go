//go:build freebsd

package cmd

import (
	"fmt"
	"log"
	"net"
	"os/exec"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"golang.zx2c4.com/wireguard/tun"
)

var longDescription = "Expose Warp as a native TUN device that accepts any IP traffic." +
	" Requires root on FreeBSD."

func (t *tunDevice) create() (api.TunnelDevice, error) {
	if t.name == "" {
		t.name = "tun0"
	}

	dev, err := tun.CreateTUN(t.name, t.mtu)
	if err != nil {
		return nil, fmt.Errorf("create tun: %w", err)
	}

	t.name, err = dev.Name()
	if err != nil {
		return nil, fmt.Errorf("get tun name: %w", err)
	}

	if t.ipv4 {
		localIP := config.AppConfig.IPv4
		peerIP := derivePeerIPv4(localIP)
		if err := ifconfig(t.name, "inet", localIP, peerIP); err != nil {
			return nil, fmt.Errorf("set IPv4 ptp: %w", err)
		}
		log.Printf("FreeBSD IPv4 ptp: %s -> %s", localIP, peerIP)
	}

	if t.ipv6 {
		localIP := config.AppConfig.IPv6
		peerIP := "fe80::1"
		if err := ifconfig(t.name, "inet6", localIP, peerIP, "prefixlen", "128"); err != nil {
			return nil, fmt.Errorf("set IPv6 ptp: %w", err)
		}
		log.Printf("FreeBSD IPv6 ptp: %s -> %s", localIP, peerIP)
	}

	if err := ifconfig(t.name, "up"); err != nil {
		return nil, fmt.Errorf("bring up: %w", err)
	}

	return api.NewNetstackAdapter(dev), nil
}

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

func ifconfig(name string, args ...string) error {
	cmdArgs := append([]string{name}, args...)
	out, err := exec.Command("ifconfig", cmdArgs...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ifconfig %s: %s", cmdArgs, string(out))
	}
	return nil
}
