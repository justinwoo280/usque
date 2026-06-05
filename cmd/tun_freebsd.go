//go:build freebsd

package cmd

import (
	"fmt"
	"log"
	"net"
	"os/exec"

	"github.com/Diniboy1123/usque/api"
	"golang.zx2c4.com/wireguard/tun"
)

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
		localIP := t.account.IPv4
		peerIP := derivePeerIPv4FreeBSD(localIP)
		if err := ifconfigFreeBSD(t.name, "inet", localIP, peerIP); err != nil {
			return nil, fmt.Errorf("set IPv4 ptp: %w", err)
		}
		log.Printf("FreeBSD IPv4 ptp: %s -> %s", localIP, peerIP)
	}

	if t.ipv6 {
		localIP := t.account.IPv6
		peerIP := "fe80::1"
		if err := ifconfigFreeBSD(t.name, "inet6", localIP, peerIP, "prefixlen", "128"); err != nil {
			return nil, fmt.Errorf("set IPv6 ptp: %w", err)
		}
		log.Printf("FreeBSD IPv6 ptp: %s -> %s", localIP, peerIP)
	}

	if err := ifconfigFreeBSD(t.name, "up"); err != nil {
		return nil, fmt.Errorf("bring up: %w", err)
	}

	return api.NewNetstackAdapter(dev), nil
}

func derivePeerIPv4FreeBSD(localIP string) string {
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

func ifconfigFreeBSD(name string, args ...string) error {
	cmdArgs := append([]string{name}, args...)
	out, err := exec.Command("ifconfig", cmdArgs...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ifconfig %s: %s", cmdArgs, string(out))
	}
	return nil
}
