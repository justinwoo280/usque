//go:build linux

package cmd

import (
	"fmt"
	"log"
	"net"

	"github.com/Diniboy1123/usque/api"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
)

func (t *tunDevice) create() (api.TunnelDevice, error) {
	if t.tunFd > 0 {
		log.Printf("Using pre-existing TUN fd: %d (Android VpnService mode)", t.tunFd)
		if t.name == "" {
			t.name = "tun-android"
		}
		return api.NewFdAdapter(t.tunFd), nil
	}

	platformSpecificParams := water.PlatformSpecificParams{
		Name:    t.name,
		Persist: t.persist,
	}

	dev, err := water.New(water.Config{DeviceType: water.TUN, PlatformSpecificParams: platformSpecificParams})
	if err != nil {
		return nil, err
	}

	t.name = dev.Name()

	if t.iproute2 {
		link, err := netlink.LinkByName(dev.Name())
		if err != nil {
			return nil, fmt.Errorf("failed to get link: %v", err)
		}

		if err := netlink.LinkSetMTU(link, t.mtu); err != nil {
			return nil, fmt.Errorf("failed to set MTU: %v", err)
		}
		if t.ipv4 {
			if err := netlink.AddrAdd(link, &netlink.Addr{
				IPNet: &net.IPNet{
					IP:   net.ParseIP(t.account.IPv4),
					Mask: net.CIDRMask(32, 32),
				}}); err != nil {
				return nil, fmt.Errorf("failed to add IPv4 address: %v", err)
			}
		}
		if t.ipv6 {
			if err := netlink.AddrAdd(link, &netlink.Addr{
				IPNet: &net.IPNet{
					IP:   net.ParseIP(t.account.IPv6),
					Mask: net.CIDRMask(128, 128),
				}}); err != nil {
				return nil, fmt.Errorf("failed to add IPv6 address: %v", err)
			}
		}
		if err := netlink.LinkSetUp(link); err != nil {
			return nil, fmt.Errorf("failed to set link up: %v", err)
		}
	} else {
		log.Println("Skipping IP address and link setup. You should set the link up manually.")
		log.Printf("Config has the following IP addresses: IPv4=%s IPv6=%s", t.account.IPv4, t.account.IPv6)
	}

	return api.NewWaterAdapter(dev), nil
}
