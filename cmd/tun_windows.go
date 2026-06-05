//go:build windows

package cmd

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/Diniboy1123/usque/api"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
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

	iface, err := net.InterfaceByName(t.name)
	if err != nil {
		return nil, fmt.Errorf("find interface %s: %w", t.name, err)
	}
	luid := winipcfg.LUID(iface.Index)

	if t.ipv4 {
		v4Addr := netip.MustParseAddr(t.account.IPv4)
		if err := luid.SetIPAddresses([]netip.Prefix{
			netip.PrefixFrom(v4Addr, 32),
		}); err != nil {
			return nil, fmt.Errorf("set IPv4 address: %w", err)
		}
	}

	if t.ipv6 {
		v6Addr := netip.MustParseAddr(t.account.IPv6)
		if err := luid.SetIPAddresses([]netip.Prefix{
			netip.PrefixFrom(v6Addr, 128),
		}); err != nil {
			return nil, fmt.Errorf("set IPv6 address: %w", err)
		}
	}

	if t.ipv4 {
		ipif, err := luid.IPInterface(windows.AF_INET)
		if err != nil {
			return nil, fmt.Errorf("get IPv4 interface: %w", err)
		}
		ipif.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
		ipif.DadTransmits = 0
		ipif.ManagedAddressConfigurationSupported = false
		ipif.OtherStatefulConfigurationSupported = false
		ipif.NLMTU = uint32(t.mtu)
		ipif.UseAutomaticMetric = false
		ipif.Metric = 0
		if err := ipif.Set(); err != nil {
			return nil, fmt.Errorf("set IPv4 interface: %w", err)
		}
	}

	if t.ipv6 {
		ipif, err := luid.IPInterface(windows.AF_INET6)
		if err != nil {
			return nil, fmt.Errorf("get IPv6 interface: %w", err)
		}
		ipif.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
		ipif.DadTransmits = 0
		ipif.ManagedAddressConfigurationSupported = false
		ipif.OtherStatefulConfigurationSupported = false
		ipif.NLMTU = uint32(t.mtu)
		ipif.UseAutomaticMetric = false
		ipif.Metric = 0
		if err := ipif.Set(); err != nil {
			return nil, fmt.Errorf("set IPv6 interface: %w", err)
		}
	}

	return api.NewNetstackAdapter(dev), nil
}
