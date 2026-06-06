//go:build windows

package cmd

import (
	"fmt"
	"net/netip"

	"github.com/Diniboy1123/usque/api"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func (t *tunDevice) create() (api.TunnelDevice, error) {
	if t.name == "" {
		t.name = "usque"
	}

	wAdapter, err := api.NewWintunAdapter(t.name)
	if err != nil {
		return nil, err
	}

	luid := winipcfg.LUID(wAdapter.LUID())

	var prefixes []netip.Prefix
	if t.ipv4 {
		prefixes = append(prefixes, netip.PrefixFrom(netip.MustParseAddr(t.account.IPv4), 32))
	}
	if t.ipv6 {
		prefixes = append(prefixes, netip.PrefixFrom(netip.MustParseAddr(t.account.IPv6), 128))
	}
	if len(prefixes) > 0 {
		if err := luid.SetIPAddresses(prefixes); err != nil {
			_ = wAdapter.Close()
			return nil, fmt.Errorf("set IP addresses: %w", err)
		}
	}

	if t.ipv4 {
		ipif, err := luid.IPInterface(windows.AF_INET)
		if err != nil {
			_ = wAdapter.Close()
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
			_ = wAdapter.Close()
			return nil, fmt.Errorf("set IPv4 interface: %w", err)
		}
	}

	if t.ipv6 {
		ipif, err := luid.IPInterface(windows.AF_INET6)
		if err != nil {
			_ = wAdapter.Close()
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
			_ = wAdapter.Close()
			return nil, fmt.Errorf("set IPv6 interface: %w", err)
		}
	}

	return wAdapter, nil
}
