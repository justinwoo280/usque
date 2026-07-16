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

	t.luid = wAdapter.LUID()
	luid := winipcfg.LUID(t.luid)

	// Assign an address for BOTH families. Enabled stacks get their real WARP
	// address; a disabled stack gets a placeholder from a reserved range so that
	// its default route (added by the route manager) is installable and its
	// traffic is pulled into the TUN — where the engine black-holes it — instead
	// of leaking out the physical NIC. The placeholder never sources real
	// traffic because the engine drops the disabled family at the tunnel ingress.
	var prefixes []netip.Prefix
	if t.ipv4 {
		prefixes = append(prefixes, netip.PrefixFrom(netip.MustParseAddr(t.account.IPv4), 32))
	} else {
		// TEST-NET-1 (RFC 5737): 192.0.2.0/24, guaranteed non-routable.
		prefixes = append(prefixes, netip.PrefixFrom(netip.MustParseAddr("192.0.2.1"), 32))
	}
	if t.ipv6 {
		prefixes = append(prefixes, netip.PrefixFrom(netip.MustParseAddr(t.account.IPv6), 128))
	} else {
		// Documentation prefix (RFC 3849): 2001:db8::/32, guaranteed non-routable.
		prefixes = append(prefixes, netip.PrefixFrom(netip.MustParseAddr("2001:db8::1"), 128))
	}
	if err := luid.SetIPAddresses(prefixes); err != nil {
		_ = wAdapter.Close()
		return nil, fmt.Errorf("set IP addresses: %w", err)
	}

	// Configure BOTH address families' interface parameters. Both now carry an
	// address (real or placeholder) and both default routes point at the TUN,
	// so both interfaces must be set up for routing to install cleanly. The
	// disabled family only ever black-holes traffic (dropped by the engine).
	{
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

	{
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
