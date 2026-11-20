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

	// Disabled families are blocked by WFP, so don't assign them a dummy
	// address or try to divert them by default route.
	v4, err := windowsTUNAddress(t.account.IPv4, t.ipv4, 4)
	if err != nil {
		return nil, err
	}
	v6, err := windowsTUNAddress(t.account.IPv6, t.ipv6, 6)
	if err != nil {
		return nil, err
	}
	wAdapter, err := api.NewWintunAdapter(t.name)
	if err != nil {
		return nil, err
	}
	luid := winipcfg.LUID(wAdapter.LUID())
	if err := configureWintun(luid, t.mtu, []netip.Prefix{v4, v6}); err != nil {
		_ = wAdapter.Close()
		return nil, err
	}
	t.luid = uint64(luid)
	return wAdapter, nil
}

func windowsTUNAddress(value string, enabled bool, family int) (netip.Prefix, error) {
	if !enabled {
		return netip.Prefix{}, nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil || addr.Is4() != (family == 4) || addr.IsUnspecified() || addr.IsMulticast() || addr.Is4In6() || addr.Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("invalid WARP IPv%d tunnel address %q", family, value)
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

func configureWintun(luid winipcfg.LUID, mtu int, prefixes []netip.Prefix) error {
	addresses := make([]netip.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		if !prefix.IsValid() {
			continue
		}
		addresses = append(addresses, prefix)
		family := winipcfg.AddressFamily(windows.AF_INET6)
		if prefix.Addr().Is4() {
			family = windows.AF_INET
		}
		ipif, err := luid.IPInterface(family)
		if err != nil {
			return fmt.Errorf("get Wintun IP interface (family %d): %w", family, err)
		}
		ipif.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
		ipif.DadTransmits = 0
		ipif.ManagedAddressConfigurationSupported = false
		ipif.OtherStatefulConfigurationSupported = false
		ipif.NLMTU = uint32(mtu) // local link only, never lowered by tunnel PMTU
		ipif.UseAutomaticMetric = false
		ipif.Metric = 0
		if err := ipif.Set(); err != nil {
			return fmt.Errorf("set Wintun MTU %d (family %d): %w", mtu, family, err)
		}
		actual, err := luid.IPInterface(family)
		if err != nil {
			return fmt.Errorf("verify Wintun MTU (family %d): %w", family, err)
		}
		if actual.NLMTU != uint32(mtu) {
			return fmt.Errorf("Wintun did not apply MTU %d (family %d reports %d)", mtu, family, actual.NLMTU)
		}
	}
	if err := luid.SetIPAddresses(addresses); err != nil {
		return fmt.Errorf("set Wintun IP addresses: %w", err)
	}
	return nil
}
