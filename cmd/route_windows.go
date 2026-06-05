//go:build windows

package cmd

import (
	"fmt"
	"log"
	"net"
	"net/netip"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

var dnsapi = windows.NewLazySystemDLL("dnsapi.dll")

func flushResolverCache() error {
	proc := dnsapi.NewProc("DnsFlushResolverCache")
	r, _, err := proc.Call()
	if r == 0 {
		return err
	}
	return nil
}

type windowsRouteManager struct {
	cfg   AutoRouteConfig
	luid  winipcfg.LUID
	ifIdx int
}

func newRouteManager(cfg AutoRouteConfig) RouteManager {
	cfg.applyDefaults()
	return &windowsRouteManager{cfg: cfg}
}

func (m *windowsRouteManager) Setup() error {
	iface, err := net.InterfaceByName(m.cfg.InterfaceName)
	if err != nil {
		return fmt.Errorf("find interface %s: %w", m.cfg.InterfaceName, err)
	}
	m.ifIdx = iface.Index
	m.luid = winipcfg.LUID(iface.Index)

	physIdx, err := findPhysicalInterfaceIndex()
	if err != nil {
		return fmt.Errorf("find physical interface: %w", err)
	}
	m.cfg.PhysicalIfIndex = physIdx
	log.Printf("Physical interface index: %d (for QUIC socket binding)", physIdx)

	if err := m.setupRoutes(); err != nil {
		return fmt.Errorf("setup routes: %w", err)
	}
	if err := m.setupDNS(); err != nil {
		log.Printf("Warning: DNS setup failed: %v", err)
	}
	if err := m.setupInterface(); err != nil {
		return fmt.Errorf("setup interface: %w", err)
	}
	if err := flushResolverCache(); err != nil {
		log.Printf("Warning: failed to flush DNS cache: %v", err)
	}
	log.Println("Auto-route enabled (Windows): metric=0")
	return nil
}

func (m *windowsRouteManager) Cleanup() error {
	if err := m.cleanupRoutes(); err != nil {
		log.Printf("Warning: route cleanup failed: %v", err)
	}
	_ = flushResolverCache()
	return nil
}

func (m *windowsRouteManager) setupRoutes() error {
	// Default routes are already installed by internal.SetIPv4Peer / SetIPv6Peer
	// (netsh) when the Wintun adapter was brought up, with the peer gateway as
	// next-hop. Calling luid.SetRoutes with NextHop=0.0.0.0/:: on a Wintun
	// point-to-point adapter fails with "Element not found", so skip it here.
	return nil
}

func (m *windowsRouteManager) setupDNS() error {
	if len(m.cfg.DNSServers) == 0 {
		return nil
	}

	var dns4, dns6 []netip.Addr
	for _, dns := range m.cfg.DNSServers {
		addr, ok := netip.AddrFromSlice(dns)
		if !ok {
			continue
		}
		if dns.To4() != nil {
			dns4 = append(dns4, addr)
		} else {
			dns6 = append(dns6, addr)
		}
	}

	if m.cfg.EnableIPv4 && len(dns4) > 0 {
		if err := m.luid.SetDNS(windows.AF_INET, dns4, nil); err != nil {
			return fmt.Errorf("set IPv4 DNS: %w", err)
		}
	}
	if m.cfg.EnableIPv6 && len(dns6) > 0 {
		if err := m.luid.SetDNS(windows.AF_INET6, dns6, nil); err != nil {
			return fmt.Errorf("set IPv6 DNS: %w", err)
		}
	}
	return nil
}

func (m *windowsRouteManager) setupInterface() error {
	if m.cfg.EnableIPv4 {
		ipif, err := m.luid.IPInterface(windows.AF_INET)
		if err != nil {
			return fmt.Errorf("get IPv4 interface: %w", err)
		}
		ipif.ForwardingEnabled = true
		ipif.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
		ipif.DadTransmits = 0
		ipif.ManagedAddressConfigurationSupported = false
		ipif.OtherStatefulConfigurationSupported = false
		ipif.UseAutomaticMetric = false
		ipif.Metric = 0
		if err := ipif.Set(); err != nil {
			return fmt.Errorf("set IPv4 interface: %w", err)
		}
	}

	if m.cfg.EnableIPv6 {
		ipif, err := m.luid.IPInterface(windows.AF_INET6)
		if err != nil {
			return fmt.Errorf("get IPv6 interface: %w", err)
		}
		ipif.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
		ipif.DadTransmits = 0
		ipif.ManagedAddressConfigurationSupported = false
		ipif.OtherStatefulConfigurationSupported = false
		ipif.UseAutomaticMetric = false
		ipif.Metric = 0
		if err := ipif.Set(); err != nil {
			return fmt.Errorf("set IPv6 interface: %w", err)
		}
	}
	return nil
}

func (m *windowsRouteManager) cleanupRoutes() error {
	if m.cfg.EnableIPv4 {
		_ = m.luid.FlushRoutes(windows.AF_INET)
	}
	if m.cfg.EnableIPv6 {
		_ = m.luid.FlushRoutes(windows.AF_INET6)
	}
	return nil
}

func findPhysicalInterfaceIndex() (int, error) {
	routes, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return 0, fmt.Errorf("get IPv4 routes: %w", err)
	}
	for _, route := range routes {
		if route.DestinationPrefix.PrefixLength == 0 {
			return int(route.InterfaceIndex), nil
		}
	}
	return 0, fmt.Errorf("no default IPv4 route found")
}
