//go:build windows

package cmd

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"

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
	cfg      AutoRouteConfig
	luid     winipcfg.LUID
	defaults []windowsRoute

	mu     sync.Mutex // serializes endpoint selection with Cleanup
	bypass *windowsRoute
	closed bool
}

type windowsRoute struct {
	luid        winipcfg.LUID
	destination netip.Prefix
	nextHop     netip.Addr
}

func (r windowsRoute) matches(luid winipcfg.LUID, destination netip.Prefix, nextHop netip.Addr) bool {
	// Windows can report a link-local gateway with or without a scope ID.
	// The interface LUID already distinguishes the scope for this route.
	return r.luid == luid && r.destination == destination && r.nextHop.WithZone("") == nextHop.WithZone("")
}

func (r windowsRoute) remove() error {
	err := r.luid.DeleteRoute(r.destination, r.nextHop)
	if errors.Is(err, windows.ERROR_NOT_FOUND) {
		return nil // Windows may have already removed the route on link loss.
	}
	if err != nil {
		return fmt.Errorf("delete route %s via %s: %w", r.destination, r.nextHop, err)
	}
	return nil
}

func newRouteManager(cfg AutoRouteConfig) RouteManager {
	cfg.applyDefaults()
	return &windowsRouteManager{cfg: cfg}
}

func (m *windowsRouteManager) Setup() error {
	if m.cfg.LUID != 0 {
		m.luid = winipcfg.LUID(m.cfg.LUID)
	} else {
		iface, err := net.InterfaceByName(m.cfg.InterfaceName)
		if err != nil {
			return fmt.Errorf("find interface %s: %w", m.cfg.InterfaceName, err)
		}
		m.luid, err = winipcfg.LUIDFromIndex(uint32(iface.Index))
		if err != nil {
			return fmt.Errorf("get LUID for %s: %w", m.cfg.InterfaceName, err)
		}
	}

	// Resolve and install the endpoint host route before capturing either
	// default route. Failing here is safer than dialing back into Wintun.
	if _, err := m.OutboundInterfaceIndex(); err != nil {
		return err
	}

	if err := m.setupRoutes(); err != nil {
		return errors.Join(fmt.Errorf("setup routes: %w", err), m.Cleanup())
	}

	if err := m.setupDNS(); err != nil {
		log.Printf("Warning: DNS setup failed: %v", err)
	}

	// Prevent DNS leaks via Windows smart multi-homed name resolution: install
	// WFP filters that block all port-53 traffic except to our tunnel DNS
	// servers. Setting DNS on the TUN interface alone is insufficient because
	// Windows queries every interface's DNS in parallel, and the physical NIC's
	// queries never enter the TUN (so the L3 hijack rewriter can't catch them).
	if len(m.cfg.DNSServers) > 0 {
		if err := enableDNSFirewall(m.cfg.DNSServers); err != nil {
			log.Printf("Warning: DNS leak prevention (WFP) failed: %v", err)
		} else {
			log.Printf("DNS leak prevention active (WFP): only %d server(s) permitted on port 53", len(m.cfg.DNSServers))
		}
	}

	if err := flushResolverCache(); err != nil {
		log.Printf("Warning: failed to flush DNS cache: %v", err)
	}

	log.Printf("Auto-route enabled (Windows): dns=%d servers", len(m.cfg.DNSServers))
	return nil
}

func (m *windowsRouteManager) Cleanup() error {
	// Tear down the WFP DNS-leak filters first so name resolution is restored
	// immediately, even if later route/DNS cleanup steps fail.
	disableDNSFirewall()

	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	var errs []error
	for _, route := range m.defaults {
		errs = append(errs, route.remove())
	}
	m.defaults = nil
	if m.bypass != nil {
		errs = append(errs, m.bypass.remove())
		m.bypass = nil
	}

	if err := flushResolverCache(); err != nil {
		log.Printf("Warning: failed to flush DNS cache: %v", err)
	}
	return errors.Join(errs...)
}

// Windows reselects egress on every dial instead of caching an interface name.
func (*windowsRouteManager) SetInterfaceChangeCallback(func()) {}

func (m *windowsRouteManager) OutboundInterfaceIndex() (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return 0, net.ErrClosed
	}
	addr, ok := netip.AddrFromSlice(m.cfg.EndpointIP)
	addr = addr.Unmap()
	if !ok || addr.IsUnspecified() {
		return 0, errors.New("Windows auto-route requires a WARP endpoint IP")
	}
	family := winipcfg.AddressFamily(windows.AF_INET6)
	if addr.Is4() {
		family = windows.AF_INET
	}
	routes, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		return 0, fmt.Errorf("get Windows routes for %s: %w", addr, err)
	}
	ifaces, err := winipcfg.GetIPInterfaceTable(family)
	if err != nil {
		return 0, fmt.Errorf("get Windows IP interfaces for %s: %w", addr, err)
	}
	row := bestWindowsEndpointRoute(addr, m.luid, m.bypass, routes, ifaces)
	if row == nil {
		return 0, fmt.Errorf("no Windows egress route to WARP endpoint %s outside Wintun", addr)
	}
	next := windowsRoute{row.InterfaceLUID, netip.PrefixFrom(addr, addr.BitLen()), row.NextHop.Addr()}
	var owned *windowsRoute
	sameBypass := m.bypass != nil && m.bypass.matches(next.luid, next.destination, next.nextHop)
	if row.DestinationPrefix.Prefix() != next.destination {
		if sameBypass && windowsRouteExists(next, routes) {
			owned = m.bypass
		} else if err := next.luid.AddRoute(next.destination, next.nextHop, row.Metric); err == nil {
			owned = &next
			log.Printf("Windows endpoint route: %s via %s (interface %d)", next.destination, next.nextHop, row.InterfaceIndex)
		} else if errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) || errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			if sameBypass {
				owned = m.bypass
			}
		} else {
			return 0, fmt.Errorf("add Windows endpoint route %s: %w", next.destination, err)
		}
	}
	if m.bypass != nil && !sameBypass {
		if err := m.bypass.remove(); err != nil {
			// Keep tracking the old route if the switch couldn't complete.
			// Only roll back a newly created route, not a user's host route.
			if owned != nil {
				return 0, errors.Join(err, owned.remove())
			}
			return 0, err
		}
	}
	m.bypass = owned
	return int(row.InterfaceIndex), nil
}

func windowsRouteExists(want windowsRoute, rows []winipcfg.MibIPforwardRow2) bool {
	for _, r := range rows {
		if want.matches(r.InterfaceLUID, r.DestinationPrefix.Prefix(), r.NextHop.Addr()) {
			return true
		}
	}
	return false
}

// Longest prefix wins, followed by route + interface metric. Ignore our own
// /32 or /128 so it doesn't pin reconnects to an old Wi-Fi/Ethernet route.
func bestWindowsEndpointRoute(target netip.Addr, tun winipcfg.LUID, bypass *windowsRoute, routes []winipcfg.MibIPforwardRow2, ifaces []winipcfg.MibIPInterfaceRow) *winipcfg.MibIPforwardRow2 {
	metrics := make(map[winipcfg.LUID]uint32, len(ifaces))
	for _, iface := range ifaces {
		if iface.Connected {
			metrics[iface.InterfaceLUID] = iface.Metric
		}
	}
	var best *winipcfg.MibIPforwardRow2
	bestBits := -1
	var bestMetric uint64
	for i := range routes {
		r := &routes[i]
		prefix, hop := r.DestinationPrefix.Prefix(), r.NextHop.Addr()
		metric, connected := metrics[r.InterfaceLUID]
		if !connected || r.InterfaceLUID == tun || r.InterfaceIndex == 0 || r.Loopback ||
			!prefix.Contains(target) || !hop.IsValid() || hop.BitLen() != target.BitLen() ||
			(bypass != nil && bypass.matches(r.InterfaceLUID, prefix, hop)) {
			continue
		}
		combined := uint64(metric) + uint64(r.Metric)
		if prefix.Bits() > bestBits || prefix.Bits() == bestBits && combined < bestMetric {
			best, bestBits, bestMetric = r, prefix.Bits(), combined
		}
	}
	return best
}

func (m *windowsRouteManager) setupRoutes() error {
	// A disabled family is dropped by WFP, not by route preference. Leave
	// that family's physical routes intact for the WARP outer transport.
	for _, ip := range windowsTUNDefaultRoutes(m.cfg.EnableIPv4, m.cfg.EnableIPv6) {
		if err := m.luid.AddRoute(ip, ip.Addr(), 0); err != nil {
			return fmt.Errorf("add Wintun default route %s: %w", ip, err)
		}
		m.defaults = append(m.defaults, windowsRoute{m.luid, ip, ip.Addr()})
	}

	return nil
}

func windowsTUNDefaultRoutes(ipv4, ipv6 bool) []netip.Prefix {
	var routes []netip.Prefix
	if ipv4 {
		routes = append(routes, netip.PrefixFrom(netip.IPv4Unspecified(), 0))
	}
	if ipv6 {
		routes = append(routes, netip.PrefixFrom(netip.IPv6Unspecified(), 0))
	}
	return routes
}

func (m *windowsRouteManager) setupDNS() error {
	if len(m.cfg.DNSServers) == 0 {
		return nil
	}

	var dns4, dns6 []netip.Addr
	for _, dns := range m.cfg.DNSServers {
		if addr, ok := netip.AddrFromSlice(dns); ok {
			addr = addr.Unmap()
			if addr.Is4() {
				dns4 = append(dns4, addr)
			} else {
				dns6 = append(dns6, addr)
			}
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
