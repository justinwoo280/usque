//go:build windows

package cmd

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"os/exec"
	"strings"

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
	cfg            AutoRouteConfig
	luid           winipcfg.LUID
	changeCallback *winipcfg.InterfaceChangeCallback
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
	m.luid = winipcfg.LUID(iface.Index)

	gw, gwIface, err := findDefaultGateway()
	if err != nil {
		log.Printf("Warning: failed to find default gateway: %v (endpoint bypass may not work)", err)
	}

	if m.cfg.EndpointIP != nil && gw != "" {
		if err := addEndpointBypass(m.cfg.EndpointIP, gw, gwIface); err != nil {
			log.Printf("Warning: endpoint bypass failed: %v", err)
		} else {
			log.Printf("Endpoint bypass: %s via %s", m.cfg.EndpointIP, gw)
		}
	}

	if err := m.setupRoutes(); err != nil {
		return fmt.Errorf("setup routes: %w", err)
	}

	if err := m.setupDNS(); err != nil {
		log.Printf("Warning: DNS setup failed: %v", err)
	}

	if err := flushResolverCache(); err != nil {
		log.Printf("Warning: failed to flush DNS cache: %v", err)
	}

	log.Printf("Auto-route enabled (Windows): dns=%d servers", len(m.cfg.DNSServers))
	return nil
}

func (m *windowsRouteManager) Cleanup() error {
	if m.changeCallback != nil {
		if err := m.changeCallback.Unregister(); err != nil {
			log.Printf("Warning: failed to unregister interface change callback: %v", err)
		}
		m.changeCallback = nil
	}

	if m.cfg.EndpointIP != nil {
		mask := "255.255.255.255"
		if m.cfg.EndpointIP.To4() == nil {
			mask = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
		}
		_ = exec.Command("route", "delete", m.cfg.EndpointIP.String(), "mask", mask).Run()
	}

	if m.cfg.EnableIPv4 {
		_ = m.luid.FlushRoutes(windows.AF_INET)
	}
	if m.cfg.EnableIPv6 {
		_ = m.luid.FlushRoutes(windows.AF_INET6)
	}

	if err := flushResolverCache(); err != nil {
		log.Printf("Warning: failed to flush DNS cache: %v", err)
	}
	return nil
}

func (m *windowsRouteManager) SetInterfaceChangeCallback(cb func()) {
	if m.changeCallback != nil {
		_ = m.changeCallback.Unregister()
		m.changeCallback = nil
	}
	reg, err := winipcfg.RegisterInterfaceChangeCallback(func(_ winipcfg.MibNotificationType, _ *winipcfg.MibIPInterfaceRow) {
		cb()
	})
	if err != nil {
		log.Printf("Warning: failed to register interface change callback: %v", err)
		return
	}
	m.changeCallback = reg
	log.Println("Interface change callback registered")
}

func findDefaultGateway() (string, string, error) {
	routes, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return "", "", fmt.Errorf("get routes: %w", err)
	}

	for _, route := range routes {
		if route.DestinationPrefix.Prefix().Bits() == 0 &&
			route.DestinationPrefix.Prefix().Addr().Is4() {
			nextHop := route.NextHop.Addr().String()
			ifIdx := route.InterfaceIndex

			ifaces, err := net.Interfaces()
			if err != nil {
				return nextHop, "", nil
			}
			for _, iface := range ifaces {
				if iface.Index == int(ifIdx) {
					return nextHop, iface.Name, nil
				}
			}
			return nextHop, "", nil
		}
	}

	return "", "", fmt.Errorf("no default route found")
}

func addEndpointBypass(endpointIP net.IP, gateway, gwIface string) error {
	mask := "255.255.255.255"
	if endpointIP.To4() == nil {
		mask = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
	}

	args := []string{"add", endpointIP.String(), "mask", mask, gateway, "metric", "1"}
	if gwIface != "" {
		iface, err := net.InterfaceByName(gwIface)
		if err == nil {
			args = append(args, "if", fmt.Sprintf("%d", iface.Index))
		}
	}

	out, err := exec.Command("route", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("route add: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

func (m *windowsRouteManager) setupRoutes() error {
	var routes []winipcfg.RouteData

	if m.cfg.EnableIPv4 {
		routes = append(routes, winipcfg.RouteData{
			Destination: netip.MustParsePrefix("0.0.0.0/0"),
			NextHop:     netip.IPv4Unspecified(),
			Metric:      0,
		})
	}

	if m.cfg.EnableIPv6 {
		routes = append(routes, winipcfg.RouteData{
			Destination: netip.MustParsePrefix("::/0"),
			NextHop:     netip.IPv6Unspecified(),
			Metric:      0,
		})
	}

	if len(routes) > 0 {
		routePtrs := make([]*winipcfg.RouteData, len(routes))
		for i := range routes {
			routePtrs[i] = &routes[i]
		}
		if err := m.luid.SetRoutes(routePtrs); err != nil {
			return fmt.Errorf("set default routes: %w", err)
		}
	}

	return nil
}

func (m *windowsRouteManager) setupDNS() error {
	if len(m.cfg.DNSServers) == 0 {
		return nil
	}

	var dns4, dns6 []netip.Addr
	for _, dns := range m.cfg.DNSServers {
		if dns.To4() != nil {
			dns4 = append(dns4, netip.MustParseAddr(dns.String()))
		} else {
			dns6 = append(dns6, netip.MustParseAddr(dns.String()))
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
