//go:build windows

package cmd

import (
	"net/netip"
	"testing"

	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func TestWindowsEndpointRouteSelection(t *testing.T) {
	for _, tc := range []struct {
		name, target, catchAll, subnet, gateway, onLink string
	}{
		{"IPv4", "192.0.2.23", "0.0.0.0/0", "192.0.2.0/24", "198.51.100.1", "0.0.0.0"},
		{"IPv6", "2001:db8::23", "::/0", "2001:db8::/64", "fe80::1%7", "::"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := netip.MustParseAddr(tc.target)
			host := netip.PrefixFrom(target, target.BitLen())
			hop := netip.MustParseAddr(tc.gateway)
			onLink := netip.MustParseAddr(tc.onLink)
			def := netip.MustParsePrefix(tc.catchAll)
			iface := func(id winipcfg.LUID, metric uint32, connected bool) winipcfg.MibIPInterfaceRow {
				return winipcfg.MibIPInterfaceRow{InterfaceLUID: id, Metric: metric, Connected: connected}
			}
			route := func(id winipcfg.LUID, dst netip.Prefix, hop netip.Addr, metric uint32) winipcfg.MibIPforwardRow2 {
				r := winipcfg.MibIPforwardRow2{InterfaceLUID: id, InterfaceIndex: uint32(id), Metric: metric}
				if err := r.DestinationPrefix.SetPrefix(dst); err != nil {
					t.Fatal(err)
				}
				if err := r.NextHop.SetAddr(hop); err != nil {
					t.Fatal(err)
				}
				return r
			}
			const tun = 1
			ifaces := []winipcfg.MibIPInterfaceRow{iface(tun, 0, true), iface(2, 10, false), iface(3, 50, true), iface(7, 1, true)}
			bypass := &windowsRoute{luid: 3, destination: host, nextHop: hop}
			routes := []winipcfg.MibIPforwardRow2{
				route(tun, def, onLink, 0),
				route(2, host, onLink, 0),           // disconnected
				route(3, host, hop.WithZone(""), 0), // old bypass, scope may not be reported
				route(3, def, hop, 1),
				route(7, def, hop, 20),
			}
			check := func(want winipcfg.LUID) *winipcfg.MibIPforwardRow2 {
				t.Helper()
				r := bestWindowsEndpointRoute(target, tun, bypass, routes, ifaces)
				if r == nil || r.InterfaceLUID != want {
					t.Fatalf("best route = %+v, want LUID %d", r, want)
				}
				return r
			}
			if got := check(7).NextHop.Addr(); got != hop {
				t.Fatalf("next hop = %s, want %s (including IPv6 scope)", got, hop)
			}
			routes = append(routes, route(3, netip.MustParsePrefix(tc.subnet), onLink, 100))
			if got := check(3).NextHop.Addr(); got != onLink {
				t.Fatalf("on-link next hop = %s, want %s", got, onLink)
			}
			// Do not ignore users' pre-existing host routes.
			routes = append(routes, route(7, host, hop, 300))
			check(7)
			ifaces = ifaces[:2]
			if r := bestWindowsEndpointRoute(target, tun, bypass, routes, ifaces); r != nil {
				t.Fatalf("found a route through Wintun or a disconnected link: %+v", r)
			}
		})
	}
}
