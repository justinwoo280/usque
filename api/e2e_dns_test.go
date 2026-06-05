//go:build e2e

package api

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func createTunnelNetstack(t *testing.T) (*netstack.Net, func()) {
	t.Helper()

	localV4, err := netip.ParseAddr(config.AppConfig.IPv4)
	if err != nil {
		t.Fatalf("parse IPv4: %v", err)
	}
	localV6, err := netip.ParseAddr(config.AppConfig.IPv6)
	if err != nil {
		t.Fatalf("parse IPv6: %v", err)
	}

	dnsAddrs := []netip.Addr{
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("2606:4700:4700::1111"),
	}

	tunDev, tunNet, err := netstack.CreateNetTUN(
		[]netip.Addr{localV4, localV6},
		dnsAddrs,
		1280,
	)
	if err != nil {
		t.Fatalf("CreateNetTUN: %v", err)
	}

	var ipConn2 *connectip.Conn
	var cleanup func()
	for attempt := 1; attempt <= 3; attempt++ {
		var err2 error
		_, ipConn2, cleanup, err2 = dialTunnelErr(t, nil, internal.NoiseConfig{})
		if err2 == nil {
			break
		}
		t.Logf("tunnel dial attempt %d: %v", attempt, err2)
		time.Sleep(time.Second)
	}
	if ipConn2 == nil {
		t.Fatal("failed to establish tunnel after 3 attempts")
	}
	ipConn := ipConn2

	go func() {
		buf := make([]byte, 1500)
		for {
			bufs := [][]byte{buf}
			sizes := make([]int, 1)
			n, readErr := tunDev.Read(bufs, sizes, 0)
			if readErr != nil {
				return
			}
			if n > 0 && sizes[0] > 0 {
				_, _ = ipConn.WritePacket(buf[:sizes[0]])
			}
		}
	}()

	go func() {
		buf := make([]byte, 1500)
		for {
			n, readErr := ipConn.ReadPacket(buf, true)
			if readErr != nil {
				return
			}
			if n > 0 {
				bufs := [][]byte{buf[:n]}
				_, _ = tunDev.Write(bufs, 0)
			}
		}
	}()

	fullCleanup := func() {
		cleanup()
		_ = tunDev.Close()
	}

	return tunNet, fullCleanup
}

func TestE2E_DNSResolveThroughTunnel(t *testing.T) {
	loadE2EConfig(t)

	tunNet, cleanup := createTunnelNetstack(t)
	defer cleanup()

	dnsAddrs := []netip.Addr{
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("2606:4700:4700::1111"),
	}

	resolver := &internal.TunnelDNSResolver{
		TunNet:   tunNet,
		DNSAddrs: dnsAddrs,
		Timeout:  10 * time.Second,
	}

	_, ip, err := resolver.Resolve(context.Background(), "cloudflare.com.")
	if err != nil {
		t.Fatalf("Resolve through tunnel: %v", err)
	}
	if ip == nil {
		t.Fatal("got nil IP")
	}
	t.Logf("cloudflare.com resolved via tunnel: %s", ip)
}

func TestE2E_DNSResolve_MultipleDomains(t *testing.T) {
	loadE2EConfig(t)

	tunNet, cleanup := createTunnelNetstack(t)
	defer cleanup()

	dnsAddrs := []netip.Addr{
		netip.MustParseAddr("1.1.1.1"),
	}

	resolver := &internal.TunnelDNSResolver{
		TunNet:   tunNet,
		DNSAddrs: dnsAddrs,
		Timeout:  10 * time.Second,
	}

	domains := []string{
		"cloudflare.com.",
		"google.com.",
		"github.com.",
		"example.com.",
	}

	for _, domain := range domains {
		_, ip, err := resolver.Resolve(context.Background(), domain)
		if err != nil {
			t.Errorf("resolve %s through tunnel: %v", domain, err)
			continue
		}
		t.Logf("%s → %s (via MASQUE tunnel)", domain, ip)
	}
}

func TestE2E_DNSNoLeak_TunnelNetstackUsed(t *testing.T) {
	loadE2EConfig(t)

	tunNet, cleanup := createTunnelNetstack(t)
	defer cleanup()

	dnsAddrs := []netip.Addr{
		netip.MustParseAddr("8.8.8.8"),
	}

	var tunnelDialCalled bool
	testResolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			tunnelDialCalled = true
			dnsHost := net.JoinHostPort(dnsAddrs[0].String(), "53")
			return tunNet.DialContext(ctx, "udp", dnsHost)
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ips, err := testResolver.LookupIP(ctx, "ip", "dnsleaktest.com")
	if err != nil {
		t.Fatalf("LookupIP through tunnel: %v", err)
	}
	if len(ips) == 0 {
		t.Fatal("no IPs returned")
	}

	if !tunnelDialCalled {
		t.Error("DNS LEAK: tunnel dial was NOT called — DNS may have used system network")
	} else {
		t.Logf("no leak: tunnel dial used, resolved %s → %s", "dnsleaktest.com", ips[0])
	}
}

func TestE2E_DNSResolve_CustomServer(t *testing.T) {
	loadE2EConfig(t)

	tunNet, cleanup := createTunnelNetstack(t)
	defer cleanup()

	customDNS := netip.MustParseAddr("8.8.8.8")
	resolver := &internal.TunnelDNSResolver{
		TunNet:   tunNet,
		DNSAddrs: []netip.Addr{customDNS},
		Timeout:  10 * time.Second,
	}

	_, ip, err := resolver.Resolve(context.Background(), "dns.google.")
	if err != nil {
		t.Fatalf("resolve via custom DNS 8.8.8.8 through tunnel: %v", err)
	}
	t.Logf("dns.google resolved via custom DNS (8.8.8.8) through tunnel: %s", ip)
}

func TestE2E_DNSNetstackResolver(t *testing.T) {
	loadE2EConfig(t)

	tunNet, cleanup := createTunnelNetstack(t)
	defer cleanup()

	dnsAddrs := []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	resolver := internal.NewNetstackResolver(tunNet, dnsAddrs)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ips, err := resolver.LookupIP(ctx, "ip", "one.one.one.one")
	if err != nil {
		t.Fatalf("netstack resolver through tunnel: %v", err)
	}
	t.Logf("NewNetstackResolver: one.one.one.one → %v (through MASQUE tunnel)", ips)
}
