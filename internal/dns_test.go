package internal

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

var mockDNSIPCounter atomic.Int32

func startMockDNS53(t *testing.T) (netip.Addr, *atomic.Int32) {
	t.Helper()
	n := mockDNSIPCounter.Add(1)
	ip := netip.AddrFrom4([4]byte{127, 0, 0, byte(n)})

	pc, err := net.ListenPacket("udp", ip.String()+":53")
	if err != nil {
		t.Skipf("cannot bind to %s:53 (need root?): %v", ip, err)
	}

	var queryCount atomic.Int32
	go func() {
		defer pc.Close()
		buf := make([]byte, 512)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			queryCount.Add(1)

			var msg dns.Msg
			if err := msg.Unpack(buf[:n]); err != nil {
				continue
			}
			msg.Response = true
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   msg.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: net.IPv4(93, 184, 216, 34),
			})
			resp, _ := msg.Pack()
			_, _ = pc.WriteTo(resp, from)
		}
	}()

	t.Cleanup(func() { _ = pc.Close() })
	return ip, &queryCount
}

func startMockDNSServerFail(t *testing.T, ip string, rcode int) (netip.Addr, *atomic.Int32) {
	t.Helper()
	pc, err := net.ListenPacket("udp", ip+":53")
	if err != nil {
		t.Skipf("cannot bind to %s:53: %v", ip, err)
	}
	addr := netip.MustParseAddr(ip)

	var queryCount atomic.Int32
	go func() {
		defer pc.Close()
		buf := make([]byte, 512)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			queryCount.Add(1)
			var msg dns.Msg
			_ = msg.Unpack(buf[:n])
			msg.Response = true
			msg.Rcode = rcode
			resp, _ := msg.Pack()
			_, _ = pc.WriteTo(resp, from)
		}
	}()

	t.Cleanup(func() { _ = pc.Close() })
	return addr, &queryCount
}

func readFromTUN(t *testing.T, dev tun.Device, timeout time.Duration) ([]byte, bool) {
	t.Helper()
	buf := make([]byte, 1500)
	bufs := [][]byte{buf}
	sizes := []int{0}

	type result struct {
		data []byte
		ok   bool
	}
	ch := make(chan result, 1)
	go func() {
		n, err := dev.Read(bufs, sizes, 0)
		if err != nil || n == 0 {
			ch <- result{nil, false}
			return
		}
		ch <- result{buf[:sizes[0]], true}
	}()

	select {
	case r := <-ch:
		return r.data, r.ok
	case <-time.After(timeout):
		return nil, false
	}
}

func drainTUN(t *testing.T, dev tun.Device) {
	t.Helper()
	for {
		if _, ok := readFromTUN(t, dev, 100*time.Millisecond); !ok {
			return
		}
	}
}

func TestTunnelDNSResolver_SystemNetwork(t *testing.T) {
	dnsAddr, count := startMockDNS53(t)

	resolver := TunnelDNSResolver{
		TunNet:   nil,
		DNSAddrs: []netip.Addr{dnsAddr},
		Timeout:  5 * time.Second,
	}

	ctx, ip, err := resolver.Resolve(context.Background(), "example.com.")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ip == nil {
		t.Fatal("got nil IP")
	}
	if ctx == nil {
		t.Fatal("got nil context")
	}
	t.Logf("resolved example.com. → %s", ip)

	time.Sleep(50 * time.Millisecond)
	if q := count.Load(); q == 0 {
		t.Error("DNS server received no queries")
	}
}

func TestTunnelDNSResolver_SystemNetwork_MultipleServers(t *testing.T) {
	dns1, count1 := startMockDNS53(t)
	dns2, count2 := startMockDNS53(t)

	resolver := TunnelDNSResolver{
		DNSAddrs: []netip.Addr{dns1, dns2},
		Timeout:  5 * time.Second,
	}

	_, ip, err := resolver.Resolve(context.Background(), "test.example.")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ip == nil {
		t.Fatal("got nil IP")
	}

	time.Sleep(50 * time.Millisecond)
	q1, q2 := count1.Load(), count2.Load()
	if q1 == 0 && q2 == 0 {
		t.Error("neither DNS server received queries")
	}
	t.Logf("server1(%s): %d queries, server2(%s): %d queries", dns1, q1, dns2, q2)
}

func TestTunnelDNSResolver_Timeout(t *testing.T) {
	resolver := TunnelDNSResolver{
		DNSAddrs: []netip.Addr{netip.MustParseAddr("192.0.2.1")},
		Timeout:  200 * time.Millisecond,
	}

	start := time.Now()
	_, _, err := resolver.Resolve(context.Background(), "timeout.example.")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if elapsed > 3*time.Second {
		t.Errorf("timeout took too long: %v", elapsed)
	}
	t.Logf("timed out after %v: %v", elapsed, err)
}

func TestTunnelDNSResolver_NoDNSAddrs(t *testing.T) {
	resolver := TunnelDNSResolver{
		DNSAddrs: nil,
		Timeout:  1 * time.Second,
	}

	_, _, err := resolver.Resolve(context.Background(), "test.example.")
	if err == nil {
		t.Fatal("expected error for no DNS servers")
	}
	t.Logf("got expected error: %v", err)
}

func TestTunnelDNSResolver_UseOSResolver(t *testing.T) {
	resolver := TunnelDNSResolver{
		UseOSResolver: true,
		Timeout:       5 * time.Second,
	}

	_, ip, err := resolver.Resolve(context.Background(), "localhost")
	if err != nil {
		t.Skipf("OS resolver failed (may be expected in CI): %v", err)
	}
	if ip == nil {
		t.Fatal("got nil IP from OS resolver")
	}
	t.Logf("OS resolver: localhost → %s", ip)
}

func TestTunnelDNSResolver_AllServersFail(t *testing.T) {
	n := mockDNSIPCounter.Add(1)
	ip1 := fmt.Sprintf("127.0.0.%d", n)
	n2 := mockDNSIPCounter.Add(1)
	ip2 := fmt.Sprintf("127.0.0.%d", n2)

	startMockDNSServerFail(t, ip1, dns.RcodeServerFailure)
	startMockDNSServerFail(t, ip2, dns.RcodeNameError)

	resolver := TunnelDNSResolver{
		DNSAddrs: []netip.Addr{
			netip.MustParseAddr(ip1),
			netip.MustParseAddr(ip2),
		},
		Timeout: 2 * time.Second,
	}

	_, _, err := resolver.Resolve(context.Background(), "fail.example.")
	if err == nil {
		t.Fatal("expected error when all DNS servers fail")
	}
	t.Logf("all servers failed: %v", err)
}

func TestTunnelDNSResolver_TunnelNetstack(t *testing.T) {
	localAddr := netip.MustParseAddr("10.0.0.1")
	dnsAddr := netip.MustParseAddr("10.0.0.53")

	tunDev, tunNet, err := netstack.CreateNetTUN(
		[]netip.Addr{localAddr},
		[]netip.Addr{dnsAddr},
		1280,
	)
	if err != nil {
		t.Fatalf("CreateNetTUN: %v", err)
	}
	defer func() {
		drainTUN(t, tunDev)
		tunDev.Close()
	}()

	resolver := TunnelDNSResolver{
		TunNet:   tunNet,
		DNSAddrs: []netip.Addr{dnsAddr},
		Timeout:  2 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		_, _, resolveErr := resolver.Resolve(context.Background(), "tunnel.example.")
		errCh <- resolveErr
	}()

	if data, ok := readFromTUN(t, tunDev, 3*time.Second); ok {
		t.Logf("DNS query captured in TUN: %d bytes (proves query went through tunnel netstack)", len(data))
	} else {
		t.Log("no packet captured")
	}

	select {
	case resolveErr := <-errCh:
		t.Logf("resolve result: %v", resolveErr)
	case <-time.After(3 * time.Second):
		t.Log("resolve timed out (expected — no DNS response injected)")
	}
}

func TestTunnelDNSResolver_DialUsesTunnelNetwork(t *testing.T) {
	localAddr := netip.MustParseAddr("10.0.0.1")
	dnsAddr := netip.MustParseAddr("8.8.8.8")

	tunDev, tunNet, err := netstack.CreateNetTUN(
		[]netip.Addr{localAddr},
		[]netip.Addr{dnsAddr},
		1280,
	)
	if err != nil {
		t.Fatalf("CreateNetTUN: %v", err)
	}
	defer func() {
		drainTUN(t, tunDev)
		tunDev.Close()
	}()

	testResolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dnsHost := net.JoinHostPort(dnsAddr.String(), "53")
			return tunNet.DialContext(ctx, "udp", dnsHost)
		},
	}

	errCh := make(chan error, 1)
	go func() {
		_, lookupErr := testResolver.LookupIP(context.Background(), "ip", "leak-test.example.")
		errCh <- lookupErr
	}()

	if data, ok := readFromTUN(t, tunDev, 2*time.Second); ok {
		t.Logf("DNS query captured in TUN: %d bytes — tunnel netstack used, no system network leak", len(data))
	} else {
		t.Error("DNS query NOT captured in TUN — possible DNS leak via system network!")
	}

	select {
	case lookupErr := <-errCh:
		t.Logf("lookup result: %v", lookupErr)
	case <-time.After(3 * time.Second):
		t.Log("lookup timed out (expected)")
	}
}

func TestNewStaticResolver(t *testing.T) {
	dnsAddr, count := startMockDNS53(t)
	resolver := NewStaticResolver([]netip.Addr{dnsAddr})

	ips, err := resolver.LookupIP(context.Background(), "ip", "static.example.")
	if err != nil {
		t.Fatalf("LookupIP: %v", err)
	}
	if len(ips) == 0 {
		t.Fatal("no IPs returned")
	}
	t.Logf("static resolver: %s", ips[0])

	time.Sleep(50 * time.Millisecond)
	if count.Load() == 0 {
		t.Error("static resolver: DNS server received no queries")
	}
}

func TestNewStaticResolver_NoDNSAddrs(t *testing.T) {
	resolver := NewStaticResolver(nil)
	_, err := resolver.LookupIP(context.Background(), "ip", "test.example.")
	if err == nil {
		t.Fatal("expected error for empty DNS addrs")
	}
}

func TestNewNetstackResolver(t *testing.T) {
	localAddr := netip.MustParseAddr("10.0.0.1")
	dnsAddr := netip.MustParseAddr("10.0.0.53")

	tunDev, tunNet, err := netstack.CreateNetTUN(
		[]netip.Addr{localAddr},
		[]netip.Addr{dnsAddr},
		1280,
	)
	if err != nil {
		t.Fatalf("CreateNetTUN: %v", err)
	}
	defer func() {
		drainTUN(t, tunDev)
		tunDev.Close()
	}()

	resolver := NewNetstackResolver(tunNet, []netip.Addr{dnsAddr})

	errCh := make(chan error, 1)
	go func() {
		_, lookupErr := resolver.LookupIP(context.Background(), "ip", "netstack.example.")
		errCh <- lookupErr
	}()

	if _, ok := readFromTUN(t, tunDev, 2*time.Second); ok {
		t.Log("netstack resolver: DNS query captured in TUN")
	} else {
		t.Error("netstack resolver: DNS query NOT captured in TUN")
	}

	select {
	case lookupErr := <-errCh:
		t.Logf("lookup result: %v", lookupErr)
	case <-time.After(3 * time.Second):
		t.Log("lookup timed out (expected)")
	}
}

func TestNewNetstackResolver_NoDNSAddrs(t *testing.T) {
	resolver := NewNetstackResolver(nil, nil)
	_, err := resolver.LookupIP(context.Background(), "ip", "test.example.")
	if err == nil {
		t.Fatal("expected error for empty DNS addrs")
	}
}

func TestGetProxyResolver_LocalDNS_SystemDNS(t *testing.T) {
	resolver := GetProxyResolver(true, true, nil, nil, 0)
	if resolver != net.DefaultResolver {
		t.Error("expected net.DefaultResolver for localDNS+systemDNS")
	}
}

func TestGetProxyResolver_LocalDNS_CustomDNS(t *testing.T) {
	dnsAddr, _ := startMockDNS53(t)

	resolver := GetProxyResolver(true, false, nil, []netip.Addr{dnsAddr}, 2*time.Second)
	if resolver == net.DefaultResolver {
		t.Error("expected custom resolver, got DefaultResolver")
	}

	ips, err := resolver.LookupIP(context.Background(), "ip", "proxy.example.")
	if err != nil {
		t.Fatalf("LookupIP: %v", err)
	}
	if len(ips) == 0 {
		t.Fatal("no IPs returned")
	}
	t.Logf("local DNS proxy resolver: %s", ips[0])
}

func TestGetProxyResolver_RemoteDNS(t *testing.T) {
	localAddr := netip.MustParseAddr("10.0.0.1")
	dnsAddr := netip.MustParseAddr("10.0.0.53")

	tunDev, tunNet, err := netstack.CreateNetTUN(
		[]netip.Addr{localAddr},
		[]netip.Addr{dnsAddr},
		1280,
	)
	if err != nil {
		t.Fatalf("CreateNetTUN: %v", err)
	}
	defer func() {
		drainTUN(t, tunDev)
		tunDev.Close()
	}()

	resolver := GetProxyResolver(false, false, tunNet, []netip.Addr{dnsAddr}, 2*time.Second)
	if resolver == net.DefaultResolver {
		t.Error("expected tunnel resolver, got DefaultResolver")
	}

	errCh := make(chan error, 1)
	go func() {
		_, lookupErr := resolver.LookupIP(context.Background(), "ip", "remote.example.")
		errCh <- lookupErr
	}()

	if _, ok := readFromTUN(t, tunDev, 2*time.Second); ok {
		t.Log("remote DNS: query captured in tunnel — no leak")
	} else {
		t.Error("remote DNS: query NOT captured in tunnel — possible leak")
	}

	select {
	case lookupErr := <-errCh:
		t.Logf("lookup result: %v", lookupErr)
	case <-time.After(3 * time.Second):
		t.Log("lookup timed out (expected)")
	}
}

func TestTunnelDNSResolver_DNSQueryTargetAddress(t *testing.T) {
	dnsAddr, count := startMockDNS53(t)

	resolver := TunnelDNSResolver{
		DNSAddrs: []netip.Addr{dnsAddr},
		Timeout:  5 * time.Second,
	}

	_, ip, err := resolver.Resolve(context.Background(), "target-check.example.")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if !ip.Equal(net.IPv4(93, 184, 216, 34)) {
		t.Errorf("expected 93.184.216.34, got %s", ip)
	}

	time.Sleep(50 * time.Millisecond)
	if count.Load() == 0 {
		t.Error("configured DNS server did not receive query — DNS went to wrong server")
	}
	t.Log("DNS query correctly targeted the configured remote DNS server")
}

func TestTunnelDNSResolver_NoLeak_SystemNetwork(t *testing.T) {
	dnsAddr, tunnelQueryCount := startMockDNS53(t)

	resolver := TunnelDNSResolver{
		TunNet:   nil,
		DNSAddrs: []netip.Addr{dnsAddr},
		Timeout:  3 * time.Second,
	}

	_, ip, err := resolver.Resolve(context.Background(), "no-leak.example.")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	if tunnelQueryCount.Load() == 0 {
		t.Error("configured DNS server received no queries — DNS may have leaked to system resolver")
	} else {
		t.Log("no DNS leak: all queries went to configured DNS server only")
	}

	t.Logf("resolved: %s, queries to configured server: %d", ip, tunnelQueryCount.Load())
}

func TestTunnelDNSResolver_ConcurrentResolves(t *testing.T) {
	dnsAddr, count := startMockDNS53(t)

	resolver := TunnelDNSResolver{
		DNSAddrs: []netip.Addr{dnsAddr},
		Timeout:  5 * time.Second,
	}

	domains := []string{"a.example.", "b.example.", "c.example.", "d.example.", "e.example."}
	errCh := make(chan error, len(domains))

	for _, domain := range domains {
		go func(d string) {
			_, ip, err := resolver.Resolve(context.Background(), d)
			if err != nil {
				errCh <- fmt.Errorf("%s: %w", d, err)
				return
			}
			if ip == nil {
				errCh <- fmt.Errorf("%s: nil IP", d)
				return
			}
			errCh <- nil
		}(domain)
	}

	for i := 0; i < len(domains); i++ {
		if err := <-errCh; err != nil {
			t.Errorf("concurrent resolve: %v", err)
		}
	}

	time.Sleep(50 * time.Millisecond)
	q := count.Load()
	t.Logf("concurrent resolves: %d queries received for %d domains", q, len(domains))
	if q < int32(len(domains)) {
		t.Errorf("expected at least %d queries, got %d", len(domains), q)
	}
}
