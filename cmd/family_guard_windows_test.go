//go:build windows

package cmd

import (
	"encoding/binary"
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/Diniboy1123/usque/config"
	"golang.org/x/sys/windows"
)

func TestWindowsIPv6OnlyFamilyGuard(t *testing.T) {
	warp := netip.MustParseAddr("192.0.2.9")
	native6 := netip.MustParseAddr("2001:db8::9")
	dns4 := netip.MustParseAddr("1.1.1.1")
	mapped := netip.AddrFrom16(warp.As16())
	var usque, other wtFwpByteBlob
	appID := &usque
	s := config.TunInboundSettings{IPv6: true}
	for _, mode := range []struct {
		name     string
		endpoint net.Addr
		protocol uint8
		port     uint16
		outer4   bool
	}{
		{"IPv6 outer", net.UDPAddrFromAddrPort(netip.AddrPortFrom(native6, 443)), 17, 443, false},
		{"IPv4 QUIC outer", net.UDPAddrFromAddrPort(netip.AddrPortFrom(warp, 2408)), 17, 2408, true},
		{"IPv4 direct HTTP2 outer", net.TCPAddrFromAddrPort(netip.AddrPortFrom(warp, 443)), 6, 443, true},
	} {
		t.Run(mode.name, func(t *testing.T) {
			p, err := newFamilyGuardPolicy(s, mode.endpoint)
			if err != nil {
				t.Fatal(err)
			}
			rules := p.rules(appID)
			outer4 := mode.outer4
			flow := familyFlow{remote: warp, protocol: mode.protocol, port: mode.port, app: appID}
			for _, layer := range []windows.GUID{cFWPM_LAYER_ALE_AUTH_CONNECT_V4, cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4} {
				assertFamilyAllows(t, rules, layer, flow, outer4)
				wrong := flow
				wrong.app = &other
				assertFamilyAllows(t, rules, layer, wrong, false)
				wrong = flow
				wrong.port++
				assertFamilyAllows(t, rules, layer, wrong, false)
				wrong = flow
				wrong.protocol = 1 // ICMP echo, even to the WARP IP
				assertFamilyAllows(t, rules, layer, wrong, false)
				assertFamilyAllows(t, rules, layer, familyFlow{remote: dns4, protocol: 17, port: 53, app: appID}, false)
				assertFamilyAllows(t, rules, layer, familyFlow{remote: netip.MustParseAddr("127.0.0.1"), loopback: true}, true)
			}
			for _, layer := range []windows.GUID{cFWPM_LAYER_ALE_AUTH_CONNECT_V6, cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6} {
				flow.remote = mapped
				assertFamilyAllows(t, rules, layer, flow, outer4)
				flow.app = &other
				assertFamilyAllows(t, rules, layer, flow, false)
				flow.app = appID
				assertFamilyAllows(t, rules, layer, familyFlow{remote: native6, protocol: 17, port: 443}, true)
			}
			// Packet filtering doesn't depend on a route or on the application
			// having started a NEW connection after the filters were installed.
			assertFamilyAllows(t, rules, wfpIPOut4, familyFlow{remote: dns4}, false)
			assertFamilyAllows(t, rules, wfpIPOut4, familyFlow{remote: warp}, outer4)
			assertFamilyAllows(t, rules, wfpForward4, familyFlow{remote: warp}, false)
			if outer4 {
				flow.remote = warp
				assertFamilyAllows(t, rules, wfpTransport4, flow, true)
				flow.protocol = 1
				assertFamilyAllows(t, rules, wfpTransport4, flow, false)
				assertFamilyAllows(t, rules, wfpICMPErr4, flow, false)
			}
		})
	}
}

func TestWindowsIPv4OnlyFamilyGuard(t *testing.T) {
	peer := netip.MustParseAddr("2001:db8::2")
	p, err := newFamilyGuardPolicy(config.TunInboundSettings{IPv4: true}, net.UDPAddrFromAddrPort(netip.AddrPortFrom(peer, 443)))
	if err != nil {
		t.Fatal(err)
	}
	app := new(wtFwpByteBlob)
	rules := p.rules(app)
	ale := cFWPM_LAYER_ALE_AUTH_CONNECT_V6
	assertFamilyAllows(t, rules, ale, familyFlow{remote: netip.MustParseAddr("::ffff:1.1.1.1")}, true)
	assertFamilyAllows(t, rules, ale, familyFlow{remote: peer, protocol: 17, port: 443, app: app}, true)
	assertFamilyAllows(t, rules, ale, familyFlow{remote: peer, protocol: 17, port: 443}, false)
	nd := familyFlow{remote: netip.MustParseAddr("ff02::1:ff00:2"), protocol: 58, localPort: 135}
	assertFamilyAllows(t, rules, ale, nd, true)
	assertFamilyAllows(t, rules, wfpTransport6, nd, true)
	assertFamilyAllows(t, rules, wfpIPOut6, nd, true)
	nd.localPort = 128 // Echo request is not neighbor discovery.
	assertFamilyAllows(t, rules, ale, nd, false)
	assertFamilyAllows(t, rules, wfpTransport6, nd, false)
	nd.remote, nd.localPort = netip.MustParseAddr("2001:db8::3"), 135
	assertFamilyAllows(t, rules, wfpIPOut6, nd, false)
}

func TestWindowsFamilyGuardPolicyAndRoutes(t *testing.T) {
	if p, err := newFamilyGuardPolicy(config.TunInboundSettings{IPv4: true, IPv6: true}, nil); err != nil || len(p.rules(nil)) != 0 {
		t.Fatalf("dual-stack config should not install family filters: %v", err)
	}
	if _, err := newFamilyGuardPolicy(config.TunInboundSettings{IPv6: true}, &net.UDPAddr{IP: net.IPv4zero, Port: 443}); err == nil {
		t.Fatal("accepted unspecified guard endpoint")
	}
	if _, err := newFamilyGuardPolicy(config.TunInboundSettings{IPv6: true}, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 65536}); err == nil {
		t.Fatal("accepted invalid guard endpoint port")
	}
	for _, tc := range []struct {
		v4, v6 bool
		want   []netip.Prefix
	}{
		{false, true, []netip.Prefix{netip.MustParsePrefix("::/0")}},
		{true, false, []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}},
		{true, true, []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}},
		{false, false, nil},
	} {
		if got := windowsTUNDefaultRoutes(tc.v4, tc.v6); !slices.Equal(got, tc.want) {
			t.Errorf("routes for IPv4=%t IPv6=%t: got %v, want %v", tc.v4, tc.v6, got, tc.want)
		}
	}
}

// Evaluate the intended WFP policy independently of the Windows BFE. Real
// filter installation and traffic checks are covered by the opt-in smoke test.
type familyFlow struct {
	remote          netip.Addr
	protocol        uint8
	port, localPort uint16
	app             *wtFwpByteBlob
	loopback        bool
}

func assertFamilyAllows(t *testing.T, rules []familyRule, layer windows.GUID, flow familyFlow, want bool) {
	t.Helper()
	blocked := false
	for _, r := range rules {
		if r.layer != layer || slices.ContainsFunc(r.conds, func(c familyCondition) bool { return !flow.matches(c) }) {
			continue
		}
		if r.permit {
			if !want {
				t.Fatalf("%s unexpectedly matched %s for %+v", r.name, layer, flow)
			}
			return
		}
		blocked = true
	}
	if got := !blocked; got != want {
		t.Fatalf("layer %s allows %+v: got %t, want %t", layer, flow, got, want)
	}
}

func (f familyFlow) matches(c familyCondition) bool {
	v := c.raw.conditionValue.value
	switch c.raw.fieldKey {
	case wfpFlags:
		return c.raw.matchType == wfpMatchFlagsNone && v == wfpLoopback && !f.loopback
	case wfpAppID:
		return c.ptr != nil && (*wtFwpByteBlob)(c.ptr) == f.app
	case cFWPM_CONDITION_IP_PROTOCOL:
		return v == uintptr(f.protocol)
	case cFWPM_CONDITION_IP_REMOTE_PORT:
		return v == uintptr(f.port)
	case wfpLocalPort:
		return v == uintptr(f.localPort)
	case cFWPM_CONDITION_IP_REMOTE_ADDRESS:
		switch c.raw.conditionValue._type {
		case cFWP_UINT32:
			if !f.remote.Is4() {
				return false
			}
			ip := f.remote.As4()
			return v == uintptr(binary.BigEndian.Uint32(ip[:]))
		case cFWP_BYTE_ARRAY16_TYPE:
			return netip.AddrFrom16(*(*[16]byte)(c.ptr)) == f.remote
		case wfpV6Mask:
			m := (*wfpV6AddrMask)(c.ptr)
			return netip.PrefixFrom(netip.AddrFrom16(m.address), int(m.bits)).Contains(f.remote)
		}
	}
	panic("unexpected WFP condition in test")
}
