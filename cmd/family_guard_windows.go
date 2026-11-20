//go:build windows

package cmd

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"golang.org/x/sys/windows"
)

// Additional WFP conditions and layers from fwpmu.h. The ALE layers know the
// application's identity; the packet layers know the actual wire IP family.
var (
	wfpAppID      = windows.GUID{Data1: 0xd78e1e87, Data2: 0x8644, Data3: 0x4ea5, Data4: [8]byte{0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71}}
	wfpFlags      = windows.GUID{Data1: 0x632ce23b, Data2: 0x5167, Data3: 0x435c, Data4: [8]byte{0x86, 0xd7, 0xe9, 0x03, 0x68, 0x4a, 0xa8, 0x0c}}
	wfpLocalPort  = windows.GUID{Data1: 0x0c1ba1af, Data2: 0x5765, Data3: 0x453f, Data4: [8]byte{0xaf, 0x22, 0xa8, 0xf7, 0x91, 0xac, 0x77, 0x5b}}
	wfpIPOut4     = windows.GUID{Data1: 0x1e5c9fae, Data2: 0x8a84, Data3: 0x4135, Data4: [8]byte{0xa3, 0x31, 0x95, 0x0b, 0x54, 0x22, 0x9e, 0xcd}}
	wfpIPOut6     = windows.GUID{Data1: 0xa3b3ab6b, Data2: 0x3564, Data3: 0x488c, Data4: [8]byte{0x91, 0x17, 0xf3, 0x4e, 0x82, 0x14, 0x27, 0x63}}
	wfpTransport4 = windows.GUID{Data1: 0x09e61aea, Data2: 0xd214, Data3: 0x46e2, Data4: [8]byte{0x9b, 0x21, 0xb2, 0x6b, 0x0b, 0x2f, 0x28, 0xc8}}
	wfpTransport6 = windows.GUID{Data1: 0xe1735bde, Data2: 0x013f, Data3: 0x4655, Data4: [8]byte{0xb3, 0x51, 0xa4, 0x9e, 0x15, 0x76, 0x2d, 0xf0}}
	wfpForward4   = windows.GUID{Data1: 0xa82acc24, Data2: 0x4ee1, Data3: 0x4ee1, Data4: [8]byte{0xb4, 0x65, 0xfd, 0x1d, 0x25, 0xcb, 0x10, 0xa4}}
	wfpForward6   = windows.GUID{Data1: 0x7b964818, Data2: 0x19c7, Data3: 0x493a, Data4: [8]byte{0xb7, 0x1f, 0x83, 0x2c, 0x36, 0x84, 0xd2, 0x8c}}
	wfpICMPErr4   = windows.GUID{Data1: 0x41390100, Data2: 0x564c, Data3: 0x4b32, Data4: [8]byte{0xbc, 0x1d, 0x71, 0x80, 0x48, 0x35, 0x4d, 0x7c}}
	wfpICMPErr6   = windows.GUID{Data1: 0x7fb03b60, Data2: 0x7b8d, Data3: 0x4dfa, Data4: [8]byte{0xba, 0xdd, 0x98, 0x01, 0x76, 0xfc, 0x4e, 0x12}}

	wfpGetAppID = modfwpuclnt.NewProc("FwpmGetAppIdFromFileName0")
	wfpFree     = modfwpuclnt.NewProc("FwpmFreeMemory0")
)

const (
	wfpMatchFlagsNone wtFwpMatchType = 8
	wfpLoopback       uintptr        = 1
	wfpByteBlob       wtFwpDataType  = 12
	wfpV6Mask         wtFwpDataType  = 0x101
)

type familyGuardPolicy struct {
	block4, block6 bool
	peer           netip.AddrPort
	protocol       uint8
}

func newFamilyGuardPolicy(s config.TunInboundSettings, endpoint net.Addr) (familyGuardPolicy, error) {
	p := familyGuardPolicy{block4: !s.IPv4, block6: !s.IPv6}
	if !p.block4 && !p.block6 {
		return p, nil
	}
	var addr netip.AddrPort
	switch ep := endpoint.(type) {
	case *net.UDPAddr:
		if ep != nil && ep.Port > 0 && ep.Port <= 65535 {
			addr, p.protocol = ep.AddrPort(), uint8(cIPPROTO_UDP)
		}
	case *net.TCPAddr:
		if ep != nil && ep.Port > 0 && ep.Port <= 65535 {
			addr, p.protocol = ep.AddrPort(), uint8(cIPPROTO_TCP)
		}
	}
	ip := addr.Addr().Unmap()
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || ip.Zone() != "" {
		return p, fmt.Errorf("expected a concrete WARP endpoint with a valid port, got %v", endpoint)
	}
	if ip.Is4() && p.block4 || ip.Is6() && p.block6 {
		p.peer = netip.AddrPortFrom(ip, addr.Port())
	}
	return p, nil
}

func startTUNFamilyGuard(s config.TunInboundSettings, endpoint net.Addr) (io.Closer, error) {
	p, err := newFamilyGuardPolicy(s, endpoint)
	if err != nil || !p.block4 && !p.block6 {
		return nil, err
	}
	if p.protocol == uint8(cIPPROTO_TCP) {
		// An environment proxy would dial a different address, possibly in a
		// different family. Don't widen the exception or silently retry it.
		req, err := http.NewRequest(http.MethodConnect, internal.ConnectURI, nil)
		if err != nil {
			return nil, err
		}
		proxy, err := http.ProxyFromEnvironment(req)
		if err != nil {
			return nil, err
		}
		if proxy != nil {
			return nil, fmt.Errorf("Windows single-stack TUN requires direct HTTP/2; unset HTTPS_PROXY or add %s to NO_PROXY", req.URL.Hostname())
		}
	}
	guard, err := installFamilyGuard(p)
	if err != nil {
		return nil, err
	}
	log.Printf("Windows WFP family guard active: block IPv4=%t, IPv6=%t", p.block4, p.block6)
	if p.peer.IsValid() {
		log.Printf("Windows WFP family guard: usque exception for WARP %s (%s)", p.peer, endpoint.Network())
	}
	return guard, nil
}

// Pointer values in the WFP C union require a separate GC-visible reference
// until FwpmFilterAdd0 finishes copying its input.
type familyCondition struct {
	raw wtFwpmFilterCondition0
	ptr unsafe.Pointer
}

func wfpEqual(key windows.GUID, kind wtFwpDataType, value uintptr) familyCondition {
	return familyCondition{raw: wtFwpmFilterCondition0{
		fieldKey: key, matchType: cFWP_MATCH_EQUAL, conditionValue: wtFwpConditionValue0{_type: kind, value: value},
	}}
}

func wfpRemote(ip netip.Addr) familyCondition {
	if ip.Is4() {
		v := ip.As4()
		return wfpEqual(cFWPM_CONDITION_IP_REMOTE_ADDRESS, cFWP_UINT32, uintptr(binary.BigEndian.Uint32(v[:])))
	}
	v := ip.As16()
	c := wfpEqual(cFWPM_CONDITION_IP_REMOTE_ADDRESS, cFWP_BYTE_ARRAY16_TYPE, 0)
	c.ptr = unsafe.Pointer(&v)
	return c
}

type wfpV6AddrMask struct {
	address [16]byte
	bits    uint8
}

func wfpRemoteV6Prefix(prefix netip.Prefix) familyCondition {
	c := wfpEqual(cFWPM_CONDITION_IP_REMOTE_ADDRESS, wfpV6Mask, 0)
	c.ptr = unsafe.Pointer(&wfpV6AddrMask{prefix.Addr().As16(), uint8(prefix.Bits())})
	return c
}

type familyRule struct {
	name   string
	layer  windows.GUID
	permit bool
	conds  []familyCondition
}

func (p familyGuardPolicy) rules(appID *wtFwpByteBlob) []familyRule {
	var rules []familyRule
	add := func(name string, layer windows.GUID, permit bool, conds ...familyCondition) {
		rules = append(rules, familyRule{name, layer, permit, conds})
	}
	nonLoopback := wfpEqual(wfpFlags, cFWP_UINT32, wfpLoopback)
	nonLoopback.raw.matchType = wfpMatchFlagsNone
	mapped := wfpRemoteV6Prefix(netip.MustParsePrefix("::ffff:0.0.0.0/96"))
	app := wfpEqual(wfpAppID, wfpByteBlob, 0)
	app.ptr = unsafe.Pointer(appID)
	peerAllow := func(layer windows.GUID, addr netip.Addr, matchApp bool) {
		conds := []familyCondition{wfpRemote(addr),
			wfpEqual(cFWPM_CONDITION_IP_PROTOCOL, cFWP_UINT8, uintptr(p.protocol)),
			wfpEqual(cFWPM_CONDITION_IP_REMOTE_PORT, cFWP_UINT16, uintptr(p.peer.Port()))}
		if matchApp {
			conds = append(conds, app)
		}
		add("Allow WARP endpoint", layer, true, conds...)
	}
	ale4 := [...]windows.GUID{cFWPM_LAYER_ALE_AUTH_CONNECT_V4, cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4}
	ale6 := [...]windows.GUID{cFWPM_LAYER_ALE_AUTH_CONNECT_V6, cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6}
	if p.block4 {
		for _, layer := range ale4 {
			add("Block disabled IPv4", layer, false, nonLoopback)
			if p.peer.Addr().Is4() {
				peerAllow(layer, p.peer.Addr(), true)
			}
		}
		// Winsock dual-stack sockets can authorize a v4-mapped destination
		// at the v6 ALE layer. Do not let them escape the app/port check.
		for _, layer := range ale6 {
			add("Block IPv4-mapped socket traffic", layer, false, nonLoopback, mapped)
			if p.peer.Addr().Is4() {
				peerAllow(layer, netip.AddrFrom16(p.peer.Addr().As16()), true)
			}
		}
		add("Drop disabled IPv4 packets", wfpIPOut4, false, nonLoopback)
		add("Drop forwarded IPv4", wfpForward4, false)
		if ip := p.peer.Addr(); ip.Is4() {
			// IPPACKET has no app identity or ports. Keep its address-only
			// permit behind the transport tuple and the ALE app-ID check.
			add("Allow packets to WARP IPv4 endpoint", wfpIPOut4, true, wfpRemote(ip))
			add("Drop other IPv4 transport traffic", wfpTransport4, false, nonLoopback)
			peerAllow(wfpTransport4, ip, false)
			add("Drop outgoing IPv4 ICMP errors", wfpICMPErr4, false, nonLoopback)
		}
	}
	if p.block6 {
		for _, layer := range ale6 {
			add("Block disabled IPv6", layer, false, nonLoopback)
			if !p.block4 {
				// A permitted IPv4 family still needs Windows' dual-stack sockets.
				add("Leave IPv4-mapped sockets unchanged", layer, true, mapped)
			}
			if p.peer.Addr().Is6() {
				peerAllow(layer, p.peer.Addr(), true)
			}
		}
		add("Drop forwarded IPv6", wfpForward6, false)
		add("Drop disabled IPv6 packets", wfpIPOut6, false, nonLoopback)
		if ip := p.peer.Addr(); ip.Is6() {
			// On an IPv6 underlay, allow only the transport tuple and link
			// maintenance (ICMPv6 ND), not arbitrary application IPv6 traffic.
			add("Drop other IPv6 transport traffic", wfpTransport6, false, nonLoopback)
			peerAllow(wfpTransport6, ip, false)
			add("Drop outgoing IPv6 ICMP errors", wfpICMPErr6, false, nonLoopback)
			add("Allow packets to WARP IPv6 endpoint", wfpIPOut6, true, wfpRemote(ip))
			// Separate the packet-level address allowlist from the transport
			// type/code checks, so a local UDP/TCP flow cannot use these permits.
			ndPeers := []familyCondition{
				wfpRemoteV6Prefix(netip.MustParsePrefix("fe80::/10")),
				wfpRemoteV6Prefix(netip.MustParsePrefix("ff02::1:ff00:0/104")),
				wfpRemote(netip.MustParseAddr("ff02::1")),
				wfpRemote(netip.MustParseAddr("ff02::2")),
			}
			for _, dst := range ndPeers {
				add("Allow IPv6 link-control destinations", wfpIPOut6, true, dst)
			}
			allowND := func(layer windows.GUID, kind uint8, remotes ...familyCondition) {
				for _, remote := range remotes {
					add("Allow IPv6 underlay neighbor discovery", layer, true, remote,
						wfpEqual(cFWPM_CONDITION_IP_PROTOCOL, cFWP_UINT8, 58),
						wfpEqual(wfpLocalPort, cFWP_UINT16, uintptr(kind)),       // ICMP type
						wfpEqual(cFWPM_CONDITION_IP_REMOTE_PORT, cFWP_UINT16, 0)) // ICMP code
				}
			}
			for _, layer := range []windows.GUID{ale6[0], wfpTransport6} {
				allowND(layer, 133, ndPeers[3])
				allowND(layer, 135, ndPeers[0], ndPeers[1], wfpRemote(ip))
				allowND(layer, 136, ndPeers[0], ndPeers[2], wfpRemote(ip))
			}
			allowND(ale6[1], 134, ndPeers[0])
			allowND(ale6[1], 135, ndPeers[0], wfpRemote(ip), wfpRemote(netip.IPv6Unspecified()))
			allowND(ale6[1], 136, ndPeers[0], wfpRemote(ip))
		}
	}
	return rules
}

type familyGuardSession struct{ handle uintptr }

func (s *familyGuardSession) Close() error {
	if s.handle == 0 {
		return nil
	}
	if err := fwpmEngineClose0(s.handle); err != nil {
		return fmt.Errorf("close WFP session: %w", err)
	}
	s.handle = 0
	return nil
}

func installFamilyGuard(p familyGuardPolicy) (_ *familyGuardSession, err error) {
	var appID *wtFwpByteBlob
	if p.peer.IsValid() {
		exe, err := os.Executable()
		if err != nil {
			return nil, err
		}
		path, err := windows.UTF16PtrFromString(exe)
		if err != nil {
			return nil, err
		}
		ret, _, _ := wfpGetAppID.Call(uintptr(unsafe.Pointer(path)), uintptr(unsafe.Pointer(&appID)))
		if ret != 0 {
			return nil, fmt.Errorf("FwpmGetAppIdFromFileName0: %w", syscall.Errno(ret))
		}
		if appID == nil {
			return nil, fmt.Errorf("FwpmGetAppIdFromFileName0 returned no application identity")
		}
		defer func() { _, _, _ = wfpFree.Call(uintptr(unsafe.Pointer(&appID))) }()
	}
	dd, err := displayData("usque address-family guard", "Enforce disabled TUN address families")
	if err != nil {
		return nil, err
	}
	session := wtFwpmSession0{displayData: *dd, flags: cFWPM_SESSION_FLAG_DYNAMIC, txnWaitTimeoutInMSec: 5000}
	var handle uintptr
	if err := fwpmEngineOpen0(nil, cRPC_C_AUTHN_WINNT, nil, &session, unsafe.Pointer(&handle)); err != nil {
		return nil, fmt.Errorf("open WFP session: %w", err)
	}
	guard := &familyGuardSession{handle: handle}
	defer func() {
		if err != nil {
			_ = guard.Close()
		}
	}()
	sublayer, err := windows.GenerateGUID()
	if err != nil {
		return nil, err
	}
	if err := fwpmTransactionBegin0(handle, 0); err != nil {
		return nil, fmt.Errorf("begin WFP transaction: %w", err)
	}
	defer func() {
		if err != nil {
			_ = fwpmTransactionAbort0(handle)
		}
	}()
	if err := fwpmSubLayerAdd0(handle, &wtFwpmSublayer0{subLayerKey: sublayer, displayData: *dd, weight: ^uint16(0)}, 0); err != nil {
		return nil, fmt.Errorf("add WFP sublayer: %w", err)
	}
	for _, rule := range p.rules(appID) {
		if err := rule.install(handle, sublayer); err != nil {
			return nil, err
		}
	}
	if err := fwpmTransactionCommit0(handle); err != nil {
		return nil, fmt.Errorf("commit WFP transaction: %w", err)
	}
	return guard, nil
}

func (r familyRule) install(handle uintptr, sublayer windows.GUID) error {
	dd, err := displayData(r.name, "usque address-family guard")
	if err != nil {
		return err
	}
	conds := make([]wtFwpmFilterCondition0, len(r.conds))
	for i, c := range r.conds {
		conds[i] = c.raw
		if c.ptr != nil {
			conds[i].conditionValue.value = uintptr(c.ptr)
		}
	}
	weight, action := uint8(0), cFWP_ACTION_BLOCK
	if r.permit {
		weight, action = 15, cFWP_ACTION_PERMIT // soft permit; other firewalls may still block
	}
	f := wtFwpmFilter0{displayData: *dd, layerKey: r.layer, subLayerKey: sublayer,
		weight: filterWeight(weight), numFilterConditions: uint32(len(conds)),
		action: wtFwpmAction0{_type: action}}
	if len(conds) > 0 {
		f.filterCondition = &conds[0]
	}
	err = fwpmFilterAdd0(handle, &f, 0, nil)
	runtime.KeepAlive(r.conds)
	if err != nil {
		return fmt.Errorf("add WFP filter %q: %w", r.name, err)
	}
	return nil
}
