//go:build windows

// DNS leak prevention via the Windows Filtering Platform (WFP).
//
// On Windows, setting DNS servers only on the TUN interface is not sufficient
// to prevent DNS leaks. Windows' "smart multi-homed name resolution" sends DNS
// queries out ALL interfaces in parallel — including the physical NIC, whose
// queries never enter the TUN and therefore bypass the L3 DNS hijack rewriter.
//
// This module installs WFP filters that BLOCK all outbound/inbound UDP+TCP
// port-53 traffic at the kernel filtering layer, then PERMIT (at higher weight)
// only traffic destined to the configured tunnel DNS servers. Since the default
// route points at the TUN, the permitted queries flow into the TUN and are
// hijack-rewritten as intended; every other parallel query is dropped in-kernel.
//
// The filters live in a dynamic WFP session, so they are automatically torn
// down if the process dies without calling disableDNSFirewall.
//
// This is a self-contained re-implementation of the DNS-blocking subset of
// golang.zx2c4.com/wireguard/windows/tunnel/firewall (whose primitives are
// unexported), covering only what usque needs — no full kill-switch.

package cmd

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// --- WFP DLL procs ---

var (
	modfwpuclnt = windows.NewLazySystemDLL("fwpuclnt.dll")

	procFwpmEngineOpen0        = modfwpuclnt.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose0       = modfwpuclnt.NewProc("FwpmEngineClose0")
	procFwpmSubLayerAdd0       = modfwpuclnt.NewProc("FwpmSubLayerAdd0")
	procFwpmProviderAdd0       = modfwpuclnt.NewProc("FwpmProviderAdd0")
	procFwpmFilterAdd0         = modfwpuclnt.NewProc("FwpmFilterAdd0")
	procFwpmTransactionBegin0  = modfwpuclnt.NewProc("FwpmTransactionBegin0")
	procFwpmTransactionCommit0 = modfwpuclnt.NewProc("FwpmTransactionCommit0")
	procFwpmTransactionAbort0  = modfwpuclnt.NewProc("FwpmTransactionAbort0")
)

// --- WFP enums / constants ---

type wtFwpActionType uint32

const (
	cFWP_ACTION_FLAG_TERMINATING wtFwpActionType = 0x00001000
	cFWP_ACTION_BLOCK            wtFwpActionType = 0x00000001 | cFWP_ACTION_FLAG_TERMINATING
	cFWP_ACTION_PERMIT           wtFwpActionType = 0x00000002 | cFWP_ACTION_FLAG_TERMINATING
)

type wtFwpMatchType uint32

const cFWP_MATCH_EQUAL wtFwpMatchType = 0

type wtFwpDataType uint

const (
	cFWP_UINT8             wtFwpDataType = 1
	cFWP_UINT16            wtFwpDataType = 2
	cFWP_UINT32            wtFwpDataType = 3
	cFWP_BYTE_ARRAY16_TYPE wtFwpDataType = 11
)

type wtRpcCAuthN uint32

const cRPC_C_AUTHN_WINNT wtRpcCAuthN = 10

type wtFwpmSessionFlagsValue uint32

const cFWPM_SESSION_FLAG_DYNAMIC wtFwpmSessionFlagsValue = 0x00000001

type wtIPProto uint32

const (
	cIPPROTO_TCP wtIPProto = 6
	cIPPROTO_UDP wtIPProto = 17
)

// --- WFP condition / layer GUIDs (from fwpmu.h) ---

var (
	// 3971ef2b-623e-4f9a-8cb1-6e79b806b9a7
	cFWPM_CONDITION_IP_PROTOCOL = windows.GUID{
		Data1: 0x3971ef2b, Data2: 0x623e, Data3: 0x4f9a,
		Data4: [8]byte{0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7},
	}
	// c35a604d-d22b-4e1a-91b4-68f674ee674b
	cFWPM_CONDITION_IP_REMOTE_PORT = windows.GUID{
		Data1: 0xc35a604d, Data2: 0xd22b, Data3: 0x4e1a,
		Data4: [8]byte{0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b},
	}
	// b235ae9a-1d64-49b8-a44c-5ff3d9095045
	cFWPM_CONDITION_IP_REMOTE_ADDRESS = windows.GUID{
		Data1: 0xb235ae9a, Data2: 0x1d64, Data3: 0x49b8,
		Data4: [8]byte{0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45},
	}

	// FWPM_LAYER_ALE_AUTH_CONNECT_V4 c38d57d1-05a7-4c33-904f-7fbceee60e82
	cFWPM_LAYER_ALE_AUTH_CONNECT_V4 = windows.GUID{
		Data1: 0xc38d57d1, Data2: 0x05a7, Data3: 0x4c33,
		Data4: [8]byte{0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82},
	}
	// FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 e1cd9fe7-f4b5-4273-96c0-592e487b8650
	cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 = windows.GUID{
		Data1: 0xe1cd9fe7, Data2: 0xf4b5, Data3: 0x4273,
		Data4: [8]byte{0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50},
	}
	// FWPM_LAYER_ALE_AUTH_CONNECT_V6 4a72393b-319f-44bc-84c3-ba54dcb3b6b4
	cFWPM_LAYER_ALE_AUTH_CONNECT_V6 = windows.GUID{
		Data1: 0x4a72393b, Data2: 0x319f, Data3: 0x44bc,
		Data4: [8]byte{0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4},
	}
	// FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6 a3b42c97-9f04-4672-b87e-cee9c483257f
	cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6 = windows.GUID{
		Data1: 0xa3b42c97, Data2: 0x9f04, Data3: 0x4672,
		Data4: [8]byte{0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f},
	}
)

// --- WFP structs (layouts must match fwpmtypes.h; validated against
// golang.zx2c4.com/wireguard/windows types_windows*.go) ---

type wtFwpByteBlob struct {
	size uint32
	data *uint8
}

type wtFwpmDisplayData0 struct {
	name        *uint16
	description *uint16
}

type wtFwpValue0 struct {
	_type wtFwpDataType
	value uintptr
}

type wtFwpConditionValue0 wtFwpValue0

type wtFwpmFilterCondition0 struct {
	fieldKey       windows.GUID
	matchType      wtFwpMatchType
	conditionValue wtFwpConditionValue0
}

type wtFwpmAction0 struct {
	_type      wtFwpActionType
	filterType windows.GUID
}

type wtFwpByteArray16 struct {
	byteArray16 [16]uint8
}

type wtFwpmSession0 struct {
	sessionKey           windows.GUID
	displayData          wtFwpmDisplayData0
	flags                wtFwpmSessionFlagsValue
	txnWaitTimeoutInMSec uint32
	processId            uint32
	sid                  *windows.SID
	username             *uint16
	kernelMode           uint8
}

type wtFwpmProvider0 struct {
	providerKey  windows.GUID
	displayData  wtFwpmDisplayData0
	flags        uint32
	providerData wtFwpByteBlob
	serviceName  *uint16
}

type wtFwpmSublayer0 struct {
	subLayerKey  windows.GUID
	displayData  wtFwpmDisplayData0
	flags        uint32
	providerKey  *windows.GUID
	providerData wtFwpByteBlob
	weight       uint16
}

type wtFwpmFilter0 struct {
	filterKey           windows.GUID
	displayData         wtFwpmDisplayData0
	flags               uint32
	providerKey         *windows.GUID
	providerData        wtFwpByteBlob
	layerKey            windows.GUID
	subLayerKey         windows.GUID
	weight              wtFwpValue0
	numFilterConditions uint32
	filterCondition     *wtFwpmFilterCondition0
	action              wtFwpmAction0
	offset1             [4]byte
	providerContextKey  windows.GUID
	reserved            *windows.GUID
	filterID            uint64
	effectiveWeight     wtFwpValue0
}

// --- syscall wrappers ---

func fwpmEngineOpen0(serverName *uint16, authnService wtRpcCAuthN, authIdentity *uintptr, session *wtFwpmSession0, engineHandle unsafe.Pointer) error {
	r1, _, _ := procFwpmEngineOpen0.Call(
		uintptr(unsafe.Pointer(serverName)), uintptr(authnService),
		uintptr(unsafe.Pointer(authIdentity)), uintptr(unsafe.Pointer(session)),
		uintptr(engineHandle))
	if r1 != 0 {
		return syscall.Errno(r1)
	}
	return nil
}

func fwpmEngineClose0(engineHandle uintptr) error {
	r1, _, _ := procFwpmEngineClose0.Call(engineHandle)
	if r1 != 0 {
		return syscall.Errno(r1)
	}
	return nil
}

func fwpmProviderAdd0(engineHandle uintptr, provider *wtFwpmProvider0, sd uintptr) error {
	r1, _, _ := procFwpmProviderAdd0.Call(engineHandle, uintptr(unsafe.Pointer(provider)), sd)
	if r1 != 0 {
		return syscall.Errno(r1)
	}
	return nil
}

func fwpmSubLayerAdd0(engineHandle uintptr, subLayer *wtFwpmSublayer0, sd uintptr) error {
	r1, _, _ := procFwpmSubLayerAdd0.Call(engineHandle, uintptr(unsafe.Pointer(subLayer)), sd)
	if r1 != 0 {
		return syscall.Errno(r1)
	}
	return nil
}

func fwpmFilterAdd0(engineHandle uintptr, filter *wtFwpmFilter0, sd uintptr, id *uint64) error {
	r1, _, _ := procFwpmFilterAdd0.Call(engineHandle, uintptr(unsafe.Pointer(filter)), sd, uintptr(unsafe.Pointer(id)))
	if r1 != 0 {
		return syscall.Errno(r1)
	}
	return nil
}

func fwpmTransactionBegin0(engineHandle uintptr, flags uint32) error {
	r1, _, _ := procFwpmTransactionBegin0.Call(engineHandle, uintptr(flags))
	if r1 != 0 {
		return syscall.Errno(r1)
	}
	return nil
}

func fwpmTransactionCommit0(engineHandle uintptr) error {
	r1, _, _ := procFwpmTransactionCommit0.Call(engineHandle)
	if r1 != 0 {
		return syscall.Errno(r1)
	}
	return nil
}

func fwpmTransactionAbort0(engineHandle uintptr) error {
	r1, _, _ := procFwpmTransactionAbort0.Call(engineHandle)
	if r1 != 0 {
		return syscall.Errno(r1)
	}
	return nil
}

// --- helpers ---

func displayData(name, description string) (*wtFwpmDisplayData0, error) {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	descPtr, err := windows.UTF16PtrFromString(description)
	if err != nil {
		return nil, err
	}
	return &wtFwpmDisplayData0{name: namePtr, description: descPtr}, nil
}

func filterWeight(weight uint8) wtFwpValue0 {
	return wtFwpValue0{_type: cFWP_UINT8, value: uintptr(weight)}
}

// --- module state ---

var dnsFirewallSession uintptr

// enableDNSFirewall installs WFP filters that drop all UDP/TCP port-53 traffic
// except queries destined to the given DNS servers. allowedDNS is typically the
// tunnel DNS list from inbound.settings.dns (e.g. 1.1.1.1, 2606:4700:4700::1111).
//
// Idempotent-guarded: returns an error if already enabled.
func enableDNSFirewall(allowedDNS []net.IP) error {
	if dnsFirewallSession != 0 {
		return errors.New("DNS firewall already enabled")
	}
	if len(allowedDNS) == 0 {
		return errors.New("no allowed DNS servers provided")
	}

	// Convert to netip.Addr, splitting by family.
	var except []netip.Addr
	for _, ip := range allowedDNS {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		except = append(except, addr.Unmap())
	}
	if len(except) == 0 {
		return errors.New("no valid allowed DNS servers")
	}

	sessionDisplay, err := displayData("UsqueBox", "UsqueBox DNS leak prevention (dynamic)")
	if err != nil {
		return err
	}
	session := wtFwpmSession0{
		displayData:          *sessionDisplay,
		flags:                cFWPM_SESSION_FLAG_DYNAMIC,
		txnWaitTimeoutInMSec: windows.INFINITE,
	}
	var handle uintptr
	if err := fwpmEngineOpen0(nil, cRPC_C_AUTHN_WINNT, nil, &session, unsafe.Pointer(&handle)); err != nil {
		return fmt.Errorf("FwpmEngineOpen0: %w", err)
	}

	provider, err := windows.GenerateGUID()
	if err != nil {
		fwpmEngineClose0(handle)
		return err
	}
	sublayer, err := windows.GenerateGUID()
	if err != nil {
		fwpmEngineClose0(handle)
		return err
	}

	install := func() error {
		// Register provider.
		pd, err := displayData("UsqueBox", "UsqueBox DNS firewall provider")
		if err != nil {
			return err
		}
		prov := wtFwpmProvider0{providerKey: provider, displayData: *pd}
		if err := fwpmProviderAdd0(handle, &prov, 0); err != nil {
			return fmt.Errorf("FwpmProviderAdd0: %w", err)
		}

		// Register sublayer with max weight so our filters win arbitration.
		sd, err := displayData("UsqueBox DNS filters", "DNS block + allow-except")
		if err != nil {
			return err
		}
		sl := wtFwpmSublayer0{
			subLayerKey: sublayer,
			displayData: *sd,
			providerKey: &provider,
			weight:      ^uint16(0),
		}
		if err := fwpmSubLayerAdd0(handle, &sl, 0); err != nil {
			return fmt.Errorf("FwpmSubLayerAdd0: %w", err)
		}

		return blockDNSExcept(handle, &provider, sublayer, except)
	}

	// Run inside a transaction so a partial failure leaves no filters behind.
	if err := fwpmTransactionBegin0(handle, 0); err != nil {
		fwpmEngineClose0(handle)
		return fmt.Errorf("FwpmTransactionBegin0: %w", err)
	}
	if err := install(); err != nil {
		fwpmTransactionAbort0(handle)
		fwpmEngineClose0(handle)
		return err
	}
	if err := fwpmTransactionCommit0(handle); err != nil {
		fwpmTransactionAbort0(handle)
		fwpmEngineClose0(handle)
		return fmt.Errorf("FwpmTransactionCommit0: %w", err)
	}

	dnsFirewallSession = handle
	return nil
}

// disableDNSFirewall tears down the WFP session and all its filters.
// Safe to call when not enabled.
func disableDNSFirewall() {
	if dnsFirewallSession != 0 {
		fwpmEngineClose0(dnsFirewallSession)
		dnsFirewallSession = 0
	}
}

// blockDNSExcept installs, at the four ALE layers (v4/v6 × connect/recv):
//   - a low-weight BLOCK filter matching UDP OR TCP remote port 53
//   - a higher-weight PERMIT filter matching (port 53 AND proto) AND remote
//     address ∈ except, so only the tunnel DNS servers are reachable.
func blockDNSExcept(handle uintptr, provider *windows.GUID, sublayer windows.GUID, except []netip.Addr) error {
	const weightDeny = 10
	const weightAllow = 11

	// Deny conditions: remote port == 53 AND (proto == UDP OR proto == TCP).
	// Repeating the IP_PROTOCOL field key expresses a logical OR within the
	// same field (WFP semantics: same field key ORs, different keys AND).
	denyConditions := []wtFwpmFilterCondition0{
		{
			fieldKey:  cFWPM_CONDITION_IP_REMOTE_PORT,
			matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_UINT16,
				value: uintptr(53),
			},
		},
		{
			fieldKey:  cFWPM_CONDITION_IP_PROTOCOL,
			matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_UINT8,
				value: uintptr(cIPPROTO_UDP),
			},
		},
		{
			fieldKey:  cFWPM_CONDITION_IP_PROTOCOL,
			matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_UINT8,
				value: uintptr(cIPPROTO_TCP),
			},
		},
	}

	layers := []windows.GUID{
		cFWPM_LAYER_ALE_AUTH_CONNECT_V4,
		cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
		cFWPM_LAYER_ALE_AUTH_CONNECT_V6,
		cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
	}
	layerNames := []string{
		"Block DNS outbound (IPv4)",
		"Block DNS inbound (IPv4)",
		"Block DNS outbound (IPv6)",
		"Block DNS inbound (IPv6)",
	}

	// --- BLOCK filters ---
	for i, layer := range layers {
		dd, err := displayData(layerNames[i], "")
		if err != nil {
			return err
		}
		var filterID uint64
		filter := wtFwpmFilter0{
			providerKey:         provider,
			subLayerKey:         sublayer,
			displayData:         *dd,
			layerKey:            layer,
			weight:              filterWeight(weightDeny),
			numFilterConditions: uint32(len(denyConditions)),
			filterCondition:     &denyConditions[0],
			action:              wtFwpmAction0{_type: cFWP_ACTION_BLOCK},
		}
		if err := fwpmFilterAdd0(handle, &filter, 0, &filterID); err != nil {
			return fmt.Errorf("FwpmFilterAdd0 (block %s): %w", layerNames[i], err)
		}
	}

	// --- ALLOW-EXCEPT filters (one per allowed DNS, split by family) ---
	// storedAddrs keeps IPv6 byte arrays alive until the syscalls complete.
	var storedAddrs []*wtFwpByteArray16

	addAllow := func(layer windows.GUID, name string, extra wtFwpmFilterCondition0) error {
		conds := make([]wtFwpmFilterCondition0, 0, len(denyConditions)+1)
		conds = append(conds, denyConditions...)
		conds = append(conds, extra)
		dd, err := displayData(name, "")
		if err != nil {
			return err
		}
		var filterID uint64
		filter := wtFwpmFilter0{
			providerKey:         provider,
			subLayerKey:         sublayer,
			displayData:         *dd,
			layerKey:            layer,
			weight:              filterWeight(weightAllow),
			numFilterConditions: uint32(len(conds)),
			filterCondition:     &conds[0],
			action:              wtFwpmAction0{_type: cFWP_ACTION_PERMIT},
		}
		if err := fwpmFilterAdd0(handle, &filter, 0, &filterID); err != nil {
			return fmt.Errorf("FwpmFilterAdd0 (allow %s): %w", name, err)
		}
		runtime.KeepAlive(conds)
		return nil
	}

	for _, addr := range except {
		if addr.Is4() {
			v4 := addr.As4()
			cond := wtFwpmFilterCondition0{
				fieldKey:  cFWPM_CONDITION_IP_REMOTE_ADDRESS,
				matchType: cFWP_MATCH_EQUAL,
				conditionValue: wtFwpConditionValue0{
					_type: cFWP_UINT32,
					value: uintptr(binary.BigEndian.Uint32(v4[:])),
				},
			}
			if err := addAllow(cFWPM_LAYER_ALE_AUTH_CONNECT_V4, "Allow DNS outbound (IPv4)", cond); err != nil {
				return err
			}
			if err := addAllow(cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, "Allow DNS inbound (IPv4)", cond); err != nil {
				return err
			}
		} else {
			arr := &wtFwpByteArray16{byteArray16: addr.As16()}
			storedAddrs = append(storedAddrs, arr)
			cond := wtFwpmFilterCondition0{
				fieldKey:  cFWPM_CONDITION_IP_REMOTE_ADDRESS,
				matchType: cFWP_MATCH_EQUAL,
				conditionValue: wtFwpConditionValue0{
					_type: cFWP_BYTE_ARRAY16_TYPE,
					value: uintptr(unsafe.Pointer(arr)),
				},
			}
			if err := addAllow(cFWPM_LAYER_ALE_AUTH_CONNECT_V6, "Allow DNS outbound (IPv6)", cond); err != nil {
				return err
			}
			if err := addAllow(cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, "Allow DNS inbound (IPv6)", cond); err != nil {
				return err
			}
		}
	}

	runtime.KeepAlive(storedAddrs)
	runtime.KeepAlive(denyConditions)
	return nil
}
