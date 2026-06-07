package internal

import (
	"bytes"
	"encoding/binary"
	"net"
	"sync"
)

// DNSRewriter hijacks DNS packets at L3, rewriting the destination IP to a
// configured DNS server on the outbound path and restoring the original IP on
// the inbound path.
//
// The implementation is allocation-free on the hot path: map keys, map values,
// and hijack target comparisons all use fixed-size byte arrays. This avoids GC
// pressure from per-packet string/net.IP allocations that caused DNS latency.
type DNSRewriter struct {
	h4    [4]byte
	h6    [16]byte
	h4Set bool
	h6Set bool

	mu      sync.Mutex
	pending map[dnsQueryKey][16]byte
}

type dnsQueryKey struct {
	ip   [16]byte
	port uint16
	v4   bool
}

// NewDNSRewriter creates a DNSRewriter with separate IPv4 and IPv6 targets.
// Either target may be nil; packets of that address family will pass through.
func NewDNSRewriter(target4, target6 net.IP) *DNSRewriter {
	r := &DNSRewriter{
		pending: make(map[dnsQueryKey][16]byte),
	}
	if target4 != nil {
		if v4 := target4.To4(); v4 != nil {
			copy(r.h4[:], v4)
			r.h4Set = true
		}
	}
	if target6 != nil {
		if v6 := target6.To16(); v6 != nil {
			copy(r.h6[:], v6)
			r.h6Set = true
		}
	}
	return r
}

// RewriteQuery rewrites outbound DNS queries: changes the destination IP to
// the hijack target matching the packet's address family and updates IP + UDP
// checksums. Non-DNS packets are returned unchanged.
func (r *DNSRewriter) RewriteQuery(pkt []byte) []byte {
	if !isUDP(pkt) || udpDstPort(pkt) != 53 {
		return pkt
	}

	v4 := pkt[0]>>4 == 4
	if v4 {
		if !r.h4Set || isFragmentedIPv4(pkt) {
			return pkt
		}

		var key dnsQueryKey
		key.v4 = true
		copy(key.ip[:4], pkt[12:16])
		key.port = binary.BigEndian.Uint16(pkt[udpOffV4(pkt):])

		var origDst [16]byte
		copy(origDst[:4], pkt[16:20])

		r.mu.Lock()
		r.pending[key] = origDst
		if len(r.pending) > 1024 {
			r.pending = make(map[dnsQueryKey][16]byte)
		}
		r.mu.Unlock()

		copy(pkt[16:20], r.h4[:])
		updateIPv4Checksum(pkt)
	} else {
		if !r.h6Set {
			return pkt
		}

		var key dnsQueryKey
		copy(key.ip[:], pkt[8:24])
		key.port = binary.BigEndian.Uint16(pkt[udpOffV6:])

		var origDst [16]byte
		copy(origDst[:], pkt[24:40])

		r.mu.Lock()
		r.pending[key] = origDst
		if len(r.pending) > 1024 {
			r.pending = make(map[dnsQueryKey][16]byte)
		}
		r.mu.Unlock()

		copy(pkt[24:40], r.h6[:])
	}
	updateUDPChecksum(pkt)
	return pkt
}

// RewriteResponse rewrites inbound DNS responses: restores the source IP to
// the original query destination so the application receives a reply from the
// IP it originally queried.
func (r *DNSRewriter) RewriteResponse(pkt []byte) []byte {
	if !isUDP(pkt) || udpSrcPort(pkt) != 53 {
		return pkt
	}

	v4 := pkt[0]>>4 == 4
	if v4 {
		if !r.h4Set || !bytes.Equal(pkt[12:16], r.h4[:]) {
			return pkt
		}

		var key dnsQueryKey
		key.v4 = true
		copy(key.ip[:4], pkt[16:20])
		key.port = binary.BigEndian.Uint16(pkt[udpOffV4(pkt)+2:])

		r.mu.Lock()
		origDst, ok := r.pending[key]
		if ok {
			delete(r.pending, key)
		}
		r.mu.Unlock()

		if !ok {
			return pkt
		}

		copy(pkt[12:16], origDst[:4])
		updateIPv4Checksum(pkt)
	} else {
		if !r.h6Set || !bytes.Equal(pkt[8:24], r.h6[:]) {
			return pkt
		}

		var key dnsQueryKey
		copy(key.ip[:], pkt[24:40])
		key.port = binary.BigEndian.Uint16(pkt[udpOffV6+2:])

		r.mu.Lock()
		origDst, ok := r.pending[key]
		if ok {
			delete(r.pending, key)
		}
		r.mu.Unlock()

		if !ok {
			return pkt
		}

		copy(pkt[8:24], origDst[:])
	}
	updateUDPChecksum(pkt)
	return pkt
}

// udpOffV4 returns the UDP header offset for an IPv4 packet (IHL-based).
func udpOffV4(pkt []byte) int {
	return int(pkt[0]&0x0f) * 4
}

const udpOffV6 = 40

// --- IPv4 helpers ---

func isFragmentedIPv4(pkt []byte) bool {
	if len(pkt) < 8 {
		return false
	}
	fo := binary.BigEndian.Uint16(pkt[6:8])
	return fo&0x1FFF != 0
}

func updateIPv4Checksum(pkt []byte) {
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl {
		return
	}
	pkt[10] = 0
	pkt[11] = 0
	cs := ipChecksum(pkt[:ihl])
	pkt[10] = byte(cs >> 8)
	pkt[11] = byte(cs)
}

func ipChecksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(hdr[i:]))
	}
	if len(hdr)%2 != 0 {
		sum += uint32(hdr[len(hdr)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// --- UDP checksum ---

func updateUDPChecksum(pkt []byte) {
	v4 := pkt[0]>>4 == 4
	udpOff := udpOffset(pkt)
	if udpOff < 0 || len(pkt) < udpOff+8 {
		return
	}

	pkt[udpOff+6] = 0
	pkt[udpOff+7] = 0

	cs := computeUDPChecksum(pkt)
	if v4 && cs == 0 {
		cs = 0xffff
	}
	pkt[udpOff+6] = byte(cs >> 8)
	pkt[udpOff+7] = byte(cs)
}

func computeUDPChecksum(pkt []byte) uint16 {
	v4 := pkt[0]>>4 == 4
	udpOff := udpOffset(pkt)
	if udpOff < 0 || len(pkt) < udpOff+8 {
		return 0
	}
	udpLen := len(pkt) - udpOff

	var sum uint32

	if v4 {
		sum += pseudo4(pkt[12:16])
		sum += pseudo4(pkt[16:20])
		sum += 17
		sum += uint32(udpLen)
	} else {
		sum += pseudo16(pkt[8:24])
		sum += pseudo16(pkt[24:40])
		sum += 17
		sum += uint32(udpLen)
	}

	for i := udpOff; i+1 < len(pkt); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pkt[i:]))
	}
	if len(pkt)%2 != 0 {
		sum += uint32(pkt[len(pkt)-1]) << 8
	}

	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func pseudo4(b []byte) uint32 {
	return uint32(binary.BigEndian.Uint16(b[0:2])) + uint32(binary.BigEndian.Uint16(b[2:4]))
}

func pseudo16(b []byte) uint32 {
	var s uint32
	for i := 0; i < 16; i += 2 {
		s += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	return s
}

// --- Packet field accessors ---

func isUDP(pkt []byte) bool {
	if len(pkt) < 1 {
		return false
	}
	v := pkt[0] >> 4
	if v == 4 {
		return isUDPv4(pkt)
	}
	if v == 6 {
		return isUDPv6(pkt)
	}
	return false
}

func isUDPv4(pkt []byte) bool {
	if len(pkt) < 20 {
		return false
	}
	return pkt[9] == 17
}

func isUDPv6(pkt []byte) bool {
	if len(pkt) < 40 {
		return false
	}
	return pkt[6] == 17
}

func udpOffset(pkt []byte) int {
	if len(pkt) < 1 {
		return -1
	}
	if pkt[0]>>4 == 4 {
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < 20 || len(pkt) < ihl+8 {
			return -1
		}
		return ihl
	}
	if pkt[0]>>4 == 6 {
		if len(pkt) < 48 {
			return -1
		}
		return 40
	}
	return -1
}

func udpSrcPort(pkt []byte) uint16 {
	off := udpOffset(pkt)
	if off < 0 {
		return 0
	}
	return binary.BigEndian.Uint16(pkt[off:])
}

func udpDstPort(pkt []byte) uint16 {
	off := udpOffset(pkt)
	if off < 0 {
		return 0
	}
	return binary.BigEndian.Uint16(pkt[off+2:])
}

func srcIP(pkt []byte) net.IP {
	if pkt[0]>>4 == 4 {
		return net.IP(pkt[12:16])
	}
	return net.IP(pkt[8:24])
}

func dstIP(pkt []byte) net.IP {
	if pkt[0]>>4 == 4 {
		return net.IP(pkt[16:20])
	}
	return net.IP(pkt[24:40])
}

func copyIP(ip net.IP) net.IP {
	c := make(net.IP, len(ip))
	copy(c, ip)
	return c
}
