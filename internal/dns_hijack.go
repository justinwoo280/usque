package internal

import (
	"encoding/binary"
	"net"
	"sync"
)

const (
	numShards   = 16
	maxPerShard = 256
)

// DNSRewriter hijacks DNS packets at L3, rewriting the destination IP to a
// configured DNS server on the outbound path and restoring the original IP on
// the inbound path.
//
// State is partitioned into 16 shards keyed by source port to reduce lock
// contention. Each shard uses a ring buffer for FIFO eviction so that a burst
// of queries only drops the oldest entry rather than wiping all mappings.
//
// Checksum updates use RFC 1624 incremental adjustment: only the changed IP
// words feed into the correction, making the update O(1) regardless of DNS
// payload size.
type DNSRewriter struct {
	h4    [4]byte
	h6    [16]byte
	h4Set bool
	h6Set bool

	shards [numShards]shard
}

type shard struct {
	mu      sync.Mutex
	pending map[dnsQueryKey][16]byte
	ring    [maxPerShard]dnsQueryKey
	pos     int
}

type dnsQueryKey struct {
	ip   [16]byte
	port uint16
	v4   bool
}

// NewDNSRewriter creates a DNSRewriter with separate IPv4 and IPv6 targets.
// Either target may be nil; packets of that address family will pass through.
func NewDNSRewriter(target4, target6 net.IP) *DNSRewriter {
	r := &DNSRewriter{}
	for i := range r.shards {
		r.shards[i].pending = make(map[dnsQueryKey][16]byte)
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

func (r *DNSRewriter) shardFor(port uint16) *shard {
	return &r.shards[port&(numShards-1)]
}

// RewriteQuery rewrites outbound DNS queries: changes the destination IP to
// the hijack target matching the packet's address family and updates IP + UDP
// checksums incrementally. Non-DNS packets are returned unchanged.
func (r *DNSRewriter) RewriteQuery(pkt []byte) []byte {
	udpOff := udpOffset(pkt)
	if udpOff < 0 || binary.BigEndian.Uint16(pkt[udpOff+2:]) != 53 {
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
		key.port = binary.BigEndian.Uint16(pkt[udpOff:])

		var origDst [16]byte
		copy(origDst[:4], pkt[16:20])

		s := r.shardFor(key.port)
		s.mu.Lock()
		if len(s.pending) >= maxPerShard {
			delete(s.pending, s.ring[s.pos])
		}
		s.ring[s.pos] = key
		s.pos = (s.pos + 1) % maxPerShard
		s.pending[key] = origDst
		s.mu.Unlock()

		oldW := [2]uint16{
			binary.BigEndian.Uint16(pkt[16:18]),
			binary.BigEndian.Uint16(pkt[18:20]),
		}
		copy(pkt[16:20], r.h4[:])
		newW := [2]uint16{
			binary.BigEndian.Uint16(pkt[16:18]),
			binary.BigEndian.Uint16(pkt[18:20]),
		}

		cs := binary.BigEndian.Uint16(pkt[10:12])
		cs = adjustChecksum(cs, oldW[:], newW[:])
		pkt[10] = byte(cs >> 8)
		pkt[11] = byte(cs)

		udpCS := binary.BigEndian.Uint16(pkt[udpOff+6:])
		udpCS = adjustChecksum(udpCS, oldW[:], newW[:])
		if udpCS == 0 {
			udpCS = 0xffff
		}
		pkt[udpOff+6] = byte(udpCS >> 8)
		pkt[udpOff+7] = byte(udpCS)
	} else {
		if !r.h6Set {
			return pkt
		}

		var key dnsQueryKey
		copy(key.ip[:], pkt[8:24])
		key.port = binary.BigEndian.Uint16(pkt[udpOff:])

		var origDst [16]byte
		copy(origDst[:], pkt[24:40])

		s := r.shardFor(key.port)
		s.mu.Lock()
		if len(s.pending) >= maxPerShard {
			delete(s.pending, s.ring[s.pos])
		}
		s.ring[s.pos] = key
		s.pos = (s.pos + 1) % maxPerShard
		s.pending[key] = origDst
		s.mu.Unlock()

		var oldW, newW [8]uint16
		for i := 0; i < 8; i++ {
			oldW[i] = binary.BigEndian.Uint16(pkt[24+i*2:])
		}
		copy(pkt[24:40], r.h6[:])
		for i := 0; i < 8; i++ {
			newW[i] = binary.BigEndian.Uint16(pkt[24+i*2:])
		}

		udpCS := binary.BigEndian.Uint16(pkt[udpOff+6:])
		udpCS = adjustChecksum(udpCS, oldW[:], newW[:])
		pkt[udpOff+6] = byte(udpCS >> 8)
		pkt[udpOff+7] = byte(udpCS)
	}

	return pkt
}

// RewriteResponse rewrites inbound DNS responses: restores the source IP to
// the original query destination so the application receives a reply from the
// IP it originally queried.
func (r *DNSRewriter) RewriteResponse(pkt []byte) []byte {
	udpOff := udpOffset(pkt)
	if udpOff < 0 || binary.BigEndian.Uint16(pkt[udpOff:]) != 53 {
		return pkt
	}

	v4 := pkt[0]>>4 == 4
	if v4 {
		if !r.h4Set {
			return pkt
		}
		if pkt[12] != r.h4[0] || pkt[13] != r.h4[1] ||
			pkt[14] != r.h4[2] || pkt[15] != r.h4[3] {
			return pkt
		}

		var key dnsQueryKey
		key.v4 = true
		copy(key.ip[:4], pkt[16:20])
		key.port = binary.BigEndian.Uint16(pkt[udpOff+2:])

		s := r.shardFor(key.port)
		s.mu.Lock()
		origDst, ok := s.pending[key]
		if ok {
			delete(s.pending, key)
		}
		s.mu.Unlock()

		if !ok {
			return pkt
		}

		oldW := [2]uint16{
			binary.BigEndian.Uint16(pkt[12:14]),
			binary.BigEndian.Uint16(pkt[14:16]),
		}
		copy(pkt[12:16], origDst[:4])
		newW := [2]uint16{
			binary.BigEndian.Uint16(pkt[12:14]),
			binary.BigEndian.Uint16(pkt[14:16]),
		}

		cs := binary.BigEndian.Uint16(pkt[10:12])
		cs = adjustChecksum(cs, oldW[:], newW[:])
		pkt[10] = byte(cs >> 8)
		pkt[11] = byte(cs)

		udpCS := binary.BigEndian.Uint16(pkt[udpOff+6:])
		udpCS = adjustChecksum(udpCS, oldW[:], newW[:])
		if udpCS == 0 {
			udpCS = 0xffff
		}
		pkt[udpOff+6] = byte(udpCS >> 8)
		pkt[udpOff+7] = byte(udpCS)
	} else {
		if !r.h6Set {
			return pkt
		}
		match := true
		for i := 0; i < 16; i++ {
			if pkt[8+i] != r.h6[i] {
				match = false
				break
			}
		}
		if !match {
			return pkt
		}

		var key dnsQueryKey
		copy(key.ip[:], pkt[24:40])
		key.port = binary.BigEndian.Uint16(pkt[udpOff+2:])

		s := r.shardFor(key.port)
		s.mu.Lock()
		origDst, ok := s.pending[key]
		if ok {
			delete(s.pending, key)
		}
		s.mu.Unlock()

		if !ok {
			return pkt
		}

		var oldW, newW [8]uint16
		for i := 0; i < 8; i++ {
			oldW[i] = binary.BigEndian.Uint16(pkt[8+i*2:])
		}
		copy(pkt[8:24], origDst[:])
		for i := 0; i < 8; i++ {
			newW[i] = binary.BigEndian.Uint16(pkt[8+i*2:])
		}

		udpCS := binary.BigEndian.Uint16(pkt[udpOff+6:])
		udpCS = adjustChecksum(udpCS, oldW[:], newW[:])
		pkt[udpOff+6] = byte(udpCS >> 8)
		pkt[udpOff+7] = byte(udpCS)
	}

	return pkt
}

// --- IPv4 helpers ---

func isFragmentedIPv4(pkt []byte) bool {
	if len(pkt) < 8 {
		return false
	}
	fo := binary.BigEndian.Uint16(pkt[6:8])
	return fo&0x1FFF != 0
}

// --- Incremental checksum (RFC 1624) ---

func foldCarry(sum uint32) uint32 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return sum
}

// adjustChecksum updates a one's-complement checksum incrementally.
// HC' = ~(~HC + sum(~m) + sum(m'))
func adjustChecksum(cs uint16, oldWords, newWords []uint16) uint16 {
	sum := uint32(^cs)
	for _, w := range oldWords {
		sum += uint32(^w)
	}
	for _, w := range newWords {
		sum += uint32(w)
	}
	return ^uint16(foldCarry(sum))
}

// --- IPv6 extension headers ---

// skipIPv6ExtHeaders walks the IPv6 extension header chain. Returns the final
// next-header value and the byte offset of the upper-layer protocol payload.
func skipIPv6ExtHeaders(pkt []byte, nextHeader byte, off int) (byte, int) {
	for {
		switch nextHeader {
		case 0, 43, 60, 135: // Hop-by-Hop, Routing, Destination Options, Mobility
			if off+2 > len(pkt) {
				return 0, -1
			}
			nextHeader = pkt[off]
			hdrLen := int(pkt[off+1])*8 + 8
			off += hdrLen
			if off > len(pkt) {
				return 0, -1
			}
		case 44: // Fragment
			if off+8 > len(pkt) {
				return 0, -1
			}
			nextHeader = pkt[off]
			off += 8
		case 51: // AH
			if off+2 > len(pkt) {
				return 0, -1
			}
			nextHeader = pkt[off]
			hdrLen := (int(pkt[off+1]) + 2) * 4
			off += hdrLen
			if off > len(pkt) {
				return 0, -1
			}
		default:
			return nextHeader, off
		}
	}
}

// --- Packet field accessors ---

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
		nh, off := skipIPv6ExtHeaders(pkt, pkt[6], 40)
		if off < 0 || nh != 17 || off+8 > len(pkt) {
			return -1
		}
		return off
	}
	return -1
}

// --- Full checksum computation (test verification only) ---

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
