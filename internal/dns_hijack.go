package internal

import (
	"encoding/binary"
	"net"
)

// DNSRewriter hijacks DNS packets at L3, rewriting the destination IP to a
// configured DNS server on the outbound path and restoring the original IP on
// the inbound path. This ensures that even when the OS uses the wrong DNS
// server (e.g. system DNS on Windows), the actual queries reach the configured
// DNS server through the MASQUE tunnel.
//
// Supports separate IPv4 and IPv6 hijack targets so that IPv4 DNS queries are
// rewritten to the configured IPv4 DNS server and IPv6 queries to the IPv6 one.
//
// Only unfragmented UDP port 53 packets are rewritten; everything else passes
// through unchanged.
type DNSRewriter struct {
	hijackDst4 net.IP
	hijackDst6 net.IP

	origSrcIP net.IP
	origSrcP  uint16
	origDstIP net.IP
}

// NewDNSRewriter creates a DNSRewriter with separate IPv4 and IPv6 targets.
// Either target may be nil; packets of that address family will pass through.
func NewDNSRewriter(target4, target6 net.IP) *DNSRewriter {
	return &DNSRewriter{hijackDst4: target4, hijackDst6: target6}
}

// RewriteQuery rewrites outbound DNS queries: changes the destination IP to
// the hijack target matching the packet's address family and updates IP + UDP
// checksums. Returns the same buffer. Non-DNS packets are returned unchanged.
func (r *DNSRewriter) RewriteQuery(pkt []byte) []byte {
	if !isUDP(pkt) || udpDstPort(pkt) != 53 {
		return pkt
	}

	v4 := pkt[0]>>4 == 4
	hijackDst := r.hijackDst6
	if v4 {
		hijackDst = r.hijackDst4
		if isFragmentedIPv4(pkt) {
			return pkt
		}
	}
	if hijackDst == nil {
		return pkt
	}

	r.origSrcIP = copyIP(srcIP(pkt))
	r.origSrcP = udpSrcPort(pkt)
	r.origDstIP = copyIP(dstIP(pkt))

	if v4 {
		copy(pkt[16:20], hijackDst.To4())
		updateIPv4Checksum(pkt)
	} else {
		copy(pkt[24:40], hijackDst.To16())
	}
	updateUDPChecksum(pkt)
	return pkt
}

// RewriteResponse rewrites inbound DNS responses: restores the source IP to
// the original query destination so the application receives a reply from the
// IP it originally queried. Returns the same buffer.
func (r *DNSRewriter) RewriteResponse(pkt []byte) []byte {
	if r.origDstIP == nil {
		return pkt
	}
	if !isUDP(pkt) || udpSrcPort(pkt) != 53 {
		return pkt
	}

	v4 := pkt[0]>>4 == 4
	hijackDst := r.hijackDst6
	if v4 {
		hijackDst = r.hijackDst4
	}
	if hijackDst == nil {
		return pkt
	}

	var curSrc net.IP
	if v4 {
		curSrc = net.IP(pkt[12:16])
	} else {
		curSrc = net.IP(pkt[8:24])
	}
	if !curSrc.Equal(hijackDst) {
		return pkt
	}

	if v4 {
		copy(pkt[12:16], r.origDstIP.To4())
		updateIPv4Checksum(pkt)
	} else {
		copy(pkt[8:24], r.origDstIP.To16())
	}
	updateUDPChecksum(pkt)

	r.origDstIP = nil
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
