package internal

import (
	"encoding/binary"
)

// TCP option kind constants.
const (
	tcKindEOL    = 0 // End of Option List
	tcKindNOP    = 1 // No-Operation
	tcKindMSS    = 2 // Maximum Segment Size
	tcKindLength = 4 // Length of MSS option (kind + len + 2 bytes value)
)

// ClampMSS clamps the TCP Maximum Segment Size option in-place for packets
// passing through a TUN device whose MTU is smaller than the sender's path
// MTU. This prevents PMTU black holes when ICMP Packet Too Big messages are
// filtered or PMTUD is disabled on the endpoint.
//
// It inspects TCP SYN and SYN-ACK packets (i.e., any segment with the SYN flag
// set), locates the MSS option in the TCP options, and reduces its value to
// maxMSS if the advertised MSS exceeds it. The TCP checksum is updated
// incrementally to account for the changed MSS bytes.
//
// Parameters:
//   - packet: the raw IP packet (IPv4 or IPv6), modified in-place.
//   - maxMSS: the maximum allowed MSS value (e.g. TUN_MTU - 40 for IPv4,
//     TUN_MTU - 60 for IPv6).
//
// The function is a no-op for non-TCP packets, TCP packets without the SYN
// flag, or SYN packets that have no MSS option or an MSS already <= maxMSS.
func ClampMSS(packet []byte, maxMSS int) {
	if len(packet) < 1 {
		return
	}

	version := packet[0] >> 4
	var ipHdrLen int
	var protocol byte

	switch version {
	case 4:
		if len(packet) < 20 {
			return
		}
		ihl := int(packet[0]&0x0f) * 4
		if ihl < 20 || len(packet) < ihl {
			return
		}
		protocol = packet[9]
		ipHdrLen = ihl
	case 6:
		if len(packet) < 40 {
			return
		}
		protocol = packet[6]
		ipHdrLen = 40
	default:
		return
	}

	if protocol != 6 { // TCP
		return
	}

	tcpOff := ipHdrLen
	if len(packet) < tcpOff+20 {
		return
	}

	tcp := packet[tcpOff:]
	flags := tcp[13]
	if flags&0x02 == 0 { // SYN flag not set
		return
	}

	dataOff := int(tcp[12]>>4) * 4
	if dataOff < 20 || len(tcp) < dataOff {
		return
	}

	mssOff, mssVal, found := findMSSOption(tcp[20:dataOff])
	if !found || mssVal <= uint16(maxMSS) {
		return
	}

	newMSS := uint16(maxMSS)
	off := tcpOff + 20 + mssOff

	// Incremental TCP checksum update: replace the 2 MSS bytes.
	oldWord := uint32(binary.BigEndian.Uint16(packet[off : off+2]))
	newWord := uint32(newMSS)

	// TCP checksum is at offset 16 in the TCP header (same for v4 and v6).
	csum := uint32(binary.BigEndian.Uint16(tcp[16:18]))
	csum = onesComplementSub(csum, oldWord, newWord)

	binary.BigEndian.PutUint16(packet[off:off+2], newMSS)
	binary.BigEndian.PutUint16(tcp[16:18], uint16(csum))
}

// findMSSOption scans TCP options starting at offset 0 (relative to the start
// of the options field). Returns the offset of the MSS value within the
// options, the MSS value, and whether an MSS option was found.
func findMSSOption(opts []byte) (offset int, value uint16, found bool) {
	i := 0
	for i < len(opts) {
		kind := opts[i]
		switch kind {
		case tcKindEOL:
			return 0, 0, false
		case tcKindNOP:
			i++
			continue
		case tcKindMSS:
			if i+tcKindLength > len(opts) {
				return 0, 0, false
			}
			// opts[i] = kind (2), opts[i+1] = length (4), opts[i+2:i+4] = MSS value
			mss := binary.BigEndian.Uint16(opts[i+2 : i+4])
			return i + 2, mss, true
		default:
			// Other options: use length field to skip.
			if i+1 >= len(opts) {
				return 0, 0, false
			}
			length := int(opts[i+1])
			if length < 2 {
				return 0, 0, false // malformed option
			}
			i += length
		}
	}
	return 0, 0, false
}

// onesComplementSub performs RFC 1624 incremental checksum update.
//
//	HC' = HC + ~old + new  (in 1's complement arithmetic)
//
// where ~old = 0xFFFF - old for 16-bit values.
// See RFC 1624: HC' = ~(~HC + ~m + m') = HC + ~m' + m.
// Here oldWord = m (the value being removed), newWord = m' (the value being added).
func onesComplementSub(hc, oldWord, newWord uint32) uint32 {
	// HC' = HC + ~newWord + oldWord  (RFC 1624 equation 3)
	hc = hc + (0xFFFF - newWord) + oldWord
	for hc>>16 != 0 {
		hc = (hc & 0xffff) + (hc >> 16)
	}
	return hc
}

// MSSForMTU returns the maximum TCP MSS for a given IP version and TUN MTU.
//
//	IPv4: MTU - 20 (IP header) - 20 (TCP header) = MTU - 40
//	IPv6: MTU - 40 (IP header) - 20 (TCP header) = MTU - 60
func MSSForMTU(version int, mtu int) int {
	switch version {
	case 4:
		return mtu - 40
	case 6:
		return mtu - 60
	default:
		return mtu - 40
	}
}

// ClampMSSPacket is a convenience that determines the right maxMSS from the
// packet's IP version and the TUN MTU, then calls ClampMSS.
func ClampMSSPacket(packet []byte, mtu int) {
	if len(packet) < 1 {
		return
	}
	version := int(packet[0] >> 4)
	maxMSS := MSSForMTU(version, mtu)
	ClampMSS(packet, maxMSS)
}
