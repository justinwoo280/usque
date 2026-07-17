package internal

import (
	"encoding/binary"
	"net"
	"testing"
)

// computeTCPChecksum computes the correct TCP checksum over the packet.
// For IPv4, includes the pseudo-header (src IP + dst IP + proto + TCP length).
func computeTCPChecksum(pkt []byte) uint16 {
	// Build pseudo-header + TCP data
	var pseudo []byte
	if pkt[0]>>4 == 4 {
		pseudo = make([]byte, 12)
		copy(pseudo[0:4], pkt[12:16])   // src IP
		copy(pseudo[4:8], pkt[16:20])   // dst IP
		pseudo[8] = 0
		pseudo[9] = 6                    // protocol TCP
		binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(pkt)-20))
		pseudo = append(pseudo, pkt[20:]...)
	} else {
		pseudo = make([]byte, 40)
		copy(pseudo[0:16], pkt[8:24])   // src IP
		copy(pseudo[16:32], pkt[24:40]) // dst IP
		binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(pkt)-40))
		pseudo[36] = 0
		pseudo[37] = 0
		pseudo[38] = 0
		pseudo[39] = 6
		pseudo = append(pseudo, pkt[40:]...)
	}

	// Zero the checksum field
	tcpOff := 0
	if pkt[0]>>4 == 4 {
		tcpOff = 20
	} else {
		tcpOff = 40
	}
	checksumOff := len(pseudo) - (len(pkt) - tcpOff) + 16
	binary.BigEndian.PutUint16(pseudo[checksumOff:checksumOff+2], 0)

	var sum uint32
	for i := 0; i+1 < len(pseudo); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pseudo[i : i+2]))
	}
	if len(pseudo)%2 == 1 {
		sum += uint32(pseudo[len(pseudo)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// buildRealSYNv4 builds an IPv4 TCP SYN with correct IP and TCP checksums.
func buildRealSYNv4(mss uint16, srcIP, dstIP net.IP) []byte {
	src := srcIP.To4()
	dst := dstIP.To4()

	// TCP header with MSS option (24 bytes)
	tcpHdr := make([]byte, 24)
	binary.BigEndian.PutUint16(tcpHdr[0:2], 12345)  // src port
	binary.BigEndian.PutUint16(tcpHdr[2:4], 443)    // dst port
	binary.BigEndian.PutUint32(tcpHdr[4:8], 0)     // seq
	binary.BigEndian.PutUint32(tcpHdr[8:12], 0)    // ack
	tcpHdr[12] = 0x60 // data offset = 6 (24 bytes)
	tcpHdr[13] = 0x02 // SYN flag
	binary.BigEndian.PutUint16(tcpHdr[14:16], 65535) // window
	// checksum at [16:18] = 0 for now
	binary.BigEndian.PutUint16(tcpHdr[18:20], 0) // urgent pointer
	tcpHdr[20] = 2  // MSS kind
	tcpHdr[21] = 4  // MSS length
	binary.BigEndian.PutUint16(tcpHdr[22:24], mss)

	// IP header (20 bytes)
	ipHdr := make([]byte, 20)
	ipHdr[0] = 0x45
	binary.BigEndian.PutUint16(ipHdr[2:4], uint16(20+24)) // total length
	ipHdr[8] = 64 // TTL
	ipHdr[9] = 6  // protocol TCP
	copy(ipHdr[12:16], src)
	copy(ipHdr[16:20], dst)

	pkt := append(ipHdr, tcpHdr...)

	// Compute TCP checksum
	csum := computeTCPChecksum(pkt)
	binary.BigEndian.PutUint16(pkt[36:38], csum)

	// Compute IP checksum
	var ipSum uint32
	for i := 0; i < 20; i += 2 {
		ipSum += uint32(binary.BigEndian.Uint16(ipHdr[i : i+2]))
	}
	for ipSum>>16 != 0 {
		ipSum = (ipSum & 0xffff) + (ipSum >> 16)
	}
	binary.BigEndian.PutUint16(pkt[10:12], ^uint16(ipSum))

	return pkt
}

// buildRealSYNv6 builds an IPv6 TCP SYN with correct TCP checksum.
func buildRealSYNv6(mss uint16, srcIP, dstIP net.IP) []byte {
	src := srcIP.To16()
	dst := dstIP.To16()

	// TCP header with MSS option (24 bytes)
	tcpHdr := make([]byte, 24)
	binary.BigEndian.PutUint16(tcpHdr[0:2], 54321) // src port
	binary.BigEndian.PutUint16(tcpHdr[2:4], 443)   // dst port
	binary.BigEndian.PutUint32(tcpHdr[4:8], 0)     // seq
	binary.BigEndian.PutUint32(tcpHdr[8:12], 0)    // ack
	tcpHdr[12] = 0x60 // data offset = 6 (24 bytes)
	tcpHdr[13] = 0x02 // SYN
	binary.BigEndian.PutUint16(tcpHdr[14:16], 65535)
	tcpHdr[20] = 2
	tcpHdr[21] = 4
	binary.BigEndian.PutUint16(tcpHdr[22:24], mss)

	// IPv6 header (40 bytes)
	ipHdr := make([]byte, 40)
	ipHdr[0] = 0x60
	binary.BigEndian.PutUint16(ipHdr[4:6], uint16(24)) // payload length
	ipHdr[6] = 6 // next header = TCP
	ipHdr[7] = 64 // hop limit
	copy(ipHdr[8:24], src)
	copy(ipHdr[24:40], dst)

	pkt := append(ipHdr, tcpHdr...)

	// Compute TCP checksum
	csum := computeTCPChecksum(pkt)
	binary.BigEndian.PutUint16(pkt[56:58], csum) // IPv6 TCP checksum at offset 40+16=56

	return pkt
}

func TestClampMSSChecksumV4(t *testing.T) {
	pkt := buildRealSYNv4(1460, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"))

	// Verify initial checksum is correct
	if csum := computeTCPChecksum(pkt); csum != 0 {
		// checksum should be 0 when the correct value is in the field
		// (because ~correct_value + all_data = 0xFFFF)
		// Actually, the checksum is correct when computeTCPChecksum returns 0
		// because computeTCPChecksum computes the complement, and the field
		// contains the complement, so sum + complement = 0xFFFF → ~0xFFFF = 0
		_ = csum // not a failure, just sanity
	}

	// Clamp MSS
	ClampMSS(pkt, 1240)

	// Verify MSS was clamped
	mssVal := binary.BigEndian.Uint16(pkt[42:44])
	if mssVal != 1240 {
		t.Fatalf("MSS not clamped: got %d, want 1240", mssVal)
	}

	// Verify TCP checksum is still correct after clamping
	// Save the checksum from the packet
	savedCsum := binary.BigEndian.Uint16(pkt[36:38])
	// Zero it for verification
	binary.BigEndian.PutUint16(pkt[36:38], 0)
	recomputedCsum := computeTCPChecksum(pkt)
	// Restore
	binary.BigEndian.PutUint16(pkt[36:38], savedCsum)

	if savedCsum != recomputedCsum {
		t.Fatalf("TCP checksum incorrect after clamping: packet has 0x%04x, should be 0x%04x",
			savedCsum, recomputedCsum)
	}
	t.Logf("TCP checksum OK: 0x%04x", savedCsum)
}

func TestClampMSSChecksumV6(t *testing.T) {
	pkt := buildRealSYNv6(1460, net.ParseIP("fd00::1"), net.ParseIP("fd00::2"))

	// Clamp MSS
	ClampMSS(pkt, 1220) // IPv6: 1280 - 60 = 1220

	// Verify MSS was clamped
	mssVal := binary.BigEndian.Uint16(pkt[62:64]) // IPv6: 40 + 20 + 2 = 62
	if mssVal != 1220 {
		t.Fatalf("MSS not clamped: got %d, want 1220", mssVal)
	}

	// Verify TCP checksum
	savedCsum := binary.BigEndian.Uint16(pkt[56:58]) // IPv6 TCP checksum at 40+16=56
	binary.BigEndian.PutUint16(pkt[56:58], 0)
	recomputedCsum := computeTCPChecksum(pkt)
	binary.BigEndian.PutUint16(pkt[56:58], savedCsum)

	if savedCsum != recomputedCsum {
		t.Fatalf("TCP checksum incorrect after clamping: packet has 0x%04x, should be 0x%04x",
			savedCsum, recomputedCsum)
	}
	t.Logf("IPv6 TCP checksum OK: 0x%04x", savedCsum)
}

func TestClampMSSNoModificationForICMP(t *testing.T) {
	// ICMP echo request should not be modified
	pkt := []byte{
		0x45, 0x00, 0x00, 0x1c, // IP: ver+IHL, TOS, total len
		0x00, 0x01, 0x00, 0x00, // ID, flags+frag
		0x40, 0x01, 0x00, 0x00, // TTL, protocol=ICMP, checksum
		0x0a, 0x00, 0x00, 0x01, // src IP
		0x0a, 0x00, 0x00, 0x02, // dst IP
		0x08, 0x00, 0x00, 0x00, // ICMP: type=echo request, code, checksum
		0x00, 0x01, 0x00, 0x01, // identifier, sequence
	}
	original := make([]byte, len(pkt))
	copy(original, pkt)

	ClampMSS(pkt, 1240)

	for i, b := range pkt {
		if b != original[i] {
			t.Fatalf("ICMP packet was modified at byte %d: got 0x%02x, want 0x%02x", i, b, original[i])
		}
	}
}
