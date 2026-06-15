package internal

import (
	"encoding/binary"
	"net"
	"testing"
)

// buildIPv4UDP constructs a minimal IPv4+UDP packet for testing.
func buildIPv4UDP(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	udpLen := 8 + len(payload)
	totalLen := 20 + udpLen
	pkt := make([]byte, totalLen)

	pkt[0] = 0x45
	pkt[1] = 0x00
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[4:6], 0x1234)
	binary.BigEndian.PutUint16(pkt[6:8], 0x0000)
	pkt[8] = 64
	pkt[9] = 17
	pkt[10] = 0
	pkt[11] = 0
	copy(pkt[12:16], srcIP.To4())
	copy(pkt[16:20], dstIP.To4())

	cs := ipChecksum(pkt[:20])
	pkt[10] = byte(cs >> 8)
	pkt[11] = byte(cs)

	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	binary.BigEndian.PutUint16(pkt[24:26], uint16(udpLen))
	pkt[26] = 0
	pkt[27] = 0
	copy(pkt[28:], payload)

	udpCS := computeUDPChecksum(pkt)
	if udpCS == 0 {
		udpCS = 0xffff
	}
	pkt[26] = byte(udpCS >> 8)
	pkt[27] = byte(udpCS)

	return pkt
}

// buildIPv6UDP constructs a minimal IPv6+UDP packet for testing.
func buildIPv6UDP(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	udpLen := 8 + len(payload)
	pkt := make([]byte, 40+udpLen)

	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(udpLen))
	pkt[6] = 17
	pkt[7] = 64
	copy(pkt[8:24], srcIP.To16())
	copy(pkt[24:40], dstIP.To16())

	binary.BigEndian.PutUint16(pkt[40:42], srcPort)
	binary.BigEndian.PutUint16(pkt[42:44], dstPort)
	binary.BigEndian.PutUint16(pkt[44:46], uint16(udpLen))
	pkt[46] = 0
	pkt[47] = 0
	copy(pkt[48:], payload)

	udpCS := computeUDPChecksum(pkt)
	pkt[46] = byte(udpCS >> 8)
	pkt[47] = byte(udpCS)

	return pkt
}

func verifyIPv4Checksum(t *testing.T, pkt []byte) {
	t.Helper()
	ihl := int(pkt[0]&0x0f) * 4
	var sum uint32
	for i := 0; i+1 < ihl; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pkt[i:]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	if uint16(sum) != 0xffff {
		t.Errorf("IPv4 header checksum invalid: sum=0x%04x", sum)
	}
}

func verifyUDPChecksum(t *testing.T, pkt []byte) {
	t.Helper()
	udpOff := udpOffset(pkt)
	if udpOff < 0 || len(pkt) < udpOff+8 {
		t.Fatal("invalid packet for UDP checksum verification")
	}

	saved := pkt[udpOff+6]
	saved2 := pkt[udpOff+7]
	pkt[udpOff+6] = 0
	pkt[udpOff+7] = 0
	expected := computeUDPChecksum(pkt)
	pkt[udpOff+6] = saved
	pkt[udpOff+7] = saved2

	actual := binary.BigEndian.Uint16(pkt[udpOff+6:])
	if actual != expected {
		t.Errorf("UDP checksum mismatch: actual=0x%04x expected=0x%04x", actual, expected)
	}
}

func TestDNSRewriter_IPv4_QueryRewrite(t *testing.T) {
	srcIP := net.ParseIP("10.0.0.1")
	origDst := net.ParseIP("203.0.113.1")
	hijackDst := net.ParseIP("1.1.1.1")
	payload := []byte{0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00}

	pkt := buildIPv4UDP(srcIP, origDst, 12345, 53, payload)
	origIPCS := binary.BigEndian.Uint16(pkt[10:12])
	origUDPCS := binary.BigEndian.Uint16(pkt[26:28])

	r := NewDNSRewriter(hijackDst, nil)
	r.RewriteQuery(pkt)

	if !net.IP(pkt[16:20]).Equal(hijackDst.To4()) {
		t.Errorf("dst IP not rewritten: got %v, want %v", net.IP(pkt[16:20]), hijackDst)
	}
	if binary.BigEndian.Uint16(pkt[10:12]) == origIPCS {
		t.Error("IP checksum should change after dst rewrite")
	}
	if binary.BigEndian.Uint16(pkt[26:28]) == origUDPCS {
		t.Error("UDP checksum should change after dst rewrite")
	}

	verifyIPv4Checksum(t, pkt)
	verifyUDPChecksum(t, pkt)
}

func TestDNSRewriter_IPv4_FullRoundtrip(t *testing.T) {
	srcIP := net.ParseIP("10.0.0.1")
	origDst := net.ParseIP("203.0.113.1")
	hijackDst := net.ParseIP("1.1.1.1")
	payload := []byte{0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00}

	query := buildIPv4UDP(srcIP, origDst, 12345, 53, payload)
	origSrcBytes := make([]byte, 4)
	copy(origSrcBytes, query[12:16])
	origDstBytes := make([]byte, 4)
	copy(origDstBytes, query[16:20])

	r := NewDNSRewriter(hijackDst, nil)
	r.RewriteQuery(query)

	if !net.IP(query[16:20]).Equal(hijackDst.To4()) {
		t.Fatal("query dst not rewritten")
	}

	respPayload := []byte{0xAB, 0xCD, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01}
	resp := buildIPv4UDP(hijackDst, srcIP, 53, 12345, respPayload)

	r.RewriteResponse(resp)

	if !net.IP(resp[12:16]).Equal(origDst) {
		t.Errorf("response src not restored: got %v, want %v", net.IP(resp[12:16]), origDst)
	}
	if !net.IP(resp[16:20]).Equal(srcIP) {
		t.Errorf("response dst should be original src: got %v, want %v", net.IP(resp[16:20]), srcIP)
	}

	verifyIPv4Checksum(t, resp)
	verifyUDPChecksum(t, resp)
}

func TestDNSRewriter_IPv6_QueryRewrite(t *testing.T) {
	srcIP := net.ParseIP("fd00::1")
	origDst := net.ParseIP("2001:4860:4860::8888")
	hijackDst := net.ParseIP("2606:4700:4700::1111")
	payload := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00}

	pkt := buildIPv6UDP(srcIP, origDst, 54321, 53, payload)

	r := NewDNSRewriter(nil, hijackDst)
	r.RewriteQuery(pkt)

	if !net.IP(pkt[24:40]).Equal(hijackDst) {
		t.Errorf("IPv6 dst not rewritten: got %v, want %v", net.IP(pkt[24:40]), hijackDst)
	}
	if !net.IP(pkt[8:24]).Equal(srcIP) {
		t.Errorf("IPv6 src should not change: got %v", net.IP(pkt[8:24]))
	}

	verifyUDPChecksum(t, pkt)
}

func TestDNSRewriter_IPv6_FullRoundtrip(t *testing.T) {
	srcIP := net.ParseIP("fd00::1")
	origDst := net.ParseIP("2001:4860:4860::8888")
	hijackDst := net.ParseIP("2606:4700:4700::1111")
	payload := []byte{0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00}

	r := NewDNSRewriter(nil, hijackDst)

	query := buildIPv6UDP(srcIP, origDst, 54321, 53, payload)
	r.RewriteQuery(query)
	if !net.IP(query[24:40]).Equal(hijackDst) {
		t.Fatal("IPv6 query dst not rewritten")
	}

	respPayload := []byte{0xAB, 0xCD, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01}
	resp := buildIPv6UDP(hijackDst, srcIP, 53, 54321, respPayload)
	r.RewriteResponse(resp)

	if !net.IP(resp[8:24]).Equal(origDst) {
		t.Errorf("IPv6 response src not restored: got %v, want %v", net.IP(resp[8:24]), origDst)
	}

	verifyUDPChecksum(t, resp)
}

func TestDNSRewriter_NonDNS_PassThrough(t *testing.T) {
	srcIP := net.ParseIP("10.0.0.1")
	dstIP := net.ParseIP("93.184.216.34")
	payload := []byte("GET / HTTP/1.1\r\n")

	pkt := buildIPv4UDP(srcIP, dstIP, 50000, 443, payload)
	orig := make([]byte, len(pkt))
	copy(orig, pkt)

	r := NewDNSRewriter(net.ParseIP("1.1.1.1"), nil)
	r.RewriteQuery(pkt)
	r.RewriteResponse(pkt)

	for i := range pkt {
		if pkt[i] != orig[i] {
			t.Fatalf("non-DNS packet modified at byte %d: got 0x%02x, want 0x%02x", i, pkt[i], orig[i])
		}
	}
}

func TestDNSRewriter_NilTarget_NoOp(t *testing.T) {
	pkt := buildIPv4UDP(
		net.ParseIP("10.0.0.1"), net.ParseIP("8.8.8.8"),
		12345, 53, []byte{0x01, 0x02},
	)
	orig := make([]byte, len(pkt))
	copy(orig, pkt)

	r := NewDNSRewriter(nil, nil)
	r.RewriteQuery(pkt)

	for i := range pkt {
		if pkt[i] != orig[i] {
			t.Fatalf("nil target should be no-op, but byte %d changed", i)
		}
	}
}

func TestDNSRewriter_FragmentedPacket_Skipped(t *testing.T) {
	pkt := buildIPv4UDP(
		net.ParseIP("10.0.0.1"), net.ParseIP("8.8.8.8"),
		12345, 53, []byte{0x01, 0x02},
	)
	binary.BigEndian.PutUint16(pkt[6:8], 0x0001)

	orig := make([]byte, len(pkt))
	copy(orig, pkt)

	r := NewDNSRewriter(net.ParseIP("1.1.1.1"), nil)
	r.RewriteQuery(pkt)

	for i := range pkt {
		if pkt[i] != orig[i] {
			t.Fatalf("fragmented packet should be skipped, but byte %d changed", i)
		}
	}
}

func TestDNSRewriter_ResponseWithoutQuery_NoOp(t *testing.T) {
	pkt := buildIPv4UDP(
		net.ParseIP("1.1.1.1"), net.ParseIP("10.0.0.1"),
		53, 12345, []byte{0xAB, 0xCD},
	)
	orig := make([]byte, len(pkt))
	copy(orig, pkt)

	r := NewDNSRewriter(net.ParseIP("1.1.1.1"), nil)
	r.RewriteResponse(pkt)

	for i := range pkt {
		if pkt[i] != orig[i] {
			t.Fatalf("response without prior query should be no-op, but byte %d changed", i)
		}
	}
}

func TestDNSRewriter_WrongSourceIP_NoOp(t *testing.T) {
	srcIP := net.ParseIP("10.0.0.1")
	origDst := net.ParseIP("203.0.113.1")
	hijackDst := net.ParseIP("1.1.1.1")

	r := NewDNSRewriter(hijackDst, nil)

	query := buildIPv4UDP(srcIP, origDst, 12345, 53, []byte{0x01})
	r.RewriteQuery(query)

	wrongSrc := net.ParseIP("9.9.9.9")
	resp := buildIPv4UDP(wrongSrc, srcIP, 53, 12345, []byte{0x02})
	orig := make([]byte, len(resp))
	copy(orig, resp)

	r.RewriteResponse(resp)

	for i := range resp {
		if resp[i] != orig[i] {
			t.Fatalf("response from wrong IP should be no-op, but byte %d changed", i)
		}
	}
}

func TestDNSRewriter_MultipleRoundtrips(t *testing.T) {
	hijackDst := net.ParseIP("1.1.1.1")
	r := NewDNSRewriter(hijackDst, nil)

	for i := 0; i < 3; i++ {
		srcIP := net.ParseIP("10.0.0.1")
		origDst := net.IPv4(203, 0, 113, byte(i+1))
		srcPort := uint16(12345 + i)

		query := buildIPv4UDP(srcIP, origDst, srcPort, 53, []byte{byte(i)})
		r.RewriteQuery(query)

		if !net.IP(query[16:20]).Equal(hijackDst.To4()) {
			t.Fatalf("round %d: query dst not rewritten", i)
		}

		resp := buildIPv4UDP(hijackDst, srcIP, 53, srcPort, []byte{byte(i + 0x80)})
		r.RewriteResponse(resp)

		if !net.IP(resp[12:16]).Equal(origDst) {
			t.Errorf("round %d: response src not restored: got %v, want %v", i, net.IP(resp[12:16]), origDst)
		}

		verifyIPv4Checksum(t, resp)
		verifyUDPChecksum(t, resp)
	}
}

func TestIPChecksum_ValidHeader(t *testing.T) {
	pkt := buildIPv4UDP(
		net.ParseIP("10.0.0.1"), net.ParseIP("1.1.1.1"),
		12345, 53, []byte{0x01, 0x02, 0x03, 0x04},
	)
	verifyIPv4Checksum(t, pkt)
}

func TestUDPChecksum_IPv4_Valid(t *testing.T) {
	pkt := buildIPv4UDP(
		net.ParseIP("10.0.0.1"), net.ParseIP("1.1.1.1"),
		12345, 53, []byte("dns query payload"),
	)
	verifyUDPChecksum(t, pkt)
}

func TestUDPChecksum_IPv6_Valid(t *testing.T) {
	pkt := buildIPv6UDP(
		net.ParseIP("fd00::1"), net.ParseIP("2606:4700:4700::1111"),
		54321, 53, []byte("dns query payload"),
	)
	verifyUDPChecksum(t, pkt)
}

func TestDNSRewriter_ConcurrentQueries(t *testing.T) {
	hijackDst := net.ParseIP("1.1.1.1")
	r := NewDNSRewriter(hijackDst, nil)

	srcIP := net.ParseIP("10.0.0.1")

	queryA := buildIPv4UDP(srcIP, net.ParseIP("203.0.113.1"), 11111, 53, []byte{0x0A})
	queryB := buildIPv4UDP(srcIP, net.ParseIP("8.8.8.8"), 22222, 53, []byte{0x0B})
	queryC := buildIPv4UDP(srcIP, net.ParseIP("9.9.9.9"), 33333, 53, []byte{0x0C})

	r.RewriteQuery(queryA)
	r.RewriteQuery(queryB)
	r.RewriteQuery(queryC)

	if !net.IP(queryA[16:20]).Equal(hijackDst.To4()) {
		t.Fatal("queryA dst not rewritten")
	}
	if !net.IP(queryB[16:20]).Equal(hijackDst.To4()) {
		t.Fatal("queryB dst not rewritten")
	}

	respB := buildIPv4UDP(hijackDst, srcIP, 53, 22222, []byte{0x8B})
	r.RewriteResponse(respB)
	if !net.IP(respB[12:16]).Equal(net.ParseIP("8.8.8.8")) {
		t.Errorf("respB src not restored to 8.8.8.8: got %v", net.IP(respB[12:16]))
	}
	verifyIPv4Checksum(t, respB)
	verifyUDPChecksum(t, respB)

	respA := buildIPv4UDP(hijackDst, srcIP, 53, 11111, []byte{0x8A})
	r.RewriteResponse(respA)
	if !net.IP(respA[12:16]).Equal(net.ParseIP("203.0.113.1")) {
		t.Errorf("respA src not restored to 203.0.113.1: got %v", net.IP(respA[12:16]))
	}
	verifyIPv4Checksum(t, respA)
	verifyUDPChecksum(t, respA)

	respC := buildIPv4UDP(hijackDst, srcIP, 53, 33333, []byte{0x8C})
	r.RewriteResponse(respC)
	if !net.IP(respC[12:16]).Equal(net.ParseIP("9.9.9.9")) {
		t.Errorf("respC src not restored to 9.9.9.9: got %v", net.IP(respC[12:16]))
	}
	verifyIPv4Checksum(t, respC)
	verifyUDPChecksum(t, respC)
}

func TestDNSRewriter_RingBufferEviction(t *testing.T) {
	hijackDst := net.ParseIP("1.1.1.1")
	r := NewDNSRewriter(hijackDst, nil)

	// All source ports with &0xf == 0 land in shard 0.
	// Fill shard 0 to capacity (maxPerShard = 256).
	type queryInfo struct {
		origDst net.IP
		pkt     []byte
		port    uint16
	}
	var queries []queryInfo

	for i := 0; i < maxPerShard; i++ {
		port := uint16(i * numShards)
		origDst := net.IPv4(203, 0, byte(i>>8), byte(i&0xff))
		srcIP := net.ParseIP("10.0.0.1")
		pkt := buildIPv4UDP(srcIP, origDst, port, 53, []byte{byte(i)})
		r.RewriteQuery(pkt)
		queries = append(queries, queryInfo{origDst: origDst, pkt: pkt, port: port})
	}

	// One more query to the same shard triggers eviction of the oldest.
	overflowPort := uint16(maxPerShard * numShards)
	overflowDst := net.IPv4(203, 0, 255, 255)
	srcIP := net.ParseIP("10.0.0.1")
	overflowPkt := buildIPv4UDP(srcIP, overflowDst, overflowPort, 53, []byte{0xFF})
	r.RewriteQuery(overflowPkt)

	// The oldest entry (i=0, port 0) should be evicted.
	resp0 := buildIPv4UDP(hijackDst, srcIP, 53, queries[0].port, []byte{0x80})
	r.RewriteResponse(resp0)
	if net.IP(resp0[12:16]).Equal(queries[0].origDst) {
		t.Errorf("oldest entry (port %d) should have been evicted but was still resolved", queries[0].port)
	}

	// The second entry (i=1) should still be resolvable.
	resp1 := buildIPv4UDP(hijackDst, srcIP, 53, queries[1].port, []byte{0x81})
	r.RewriteResponse(resp1)
	if !net.IP(resp1[12:16]).Equal(queries[1].origDst) {
		t.Errorf("second entry should still resolve: got %v, want %v",
			net.IP(resp1[12:16]), queries[1].origDst)
	}

	// The last entry before overflow should still resolve.
	last := len(queries) - 1
	respLast := buildIPv4UDP(hijackDst, srcIP, 53, queries[last].port, []byte{0x82})
	r.RewriteResponse(respLast)
	if !net.IP(respLast[12:16]).Equal(queries[last].origDst) {
		t.Errorf("last pre-overflow entry should resolve: got %v, want %v",
			net.IP(respLast[12:16]), queries[last].origDst)
	}
}

// buildIPv6UDPWithExtHdr constructs an IPv6+UDP packet with a Hop-by-Hop
// extension header (8 bytes) between the IPv6 header and UDP header.
func buildIPv6UDPWithExtHdr(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	udpLen := 8 + len(payload)
	hbhLen := 8
	pkt := make([]byte, 40+hbhLen+udpLen)

	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(hbhLen+udpLen))
	pkt[6] = 0   // Next Header: Hop-by-Hop Options
	pkt[7] = 64  // Hop Limit
	copy(pkt[8:24], srcIP.To16())
	copy(pkt[24:40], dstIP.To16())

	// Hop-by-Hop: next=UDP(17), hdrExtLen=0 → (0+1)*8=8 bytes total
	pkt[40] = 17 // Next Header: UDP
	pkt[41] = 0  // Hdr Ext Len: 0 → 8 bytes
	// Pad6 option (type=1, len=4, zeros) to fill remaining 6 bytes
	pkt[42] = 1
	pkt[43] = 4

	udpOff := 48
	binary.BigEndian.PutUint16(pkt[udpOff:], srcPort)
	binary.BigEndian.PutUint16(pkt[udpOff+2:], dstPort)
	binary.BigEndian.PutUint16(pkt[udpOff+4:], uint16(udpLen))
	pkt[udpOff+6] = 0
	pkt[udpOff+7] = 0
	copy(pkt[udpOff+8:], payload)

	cs := computeUDPChecksum(pkt)
	pkt[udpOff+6] = byte(cs >> 8)
	pkt[udpOff+7] = byte(cs)

	return pkt
}

func TestDNSRewriter_IPv6_ExtensionHeaders(t *testing.T) {
	srcIP := net.ParseIP("fd00::1")
	origDst := net.ParseIP("2001:4860:4860::8888")
	hijackDst := net.ParseIP("2606:4700:4700::1111")
	payload := []byte{0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00}

	pkt := buildIPv6UDPWithExtHdr(srcIP, origDst, 54321, 53, payload)

	r := NewDNSRewriter(nil, hijackDst)
	r.RewriteQuery(pkt)

	if !net.IP(pkt[24:40]).Equal(hijackDst) {
		t.Errorf("IPv6 dst not rewritten with ext headers: got %v, want %v",
			net.IP(pkt[24:40]), hijackDst)
	}

	verifyUDPChecksum(t, pkt)
}

func TestDNSRewriter_IPv6_ExtHeaders_Roundtrip(t *testing.T) {
	srcIP := net.ParseIP("fd00::1")
	origDst := net.ParseIP("2001:4860:4860::8888")
	hijackDst := net.ParseIP("2606:4700:4700::1111")
	payload := []byte{0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00}

	r := NewDNSRewriter(nil, hijackDst)

	query := buildIPv6UDPWithExtHdr(srcIP, origDst, 54321, 53, payload)
	r.RewriteQuery(query)
	if !net.IP(query[24:40]).Equal(hijackDst) {
		t.Fatal("IPv6 query dst not rewritten with ext headers")
	}

	respPayload := []byte{0xAB, 0xCD, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01}
	resp := buildIPv6UDPWithExtHdr(hijackDst, srcIP, 53, 54321, respPayload)
	r.RewriteResponse(resp)

	if !net.IP(resp[8:24]).Equal(origDst) {
		t.Errorf("IPv6 response src not restored: got %v, want %v",
			net.IP(resp[8:24]), origDst)
	}

	verifyUDPChecksum(t, resp)
}

func TestSkipIPv6ExtHeaders(t *testing.T) {
	tests := []struct {
		name       string
		nextHeader byte
		extData    []byte // bytes starting at offset 40
		wantNH     byte
		wantOff    int
	}{
		{
			name:       "no extension (direct UDP)",
			nextHeader: 17,
			extData:    nil,
			wantNH:     17,
			wantOff:    40,
		},
		{
			name:       "hop-by-hop then UDP",
			nextHeader: 0,
			extData: []byte{
				17, 0, // next=UDP, hdrExtLen=0 → 8 bytes
				1, 4, 0, 0, 0, 0, // Pad6
			},
			wantNH:  17,
			wantOff: 48,
		},
		{
			name:       "fragment then UDP",
			nextHeader: 44,
			extData: []byte{
				17, 0, 0, 0, // next=UDP, reserved, fragOff+flags
				0, 0, 0, 0, // identification
			},
			wantNH:  17,
			wantOff: 48,
		},
		{
			name:       "hop-by-hop + fragment then UDP",
			nextHeader: 0,
			extData: []byte{
				44, 0,                   // HBH: next=Fragment, hdrExtLen=0 → 8 bytes
				1, 4, 0, 0, 0, 0,       // Pad6
				17, 0, 0, 0, 0, 0, 0, 0, // Fragment: next=UDP, 8 bytes
			},
			wantNH:  17,
			wantOff: 56,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := make([]byte, 40+len(tt.extData)+8)
			pkt[6] = tt.nextHeader
			copy(pkt[40:], tt.extData)

			nh, off := skipIPv6ExtHeaders(pkt, pkt[6], 40)
			if nh != tt.wantNH {
				t.Errorf("nextHeader: got %d, want %d", nh, tt.wantNH)
			}
			if off != tt.wantOff {
				t.Errorf("offset: got %d, want %d", off, tt.wantOff)
			}
		})
	}
}

func BenchmarkRewriteQuery_IPv4(b *testing.B) {
	hijackDst := net.ParseIP("1.1.1.1")
	r := NewDNSRewriter(hijackDst, nil)
	srcIP := net.ParseIP("10.0.0.1")
	origDst := net.ParseIP("203.0.113.1")
	payload := make([]byte, 64)
	for i := range payload {
		payload[i] = byte(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pkt := buildIPv4UDP(srcIP, origDst, uint16(i), 53, payload)
		r.RewriteQuery(pkt)
	}
}

func BenchmarkRewriteQuery_IPv6(b *testing.B) {
	hijackDst := net.ParseIP("2606:4700:4700::1111")
	r := NewDNSRewriter(nil, hijackDst)
	srcIP := net.ParseIP("fd00::1")
	origDst := net.ParseIP("2001:4860:4860::8888")
	payload := make([]byte, 64)
	for i := range payload {
		payload[i] = byte(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pkt := buildIPv6UDP(srcIP, origDst, uint16(i), 53, payload)
		r.RewriteQuery(pkt)
	}
}
