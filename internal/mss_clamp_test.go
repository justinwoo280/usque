package internal

import (
	"encoding/binary"
	"testing"
)

// buildSYNv4 constructs an IPv4 TCP SYN packet with the given MSS option value.
func buildSYNv4(mss uint16) []byte {
	// IPv4 header (20 bytes, no options)
	ipHdr := make([]byte, 20)
	ipHdr[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(ipHdr[2:4], 60) // total length
	ipHdr[8] = 64                                // TTL
	ipHdr[9] = 6                                  // protocol TCP
	// src/dst IP
	copy(ipHdr[12:16], []byte{10, 0, 0, 1})
	copy(ipHdr[16:20], []byte{10, 0, 0, 2})

	// TCP header with MSS option (24 bytes = 20 header + 4 MSS option)
	tcpHdr := make([]byte, 24)
	tcpHdr[12] = 0x60 // data offset = 6 (24 bytes)
	tcpHdr[13] = 0x02 // SYN flag
	// MSS option: kind=2, length=4, value=mss
	tcpHdr[20] = 2 // kind MSS
	tcpHdr[21] = 4 // length
	binary.BigEndian.PutUint16(tcpHdr[22:24], mss)

	pkt := append(ipHdr, tcpHdr...)
	// Compute TCP checksum (simplified: just set to a fixed value for testing)
	// In production, the incremental update will fix it regardless of initial value.
	binary.BigEndian.PutUint16(pkt[36:38], 0x1234)

	return pkt
}

func TestClampMSSReduces(t *testing.T) {
	pkt := buildSYNv4(1460)
	ClampMSS(pkt, 1240) // MTU 1280 - 40 = 1240

	tcpOff := 20
	mssVal := binary.BigEndian.Uint16(pkt[tcpOff+22 : tcpOff+24])
	if mssVal != 1240 {
		t.Errorf("MSS not clamped: got %d, want 1240", mssVal)
	}
}

func TestClampMSSAlreadySmall(t *testing.T) {
	pkt := buildSYNv4(1000)
	ClampMSS(pkt, 1240)

	tcpOff := 20
	mssVal := binary.BigEndian.Uint16(pkt[tcpOff+22 : tcpOff+24])
	if mssVal != 1000 {
		t.Errorf("MSS should not be increased: got %d, want 1000", mssVal)
	}
}

func TestClampMSSNonSYN(t *testing.T) {
	pkt := buildSYNv4(1460)
	// Change SYN to ACK
	pkt[33] = 0x10 // ACK flag only
	ClampMSS(pkt, 1240)

	tcpOff := 20
	mssVal := binary.BigEndian.Uint16(pkt[tcpOff+22 : tcpOff+24])
	if mssVal != 1460 {
		t.Errorf("MSS should not be changed for non-SYN: got %d, want 1460", mssVal)
	}
}

func TestClampMSSNonTCP(t *testing.T) {
	pkt := buildSYNv4(1460)
	pkt[9] = 17 // protocol UDP
	ClampMSS(pkt, 1240)

	tcpOff := 20
	mssVal := binary.BigEndian.Uint16(pkt[tcpOff+22 : tcpOff+24])
	if mssVal != 1460 {
		t.Errorf("MSS should not be changed for non-TCP: got %d, want 1460", mssVal)
	}
}

func TestMSSForMTU(t *testing.T) {
	if got := MSSForMTU(4, 1280); got != 1240 {
		t.Errorf("IPv4 MSS for MTU 1280: got %d, want 1240", got)
	}
	if got := MSSForMTU(6, 1280); got != 1220 {
		t.Errorf("IPv6 MSS for MTU 1280: got %d, want 1220", got)
	}
}
