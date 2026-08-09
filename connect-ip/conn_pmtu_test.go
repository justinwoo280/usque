package connectip

import (
	"context"
	"encoding/binary"
	"io"
	"sync"
	"testing"

	"github.com/apernet/quic-go"
	"golang.org/x/net/icmp"
)

type pmtuTestStream struct {
	mu         sync.Mutex
	streamID   quic.StreamID
	maxPayload int
	sendCalls  int
}

func (s *pmtuTestStream) Read([]byte) (int, error)        { return 0, io.EOF }
func (s *pmtuTestStream) Write(p []byte) (int, error)     { return len(p), nil }
func (s *pmtuTestStream) Close() error                    { return nil }
func (s *pmtuTestStream) CancelRead(quic.StreamErrorCode) {}
func (s *pmtuTestStream) StreamID() quic.StreamID         { return s.streamID }
func (s *pmtuTestStream) ReceiveDatagram(context.Context) ([]byte, error) {
	return nil, io.EOF
}
func (s *pmtuTestStream) SendDatagram(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sendCalls++
	h3PayloadLen := quicvarintLen(uint64(s.streamID/4)) + len(data)
	if h3PayloadLen > s.maxPayload {
		return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: int64(s.maxPayload)}
	}
	return nil
}

func (s *pmtuTestStream) setMaxPayload(n int) {
	s.mu.Lock()
	s.maxPayload = n
	s.mu.Unlock()
}

func (s *pmtuTestStream) calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sendCalls
}

func quicvarintLen(v uint64) int {
	switch {
	case v < 1<<6:
		return 1
	case v < 1<<14:
		return 2
	case v < 1<<30:
		return 4
	default:
		return 8
	}
}

func testIPv4Packet(size int) []byte {
	b := make([]byte, size)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(size))
	b[8] = 64
	b[9] = 17
	copy(b[12:16], []byte{192, 0, 2, 1})
	copy(b[16:20], []byte{198, 51, 100, 1})
	binary.BigEndian.PutUint16(b[10:12], calculateIPv4Checksum(([20]byte)(b[:20])))
	return b
}

func testIPv6Packet(size int) []byte {
	b := make([]byte, size)
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:6], uint16(size-40))
	b[6] = 17
	b[7] = 64
	copy(b[8:24], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	copy(b[24:40], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
	return b
}

func TestRefreshPMTUTracksChanges(t *testing.T) {
	stream := &pmtuTestStream{maxPayload: 1243}
	c := newProxiedConn(stream)

	mtu, changed, err := c.RefreshPMTU()
	if err != nil {
		t.Fatal(err)
	}
	if !changed || mtu != 1201 {
		t.Fatalf("first refresh = (%d, %t), want (1201, true)", mtu, changed)
	}

	stream.setMaxPayload(1452)
	mtu, changed, err = c.RefreshPMTU()
	if err != nil {
		t.Fatal(err)
	}
	if !changed || mtu != 1410 {
		t.Fatalf("second refresh = (%d, %t), want (1410, true)", mtu, changed)
	}

	mtu, changed, err = c.RefreshPMTU()
	if err != nil {
		t.Fatal(err)
	}
	if changed || mtu != 1410 {
		t.Fatalf("unchanged refresh = (%d, %t), want (1410, false)", mtu, changed)
	}

	stream.setMaxPayload(1300)
	mtu, changed, err = c.RefreshPMTU()
	if err != nil {
		t.Fatal(err)
	}
	if !changed || mtu != 1258 {
		t.Fatalf("decreased refresh = (%d, %t), want (1258, true)", mtu, changed)
	}
}

func TestRefreshPMTUUsesExactHTTP3StreamOverhead(t *testing.T) {
	stream := &pmtuTestStream{streamID: 256, maxPayload: 1452}
	c := newProxiedConn(stream)

	mtu, _, err := c.RefreshPMTU()
	if err != nil {
		t.Fatal(err)
	}
	// stream 256 has quarter-stream ID 64, encoded as a two-byte varint.
	if mtu != 1409 {
		t.Fatalf("effective MTU = %d, want 1409", mtu)
	}
}

func TestWritePacketPreflightsKnownPMTU(t *testing.T) {
	stream := &pmtuTestStream{maxPayload: 1300}
	c := newProxiedConn(stream)
	if _, _, err := c.RefreshPMTU(); err != nil {
		t.Fatal(err)
	}
	callsBeforeWrite := stream.calls()

	icmpPacket, err := c.WritePacket(testIPv4Packet(1299))
	if err != nil {
		t.Fatal(err)
	}
	if stream.calls() != callsBeforeWrite {
		t.Fatal("oversized packet reached SendDatagram despite cached PMTU")
	}
	if len(icmpPacket) < 28 {
		t.Fatalf("ICMP packet too short: %d", len(icmpPacket))
	}
	if got := int(binary.BigEndian.Uint32(icmpPacket[24:28])); got != 1258 {
		t.Fatalf("advertised IPv4 MTU = %d, want 1258", got)
	}
}

func TestWritePacketAdvertisesIPv6MTUBelow1280(t *testing.T) {
	stream := &pmtuTestStream{maxPayload: 1200}
	c := newProxiedConn(stream)
	if _, _, err := c.RefreshPMTU(); err != nil {
		t.Fatal(err)
	}

	icmpPacket, err := c.WritePacket(testIPv6Packet(1280))
	if err != nil {
		t.Fatal(err)
	}
	msg, err := icmp.ParseMessage(58, icmpPacket[40:])
	if err != nil {
		t.Fatal(err)
	}
	body, ok := msg.Body.(*icmp.PacketTooBig)
	if !ok {
		t.Fatalf("ICMP body type = %T, want *icmp.PacketTooBig", msg.Body)
	}
	if body.MTU != 1158 {
		t.Fatalf("advertised IPv6 MTU = %d, want 1158", body.MTU)
	}
}

func TestWritePacketProtectsWireGuardMTUFromQUICOverhead(t *testing.T) {
	stream := &pmtuTestStream{maxPayload: 1243}
	c := newProxiedConn(stream)
	if _, _, err := c.RefreshPMTU(); err != nil {
		t.Fatal(err)
	}

	if icmpPacket, err := c.WritePacket(testIPv4Packet(1420)); err != nil {
		t.Fatal(err)
	} else if len(icmpPacket) == 0 {
		t.Fatal("1420-byte packet should be rejected while the effective MTU is 1201")
	}

	stream.setMaxPayload(1452)
	if mtu, _, err := c.RefreshPMTU(); err != nil {
		t.Fatal(err)
	} else if mtu != 1410 {
		t.Fatalf("effective MTU = %d, want 1410", mtu)
	}
	callsBeforeWrite := stream.calls()

	if icmpPacket, err := c.WritePacket(testIPv4Packet(1420)); err != nil {
		t.Fatal(err)
	} else if len(icmpPacket) == 0 {
		t.Fatal("1420-byte packet should generate ICMP at effective MTU 1410")
	}
	if stream.calls() != callsBeforeWrite {
		t.Fatal("1420-byte packet reached the QUIC datagram stream")
	}

	if icmpPacket, err := c.WritePacket(testIPv4Packet(1410)); err != nil {
		t.Fatal(err)
	} else if len(icmpPacket) != 0 {
		t.Fatal("1410-byte packet unexpectedly generated ICMP")
	}
	if stream.calls() != callsBeforeWrite+1 {
		t.Fatal("1410-byte packet was not passed to the QUIC datagram stream")
	}
}
