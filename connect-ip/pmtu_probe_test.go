package connectip

import (
	"context"
	"encoding/binary"
	"io"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type echoTestStream struct {
	pmtuTestStream
	path   atomic.Int64
	rx     chan []byte
	closed chan struct{}
}

func (s *echoTestStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case b := <-s.rx:
		return b, nil
	case <-s.closed:
		return nil, io.EOF
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (s *echoTestStream) SendDatagram(b []byte) error {
	if len(b)+1 > 1452 {
		return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: 1452}
	}
	if len(b)-1 > int(s.path.Load()) {
		return nil
	} // accepted locally, black-holed on the path
	pkt := append([]byte(nil), b[1:]...)
	off, proto := 20, 1
	var pseudo []byte
	if pkt[0]>>4 == 4 {
		src := [4]byte(pkt[12:16])
		copy(pkt[12:16], pkt[16:20])
		copy(pkt[16:20], src[:])
		binary.BigEndian.PutUint16(pkt[10:12], calculateIPv4Checksum([20]byte(pkt[:20])))
	} else {
		off, proto = 40, 58
		src := [16]byte(pkt[8:24])
		copy(pkt[8:24], pkt[24:40])
		copy(pkt[24:40], src[:])
		pseudo = icmp.IPv6PseudoHeader(pkt[8:24], pkt[24:40])
	}
	m, err := icmp.ParseMessage(proto, pkt[off:])
	if err != nil {
		return err
	}
	if proto == 1 {
		m.Type = ipv4.ICMPTypeEchoReply
	} else {
		m.Type = ipv6.ICMPTypeEchoReply
	}
	msg, err := m.Marshal(pseudo)
	if err != nil {
		return err
	}
	copy(pkt[off:], msg)
	s.rx <- append([]byte{0}, pkt...)
	return nil
}

func TestWirePMTUBlackHoleRecoveryAndNoEcho(t *testing.T) {
	for _, pair := range [][2]string{{"192.0.2.1", "198.51.100.1"}, {"2001:db8::1", "2001:db8::2"}} {
		t.Run(pair[0], func(t *testing.T) {
			s := &echoTestStream{rx: make(chan []byte, 8), closed: make(chan struct{})}
			c := newConn(s, false)
			c.usesQUICDatagrams, c.httpDatagramOverhead = true, 1
			c.maxDatagramPayload.Store(1452)
			done := make(chan struct{})
			go func() { defer close(done); _, _ = c.ReadPacket(make([]byte, 2048), true) }()
			defer func() { close(s.closed); <-done }()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			for _, path := range []int{1370, 1170, 1400} {
				s.path.Store(int64(path))
				mtu, err := c.probePathMTU(ctx, netip.MustParseAddr(pair[0]), netip.MustParseAddr(pair[1]), 1450, time.Millisecond)
				if err != nil || mtu != path {
					t.Fatalf("path %d: measured %d, err %v", path, mtu, err)
				}
				for range 3 {
					_, _, _ = c.RefreshPMTU()
				}
				if c.EffectiveMTU() != path {
					t.Fatal("local size query overwrote real measurement")
				}
			}
			s.path.Store(0)
			if _, err := c.probePathMTU(ctx, netip.MustParseAddr(pair[0]), netip.MustParseAddr(pair[1]), 1450, time.Millisecond); err == nil {
				t.Fatal("all echoes blocked must be unknown, not a successful MTU")
			}
			if c.EffectiveMTU() != 1400 {
				t.Fatal("loss of control echo changed last good MTU")
			}
			cancel()
			if _, err := c.ProbePathMTU(ctx, netip.MustParseAddr(pair[0]), netip.MustParseAddr(pair[1]), 1450); err != context.Canceled {
				t.Fatalf("cancel: %v", err)
			}
		})
	}
}

func TestPMTUEchoRejectsForeignAndTruncatedReplies(t *testing.T) {
	s := &echoTestStream{rx: make(chan []byte, 1)}
	s.path.Store(1400)
	p := &mtuEchoPeer{src: netip.MustParseAddr("192.0.2.1"), dst: netip.MustParseAddr("198.51.100.1"), cookie: [12]byte{1, 2, 3}}
	a := &echoAttempt{seq: 3, size: 1200, ack: make(chan struct{}, 1)}
	p.pending.Store(a)
	pkt, _ := p.request(a)
	_ = s.SendDatagram(append([]byte{0}, pkt...))
	reply := (<-s.rx)[1:]
	foreign := append([]byte(nil), reply...)
	foreign[28] ^= 1
	if p.consumeReply(foreign) {
		t.Fatal("consumed another application's echo")
	}
	if p.consumeReply(reply[:100]) {
		t.Fatal("accepted a truncated reply")
	}
	if !p.consumeReply(reply) {
		t.Fatal("didn't accept matching reply")
	}
	select {
	case <-a.ack:
	default:
		t.Fatal("matching echo didn't acknowledge probe")
	}
}
