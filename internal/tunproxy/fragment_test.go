package tunproxy

import (
	"bytes"
	"context"
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Refragmentation can happen when the budget falls while fragments are queued.
// Verify offsets/IDs/checksums by having a real gVisor peer reassemble them.
func TestSourceFragmentsSurviveSecondMTUShrink(t *testing.T) {
	for _, pair := range [][2]string{{"192.0.2.1", "192.0.2.2"}, {"fd00::1", "fd00::2"}} {
		t.Run(pair[0], func(t *testing.T) {
			a, err := newStack(9000)
			if err != nil {
				t.Fatal(err)
			}
			defer a.close()
			b, err := newStack(1280)
			if err != nil {
				t.Fatal(err)
			}
			defer b.close()
			src, dst := netip.MustParseAddr(pair[0]), netip.MustParseAddr(pair[1])
			addTestIP(t, a, src)
			addTestIP(t, b, dst)
			remote, proto := address(dst, 1234)
			listener, err := gonet.DialUDP(b.s, &remote, nil, proto)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = listener.Close() }()
			var wq waiter.Queue
			ep, e := a.s.NewEndpoint(udp.ProtocolNumber, proto, &wq)
			if e != nil {
				t.Fatal(e)
			}
			_ = ep.SetSockOptInt(tcpip.MTUDiscoverOption, int(tcpip.PMTUDiscoveryDont))
			if e := ep.Connect(remote); e != nil {
				t.Fatal(e)
			}
			out := gonet.NewUDPConn(&wq, ep)
			defer func() { _ = out.Close() }()
			payload := bytes.Repeat([]byte("unique UDP message"), 300)
			if _, err := out.Write(payload); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			pkt := a.read(ctx)
			if pkt == nil {
				t.Fatal("no outgoing packet")
			}
			frags, err := fragmentOriginated(pkt, 1400, 6789)
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range frags {
				smaller, err := fragmentOriginated(f, 1150, 9876)
				if err != nil {
					t.Fatal(err)
				}
				for _, g := range smaller {
					if len(g) > 1150 {
						t.Fatalf("fragment has %d bytes", len(g))
					}
					b.inject(g)
				}
			}
			_ = listener.SetReadDeadline(time.Now().Add(time.Second))
			buf := make([]byte, MaxPacketSize)
			n, err := listener.Read(buf)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(payload, buf[:n]) {
				t.Fatal("reassembled datagram corrupted")
			}
		})
	}
}
