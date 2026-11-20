package tunproxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type testDevice struct {
	client   *ipStack
	ctx      context.Context
	cancel   context.CancelFunc
	max      atomic.Int64
	feedback chan []byte
}

func (d *testDevice) ReadPacket(b []byte) (int, error) {
	pkt := d.client.read(d.ctx)
	if pkt == nil {
		return 0, io.EOF
	}
	for n := d.max.Load(); int64(len(pkt)) > n; n = d.max.Load() {
		if d.max.CompareAndSwap(n, int64(len(pkt))) {
			break
		}
	}
	return copy(b, pkt), nil
}
func (d *testDevice) WritePacket(b []byte) error {
	if (len(b) >= 28 && b[0]>>4 == 4 && b[9] == 1 && b[20] == 3 && b[21] == 4) ||
		(len(b) >= 48 && b[0]>>4 == 6 && b[6] == 58 && b[40] == 2) {
		select {
		case d.feedback <- append([]byte(nil), b...):
		default:
		}
	}
	d.client.inject(b)
	return nil
}
func (d *testDevice) Close() error { d.cancel(); return nil }

func addTestIP(t *testing.T, s *ipStack, ip netip.Addr) {
	t.Helper()
	a, proto := address(ip, 0)
	if err := s.s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: proto, AddressWithPrefix: a.Addr.WithPrefix()}, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
}

// Real gVisor client -> jumbo TUN -> terminating proxy -> small IP link ->
// real gVisor server. The same TCP flow must survive a mid-transfer MTU drop;
// UDP preserves datagram boundaries; oversized datagrams get local ICMP feedback.
func TestProxyJumboTCPAndUDP(t *testing.T) {
	for _, family := range []string{"ipv4", "ipv6"} {
		t.Run(family, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			client, err := newStack(9000)
			if err != nil {
				t.Fatal(err)
			}
			defer client.close()
			server, err := newStack(1500)
			if err != nil {
				t.Fatal(err)
			}
			defer server.close()
			appIP, tunnelIP, serverIP := netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("172.16.0.2"), netip.MustParseAddr("192.0.2.1")
			cfg := Config{LocalMTU: 9000, IPv4: tunnelIP}
			if family == "ipv6" {
				appIP, tunnelIP, serverIP = netip.MustParseAddr("fd00::2"), netip.MustParseAddr("fd01::2"), netip.MustParseAddr("fd02::1")
				cfg.IPv4, cfg.IPv6 = netip.Addr{}, tunnelIP
			}
			addTestIP(t, client, appIP)
			addTestIP(t, server, serverIP)
			dctx, dcancel := context.WithCancel(ctx)
			dev := &testDevice{client: client, ctx: dctx, cancel: dcancel, feedback: make(chan []byte, 2)}
			p, err := New(ctx, dev, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			p.SetMTU(1400)
			var cap atomic.Int64
			cap.Store(1400)
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				buf := make([]byte, MaxPacketSize)
				for {
					n, err := p.ReadPacketContext(ctx, buf)
					if err != nil {
						return
					}
					if int64(n) > cap.Load() {
						// An already-queued TCP segment gets dropped; its sender
						// must retransmit after SetMTU updates the live endpoint.
						continue
					}
					server.inject(buf[:n])
				}
			}()
			go func() {
				defer wg.Done()
				for {
					b := server.read(ctx)
					if b == nil {
						return
					}
					// Source fragmentation on the echo server, including replies
					// larger than the current tunnel budget.
					pkts, err := fragmentOriginated(b, int(cap.Load()), 123)
					if err != nil {
						return
					}
					for _, pkt := range pkts {
						_ = p.WritePacket(pkt)
					}
				}
			}()
			defer func() { cancel(); wg.Wait() }()

			a, proto := address(serverIP, 8080)
			ln, err := gonet.ListenTCP(server.s, a, proto)
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			go func() {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
			c, err := gonet.DialContextTCP(ctx, client.s, a, proto)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(15 * time.Second))
			for phase := 0; phase < 2; phase++ {
				if phase == 1 {
					cap.Store(1150)
					p.SetMTU(1150)
				}
				payload := bytes.Repeat([]byte{byte(phase + 1)}, 256*1024)
				writeDone := make(chan error, 1)
				go func() { _, err := c.Write(payload); writeDone <- err }()
				reply := make([]byte, len(payload))
				if _, err := io.ReadFull(c, reply); err != nil {
					t.Fatalf("phase %d: %v", phase, err)
				}
				if err := <-writeDone; err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(reply, payload) {
					t.Fatal("TCP payload changed")
				}
			}
			if dev.max.Load() <= 1400 {
				t.Fatalf("local TUN didn't carry jumbo TCP: %d", dev.max.Load())
			}

			a.Port = 5353
			var uq waiter.Queue
			uep, uerr := server.s.NewEndpoint(udp.ProtocolNumber, proto, &uq)
			if uerr != nil {
				t.Fatal(uerr)
			}
			_ = uep.SetSockOptInt(tcpip.MTUDiscoverOption, int(tcpip.PMTUDiscoveryDont))
			if err := uep.Bind(a); err != nil {
				t.Fatal(err)
			}
			u := gonet.NewUDPConn(&uq, uep)
			defer u.Close()
			go func() {
				buf := make([]byte, MaxPacketSize)
				n, from, err := u.ReadFrom(buf)
				if err == nil {
					_, _ = u.WriteTo(buf[:n], from)
				}
			}()
			uc, err := gonet.DialUDP(client.s, nil, &a, proto)
			if err != nil {
				t.Fatal(err)
			}
			defer uc.Close()
			_ = uc.SetDeadline(time.Now().Add(3 * time.Second))
			payload := bytes.Repeat([]byte("datagram"), 130)
			if _, err := uc.Write(payload); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, MaxPacketSize)
			n, err := uc.Read(buf)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(buf[:n], payload) {
				t.Fatalf("UDP boundary/content changed: got %d bytes", n)
			}
			if _, err := uc.Write(make([]byte, 5000)); err != nil {
				t.Fatal(err)
			}
			select {
			case packet := <-dev.feedback:
				if family == "ipv4" && int(binary.BigEndian.Uint16(packet[26:28])) != 1150 {
					t.Fatal("wrong IPv4 PTB MTU")
				}
				if family == "ipv6" && int(binary.BigEndian.Uint32(packet[44:48])) != 1280 {
					t.Fatal("wrong IPv6 PTB MTU")
				}
			case <-time.After(time.Second):
				t.Fatal("oversized UDP did not produce PTB to original local sender")
			}
		})
	}
}
