//go:build e2e

package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"github.com/Diniboy1123/usque/internal/tunproxy"
	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/miekg/dns"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type e2eOwnedTUN struct {
	TunnelDevice
	dev  tun.Device
	once sync.Once
}

func (d *e2eOwnedTUN) Close() error { d.once.Do(func() { _ = d.dev.Close() }); return nil }

func TestE2E_GVisorTUN(t *testing.T) {
	loadE2EConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	// Deliberately different from the WARP-assigned addresses: successful
	// traffic demonstrates socket origination, not transparent L3 forwarding.
	dev, app, err := netstack.CreateNetTUN([]netip.Addr{
		netip.MustParseAddr("10.87.0.2"), netip.MustParseAddr("fd87::2"),
	}, nil, 9000)
	if err != nil {
		t.Fatal(err)
	}
	d := &e2eOwnedTUN{TunnelDevice: NewNetstackAdapter(dev), dev: dev}
	v4, _ := netip.ParseAddr(config.AppConfig.IPv4)
	v6, _ := netip.ParseAddr(config.AppConfig.IPv6)
	p, err := tunproxy.New(ctx, d, tunproxy.Config{LocalMTU: 9000, IPv4: v4, IPv6: v6})
	if err != nil {
		d.Close()
		t.Fatal(err)
	}
	defer p.Close()
	_, conn, cleanup := dialTunnel(t, nil, internal.NoiseConfig{})
	defer cleanup()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		b := make([]byte, 65535)
		for {
			n, err := p.ReadPacketContext(ctx, b)
			if err != nil {
				t.Logf("egress read: %v", err)
				return
			}
			feedback, err := conn.WritePacket(b[:n])
			if err != nil {
				t.Logf("tunnel write: %v", err)
				return
			}
			if len(feedback) > 0 {
				_ = p.WritePacket(feedback)
			}
		}
	}()
	go func() {
		defer wg.Done()
		b := make([]byte, 65535)
		for {
			n, err := conn.ReadPacket(b, true)
			if err != nil {
				t.Logf("tunnel read: %v", err)
				return
			}
			_ = p.WritePacket(b[:n])
		}
	}()
	defer func() { cancel(); cleanup(); wg.Wait() }()
	for _, target := range []string{"1.1.1.1", "2606:4700:4700::1111"} {
		src := v4
		dst := netip.MustParseAddr(target)
		if dst.Is6() {
			src = v6
		}
		mtu, err := conn.ProbePathMTU(ctx, src, dst, 1400)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("echo target %s: verified inner size %d", target, mtu)
		p.SetMTU(conn.EffectiveMTU())
	}
	for _, target := range []string{"1.1.1.1", "2606:4700:4700::1111"} {
		t.Run(target, func(t *testing.T) {
			addr := netip.MustParseAddr(target)
			// Exercise DNS over the actual UDP proxy path. Oversized EDNS
			// requests are dropped by this resolver even without the tunnel.
			u, err := app.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(addr, 53))
			if err != nil {
				t.Fatal(err)
			}
			defer u.Close()
			_ = u.SetDeadline(time.Now().Add(8 * time.Second))
			msg := new(dns.Msg)
			msg.SetQuestion("cloudflare.com.", dns.TypeA)
			msg.SetEdns0(4096, false)
			wire, _ := msg.Pack()
			if _, err := u.Write(wire); err != nil {
				t.Fatal(err)
			}
			b := make([]byte, 8192)
			n, err := u.Read(b)
			if err != nil {
				t.Fatal(err)
			}
			var reply dns.Msg
			if err := reply.Unpack(b[:n]); err != nil || reply.Id != msg.Id || len(reply.Answer) == 0 {
				t.Fatalf("invalid DNS reply: %v / %s", err, &reply)
			}
			t.Logf("UDP DNS: %d-byte query, %d-byte response", len(wire), n)

			tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return app.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(addr, 443))
			}}
			defer tr.CloseIdleConnections()
			h := &http.Client{Transport: tr, Timeout: 15 * time.Second}
			rsp, err := h.Get("https://one.one.one.one/cdn-cgi/trace")
			if err != nil {
				t.Fatal(err)
			}
			defer rsp.Body.Close()
			trace, err := io.ReadAll(rsp.Body)
			if err != nil || (!strings.Contains(string(trace), "warp=on") && !strings.Contains(string(trace), "warp=plus")) {
				t.Fatalf("not a working WARP egress: %v / %s", err, trace)
			}
			t.Log("HTTPS through terminating gVisor TUN: WARP confirmed")

			ping, err := app.DialPingAddr(netip.Addr{}, addr)
			if err != nil {
				t.Fatal(err)
			}
			defer ping.Close()
			_ = ping.SetDeadline(time.Now().Add(8 * time.Second))
			var typ icmp.Type = ipv4.ICMPTypeEcho
			proto := 1
			if addr.Is6() {
				typ, proto = ipv6.ICMPTypeEchoRequest, 58
			}
			body := bytes.Repeat([]byte("warp-fragment-test"), 50)
			echo := icmp.Message{Type: typ, Body: &icmp.Echo{ID: 42, Seq: 1, Data: body}}
			pingWire, _ := echo.Marshal(nil)
			if _, err := ping.Write(pingWire); err != nil {
				t.Fatal(err)
			}
			n, err = ping.Read(b)
			if err != nil {
				t.Fatal(err)
			}
			pong, err := icmp.ParseMessage(proto, b[:n])
			if err != nil {
				t.Fatal(err)
			}
			e, ok := pong.Body.(*icmp.Echo)
			if !ok || !bytes.Equal(e.Data, body) {
				t.Fatal("fragmented echo payload changed")
			}
			t.Logf("proxied ICMP: %d bytes echoed through WARP", len(body))

			bind := netip.MustParseAddr("10.87.0.2")
			if addr.Is6() {
				bind = netip.MustParseAddr("fd87::2")
			}
			quicUDP, err := app.ListenUDPAddrPort(netip.AddrPortFrom(bind, 0))
			if err != nil {
				t.Fatal(err)
			}
			defer quicUDP.Close()
			h3 := &http3.Transport{Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, _ *quic.Config) (*quic.Conn, error) {
				return quic.Dial(ctx, quicUDP, &net.UDPAddr{IP: net.IP(addr.AsSlice()), Port: 443}, tlsCfg,
					&quic.Config{InitialPacketSize: 1200, DisablePathMTUDiscovery: true})
			}}
			defer h3.Close()
			h3client := &http.Client{Transport: h3, Timeout: 15 * time.Second}
			h3rsp, err := h3client.Get("https://one.one.one.one/cdn-cgi/trace")
			if err != nil {
				t.Fatal(err)
			}
			defer h3rsp.Body.Close()
			trace, err = io.ReadAll(h3rsp.Body)
			if err != nil || !strings.Contains(string(trace), "warp=") || h3rsp.ProtoMajor != 3 {
				t.Fatalf("HTTP/3 over UDP proxy: %v / %s", err, trace)
			}
			t.Log("HTTP/3 through UDP proxy: 1200-byte QUIC datagrams succeeded")
		})
	}
}
