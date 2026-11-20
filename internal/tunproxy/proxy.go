package tunproxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type Device interface {
	ReadPacket([]byte) (int, error)
	WritePacket([]byte) error
	Close() error
}

type Config struct {
	LocalMTU       int
	IPv4, IPv6     netip.Addr
	DNS4, DNS6     netip.Addr
	Block4, Block6 bool
}

type Proxy struct {
	ctx           context.Context
	cancel        context.CancelFunc
	device        Device
	cfg           Config
	local, remote *ipStack
	mtu           atomic.Int64
	fragmentID    atomic.Uint32
	pending       [][]byte // owned by the single tunnel writer
	writeMu       sync.Mutex
	mtuMu         sync.Mutex
	mu            sync.Mutex
	closing       bool
	flows         int
	wg            sync.WaitGroup
	closeOnce     sync.Once
}

// Context is canceled on persistent local TUN I/O failure as well as shutdown.
func (p *Proxy) Context() context.Context { return p.ctx }

// New takes ownership of device on success. Local TCP ends here; dialed TCP,
// UDP and ICMP endpoints use only remote, never the host's socket/network stack.
func New(ctx context.Context, device Device, cfg Config) (*Proxy, error) {
	if cfg.LocalMTU < 1280 || cfg.LocalMTU > MaxPacketSize {
		return nil, fmt.Errorf("local TUN MTU must be in 1280..%d", MaxPacketSize)
	}
	local, err := newStack(cfg.LocalMTU)
	if err != nil {
		return nil, err
	}
	remote, err := newStack(1280)
	if err != nil {
		local.close()
		return nil, err
	}
	for _, ip := range []netip.Addr{cfg.IPv4, cfg.IPv6} {
		if !ip.IsValid() || (ip.Is4() && cfg.Block4) || (ip.Is6() && cfg.Block6) {
			continue
		}
		a, proto := address(ip, 0)
		if err := remote.s.AddProtocolAddress(1, tcpip.ProtocolAddress{
			Protocol: proto, AddressWithPrefix: a.Addr.WithPrefix(),
		}, stack.AddressProperties{}); err != nil {
			local.close()
			remote.close()
			return nil, fmt.Errorf("add tunnel address: %s", err)
		}
	}
	_ = local.s.SetPromiscuousMode(1, true)
	_ = local.s.SetSpoofing(1, true)
	ctx, cancel := context.WithCancel(ctx)
	p := &Proxy{ctx: ctx, cancel: cancel, device: device, cfg: cfg, local: local, remote: remote}
	p.mtu.Store(1280)
	local.s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcp.NewForwarder(local.s, 0, 128, p.tcp).HandlePacket)
	local.s.SetTransportProtocolHandler(udp.ProtocolNumber, p.udp)
	p.wg.Add(2)
	go p.readLocal()
	go p.writeLocal()
	return p, nil
}

func (p *Proxy) enter() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing || p.ctx.Err() != nil || p.flows >= 4096 {
		return false
	}
	p.flows++
	p.wg.Add(1)
	return true
}

func (p *Proxy) leave() {
	p.mu.Lock()
	p.flows--
	p.mu.Unlock()
	p.wg.Done()
}

func (p *Proxy) destination(id stack.TransportEndpointID) netip.Addr {
	dst, _ := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	if id.LocalPort == 53 {
		if dst.Is4() && p.cfg.DNS4.IsValid() {
			return p.cfg.DNS4
		}
		if dst.Is6() && p.cfg.DNS6.IsValid() {
			return p.cfg.DNS6
		}
	}
	return dst
}

func (p *Proxy) tcp(r *tcp.ForwarderRequest) {
	if !p.enter() {
		r.Complete(true)
		return
	}
	defer p.leave()
	id := r.ID()
	a, proto := address(p.destination(id), id.LocalPort)
	ctx, cancel := context.WithTimeout(p.ctx, 15*time.Second)
	defer cancel()
	out, err := gonet.DialContextTCP(ctx, p.remote.s, a, proto)
	if err != nil {
		r.Complete(true)
		return
	}
	defer func() { _ = out.Close() }()
	var wq waiter.Queue
	ep, e := r.CreateEndpoint(&wq)
	r.Complete(e != nil)
	if e != nil {
		return
	}
	in := gonet.NewTCPConn(&wq, ep)
	defer func() { _ = in.Close() }()
	stop := context.AfterFunc(p.ctx, func() {
		_ = in.Close()
		_ = out.Close()
	})
	defer stop()
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := io.Copy(out, in); err != nil {
			_ = in.Close()
			_ = out.Close()
			return
		}
		_ = out.CloseWrite()
	}()
	if _, err := io.Copy(in, out); err != nil {
		_ = in.Close()
		_ = out.Close()
	} else {
		_ = in.CloseWrite()
	}
	<-done
}

func (p *Proxy) udp(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	if !p.enter() {
		return true
	}
	// Register synchronously so the next datagram finds this endpoint. The
	// request borrows pkt for CreateEndpoint; don't leak a Forwarder's Clone.
	var wq waiter.Queue
	ep, err := udp.NewForwarderRequest(p.local.s, id, pkt).CreateEndpoint(&wq)
	if err != nil {
		p.leave()
		return true
	}
	_ = ep.SetSockOptInt(tcpip.MTUDiscoverOption, int(tcpip.PMTUDiscoveryDont))
	in := gonet.NewUDPConn(&wq, ep)
	go func() {
		defer p.leave()
		defer func() { _ = in.Close() }()
		a, proto := address(p.destination(id), id.LocalPort)
		var outWQ waiter.Queue
		outEP, err := p.remote.s.NewEndpoint(udp.ProtocolNumber, proto, &outWQ)
		if err != nil {
			return
		}
		_ = outEP.SetSockOptInt(tcpip.MTUDiscoverOption, int(tcpip.PMTUDiscoveryDont))
		if err := outEP.Connect(a); err != nil {
			outEP.Close()
			return
		}
		out := gonet.NewUDPConn(&outWQ, outEP)
		defer func() { _ = out.Close() }()
		stop := context.AfterFunc(p.ctx, func() {
			_ = in.Close()
			_ = out.Close()
		})
		defer stop()
		done := make(chan struct{})
		go func() {
			defer close(done)
			relayDatagrams(out, in)
			_ = in.Close()
			_ = out.Close()
		}()
		relayDatagrams(in, out)
		_ = in.Close()
		_ = out.Close()
		<-done
	}()
	return true
}

func relayDatagrams(dst, src net.Conn) {
	buf := make([]byte, MaxPacketSize)
	for {
		_ = src.SetReadDeadline(time.Now().Add(2 * time.Minute))
		n, err := src.Read(buf)
		if err != nil {
			return
		}
		_ = dst.SetReadDeadline(time.Now().Add(2 * time.Minute))
		_ = dst.SetWriteDeadline(time.Now().Add(15 * time.Second))
		if _, err := dst.Write(buf[:n]); err != nil {
			return
		}
	}
}

func (p *Proxy) readLocal() {
	defer p.wg.Done()
	buf := make([]byte, MaxPacketSize)
	for p.ctx.Err() == nil {
		n, err := p.device.ReadPacket(buf)
		if err != nil {
			p.cancel()
			p.remote.ep.Close()
			return
		}
		if n == 0 || (buf[0]>>4 == 4 && p.cfg.Block4) || (buf[0]>>4 == 6 && p.cfg.Block6) {
			continue
		}
		if p.rejectOversizedDatagram(buf[:n]) || p.echo(buf[:n]) {
			continue
		}
		p.local.inject(buf[:n])
	}
}

func (p *Proxy) writeLocal() {
	defer p.wg.Done()
	for {
		pkt := p.local.read(p.ctx)
		if pkt == nil {
			return
		}
		// Never let gVisor synthesize successful IPv6 pings to arbitrary
		// promiscuous addresses. Real echo replies use writeDevice directly.
		if len(pkt) >= 48 && pkt[0]>>4 == 6 && pkt[6] == 58 && pkt[40] == 129 {
			continue
		}
		if err := p.writeDevice(pkt); err != nil {
			p.cancel()
			p.remote.ep.Close()
			return
		}
	}
}

func (p *Proxy) writeDevice(b []byte) error {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	return p.device.WritePacket(b)
}

func (p *Proxy) Close() error {
	p.closeOnce.Do(func() {
		p.mu.Lock()
		p.closing = true
		p.mu.Unlock()
		p.cancel()
		_ = p.device.Close()
		p.local.s.Close()
		p.remote.s.Close()
		p.wg.Wait()
		p.local.close()
		p.remote.close()
	})
	return nil
}
