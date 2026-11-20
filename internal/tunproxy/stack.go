// Package tunproxy terminates TUN flows in gVisor and originates independent
// connections in a second stack whose only link is the CONNECT-IP tunnel.
package tunproxy

import (
	"context"
	"fmt"
	"io"
	"net/netip"

	"github.com/Diniboy1123/usque/internal"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const MaxPacketSize = 65535

type ipStack struct {
	s  *stack.Stack
	ep *channel.Endpoint
}

func newStack(mtu int) (*ipStack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6,
		},
	})
	ep := channel.New(256, uint32(max(1280, mtu)), "")
	if err := s.CreateNIC(1, ep); err != nil {
		s.Destroy()
		return nil, fmt.Errorf("create gVisor NIC: %s", err)
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: 1},
		{Destination: header.IPv6EmptySubnet, NIC: 1},
	})
	sack := tcpip.TCPSACKEnabled(true)
	_ = s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)
	return &ipStack{s: s, ep: ep}, nil
}

func (s *ipStack) inject(b []byte) {
	if len(b) == 0 {
		return
	}
	var proto tcpip.NetworkProtocolNumber
	switch b[0] >> 4 {
	case 4:
		proto = ipv4.ProtocolNumber
	case 6:
		proto = ipv6.ProtocolNumber
	default:
		return
	}
	// DeliverNetworkPacket can retain the payload beyond this call.
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), b...))})
	defer pkt.DecRef()
	s.ep.InjectInbound(proto, pkt)
}

func (s *ipStack) read(ctx context.Context) []byte {
	pkt := s.ep.ReadContext(ctx)
	if pkt == nil {
		return nil
	}
	defer pkt.DecRef()
	v := pkt.ToView()
	defer v.Release()
	return append([]byte(nil), v.AsSlice()...)
}

func (s *ipStack) close() {
	s.ep.Close()
	s.s.Destroy()
}

func address(a netip.Addr, port uint16) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	proto := ipv6.ProtocolNumber
	if a.Is4() {
		proto = ipv4.ProtocolNumber
	}
	return tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(a.AsSlice()), Port: port}, proto
}

// SetMTU changes the tunnel-side budget only. Existing TCP senders are notified
// too: changing a NIC MTU alone doesn't resegment their queued retransmissions.
func (p *Proxy) SetMTU(mtu int) {
	p.mtuMu.Lock()
	defer p.mtuMu.Unlock()
	mtu = max(128, min(mtu, MaxPacketSize))
	old := int(p.mtu.Swap(int64(mtu)))
	if mtu == old {
		return
	}
	p.remote.ep.SetMTU(uint32(max(1280, mtu)))
	if mtu < old {
		for _, ep := range p.remote.s.RegisteredEndpoints() {
			if e, ok := ep.(*tcp.Endpoint); ok {
				addr, err := e.GetLocalAddress()
				if err != nil {
					continue
				}
				hdr := 40
				if addr.Addr.Len() == 4 {
					hdr = 20
				}
				e.HandleError(mtuError(mtu-hdr), nil)
			}
		}
	}
}

type mtuError uint32

func (e mtuError) Info() uint32                 { return uint32(e) }
func (mtuError) Kind() stack.TransportErrorKind { return stack.PacketTooBigTransportError }
func (mtuError) Origin() tcpip.SockErrOrigin    { return tcpip.SockExtErrorOriginLocal }
func (mtuError) Type() uint8                    { return 0 }
func (mtuError) Code() uint8                    { return 0 }

// ReadPacketContext is used by the tunnel pump to cancel a read on reconnect,
// without closing the persistent application-side TUN or creating stale readers.
func (p *Proxy) ReadPacketContext(ctx context.Context, b []byte) (int, error) {
	for {
		if len(p.pending) > 0 {
			pkt := p.pending[0]
			if len(pkt) > int(p.mtu.Load()) {
				parts, err := fragmentOriginated(pkt, int(p.mtu.Load()), p.fragmentID.Add(1))
				if err != nil {
					return 0, err
				}
				p.pending = append(parts, p.pending[1:]...)
				pkt = p.pending[0]
			}
			if len(b) < len(pkt) {
				return 0, io.ErrShortBuffer
			}
			p.pending = p.pending[1:]
			return copy(b, pkt), nil
		}
		pkt := p.remote.read(ctx)
		if pkt == nil {
			return 0, io.EOF
		}
		mtu := int(p.mtu.Load())
		// The server's TCP connection may outlive an outer-path MTU decrease.
		// Advertise a receive MSS that fits even the minimum QUIC packet budget;
		// outbound segmentation can still grow with the measured path MTU.
		internal.ClampMSSPacket(pkt, min(mtu, 1120))
		var err error
		p.pending, err = fragmentOriginated(pkt, mtu, p.fragmentID.Add(1))
		if err != nil {
			return 0, err
		}
	}
}

func (p *Proxy) ReadPacket(b []byte) (int, error) { return p.ReadPacketContext(p.ctx, b) }

func (p *Proxy) WritePacket(b []byte) error {
	internal.ClampMSSPacket(b, int(p.mtu.Load()))
	p.remote.inject(b)
	return nil
}
