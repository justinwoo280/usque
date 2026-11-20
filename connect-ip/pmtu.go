package connectip

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/apernet/quic-go"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// ProbePathMTU finds a usable inner IP packet size (including the IP header)
// up to ceiling, over this CONNECT-IP session to an ICMP echo responder. It
// needs a concurrent ReadPacket consumer, not a raw socket or a second route.
// No reply to a small control packet means unknown, not a tiny path MTU.
func (c *Conn) ProbePathMTU(ctx context.Context, src, dst netip.Addr, ceiling int) (int, error) {
	return c.probePathMTU(ctx, src, dst, ceiling, time.Second)
}

func (c *Conn) probePathMTU(ctx context.Context, src, dst netip.Addr, ceiling int, wait time.Duration) (int, error) {
	const controlSize = 128
	src, dst = src.Unmap(), dst.Unmap()
	if !c.usesQUICDatagrams || ceiling < controlSize || ceiling > 65535 || !src.IsValid() ||
		src.BitLen() != dst.BitLen() || src.IsUnspecified() || dst.IsUnspecified() || dst.IsMulticast() {
		return 0, errors.New("connect-ip: invalid HTTP/3 PMTU probe addresses or size")
	}
	if !c.probeMu.TryLock() {
		return 0, errors.New("connect-ip: PMTU search already in progress")
	}
	defer c.probeMu.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	p := c.echoPeer.Load()
	if p == nil || p.src != src || p.dst != dst {
		p = &mtuEchoPeer{src: src, dst: dst}
		rand.Read(p.cookie[:])
		c.echoPeer.Store(p)
	}

	// Send real IP packets, bypassing ONLY our cached IP limit: otherwise a
	// previously lowered MTU could never recover. QUIC still enforces its cap.
	try := func(size int) (bool, error) {
		for attempt := 1; attempt <= 2; attempt++ {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			p.seq++
			probe := &echoAttempt{seq: p.seq, size: size, ack: make(chan struct{}, 1)}
			pkt, err := p.request(probe)
			if err != nil {
				return false, err
			}
			p.pending.Store(probe) // publish before sending: a reply can be immediate
			if err := c.str.SendDatagram(append([]byte{0}, pkt...)); err != nil {
				var tooLarge *quic.DatagramTooLargeError
				if errors.As(err, &tooLarge) {
					return false, nil
				}
				return false, err
			}
			t := time.NewTimer(time.Duration(attempt) * wait)
			select {
			case <-probe.ack:
				t.Stop()
				return true, nil
			case <-ctx.Done():
				t.Stop()
				return false, ctx.Err()
			case <-c.closeChan:
				t.Stop()
				return false, c.closeErr
			case <-t.C:
			}
		}
		return false, nil
	}
	defer p.pending.Store(nil)
	limit, err := c.datagramPayloadLimit()
	if err != nil {
		return 0, err
	}
	c.observePMTU(limit)
	hi := min(ceiling, int(limit)-c.httpDatagramOverhead-len(contextIDZero))
	if hi < controlSize {
		return 0, fmt.Errorf("connect-ip: transport limit %d below control probe size", hi)
	}
	mtu, err := searchPathMTU(controlSize, hi, try)
	if err != nil {
		return 0, err // keep last good measurement (including on cancellation)
	}
	// A wire reply can confirm an increase before two local refreshes. Don't
	// promote a stale local limit if it changed while the search was running.
	c.pmtuMu.Lock()
	if current := c.maxDatagramPayload.Load(); current < limit && c.pmtuIncrease == limit {
		c.maxDatagramPayload.Store(limit)
		c.pmtuIncrease, c.pmtuIncreaseCount = 0, 0
	}
	c.verifiedMTU.Store(int64(mtu))
	c.pmtuMu.Unlock()
	return mtu, nil
}

func searchPathMTU(control, hi int, try func(int) (bool, error)) (int, error) {
	// Most tunnels can carry the whole configured TUN MTU: one round trip.
	if ok, err := try(hi); ok || err != nil {
		if err != nil {
			return 0, err
		}
		return hi, nil
	}
	if ok, err := try(control); err != nil {
		return 0, err
	} else if !ok {
		return 0, errors.New("connect-ip: no ICMP echo reply to control probe; path MTU unknown")
	}
	lo := control
	// lo was echoed, hi was not. Never publish an untested midpoint.
	for hi-lo > 1 {
		mid := lo + (hi-lo)/2
		ok, err := try(mid)
		if err != nil {
			return 0, err
		}
		if ok {
			lo = mid
		} else {
			hi = mid
		}
	}
	if ok, err := try(lo); err != nil {
		return 0, err
	} else if !ok {
		return 0, errors.New("connect-ip: echo path changed during MTU search")
	}
	return lo, nil
}

type mtuEchoPeer struct {
	src, dst netip.Addr
	cookie   [12]byte // distinguishes our probes from application pings, including late replies
	seq      uint16   // written only by the search goroutine
	pending  atomic.Pointer[echoAttempt]
}

type echoAttempt struct {
	seq  uint16
	size int
	ack  chan struct{}
}

func (p *mtuEchoPeer) request(a *echoAttempt) ([]byte, error) {
	b := make([]byte, a.size)
	var offset int
	var typ icmp.Type
	var pseudo []byte
	if p.src.Is4() {
		offset, typ = ipv4.HeaderLen, ipv4.ICMPTypeEcho
		b[0], b[6], b[8], b[9] = 0x45, 0x40, 64, ipProtoICMP // DF, no fragments
		binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
		copy(b[12:16], p.src.AsSlice())
		copy(b[16:20], p.dst.AsSlice())
		binary.BigEndian.PutUint16(b[10:12], calculateIPv4Checksum([20]byte(b[:20])))
	} else {
		offset, typ = ipv6.HeaderLen, ipv6.ICMPTypeEchoRequest
		b[0], b[6], b[7] = 0x60, ipProtoICMPv6, 64 // no Fragment header
		binary.BigEndian.PutUint16(b[4:6], uint16(len(b)-offset))
		copy(b[8:24], p.src.AsSlice())
		copy(b[24:40], p.dst.AsSlice())
		pseudo = icmp.IPv6PseudoHeader(b[8:24], b[24:40])
	}
	data := b[offset+8:]
	copy(data, p.cookie[:])
	m := icmp.Message{Type: typ, Body: &icmp.Echo{
		ID: int(binary.BigEndian.Uint16(p.cookie[:2])), Seq: int(a.seq), Data: data,
	}}
	payload, err := m.Marshal(pseudo)
	if err != nil {
		return nil, err
	}
	copy(b[offset:], payload)
	return b, nil
}

func (p *mtuEchoPeer) consumeReply(b []byte) bool {
	var off int
	if p.src.Is4() {
		if len(b) < ipv4.HeaderLen || b[9] != ipProtoICMP || b[0]>>4 != 4 ||
			int(binary.BigEndian.Uint16(b[2:4])) != len(b) || binary.BigEndian.Uint16(b[6:8])&0x3fff != 0 ||
			netip.AddrFrom4([4]byte(b[12:16])) != p.dst || netip.AddrFrom4([4]byte(b[16:20])) != p.src {
			return false
		}
		off = int(b[0]&15) * 4
		if off < ipv4.HeaderLen || off >= len(b) || b[off] != byte(ipv4.ICMPTypeEchoReply) {
			return false
		}
	} else {
		off = ipv6.HeaderLen
		if len(b) <= off || b[6] != ipProtoICMPv6 || b[0]>>4 != 6 || b[off] != byte(ipv6.ICMPTypeEchoReply) ||
			int(binary.BigEndian.Uint16(b[4:6])) != len(b)-off ||
			netip.AddrFrom16([16]byte(b[8:24])) != p.dst || netip.AddrFrom16([16]byte(b[24:40])) != p.src {
			return false
		}
	}
	m := b[off:]
	if len(m) < 8+len(p.cookie) || m[1] != 0 || [12]byte(m[8:20]) != p.cookie ||
		binary.BigEndian.Uint16(m[4:6]) != binary.BigEndian.Uint16(p.cookie[:2]) {
		return false
	}
	if a := p.pending.Load(); a != nil && a.seq == binary.BigEndian.Uint16(m[6:8]) && len(b) == a.size {
		select {
		case a.ack <- struct{}{}:
		default:
		}
	}
	return true
}
