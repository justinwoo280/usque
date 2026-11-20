package tunproxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"time"

	xicmp "golang.org/x/net/icmp"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Echo uses a real ICMP endpoint in the outbound stack, rather than returning
// fake local echo replies. The endpoint assigns its own identifier, so a ping
// in one application cannot consume another application's reply.
func (p *Proxy) echo(b []byte) bool {
	var off int
	var src, dst netip.Addr
	var proto tcpip.TransportProtocolNumber
	if len(b) >= 28 && b[0]>>4 == 4 && b[9] == 1 {
		off = int(b[0]&15) * 4
		if off < 20 || off+8 > len(b) || b[off] != 8 {
			return false
		}
		if binary.BigEndian.Uint16(b[6:8])&0x3fff != 0 || checksum.Checksum(b[:off], 0) != 0xffff ||
			int(binary.BigEndian.Uint16(b[2:4])) != len(b) || checksum.Checksum(b[off:], 0) != 0xffff {
			return true
		}
		src, dst = netip.AddrFrom4([4]byte(b[12:16])), netip.AddrFrom4([4]byte(b[16:20]))
		proto = icmp.ProtocolNumber4
	} else if len(b) >= 48 && b[0]>>4 == 6 && b[6] == 58 && b[40] == 128 {
		off = 40
		if int(binary.BigEndian.Uint16(b[4:6])) != len(b)-40 {
			return true
		}
		src, dst = netip.AddrFrom16([16]byte(b[8:24])), netip.AddrFrom16([16]byte(b[24:40]))
		pseudo := xicmp.IPv6PseudoHeader(src.AsSlice(), dst.AsSlice())
		binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(b)-40))
		if checksum.Checksum(b[40:], checksum.Checksum(pseudo, 0)) != 0xffff {
			return true
		}
		proto = icmp.ProtocolNumber6
	} else {
		return false
	}
	if b[off+1] != 0 || src.IsUnspecified() || src.IsMulticast() || dst.IsMulticast() || !p.enter() {
		return true
	}
	data := append([]byte(nil), b[off:]...)
	go func() {
		defer p.leave()
		ctx, cancel := context.WithTimeout(p.ctx, 5*time.Second)
		defer cancel()
		a, netProto := address(dst, 0)
		var wq waiter.Queue
		ep, err := p.remote.s.NewEndpoint(proto, netProto, &wq)
		if err != nil {
			return
		}
		defer ep.Close()
		_ = ep.SetSockOptInt(tcpip.MTUDiscoverOption, int(tcpip.PMTUDiscoveryDont))
		entry, ready := waiter.NewChannelEntry(waiter.ReadableEvents)
		wq.EventRegister(&entry)
		defer wq.EventUnregister(&entry)
		if err := ep.Connect(a); err != nil {
			return
		}
		if _, err := ep.Write(bytes.NewReader(data), tcpip.WriteOptions{}); err != nil {
			return
		}
		var reply bytes.Buffer
		for {
			_, err := ep.Read(&reply, tcpip.ReadOptions{})
			if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
				if err != nil {
					return
				}
				break
			}
			select {
			case <-ready:
			case <-ctx.Done():
				return
			}
		}
		msg := reply.Bytes()
		if len(msg) != len(data) || !bytes.Equal(msg[6:], data[6:]) {
			return
		}
		copy(msg[4:6], data[4:6])
		pkt := echoReply(dst, src, msg)
		packets, err2 := fragmentOriginated(pkt, p.cfg.LocalMTU, p.fragmentID.Add(1))
		if err2 == nil {
			for _, b := range packets {
				_ = p.writeDevice(b)
			}
		}
	}()
	return true
}

func echoReply(src, dst netip.Addr, msg []byte) []byte {
	hlen := 40
	if src.Is4() {
		hlen = 20
	}
	b := make([]byte, hlen+len(msg))
	msg[2], msg[3] = 0, 0
	if src.Is4() {
		b[0], b[8], b[9] = 0x45, 64, 1
		binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
		copy(b[12:16], src.AsSlice())
		copy(b[16:20], dst.AsSlice())
		binary.BigEndian.PutUint16(b[10:12], ^checksum.Checksum(b[:20], 0))
		binary.BigEndian.PutUint16(msg[2:4], ^checksum.Checksum(msg, 0))
	} else {
		b[0], b[6], b[7] = 0x60, 58, 64
		binary.BigEndian.PutUint16(b[4:6], uint16(len(msg)))
		copy(b[8:24], src.AsSlice())
		copy(b[24:40], dst.AsSlice())
		pseudo := xicmp.IPv6PseudoHeader(src.AsSlice(), dst.AsSlice())
		binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(msg)))
		binary.BigEndian.PutUint16(msg[2:4], ^checksum.Checksum(msg, checksum.Checksum(pseudo, 0)))
	}
	copy(b[hlen:], msg)
	return b
}
