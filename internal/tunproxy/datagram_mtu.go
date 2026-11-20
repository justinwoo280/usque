package tunproxy

import (
	"encoding/binary"

	connectip "github.com/Diniboy1123/connect-ip-go"
)

// The local jumbo MTU is for TCP, which we can resegment. UDP/ICMP preserve
// message boundaries. Report oversize packets to the ORIGINAL local flow,
// rather than silently relying on IP fragments being accepted by WARP.
func (p *Proxy) rejectOversizedDatagram(b []byte) bool {
	var off int
	var proto byte
	mtu := int(p.mtu.Load())
	if len(b) >= 20 && b[0]>>4 == 4 {
		off, proto = int(b[0]&15)*4, b[9]
		if off < 20 || off+8 > len(b) || binary.BigEndian.Uint16(b[6:8])&0x1fff != 0 {
			return false
		}
	} else if len(b) >= 40 && b[0]>>4 == 6 {
		off, proto = 40, b[6]
		// IPv6 hosts must never install a link MTU below 1280. On a smaller
		// wire budget, source fragmentation remains necessary for datagrams.
		mtu = max(mtu, 1280)
		for proto == 0 || proto == 43 || proto == 60 || proto == 44 || proto == 51 {
			if off+8 > len(b) {
				return false
			}
			n := (int(b[off+1]) + 1) * 8
			if proto == 44 {
				if binary.BigEndian.Uint16(b[off+2:off+4])&0xfff8 != 0 {
					return false
				}
				n = 8
			} else if proto == 51 {
				n = (int(b[off+1]) + 2) * 4
			}
			proto, off = b[off], off+n
		}
		if off+8 > len(b) {
			return false
		}
	} else {
		return false
	}
	size := len(b)
	switch proto {
	case 17:
		// The first IP fragment contains UDP's full datagram length, so this
		// also catches datagrams larger than the local TUN's jumbo MTU.
		size = off + int(binary.BigEndian.Uint16(b[off+4:off+6]))
	case 1:
		if b[off] != 8 {
			return false
		}
	case 58:
		if b[off] != 128 {
			return false
		}
	default:
		return false
	}
	if size <= mtu {
		return false
	}
	feedback, err := connectip.PacketTooBig(b, mtu)
	if err == nil {
		_ = p.writeDevice(feedback)
	}
	return true
}
