package tunproxy

import (
	"encoding/binary"
	"fmt"

	"gvisor.dev/gvisor/pkg/tcpip/checksum"
)

// fragmentOriginated applies the wire budget to packets originated by our
// egress stack. It must never be used on transparently forwarded TUN packets.
// UDP message boundaries survive IP fragmentation and remote reassembly.
func fragmentOriginated(b []byte, mtu int, id uint32) ([][]byte, error) {
	if len(b) <= mtu {
		return [][]byte{b}, nil
	}
	var hdr, offset, flags int
	var more bool
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 || b[0] != 0x45 {
			return nil, fmt.Errorf("unexpected originated IPv4 header")
		}
		flags = int(binary.BigEndian.Uint16(b[6:8]))
		if flags&0x4000 != 0 { // DF TCP: let CONNECT-IP return PTB to the egress stack
			return [][]byte{b}, nil
		}
		hdr, offset, more = 20, (flags&0x1fff)*8, flags&0x2000 != 0
	case 6:
		if len(b) < 40 {
			return nil, fmt.Errorf("short originated IPv6 packet")
		}
		if b[6] != 44 {
			// gVisor originates bare IPv6 or a single Fragment header on
			// this link (no offload/extension-header options are enabled).
			next := b[6]
			x := make([]byte, len(b)+8)
			copy(x, b[:40])
			copy(x[48:], b[40:])
			x[6], x[40] = 44, next
			binary.BigEndian.PutUint32(x[44:48], id)
			b = x
		}
		if len(b) < 48 {
			return nil, fmt.Errorf("short IPv6 fragment")
		}
		flags = int(binary.BigEndian.Uint16(b[42:44]))
		hdr, offset, more = 48, flags&0xfff8, flags&1 != 0
	default:
		return nil, fmt.Errorf("invalid originated IP version")
	}
	chunk := (mtu - hdr) &^ 7
	if chunk < 8 {
		return nil, fmt.Errorf("wire MTU too small: %d", mtu)
	}
	var result [][]byte
	for pos := hdr; pos < len(b); pos += chunk {
		n := min(chunk, len(b)-pos)
		f := make([]byte, hdr+n)
		copy(f, b[:hdr])
		copy(f[hdr:], b[pos:pos+n])
		moreHere := more || pos+n < len(b)
		fragOffset := offset + pos - hdr
		if f[0]>>4 == 4 {
			v := uint16(fragOffset / 8)
			if moreHere {
				v |= 0x2000
			}
			binary.BigEndian.PutUint16(f[6:8], v)
			binary.BigEndian.PutUint16(f[2:4], uint16(len(f)))
			f[10], f[11] = 0, 0
			binary.BigEndian.PutUint16(f[10:12], ^checksum.Checksum(f[:20], 0))
		} else {
			v := uint16(fragOffset)
			if moreHere {
				v |= 1
			}
			binary.BigEndian.PutUint16(f[42:44], v)
			binary.BigEndian.PutUint16(f[4:6], uint16(len(f)-40))
		}
		result = append(result, f)
	}
	return result, nil
}
