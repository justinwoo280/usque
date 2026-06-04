package internal

import (
	"crypto/rand"
	"encoding/binary"
	"log"
	"net"
	"time"

	"github.com/apernet/quic-go/quicvarint"
)

// NoiseConfig controls DATAGRAM noise injection parameters.
type NoiseConfig struct {
	// Count is the number of noise datagrams to send.
	Count int
	// MinSize is the minimum noise datagram payload size in bytes.
	MinSize int
	// MaxSize is the maximum noise datagram payload size in bytes.
	MaxSize int
	// DelayMin is the minimum delay between noise datagrams.
	DelayMin time.Duration
	// DelayMax is the maximum delay between noise datagrams.
	DelayMax time.Duration
}

// NoiseSender is the interface for sending noise datagrams.
// Implemented by connectip.Conn.SendNoiseDatagram.
type NoiseSender interface {
	SendNoiseDatagram(data []byte) error
}

// PacketWriter is the interface for sending IP packets through the tunnel.
// Implemented by connectip.Conn.WritePacket.
type PacketWriter interface {
	WritePacket(b []byte) (icmp []byte, err error)
}

// InjectNoise sends fake IP packets through the tunnel to generate traffic
// that looks indistinguishable from real data. Each packet has a valid IPv4
// header with TTL=64 but targets an unreachable address in the TEST-NET-1
// range (192.0.2.0/24, RFC 5737), so the proxy will forward them but they
// will never reach a real host.
func InjectNoise(writer PacketWriter, cfg NoiseConfig) {
	if cfg.Count <= 0 {
		return
	}

	sent := 0
	for i := 0; i < cfg.Count; i++ {
		payloadSize := cfg.MinSize
		if cfg.MaxSize > cfg.MinSize {
			var b [2]byte
			_, _ = rand.Read(b[:])
			payloadSize = cfg.MinSize + int(binary.BigEndian.Uint16(b[:]))%(cfg.MaxSize-cfg.MinSize+1)
		}
		if payloadSize < 20 {
			payloadSize = 20
		}

		pkt := makeIPv4NoisePacket(payloadSize)

		if _, err := writer.WritePacket(pkt); err != nil {
			log.Printf("Noise: send failed at packet %d/%d: %v", i+1, cfg.Count, err)
			break
		}
		sent++

		if cfg.DelayMax > 0 {
			delay := cfg.DelayMin
			if cfg.DelayMax > cfg.DelayMin {
				var b [2]byte
				_, _ = rand.Read(b[:])
				delay = cfg.DelayMin + time.Duration(binary.BigEndian.Uint16(b[:]))%(cfg.DelayMax-cfg.DelayMin+1)
			}
			time.Sleep(delay)
		}
	}

	if sent > 0 {
		log.Printf("Noise: injected %d/%d fake IP packets", sent, cfg.Count)
	}
}

// makeIPv4NoisePacket creates a valid IPv4 packet with random payload targeting
// an unreachable address in 192.0.2.0/24 (TEST-NET-1, RFC 5737).
func makeIPv4NoisePacket(totalSize int) []byte {
	if totalSize < 20 {
		totalSize = 20
	}
	pkt := make([]byte, totalSize)

	pkt[0] = 0x45
	pkt[1] = 0x00
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalSize))
	_, _ = rand.Read(pkt[4:8])
	pkt[8] = 64
	pkt[9] = 0xFF
	pkt[10] = 0
	pkt[11] = 0

	pkt[12] = 172
	pkt[13] = 16
	pkt[14] = 0
	pkt[15] = 1

	pkt[16] = 192
	pkt[17] = 0
	pkt[18] = 2
	_, _ = rand.Read(pkt[19:20])

	if totalSize > 20 {
		_, _ = rand.Read(pkt[20:])
	}

	sum := uint32(0)
	for i := 0; i < 20; i += 2 {
		sum += uint32(pkt[i])<<8 | uint32(pkt[i+1])
	}
	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	binary.BigEndian.PutUint16(pkt[10:12], ^uint16(sum))

	return pkt
}

// Ensure quicvarint is used (imported for potential future varint-encoded Context IDs).
var _ = quicvarint.Append

// InjectUDPPreNoise sends random UDP packets to the endpoint through the same
// socket that will be used for the QUIC connection. This ensures the source
// port matches, making the noise appear as part of the same flow to any
// intermediate observer. The endpoint silently ignores unparseable UDP packets.
func InjectUDPPreNoise(conn *net.UDPConn, endpoint *net.UDPAddr, cfg NoiseConfig) {
	if cfg.Count <= 0 {
		return
	}

	sent := 0
	totalBytes := 0
	for i := 0; i < cfg.Count; i++ {
		size := cfg.MinSize
		if cfg.MaxSize > cfg.MinSize {
			var b [2]byte
			_, _ = rand.Read(b[:])
			size = cfg.MinSize + int(binary.BigEndian.Uint16(b[:]))%(cfg.MaxSize-cfg.MinSize+1)
		}

		pkt := make([]byte, size)
		_, _ = rand.Read(pkt)

		n, err := conn.WriteToUDP(pkt, endpoint)
		if err != nil {
			log.Printf("PreNoise: write failed at packet %d/%d: %v", i+1, cfg.Count, err)
			break
		}
		sent++
		totalBytes += n

		if cfg.DelayMax > 0 {
			delay := cfg.DelayMin
			if cfg.DelayMax > cfg.DelayMin {
				var b [2]byte
				_, _ = rand.Read(b[:])
				delay = cfg.DelayMin + time.Duration(binary.BigEndian.Uint16(b[:]))%(cfg.DelayMax-cfg.DelayMin+1)
			}
			time.Sleep(delay)
		}
	}

	if sent > 0 {
		log.Printf("PreNoise: sent %d/%d UDP packets (%d bytes) before QUIC handshake", sent, cfg.Count, totalBytes)
	}
}
