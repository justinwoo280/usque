package api

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/Diniboy1123/usque/internal"
	"github.com/songgao/water"
	"golang.zx2c4.com/wireguard/tun"
)

// NetBuffer is a pool of byte slices with a fixed capacity.
// Helps to reduce memory allocations and improve performance.
// It uses a sync.Pool to manage the byte slices.
// The capacity of the byte slices is set when the pool is created.
type NetBuffer struct {
	capacity int
	buf      sync.Pool
}

// Get returns a byte slice from the pool.
func (n *NetBuffer) Get() []byte {
	return *(n.buf.Get().(*[]byte))
}

// Put places a byte slice back into the pool.
// It checks if the capacity of the byte slice matches the pool's capacity.
// If it doesn't match, the byte slice is not returned to the pool.
func (n *NetBuffer) Put(buf []byte) {
	if cap(buf) != n.capacity {
		return
	}
	n.buf.Put(&buf)
}

// NewNetBuffer creates a new NetBuffer with the specified capacity.
// The capacity must be greater than 0.
func NewNetBuffer(capacity int) *NetBuffer {
	if capacity <= 0 {
		panic("capacity must be greater than 0")
	}
	return &NetBuffer{
		capacity: capacity,
		buf: sync.Pool{
			New: func() interface{} {
				b := make([]byte, capacity)
				return &b
			},
		},
	}
}

// TunnelDevice abstracts a TUN device so that we can use the same tunnel-maintenance code
// regardless of the underlying implementation.
type TunnelDevice interface {
	// ReadPacket reads a packet from the device (using the given mtu) and returns its contents.
	ReadPacket(buf []byte) (int, error)
	// WritePacket writes a packet to the device.
	WritePacket(pkt []byte) error
}

// NetstackAdapter wraps a tun.Device (e.g. from netstack) to satisfy TunnelDevice.
type NetstackAdapter struct {
	dev             tun.Device
	tunnelBufPool   sync.Pool
	tunnelSizesPool sync.Pool
}

func (n *NetstackAdapter) ReadPacket(buf []byte) (int, error) {
	packetBufsPtr := n.tunnelBufPool.Get().(*[][]byte)
	sizesPtr := n.tunnelSizesPool.Get().(*[]int)

	defer func() {
		(*packetBufsPtr)[0] = nil
		n.tunnelBufPool.Put(packetBufsPtr)
		n.tunnelSizesPool.Put(sizesPtr)
	}()

	(*packetBufsPtr)[0] = buf
	(*sizesPtr)[0] = 0

	_, err := n.dev.Read(*packetBufsPtr, *sizesPtr, 0)
	if err != nil {
		return 0, err
	}

	return (*sizesPtr)[0], nil
}

func (n *NetstackAdapter) WritePacket(pkt []byte) error {
	// Write expects a slice of packet buffers.
	_, err := n.dev.Write([][]byte{pkt}, 0)
	return err
}

// NewNetstackAdapter creates a new NetstackAdapter.
func NewNetstackAdapter(dev tun.Device) TunnelDevice {
	return &NetstackAdapter{
		dev: dev,
		tunnelBufPool: sync.Pool{
			New: func() interface{} {
				buf := make([][]byte, 1)
				return &buf
			},
		},
		tunnelSizesPool: sync.Pool{
			New: func() interface{} {
				sizes := make([]int, 1)
				return &sizes
			},
		},
	}
}

// WaterAdapter wraps a *water.Interface so it satisfies TunnelDevice.
type WaterAdapter struct {
	iface *water.Interface
}

func (w *WaterAdapter) ReadPacket(buf []byte) (int, error) {
	n, err := w.iface.Read(buf)
	if err != nil {
		return 0, err
	}

	return n, nil
}

func (w *WaterAdapter) WritePacket(pkt []byte) error {
	_, err := w.iface.Write(pkt)
	return err
}

// NewWaterAdapter creates a new WaterAdapter.
func NewWaterAdapter(iface *water.Interface) TunnelDevice {
	return &WaterAdapter{iface: iface}
}

// MaintainTunnelConfig contains runtime settings for tunnel maintenance.
type MaintainTunnelConfig struct {
	TLSConfig         *tls.Config
	KeepalivePeriod   time.Duration
	InitialPacketSize uint16
	Endpoint          *net.UDPAddr
	Device            TunnelDevice
	MTU               int
	ReconnectDelay    time.Duration
	AlwaysReconnect   bool
}

// MaintainTunnel continuously connects to the MASQUE server, then starts two
// forwarding goroutines: one forwarding from the device to the IP connection (and handling
// any ICMP reply), and the other forwarding from the IP connection to the device.
// If an error occurs in either loop, the connection is closed and a reconnect is attempted.
//
// Parameters:
//   - ctx: context.Context - The context for the connection.
//   - cfg: MaintainTunnelConfig - Tunnel maintenance runtime configuration.
func MaintainTunnel(ctx context.Context, cfg MaintainTunnelConfig) {
	packetBufferPool := NewNetBuffer(cfg.MTU)

	for {
		if !cfg.AlwaysReconnect {
			log.Println("Tunnel idle. Waiting for outbound activity before reconnecting...")
			buf := packetBufferPool.Get()
			n, err := cfg.Device.ReadPacket(buf)
			if err != nil {
				packetBufferPool.Put(buf)
				log.Printf("Failed to read from TUN device while waiting for activity: %v", err)
				time.Sleep(cfg.ReconnectDelay)
				continue
			}
			packetBufferPool.Put(buf)
			log.Printf("Detected outbound activity (%d bytes). Reconnecting...", n)
		}

		log.Printf("Establishing MASQUE connection to %s:%d", cfg.Endpoint.IP, cfg.Endpoint.Port)
		udpConn, tr, ipConn, rsp, err := ConnectTunnel(
			ctx,
			cfg.TLSConfig,
			internal.DefaultQuicConfig(cfg.KeepalivePeriod, cfg.InitialPacketSize),
			internal.ConnectURI,
			cfg.Endpoint,
		)
		if err != nil {
			log.Printf("Failed to connect tunnel: %v", err)
			time.Sleep(cfg.ReconnectDelay)
			continue
		}
		if rsp.StatusCode != 200 {
			log.Printf("Tunnel connection failed: %s", rsp.Status)
			ipConn.Close()
			if udpConn != nil {
				udpConn.Close()
			}
			if tr != nil {
				tr.Close()
			}
			time.Sleep(cfg.ReconnectDelay)
			continue
		}

		log.Println("Connected to MASQUE server")

		errChan := make(chan error, 2)

		go func() {
			for {
				buf := packetBufferPool.Get()
				n, err := cfg.Device.ReadPacket(buf)
				if err != nil {
					packetBufferPool.Put(buf)
					errChan <- fmt.Errorf("failed to read from TUN device: %v", err)
					return
				}
				icmp, err := ipConn.WritePacket(buf[:n])
				if err != nil {
					packetBufferPool.Put(buf)
					if errors.As(err, new(*connectip.CloseError)) {
						errChan <- fmt.Errorf("connection closed while writing to IP connection: %v", err)
						return
					}
					log.Printf("Error writing to IP connection: %v, continuing...", err)
					continue
				}
				packetBufferPool.Put(buf)

				if len(icmp) > 0 {
					if err := cfg.Device.WritePacket(icmp); err != nil {
						if errors.As(err, new(*connectip.CloseError)) {
							errChan <- fmt.Errorf("connection closed while writing ICMP to TUN device: %v", err)
							return
						}
						log.Printf("Error writing ICMP to TUN device: %v, continuing...", err)
					}
				}
			}
		}()

		go func() {
			buf := packetBufferPool.Get()
			defer packetBufferPool.Put(buf)
			for {
				n, err := ipConn.ReadPacket(buf, true)
				if err != nil {
					if errors.As(err, new(*connectip.CloseError)) {
						errChan <- fmt.Errorf("connection closed while reading from IP connection: %v", err)
						return
					}
					log.Printf("Error reading from IP connection: %v, continuing...", err)
					continue
				}
				if err := cfg.Device.WritePacket(buf[:n]); err != nil {
					errChan <- fmt.Errorf("failed to write to TUN device: %v", err)
					return
				}
			}
		}()

		err = <-errChan
		log.Printf("Tunnel connection lost: %v. Reconnecting...", err)
		ipConn.Close()
		if udpConn != nil {
			udpConn.Close()
		}
		if tr != nil {
			tr.Close()
		}
		time.Sleep(cfg.ReconnectDelay)
	}
}
