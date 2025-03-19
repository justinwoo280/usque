package api

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/Diniboy1123/usque/internal"
	"github.com/songgao/water"
	"golang.zx2c4.com/wireguard/tun"
)

// TunnelDevice abstracts a TUN device so that we can use the same tunnel-maintenance code
// regardless of the underlying implementation.
type TunnelDevice interface {
	// ReadPacket reads a packet from the device (using the given mtu) and returns its contents.
	ReadPacket(mtu int) ([]byte, error)
	// WritePacket writes a packet to the device.
	WritePacket(pkt []byte) error
}

// NetstackAdapter wraps a tun.Device (e.g. from netstack) to satisfy TunnelDevice.
type NetstackAdapter struct {
	dev tun.Device
}

func (n *NetstackAdapter) ReadPacket(mtu int) ([]byte, error) {
	// For netstack TUN devices we need to use the multi-buffer interface.
	packetBufs := make([][]byte, 1)
	packetBufs[0] = make([]byte, mtu)
	sizes := make([]int, 1)
	_, err := n.dev.Read(packetBufs, sizes, 0)
	if err != nil {
		return nil, err
	}
	return packetBufs[0][:sizes[0]], nil
}

func (n *NetstackAdapter) WritePacket(pkt []byte) error {
	// Write expects a slice of packet buffers.
	_, err := n.dev.Write([][]byte{pkt}, 0)
	return err
}

// NewNetstackAdapter creates a new NetstackAdapter.
func NewNetstackAdapter(dev tun.Device) TunnelDevice {
	return &NetstackAdapter{dev: dev}
}

// WaterAdapter wraps a *water.Interface so it satisfies TunnelDevice.
type WaterAdapter struct {
	iface *water.Interface
}

func (w *WaterAdapter) ReadPacket(mtu int) ([]byte, error) {
	buf := make([]byte, mtu)
	n, err := w.iface.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (w *WaterAdapter) WritePacket(pkt []byte) error {
	_, err := w.iface.Write(pkt)
	return err
}

// NewWaterAdapter creates a new WaterAdapter.
func NewWaterAdapter(iface *water.Interface) TunnelDevice {
	return &WaterAdapter{iface: iface}
}

// MaintainTunnel continuously connects to the MASQUE server, then starts two
// forwarding goroutines: one forwarding from the device to the IP connection (and handling
// any ICMP reply), and the other forwarding from the IP connection to the device.
// If an error occurs in either loop, the connection is closed and a reconnect is attempted.
//
// Parameters:
//   - ctx: context.Context - The context for the connection.
//   - tlsConfig: *tls.Config - The TLS configuration for secure communication.
//   - keepalivePeriod: time.Duration - The keepalive period for the QUIC connection.
//   - initialPacketSize: uint16 - The initial packet size for the QUIC connection.
//   - endpoint: *net.UDPAddr - The UDP address of the MASQUE server.
//   - device: TunnelDevice - The TUN device to forward packets to and from.
//   - mtu: int - The MTU of the TUN device.
//   - reconnectDelay: time.Duration - The delay between reconnect attempts.
func MaintainTunnel(ctx context.Context, tlsConfig *tls.Config, keepalivePeriod time.Duration, initialPacketSize uint16, endpoint *net.UDPAddr, device TunnelDevice, mtu int, reconnectDelay time.Duration) {
	for {
		log.Printf("Establishing MASQUE connection to %s:%d", endpoint.IP, endpoint.Port)
		udpConn, tr, ipConn, rsp, err := ConnectTunnel(
			ctx,
			tlsConfig,
			internal.DefaultQuicConfig(keepalivePeriod, initialPacketSize),
			internal.ConnectURI,
			endpoint,
		)
		if err != nil {
			log.Printf("Failed to connect tunnel: %v", err)
			time.Sleep(reconnectDelay)
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
			time.Sleep(reconnectDelay)
			continue
		}

		log.Println("Connected to MASQUE server")
		errChan := make(chan error, 2)

		go func() {
			for {
				pkt, err := device.ReadPacket(mtu)
				if err != nil {
					errChan <- fmt.Errorf("failed to read from TUN device: %v", err)
					return
				}
				icmp, err := ipConn.WritePacket(pkt)
				if err != nil {
					errChan <- fmt.Errorf("failed to write to IP connection: %v", err)
					return
				}
				if len(icmp) > 0 {
					if err := device.WritePacket(icmp); err != nil {
						errChan <- fmt.Errorf("failed to write ICMP to TUN device: %v", err)
						return
					}
				}
			}
		}()

		go func() {
			buf := make([]byte, mtu)
			for {
				n, err := ipConn.ReadPacket(buf, true)
				if err != nil {
					errChan <- fmt.Errorf("failed to read from IP connection: %v", err)
					return
				}
				if err := device.WritePacket(buf[:n]); err != nil {
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
		time.Sleep(reconnectDelay)
	}
}
