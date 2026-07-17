//go:build e2e

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"github.com/Diniboy1123/usque/internal/congestion/bbr"
	"github.com/apernet/quic-go"
)

func loadE2EConfig(t *testing.T) {
	t.Helper()
	fc, err := config.LoadFullConfig("../config.json")
	if err != nil {
		t.Skipf("config.json not available, skipping E2E: %v", err)
	}
	config.AppConfig = fc.Account
	if config.AppConfig.EndpointV4 == "" {
		t.Skip("endpoint_v4 is empty, skipping")
	}
}

func dialTunnel(t *testing.T, onConnect func(*quic.Conn), preNoise internal.NoiseConfig) (*net.UDPConn, *connectip.Conn, func()) {
	t.Helper()
	udpConn, ipConn, cleanup, err := dialTunnelErr(t, onConnect, preNoise)
	if err != nil {
		t.Fatalf("ConnectTunnel: %v", err)
	}
	return udpConn, ipConn, cleanup
}

func dialTunnelErr(t *testing.T, onConnect func(*quic.Conn), preNoise internal.NoiseConfig) (*net.UDPConn, *connectip.Conn, func(), error) {
	t.Helper()

	privKey, err := config.AppConfig.GetEcPrivateKey()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("GetEcPrivateKey: %w", err)
	}
	pubKey, err := config.AppConfig.GetEcEndpointPublicKey()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("GetEcEndpointPublicKey: %w", err)
	}
	cert, err := internal.GenerateCert(privKey, &privKey.PublicKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("GenerateCert: %w", err)
	}
	tlsCfg, err := PrepareTlsConfig(privKey, pubKey, cert, internal.ConnectSNI, false)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("PrepareTlsConfig: %w", err)
	}

	endpoint := &net.UDPAddr{
		IP:   net.ParseIP(config.AppConfig.EndpointV4),
		Port: 443,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	udpConn, tr, ipConn, rsp, err := ConnectTunnel(
		ctx, tlsCfg,
		internal.DefaultQuicConfig(30*time.Second, 0),
		internal.ConnectURI, endpoint, false,
		onConnect, preNoise, nil, nil,
	)
	if err != nil {
		if udpConn != nil {
			_ = udpConn.Close()
		}
		return nil, nil, nil, err
	}
	if rsp.StatusCode != 200 {
		_ = ipConn.Close()
		if tr != nil {
			_ = tr.Close()
		}
		if udpConn != nil {
			_ = udpConn.Close()
		}
		return nil, nil, nil, fmt.Errorf("status: %s", rsp.Status)
	}

	cleanup := func() {
		_ = ipConn.Close()
		if tr != nil {
			_ = tr.Close()
		}
		if udpConn != nil {
			_ = udpConn.Close()
		}
	}
	return udpConn, ipConn, cleanup, nil
}

func TestE2E_ConnectTunnel(t *testing.T) {
	loadE2EConfig(t)
	_, ipConn, cleanup := dialTunnel(t, nil, internal.NoiseConfig{})
	defer cleanup()

	if ipConn == nil {
		t.Fatal("ipConn is nil")
	}
	t.Log("tunnel connected to", config.AppConfig.EndpointV4)
}

func TestE2E_WriteReadPacket(t *testing.T) {
	loadE2EConfig(t)
	_, ipConn, cleanup := dialTunnel(t, nil, internal.NoiseConfig{})
	defer cleanup()

	pkt := buildTestIPv4Packet(
		net.ParseIP(config.AppConfig.IPv4).To4(),
		net.IPv4(1, 1, 1, 1).To4(),
		17,
		make([]byte, 32),
	)

	icmp, err := ipConn.WritePacket(pkt)
	if err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	if len(icmp) > 0 {
		t.Logf("got ICMP (%d bytes)", len(icmp))
	}

	buf := make([]byte, 1500)
	done := make(chan struct{})
	go func() {
		defer close(done)
		n, readErr := ipConn.ReadPacket(buf, true)
		if readErr != nil {
			return
		}
		t.Logf("received %d bytes from tunnel", n)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Log("no inbound packet within 5s (may be expected)")
	}
}

func TestE2E_SendNoiseDatagram(t *testing.T) {
	loadE2EConfig(t)
	_, ipConn, cleanup := dialTunnel(t, nil, internal.NoiseConfig{})
	defer cleanup()

	for i := 0; i < 5; i++ {
		if err := ipConn.SendNoiseDatagram(make([]byte, 64)); err != nil {
			t.Fatalf("SendNoiseDatagram[%d]: %v", i, err)
		}
	}
	t.Log("5 noise datagrams sent through tunnel")
}

func TestE2E_InjectNoise(t *testing.T) {
	loadE2EConfig(t)
	_, ipConn, cleanup := dialTunnel(t, nil, internal.NoiseConfig{})
	defer cleanup()

	internal.InjectNoise(ipConn, internal.NoiseConfig{
		Count:   10,
		MinSize: 64,
		MaxSize: 500,
	})

	pkt := buildTestIPv4Packet(
		net.ParseIP(config.AppConfig.IPv4).To4(),
		net.IPv4(1, 1, 1, 1).To4(),
		17,
		make([]byte, 32),
	)
	if _, err := ipConn.WritePacket(pkt); err != nil {
		t.Fatalf("WritePacket after noise: %v", err)
	}
	t.Log("tunnel still functional after 10 noise packets")
}

func TestE2E_PreNoise(t *testing.T) {
	loadE2EConfig(t)
	_, _, cleanup := dialTunnel(t, nil, internal.NoiseConfig{
		Count:    5,
		MinSize:  64,
		MaxSize:  256,
		DelayMin: 1 * time.Millisecond,
		DelayMax: 10 * time.Millisecond,
	})
	defer cleanup()
	t.Log("connected after 5 pre-noise UDP packets")
}

func TestE2E_OnQUICConnectCallback(t *testing.T) {
	loadE2EConfig(t)

	var mu sync.Mutex
	var called bool
	onConnect := func(conn *quic.Conn) {
		mu.Lock()
		called = true
		mu.Unlock()
	}

	_, _, cleanup := dialTunnel(t, onConnect, internal.NoiseConfig{})
	defer cleanup()

	mu.Lock()
	ok := called
	mu.Unlock()
	if !ok {
		t.Error("OnQUICConnect callback was not invoked")
	} else {
		t.Log("OnQUICConnect callback fired")
	}
}

func TestE2E_BBRCongestion(t *testing.T) {
	loadE2EConfig(t)

	profiles := []bbr.Profile{bbr.ProfileStandard, bbr.ProfileConservative, bbr.ProfileAggressive}
	for _, profile := range profiles {
		t.Run(string(profile), func(t *testing.T) {
			var lastErr error
			for attempt := 1; attempt <= 3; attempt++ {
				onConnect := func(conn *quic.Conn) {
					conn.SetCongestionControl(bbr.NewBbrSender(
						bbr.DefaultClock{},
						bbr.GetInitialPacketSize(conn.RemoteAddr()),
						profile,
					))
				}
				_, ipConn, cleanup, err := dialTunnelErr(t, onConnect, internal.NoiseConfig{})
				if err != nil {
					lastErr = err
					t.Logf("attempt %d: %v", attempt, err)
					time.Sleep(500 * time.Millisecond)
					continue
				}

				pkt := buildTestIPv4Packet(
					net.ParseIP(config.AppConfig.IPv4).To4(),
					net.IPv4(1, 1, 1, 1).To4(),
					17,
					make([]byte, 32),
				)
				if _, werr := ipConn.WritePacket(pkt); werr != nil {
					cleanup()
					lastErr = werr
					t.Logf("attempt %d write: %v", attempt, werr)
					time.Sleep(500 * time.Millisecond)
					continue
				}

				cleanup()
				t.Logf("BBR %s: connected and packet sent (attempt %d)", profile, attempt)
				return
			}
			t.Fatalf("BBR %s failed after 3 attempts: %v", profile, lastErr)
		})
	}
}

func TestE2E_MaintainTunnel(t *testing.T) {
	loadE2EConfig(t)

	privKey, err := config.AppConfig.GetEcPrivateKey()
	if err != nil {
		t.Fatalf("GetEcPrivateKey: %v", err)
	}
	pubKey, err := config.AppConfig.GetEcEndpointPublicKey()
	if err != nil {
		t.Fatalf("GetEcEndpointPublicKey: %v", err)
	}
	cert, err := internal.GenerateCert(privKey, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("GenerateCert: %v", err)
	}
	tlsCfg, err := PrepareTlsConfig(privKey, pubKey, cert, internal.ConnectSNI, false)
	if err != nil {
		t.Fatalf("PrepareTlsConfig: %v", err)
	}

	dev := &mockDevice{
		readCh:  make(chan []byte, 1),
		writeCh: make(chan []byte, 10),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	go MaintainTunnel(ctx, MaintainTunnelConfig{
		TLSConfig:       tlsCfg,
		KeepalivePeriod: 30 * time.Second,
		Endpoint:        &net.UDPAddr{IP: net.ParseIP(config.AppConfig.EndpointV4), Port: 443},
		Device:          dev,
		MTU:             1280,
		ReconnectDelay:  1 * time.Second,
		AlwaysReconnect: true,
	})

	time.Sleep(2 * time.Second)

	pkt := buildTestIPv4Packet(
		net.ParseIP(config.AppConfig.IPv4).To4(),
		net.IPv4(8, 8, 8, 8).To4(),
		17,
		make([]byte, 32),
	)
	dev.readCh <- pkt

	select {
	case resp := <-dev.writeCh:
		t.Logf("received %d bytes via MaintainTunnel", len(resp))
	case <-time.After(6 * time.Second):
		t.Log("no response within 6s (may be expected)")
	}
}

func buildTestIPv4Packet(src, dst net.IP, proto byte, payload []byte) []byte {
	totalLen := 20 + len(payload)
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45
	pkt[2] = byte(totalLen >> 8)
	pkt[3] = byte(totalLen)
	pkt[8] = 64
	pkt[9] = proto
	copy(pkt[12:16], src.To4())
	copy(pkt[16:20], dst.To4())

	sum := uint32(0)
	for i := 0; i < 20; i += 2 {
		sum += uint32(pkt[i])<<8 | uint32(pkt[i+1])
	}
	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	pkt[10] = byte(^sum >> 8)
	pkt[11] = byte(^sum)

	copy(pkt[20:], payload)
	return pkt
}

type mockDevice struct {
	readCh  chan []byte
	writeCh chan []byte
}

func (m *mockDevice) ReadPacket(buf []byte) (int, error) {
	pkt, ok := <-m.readCh
	if !ok {
		return 0, fmt.Errorf("device closed")
	}
	return copy(buf, pkt), nil
}

func (m *mockDevice) WritePacket(pkt []byte) error {
	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	select {
	case m.writeCh <- cp:
	default:
	}
	return nil
}

func (m *mockDevice) Close() error {
	close(m.readCh)
	return nil
}

// Ensure json import is used (for potential debug output)
var _ = json.Marshal

func TestE2E_PreNoiseTolerance(t *testing.T) {
	loadE2EConfig(t)

	levels := []struct {
		name    string
		count   int
		minSize int
		maxSize int
		delay   time.Duration
	}{
		{"baseline", 0, 0, 0, 0},
		{"5_small", 5, 64, 128, 10 * time.Millisecond},
		{"10_medium", 10, 256, 600, 10 * time.Millisecond},
		{"20_large", 20, 600, 1200, 20 * time.Millisecond},
		{"50_large", 50, 800, 1200, 5 * time.Millisecond},
		{"100_large", 100, 800, 1200, 2 * time.Millisecond},
	}

	for _, lv := range levels {
		t.Run(lv.name, func(t *testing.T) {
			preNoise := internal.NoiseConfig{
				Count:    lv.count,
				MinSize:  lv.minSize,
				MaxSize:  lv.maxSize,
				DelayMin: lv.delay,
				DelayMax: lv.delay,
			}

			for attempt := 1; attempt <= 3; attempt++ {
				_, ipConn, cleanup, err := dialTunnelErr(t, nil, preNoise)
				if err != nil {
					t.Logf("attempt %d: %v", attempt, err)
					time.Sleep(500 * time.Millisecond)
					continue
				}

				pkt := buildTestIPv4Packet(
					net.ParseIP(config.AppConfig.IPv4).To4(),
					net.IPv4(1, 1, 1, 1).To4(),
					17,
					make([]byte, 32),
				)
				if _, werr := ipConn.WritePacket(pkt); werr != nil {
					cleanup()
					t.Logf("attempt %d write: %v", attempt, werr)
					time.Sleep(500 * time.Millisecond)
					continue
				}

				cleanup()
				t.Logf("pre-noise %s: OK (attempt %d)", lv.name, attempt)
				return
			}
			t.Fatalf("pre-noise %s: failed after 3 attempts", lv.name)
		})

		time.Sleep(2 * time.Second)
	}
}

func TestE2E_PostConnectNoiseTolerance(t *testing.T) {
	loadE2EConfig(t)

	levels := []struct {
		name    string
		count   int
		minSize int
		maxSize int
		delay   time.Duration
	}{
		{"baseline", 0, 0, 0, 0},
		{"5_small", 5, 64, 128, 10 * time.Millisecond},
		{"10_medium", 10, 256, 600, 10 * time.Millisecond},
		{"20_large", 20, 600, 1200, 20 * time.Millisecond},
		{"50_large", 50, 800, 1200, 5 * time.Millisecond},
	}

	for _, lv := range levels {
		t.Run(lv.name, func(t *testing.T) {
			_, ipConn, cleanup := dialTunnel(t, nil, internal.NoiseConfig{})
			defer cleanup()

			if lv.count > 0 {
				internal.InjectNoise(ipConn, internal.NoiseConfig{
					Count:    lv.count,
					MinSize:  lv.minSize,
					MaxSize:  lv.maxSize,
					DelayMin: lv.delay,
					DelayMax: lv.delay,
				})
			}

			pkt := buildTestIPv4Packet(
				net.ParseIP(config.AppConfig.IPv4).To4(),
				net.IPv4(8, 8, 8, 8).To4(),
				17,
				make([]byte, 64),
			)
			if _, err := ipConn.WritePacket(pkt); err != nil {
				t.Fatalf("post-noise %s: WritePacket failed: %v", lv.name, err)
			}

			buf := make([]byte, 1500)
			done := make(chan struct{})
			go func() {
				defer close(done)
				n, readErr := ipConn.ReadPacket(buf, true)
				if readErr != nil {
					t.Logf("post-noise %s: read error: %v", lv.name, readErr)
					return
				}
				t.Logf("post-noise %s: received %d bytes", lv.name, n)
			}()

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Logf("post-noise %s: no response within 5s (may be expected)", lv.name)
			}

			t.Logf("post-noise %s: tunnel still alive", lv.name)
		})

		time.Sleep(2 * time.Second)
	}
}

func TestE2E_DatagramNoiseTolerance(t *testing.T) {
	loadE2EConfig(t)

	levels := []struct {
		name  string
		count int
		size  int
	}{
		{"5x64", 5, 64},
		{"10x256", 10, 256},
		{"20x512", 20, 512},
		{"50x1024", 50, 1024},
	}

	for _, lv := range levels {
		t.Run(lv.name, func(t *testing.T) {
			_, ipConn, cleanup := dialTunnel(t, nil, internal.NoiseConfig{})
			defer cleanup()

			for i := 0; i < lv.count; i++ {
				if err := ipConn.SendNoiseDatagram(make([]byte, lv.size)); err != nil {
					t.Fatalf("datagram noise %s: SendNoiseDatagram[%d] failed: %v", lv.name, i, err)
				}
			}

			pkt := buildTestIPv4Packet(
				net.ParseIP(config.AppConfig.IPv4).To4(),
				net.IPv4(1, 1, 1, 1).To4(),
				17,
				make([]byte, 32),
			)
			if _, err := ipConn.WritePacket(pkt); err != nil {
				t.Fatalf("datagram noise %s: tunnel broken after %d datagrams: %v", lv.name, lv.count, err)
			}
			t.Logf("datagram noise %s: tunnel OK after %d datagrams of %d bytes", lv.name, lv.count, lv.size)
		})

		time.Sleep(2 * time.Second)
	}
}
