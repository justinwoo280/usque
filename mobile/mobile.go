//go:build android

package mobile

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"sync"
	"time"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"github.com/Diniboy1123/usque/internal/congestion"
	"github.com/Diniboy1123/usque/internal/congestion/bbr"
	"github.com/apernet/quic-go"
)

// TunnelListener receives tunnel lifecycle events from the Go engine.
// Implement this interface in Kotlin/Java and pass to RegisterListener.
// All methods are called from Go goroutines — implementations must be
// thread-safe and should dispatch to the UI thread as needed.
type TunnelListener interface {
	OnStateChange(state string)
	OnTraffic(sent int64, recv int64)
}

var (
	mgr      *tunnelManager
	mgrOnce  sync.Once
	listener TunnelListener
	listMu   sync.RWMutex
)

// RegisterListener sets the callback receiver for tunnel events.
// Only one listener is active at a time; registering replaces the previous one.
func RegisterListener(l TunnelListener) {
	listMu.Lock()
	listener = l
	listMu.Unlock()
}

// UnregisterListener removes the current listener.
func UnregisterListener() {
	listMu.Lock()
	listener = nil
	listMu.Unlock()
}

func notifyState(state string) {
	listMu.RLock()
	l := listener
	listMu.RUnlock()
	if l != nil {
		l.OnStateChange(state)
	}
}

func notifyTraffic(sent, recv int64) {
	listMu.RLock()
	l := listener
	listMu.RUnlock()
	if l != nil {
		l.OnTraffic(sent, recv)
	}
}

type tunnelManager struct {
	ctx    context.Context
	cancel context.CancelFunc
	status *tunnelStatus
	done   chan struct{}
	device api.TunnelDevice
}

// StartTunnel starts the MASQUE tunnel engine.
//
// Parameters:
//   - tunFd: VpnService TUN file descriptor
//   - udpFd: pre-created, VpnService.protect()'d UDP socket fd
//   - configJSON: usque config JSON contents (FullConfig or legacy flat format)
//
// Returns "" on success, error string on failure.
func StartTunnel(tunFd int, udpFd int, configJSON string) string {
	mgrOnce.Do(func() {
		mgr = &tunnelManager{
			status: newTunnelStatus(),
		}
	})

	if mgr.ctx != nil {
		return "tunnel already running"
	}

	fc, err := parseConfigJSON(configJSON)
	if err != nil {
		return "failed to parse config: " + err.Error()
	}

	acct := &fc.Account
	privKey, err := acct.GetEcPrivateKey()
	if err != nil {
		return "failed to get private key: " + err.Error()
	}
	peerPubKey, err := acct.GetEcEndpointPublicKey()
	if err != nil {
		return "failed to get public key: " + err.Error()
	}
	cert, err := internal.GenerateCert(privKey, &privKey.PublicKey)
	if err != nil {
		return "failed to generate cert: " + err.Error()
	}

	ob := &fc.Outbound.Settings
	tlsConfig, err := api.PrepareTlsConfig(privKey, peerPubKey, cert, ob.SNIAddress, ob.Insecure)
	if err != nil {
		return "failed to prepare TLS: " + err.Error()
	}

	endpoint, err := config.SelectEndpointFromConfig(acct, ob.UseHTTP2, ob.UseIPv6, ob.Port)
	if err != nil {
		return "failed to select endpoint: " + err.Error()
	}

	var udpAddr *net.UDPAddr
	var tcpAddr *net.TCPAddr
	if ob.UseHTTP2 {
		tcpAddr, _ = endpoint.(*net.TCPAddr)
		if tcpAddr == nil {
			return "endpoint is not TCP"
		}
	} else {
		udpAddr, _ = endpoint.(*net.UDPAddr)
		if udpAddr == nil {
			return "endpoint is not UDP"
		}
	}

	tunDev := wrapTunFd(tunFd)
	udpConn := wrapUDPConn(udpFd)
	if udpConn == nil && !ob.UseHTTP2 {
		return "failed to wrap UDP fd"
	}

	var onQUICConnect func(*quic.Conn)
	if err := ob.Congestion.Validate(); err == nil {
		switch ob.Congestion.Type {
		case "brutal":
			onQUICConnect = func(conn *quic.Conn) {
				conn.SetCongestionControl(congestion.NewBrutalSender(ob.Congestion.BrutalBPS))
			}
		case "bbr":
			profile, _ := bbr.ParseProfile(ob.Congestion.BBRProfile)
			onQUICConnect = func(conn *quic.Conn) {
				conn.SetCongestionControl(bbr.NewBbrSender(
					bbr.DefaultClock{},
					bbr.GetInitialPacketSize(conn.RemoteAddr()),
					profile,
				))
			}
		}
	}

	keepalive := config.ParseDuration(ob.KeepalivePeriod, 30*time.Second)
	reconnect := config.ParseDuration(ob.ReconnectDelay, 1*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	mgr.ctx = ctx
	mgr.cancel = cancel
	mgr.done = make(chan struct{})
	mgr.device = tunDev
	mgr.status.reset()
	mgr.status.markStarted()
	mgr.status.setState(stateConnecting)

	// Extract DNS hijack targets from inbound settings
	var dnsHijack4, dnsHijack6 net.IP
	if settings, err := fc.ParseTunSettings(); err == nil {
		for _, d := range settings.DNS {
			ip := net.ParseIP(d)
			if ip == nil {
				continue
			}
			if ip.To4() != nil && dnsHijack4 == nil {
				dnsHijack4 = ip
			} else if ip.To4() == nil && dnsHijack6 == nil {
				dnsHijack6 = ip
			}
		}
	}

	go func() {
		defer close(mgr.done)
		api.MaintainTunnel(ctx, api.MaintainTunnelConfig{
			TLSConfig:         tlsConfig,
			KeepalivePeriod:   keepalive,
			InitialPacketSize: ob.InitialPacketSize,
			Endpoint:          endpoint,
			Device:            tunDev,
			MTU:               1280,
			ReconnectDelay:    reconnect,
			AlwaysReconnect:   true,
			UseHTTP2:          ob.UseHTTP2,
			UDPConn:           udpConn,
			OnQUICConnect:     onQUICConnect,
			Noise:             ob.Noise.ToNoiseConfig(),
			PreNoise:          ob.PreNoise.ToNoiseConfig(),
			DNSHijackTarget4:  dnsHijack4,
			DNSHijackTarget6:  dnsHijack6,
			OnStateChange: func(state string) {
				switch state {
				case "connecting":
					mgr.status.setState(stateConnecting)
				case "connected":
					mgr.status.setState(stateConnected)
				case "reconnecting":
					mgr.status.setState(stateReconnecting)
				case "error":
					mgr.status.setState(stateError)
				}
				notifyState(state)
			},
			OnTraffic: func(sent, recv int64) {
				mgr.status.bytesSent.Store(sent)
				mgr.status.bytesRecv.Store(recv)
				notifyTraffic(sent, recv)
			},
		})
	}()

	log.Println("mobile: tunnel engine started")
	return ""
}

// parseConfigJSON parses FullConfig from JSON string, with legacy flat format fallback.
func parseConfigJSON(jsonStr string) (*config.FullConfig, error) {
	var fc config.FullConfig
	if err := json.Unmarshal([]byte(jsonStr), &fc); err == nil && fc.Inbound.Type != "" {
		return &fc, nil
	}

	var acct config.AccountConfig
	if err := json.Unmarshal([]byte(jsonStr), &acct); err != nil {
		return nil, err
	}
	return config.NewDefaultFullConfig(acct), nil
}

// StopTunnel stops the running tunnel engine and releases resources.
func StopTunnel() {
	if mgr == nil || mgr.cancel == nil {
		return
	}
	log.Println("mobile: stopping tunnel engine")
	if mgr.device != nil {
		_ = mgr.device.Close()
	}
	mgr.cancel()
	if mgr.done != nil {
		<-mgr.done
	}
	mgr.status.setState(stateStopped)
	notifyState("stopped")
	mgr.ctx = nil
	mgr.cancel = nil
	mgr.done = nil
	mgr.device = nil
}

// GetStatus returns a JSON string describing the current tunnel state.
func GetStatus() string {
	if mgr == nil {
		return `{"state":"stopped","bytes_sent":0,"bytes_recv":0,"uptime":""}`
	}
	return mgr.status.toJSON()
}
