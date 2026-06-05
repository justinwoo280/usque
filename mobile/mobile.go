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

var (
	mgr     *tunnelManager
	mgrOnce sync.Once
)

type tunnelManager struct {
	ctx    context.Context
	cancel context.CancelFunc
	status *tunnelStatus
	done   chan struct{}
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
				mgr.status.setState(stateConnected)
			}
		case "bbr":
			profile, _ := bbr.ParseProfile(ob.Congestion.BBRProfile)
			onQUICConnect = func(conn *quic.Conn) {
				conn.SetCongestionControl(bbr.NewBbrSender(
					bbr.DefaultClock{},
					bbr.GetInitialPacketSize(conn.RemoteAddr()),
					profile,
				))
				mgr.status.setState(stateConnected)
			}
		default:
			onQUICConnect = func(conn *quic.Conn) {
				mgr.status.setState(stateConnected)
			}
		}
	}

	keepalive := config.ParseDuration(ob.KeepalivePeriod, 30*time.Second)
	reconnect := config.ParseDuration(ob.ReconnectDelay, 1*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	mgr.ctx = ctx
	mgr.cancel = cancel
	mgr.done = make(chan struct{})
	mgr.status.reset()
	mgr.status.markStarted()
	mgr.status.setState(stateConnecting)

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
	mgr.cancel()
	if mgr.done != nil {
		<-mgr.done
	}
	mgr.status.setState(stateStopped)
	mgr.ctx = nil
	mgr.cancel = nil
	mgr.done = nil
}

// GetStatus returns a JSON string describing the current tunnel state.
func GetStatus() string {
	if mgr == nil {
		return `{"state":"stopped","bytes_sent":0,"bytes_recv":0,"uptime":""}`
	}
	return mgr.status.toJSON()
}
