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
//   - configJSON: usque config.json contents as string
//
// Returns "" on success, error string on failure.
func StartTunnel(tunFd int, udpFd int, configJSON string) string {
	var startErr string
	mgrOnce.Do(func() {
		mgr = &tunnelManager{
			status: newTunnelStatus(),
		}
	})

	if mgr.ctx != nil {
		return "tunnel already running"
	}

	if err := json.Unmarshal([]byte(configJSON), &config.AppConfig); err != nil {
		return "failed to parse config: " + err.Error()
	}
	config.ConfigLoaded = true

	privKey, err := config.AppConfig.GetEcPrivateKey()
	if err != nil {
		return "failed to get private key: " + err.Error()
	}
	peerPubKey, err := config.AppConfig.GetEcEndpointPublicKey()
	if err != nil {
		return "failed to get public key: " + err.Error()
	}
	cert, err := internal.GenerateCert(privKey, &privKey.PublicKey)
	if err != nil {
		return "failed to generate cert: " + err.Error()
	}
	tlsConfig, err := api.PrepareTlsConfig(privKey, peerPubKey, cert, internal.ConnectSNI, false)
	if err != nil {
		return "failed to prepare TLS: " + err.Error()
	}

	endpoint, err := config.SelectEndpointFromConfig(false, false, 443)
	if err != nil {
		return "failed to select endpoint: " + err.Error()
	}

	udpAddr, ok := endpoint.(*net.UDPAddr)
	if !ok {
		return "endpoint is not UDP (HTTP/2 not supported in mobile mode)"
	}

	tunDev := wrapTunFd(tunFd)
	udpConn := wrapUDPConn(udpFd)
	if udpConn == nil {
		return "failed to wrap UDP fd"
	}

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
			KeepalivePeriod:   30 * time.Second,
			Endpoint:          udpAddr,
			Device:            tunDev,
			MTU:               1280,
			ReconnectDelay:    1 * time.Second,
			AlwaysReconnect:   true,
			Fwmark:            0,
			UDPConn:           udpConn,
			OnQUICConnect: func(conn *quic.Conn) {
				mgr.status.setState(stateConnected)
			},
		})
	}()

	log.Println("mobile: tunnel engine started")
	return startErr
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
//
// Example responses:
//
//	{"state":"connected","bytes_sent":12345,"bytes_recv":67890,"uptime":"5m30s"}
//	{"state":"connecting","bytes_sent":0,"bytes_recv":0,"uptime":""}
//	{"state":"error","message":"login failed","bytes_sent":0,"bytes_recv":0,"uptime":""}
//	{"state":"stopped","bytes_sent":0,"bytes_recv":0,"uptime":""}
func GetStatus() string {
	if mgr == nil {
		return `{"state":"stopped","bytes_sent":0,"bytes_recv":0,"uptime":""}`
	}
	return mgr.status.toJSON()
}
