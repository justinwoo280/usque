package cmd

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"github.com/Diniboy1123/usque/internal/congestion"
	"github.com/Diniboy1123/usque/internal/congestion/bbr"
	"github.com/apernet/quic-go"
)

// outboundBundle holds everything needed to call api.MaintainTunnel.
type outboundBundle struct {
	tlsConfig   *tls.Config
	endpoint    net.Addr
	maintainCfg api.MaintainTunnelConfig
}

func buildOutbound(fc *config.FullConfig) (*outboundBundle, error) {
	acct := &fc.Account
	ob := &fc.Outbound.Settings

	if err := ob.Congestion.Validate(); err != nil {
		return nil, err
	}

	privKey, err := acct.GetEcPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("get private key: %w", err)
	}
	peerPubKey, err := acct.GetEcEndpointPublicKey()
	if err != nil {
		return nil, fmt.Errorf("get public key: %w", err)
	}

	cert, err := internal.GenerateCert(privKey, &privKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("generate cert: %w", err)
	}

	tlsConfig, err := api.PrepareTlsConfig(privKey, peerPubKey, cert, ob.SNIAddress, ob.Insecure)
	if err != nil {
		return nil, fmt.Errorf("prepare TLS config: %w", err)
	}

	endpoint, err := config.SelectEndpointFromConfig(ob.UseHTTP2, ob.UseIPv6, ob.Port)
	if err != nil {
		return nil, fmt.Errorf("select endpoint: %w", err)
	}

	if ob.Insecure {
		config.WarnInsecure()
	}
	if ob.UseHTTP2 {
		config.LogHTTP2Endpoint(endpoint)
	}

	keepalivePeriod := config.ParseDuration(ob.KeepalivePeriod, 30*time.Second)
	reconnectDelay := config.ParseDuration(ob.ReconnectDelay, 1*time.Second)

	var onQUICConnect func(*quic.Conn)
	switch ob.Congestion.Type {
	case "brutal":
		if ob.Congestion.BrutalBPS == 0 {
			return nil, fmt.Errorf("congestion=brutal requires congestion.brutal_bps to be set")
		}
		log.Printf("Using Brutal congestion control (target: %d bps)", ob.Congestion.BrutalBPS)
		onQUICConnect = func(conn *quic.Conn) {
			conn.SetCongestionControl(congestion.NewBrutalSender(ob.Congestion.BrutalBPS))
		}
	case "bbr":
		profile, err := bbr.ParseProfile(ob.Congestion.BBRProfile)
		if err != nil {
			return nil, fmt.Errorf("invalid BBR profile: %w", err)
		}
		log.Printf("Using BBR congestion control (profile: %s)", profile)
		onQUICConnect = func(conn *quic.Conn) {
			conn.SetCongestionControl(bbr.NewBbrSender(
				bbr.DefaultClock{},
				bbr.GetInitialPacketSize(conn.RemoteAddr()),
				profile,
			))
		}
	case "reno", "":
		// default
	default:
		return nil, fmt.Errorf("unknown congestion algorithm: %q (use 'reno', 'brutal', or 'bbr')", ob.Congestion.Type)
	}

	noise := ob.Noise.ToNoiseConfig()
	preNoise := ob.PreNoise.ToNoiseConfig()

	return &outboundBundle{
		tlsConfig: tlsConfig,
		endpoint:  endpoint,
		maintainCfg: api.MaintainTunnelConfig{
			TLSConfig:         tlsConfig,
			KeepalivePeriod:   keepalivePeriod,
			InitialPacketSize: ob.InitialPacketSize,
			Endpoint:          endpoint,
			ReconnectDelay:    reconnectDelay,
			AlwaysReconnect:   ob.AlwaysReconnect,
			UseHTTP2:          ob.UseHTTP2,
			OnConnect:         ob.OnConnect,
			OnDisconnect:      ob.OnDisconnect,
			OnQUICConnect:     onQUICConnect,
			Noise:             noise,
			PreNoise:          preNoise,
		},
	}, nil
}
