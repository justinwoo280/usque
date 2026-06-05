package cmd

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func runPortFwInbound(ctx context.Context, fc *config.FullConfig, ob *outboundBundle) error {
	settings, err := fc.ParsePortFwSettings()
	if err != nil {
		return err
	}

	if settings.MTU != 1280 {
		log.Println("Warning: MTU is not the default 1280. Packet loss and other issues may occur.")
	}

	var localAddresses []netip.Addr
	v4, err := netip.ParseAddr(fc.Account.IPv4)
	if err == nil {
		localAddresses = append(localAddresses, v4)
	}
	v6, err := netip.ParseAddr(fc.Account.IPv6)
	if err == nil {
		localAddresses = append(localAddresses, v6)
	}

	var dnsAddrs []netip.Addr
	for _, dns := range settings.DNS {
		addr, err := netip.ParseAddr(dns)
		if err != nil {
			return err
		}
		dnsAddrs = append(dnsAddrs, addr)
	}

	hookEnv := map[string]string{
		"USQUE_MODE": "portfw",
		"USQUE_IPV4": fc.Account.IPv4,
		"USQUE_IPV6": fc.Account.IPv6,
	}

	tunDev, tunNet, err := netstack.CreateNetTUN(localAddresses, dnsAddrs, settings.MTU)
	if err != nil {
		return err
	}
	defer func() { _ = tunDev.Close() }()

	if !ob.maintainCfg.AlwaysReconnect {
		ob.maintainCfg.AlwaysReconnect = true
	}

	ob.maintainCfg.Device = api.NewNetstackAdapter(tunDev)
	ob.maintainCfg.MTU = settings.MTU
	ob.maintainCfg.HookEnv = hookEnv

	go api.MaintainTunnel(ctx, ob.maintainCfg)

	log.Printf("Virtual tunnel created, forwarding ports")

	for _, port := range settings.LocalPorts {
		pm, err := internal.ParsePortMapping(port)
		if err != nil {
			return fmt.Errorf("invalid local port mapping: %w", err)
		}
		go forwardPortCtx(tunNet, pm, false)
	}

	for _, port := range settings.RemotePorts {
		pm, err := internal.ParsePortMapping(port)
		if err != nil {
			return fmt.Errorf("invalid remote port mapping: %w", err)
		}
		go forwardPortCtx(tunNet, pm, true)
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: tunNet.DialContext,
		},
	}
	resp, err := client.Get("https://cloudflareok.com/test")
	if err != nil {
		return fmt.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 204 {
		return fmt.Errorf("failed to connect to Cloudflare: %s", resp.Status)
	}
	log.Println("Successfully connected to Cloudflare")

	select {}
}

func forwardPortCtx(net *netstack.Net, pm internal.PortMapping, isRemote bool) {
	if err := forwardPortInner(net, pm, isRemote); err != nil {
		log.Printf("Error in forwarding %d: %v", pm.LocalPort, err)
	}
}

func forwardPortInner(tunNet *netstack.Net, pm internal.PortMapping, isRemote bool) error {
	localAddrPort, err := netip.ParseAddrPort(fmt.Sprintf("%s:%d", pm.BindAddress, pm.LocalPort))
	if err != nil {
		return fmt.Errorf("invalid local address: %w", err)
	}

	if isRemote {
		listener, err := tunNet.ListenTCPAddrPort(localAddrPort)
		if err != nil {
			return fmt.Errorf("failed to listen on %s: %w", localAddrPort, err)
		}
		defer func() { _ = listener.Close() }()
		log.Printf("Remote forwarding: Listening on MASQUE network %s, forwarding to local %s:%d", localAddrPort, pm.RemoteIP, pm.RemotePort)
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Printf("Accept error on %s: %v", localAddrPort, err)
				continue
			}
			go handleFwdConnection(conn, pm, isRemote, tunNet)
		}
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", pm.BindAddress, pm.LocalPort))
	if err != nil {
		return fmt.Errorf("failed to listen on %s:%d: %w", pm.BindAddress, pm.LocalPort, err)
	}
	defer func() { _ = listener.Close() }()
	log.Printf("Local forwarding: Listening on %s:%d, forwarding to remote %s:%d", pm.BindAddress, pm.LocalPort, pm.RemoteIP, pm.RemotePort)
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error on %s:%d: %v", pm.BindAddress, pm.LocalPort, err)
			continue
		}
		go handleFwdConnection(conn, pm, isRemote, tunNet)
	}
}

func handleFwdConnection(localConn net.Conn, pm internal.PortMapping, isRemote bool, tunNet *netstack.Net) {
	defer func() { _ = localConn.Close() }()
	remoteAddrPort, err := netip.ParseAddrPort(fmt.Sprintf("%s:%d", pm.RemoteIP, pm.RemotePort))
	if err != nil {
		log.Printf("Invalid remote address: %v", err)
		return
	}

	var remoteConn net.Conn
	if isRemote {
		remoteConn, err = net.Dial("tcp", remoteAddrPort.String())
	} else {
		remoteConn, err = tunNet.DialContext(context.Background(), "tcp", remoteAddrPort.String())
	}
	if err != nil {
		log.Printf("Failed to connect to remote %s: %v", remoteAddrPort, err)
		return
	}
	defer func() { _ = remoteConn.Close() }()

	go func() { _, _ = io.Copy(remoteConn, localConn) }()
	_, _ = io.Copy(localConn, remoteConn)
}
