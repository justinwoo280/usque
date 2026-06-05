package cmd

import (
	"context"
	"log"
	"net/netip"
	"os"
	"time"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func runSocksInbound(ctx context.Context, fc *config.FullConfig, ob *outboundBundle) error {
	settings, err := fc.ParseSocksSettings()
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

	dnsTimeout := config.ParseDuration(settings.DNSTimeout, 2*time.Second)
	udpTimeout := config.ParseDuration(settings.UDPTimeout, 60*time.Second)

	hookEnv := map[string]string{
		"USQUE_MODE": "socks",
		"USQUE_IPV4": fc.Account.IPv4,
		"USQUE_IPV6": fc.Account.IPv6,
	}

	tunDev, tunNet, err := netstack.CreateNetTUN(localAddresses, dnsAddrs, settings.MTU)
	if err != nil {
		return err
	}
	defer func() { _ = tunDev.Close() }()

	ob.maintainCfg.Device = api.NewNetstackAdapter(tunDev)
	ob.maintainCfg.MTU = settings.MTU
	ob.maintainCfg.HookEnv = hookEnv

	go api.MaintainTunnel(ctx, ob.maintainCfg)

	resolver := &internal.TunnelDNSResolver{
		DNSAddrs:      dnsAddrs,
		Timeout:       dnsTimeout,
		UseOSResolver: settings.LocalDNS && settings.SystemDNS,
	}
	if !settings.LocalDNS {
		resolver.TunNet = tunNet
	}

	server, err := internal.NewSOCKS5Server(internal.SOCKS5Config{
		Addr:       settings.Listen,
		Username:   settings.Username,
		Password:   settings.Password,
		Resolver:   resolver,
		TunNet:     tunNet,
		UDPTimeout: udpTimeout,
		Logger:     log.New(internal.NewTZStampWriter(os.Stderr), "socks5: ", 0),
	})
	if err != nil {
		return err
	}

	log.Printf("SOCKS proxy listening on %s", settings.Listen)
	return server.Start()
}
