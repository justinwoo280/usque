package cmd

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/spf13/cobra"
)

// tunDevice holds TUN device creation parameters.
type tunDevice struct {
	name     string
	mtu      int
	iproute2 bool
	ipv4     bool
	ipv6     bool
	persist  bool
	tunFd    int
	account  *config.AccountConfig
}

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run usque with a JSON config file",
	Run: func(cmd *cobra.Command, args []string) {
		configPath, _ := cmd.Flags().GetString("config")
		fc, err := config.LoadFullConfig(configPath)
		if err != nil {
			log.Fatalf("Failed to load config: %v", err)
		}
		config.AppConfig = fc.Account

		ob, err := buildOutbound(fc)
		if err != nil {
			log.Fatalf("Failed to build outbound: %v", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

		switch fc.Inbound.Type {
		case "tun":
			err = runTunInbound(ctx, fc, ob, sigCh, cancel)
		case "socks":
			err = runSocksInbound(ctx, fc, ob)
		case "http_proxy":
			err = runHTTPProxyInbound(ctx, fc, ob)
		case "portfw":
			err = runPortFwInbound(ctx, fc, ob)
		default:
			log.Fatalf("Unknown inbound type: %q", fc.Inbound.Type)
		}
		if err != nil {
			log.Fatalf("Inbound failed: %v", err)
		}
	},
}

func runTunInbound(ctx context.Context, fc *config.FullConfig, ob *outboundBundle, sigCh chan os.Signal, cancel context.CancelFunc) error {
	settings, err := fc.ParseTunSettings()
	if err != nil {
		return err
	}

	if settings.MTU != 1280 {
		log.Println("Warning: MTU is not the default 1280. Packet loss and other issues may occur.")
	}

	t := &tunDevice{
		name:     settings.Name,
		mtu:      settings.MTU,
		iproute2: true,
		ipv4:     settings.IPv4,
		ipv6:     settings.IPv6,
		persist:  settings.Persist,
		tunFd:    settings.TunFd,
		account:  &fc.Account,
	}

	dev, err := t.create()
	if err != nil {
		log.Println("Are you root/administrator? TUN device creation usually requires elevated privileges.")
		log.Fatalf("Failed to create TUN device: %v", err)
	}
	log.Printf("Created TUN device: %s", t.name)

	var updater *api.InterfaceUpdater
	var routeMgr RouteManager
	if settings.AutoRoute {
		routeCfg := AutoRouteConfig{
			InterfaceName: t.name,
			EnableIPv4:    settings.IPv4,
			EnableIPv6:    settings.IPv6,
			IPv4:          net.ParseIP(fc.Account.IPv4),
			IPv6:          net.ParseIP(fc.Account.IPv6),
			EndpointIP:    extractEndpointIP(ob.endpoint),
		}
		if len(settings.DNS) > 0 {
			for _, d := range settings.DNS {
				routeCfg.DNSServers = append(routeCfg.DNSServers, net.ParseIP(d))
			}
		}
		routeMgr = newRouteManager(routeCfg)
		if routeMgr != nil {
			if err := routeMgr.Setup(); err != nil {
				log.Fatalf("Auto-route setup failed: %v", err)
			}
		} else {
			log.Println("Warning: auto-route is not supported on this platform")
		}

		tunIfIndex, err := getTunIfIndex(t.name)
		if err != nil {
			log.Printf("Warning: failed to get TUN interface index: %v", err)
		} else {
			updater = api.NewInterfaceUpdater("auto", tunIfIndex)
			updater.Update()
		}
	}

	hookEnv := map[string]string{
		"USQUE_MODE":  "tun",
		"USQUE_IFACE": t.name,
		"USQUE_IPV4":  fc.Account.IPv4,
		"USQUE_IPV6":  fc.Account.IPv6,
	}

	ob.maintainCfg.Device = dev
	ob.maintainCfg.MTU = settings.MTU
	ob.maintainCfg.HookEnv = hookEnv
	ob.maintainCfg.InterfaceUpdater = updater

	go api.MaintainTunnel(ctx, ob.maintainCfg)

	if settings.AutoRoute {
		log.Println("Tunnel established with auto-route enabled")
	} else {
		log.Println("Tunnel established, you may now set up routing and DNS")
	}

	sig := <-sigCh
	log.Printf("Received signal %v, shutting down...", sig)
	cancel()

	if routeMgr != nil {
		if err := routeMgr.Cleanup(); err != nil {
			log.Printf("Warning: route cleanup failed: %v", err)
		} else {
			log.Println("Auto-route cleaned up")
		}
	}
	return nil
}

func getTunIfIndex(name string) (int, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return iface.Index, nil
}

func init() {
	rootCmd.AddCommand(runCmd)
}
