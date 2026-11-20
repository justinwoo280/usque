package cmd

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"github.com/spf13/cobra"
)

var pmtuCmd = &cobra.Command{
	Use:   "pmtu",
	Short: "Measure a wire-confirmed inner IP size over the configured WARP tunnel",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		path, _ := cmd.Flags().GetString("config")
		ceiling, _ := cmd.Flags().GetInt("max")
		if ceiling < 128 || ceiling > 65535 {
			return fmt.Errorf("--max must be between 128 and 65535 inner IP bytes")
		}
		fc, err := config.LoadFullConfig(path)
		if err != nil {
			return err
		}
		if fc.Outbound.Settings.UseHTTP2 {
			return fmt.Errorf("pmtu requires HTTP/3; HTTP/2 capsules use a TCP stream")
		}
		ob, err := buildOutbound(fc)
		if err != nil {
			return err
		}
		cfg := ob.maintainCfg
		if cmd.Flags().Changed("target") {
			cfg.PMTU.Target, _ = cmd.Flags().GetString("target")
		}
		if fc.Inbound.Type == "tun" {
			s, err := fc.ParseTunSettings()
			if err != nil {
				return err
			}
			cfg.BlockIPv4, cfg.BlockIPv6 = !s.IPv4, !s.IPv6
		}
		src, dst, err := cfg.PMTU.EchoPath(cfg.BlockIPv4, cfg.BlockIPv6)
		if err != nil {
			return err
		}
		if !src.IsValid() {
			return fmt.Errorf("no enabled PMTU echo path; check the account address and pmtu_target")
		}

		ctx, cancel := context.WithTimeout(cmd.Context(), time.Minute)
		defer cancel()
		udp, tr, conn, _, err := api.ConnectTunnel(ctx, cfg.TLSConfig,
			internal.DefaultQuicConfig(cfg.KeepalivePeriod, cfg.InitialPacketSize), internal.ConnectURI,
			cfg.Endpoint, false, cfg.OnQUICConnect, cfg.PreNoise, nil, nil)
		if udp != nil {
			defer udp.Close()
		}
		if err != nil {
			return err
		}
		// Drain only this diagnostic session. No TUN, system ping or routes.
		closeConn := sync.OnceFunc(func() { _ = conn.Close(); _ = tr.Close() })
		stop := context.AfterFunc(ctx, closeConn)
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer cancel()
			buf := make([]byte, 2048)
			for {
				if _, err := conn.ReadPacket(buf, true); err != nil {
					return
				}
			}
		}()
		defer func() { stop(); closeConn(); <-done }()
		// Exercise the path while QUIC's ACK-based discovery is starting. A
		// measurement capped by the initial packet budget isn't the path maximum.
		if _, err := conn.ProbePathMTU(ctx, src, dst, 128); err != nil {
			return err
		}
		select {
		case <-time.After(2 * time.Second):
		case <-ctx.Done():
			return ctx.Err()
		}
		mtu, err := conn.ProbePathMTU(ctx, src, dst, ceiling)
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "WARP endpoint %s; echo target %s; verified inner MTU: %d bytes (search ceiling %d)\n", cfg.Endpoint, dst, mtu, ceiling)
		return nil
	},
}

func init() {
	pmtuCmd.Flags().Int("max", 1500, "largest inner IP packet to test, including IP and ICMP headers")
	pmtuCmd.Flags().String("target", "", "inner IPv4 or IPv6 echo responder (default from config)")
	rootCmd.AddCommand(pmtuCmd)
}
