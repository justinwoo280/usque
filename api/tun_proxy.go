package api

import (
	"context"
	"log"
	"net/netip"

	"github.com/Diniboy1123/usque/internal/tunproxy"
)

// MaintainTUN is the native/Android entry point. TUN packets always terminate
// in gVisor; only newly originated packets enter MaintainTunnel. MTU here is
// the local TUN MTU, independent of the tunnel's packet budget.
func MaintainTUN(ctx context.Context, cfg MaintainTunnelConfig) {
	v4, _ := netip.ParseAddr(cfg.PMTU.IPv4)
	v6, _ := netip.ParseAddr(cfg.PMTU.IPv6)
	dns4, _ := netip.AddrFromSlice(cfg.DNSHijackTarget4)
	dns6, _ := netip.AddrFromSlice(cfg.DNSHijackTarget6)
	p, err := tunproxy.New(ctx, cfg.Device, tunproxy.Config{
		LocalMTU: cfg.MTU, IPv4: v4, IPv6: v6,
		DNS4: dns4.Unmap(), DNS6: dns6, Block4: cfg.BlockIPv4, Block6: cfg.BlockIPv6,
	})
	if err != nil {
		log.Printf("Unable to start gVisor TUN proxy: %v", err)
		if cfg.OnStateChange != nil {
			cfg.OnStateChange("error")
		}
		_ = cfg.Device.Close()
		return
	}
	defer p.Close()
	log.Printf("gVisor TUN proxy: local MTU %d, independent tunnel MTU discovery", cfg.MTU)
	cfg.Device = p
	cfg.MTU = 1500
	// DNS selection is now done at the socket destination, for TCP and UDP.
	cfg.DNSHijackTarget4, cfg.DNSHijackTarget6 = nil, nil
	MaintainTunnel(p.Context(), cfg)
}
