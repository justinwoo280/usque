package api

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"time"

	connectip "github.com/Diniboy1123/connect-ip-go"
)

type PMTUConfig struct {
	IPv4, IPv6 string // addresses assigned to this client inside the tunnel
	Target     string // optional IP of an echo responder reached through the tunnel
}

// EchoPath returns zero addresses if probing is disabled or no stack is enabled.
// The inner IP family need not match the outer QUIC endpoint's family.
func (p PMTUConfig) EchoPath(block4, block6 bool) (src, dst netip.Addr, err error) {
	if p.Target == "off" || (block4 && block6) {
		return
	}
	v4, _ := netip.ParseAddr(p.IPv4)
	v6, _ := netip.ParseAddr(p.IPv6)
	if p.Target != "" {
		dst, err = netip.ParseAddr(p.Target)
		if err != nil {
			return src, dst, fmt.Errorf("invalid pmtu_target: %w", err)
		}
		dst = dst.Unmap()
		if dst.IsUnspecified() || dst.IsMulticast() || dst.Zone() != "" {
			return src, dst, fmt.Errorf("pmtu_target must be a unicast IP: %s", dst)
		}
	}
	if !block4 && v4.Is4() && (!dst.IsValid() || dst.Is4()) {
		if !dst.IsValid() {
			dst = netip.MustParseAddr("1.1.1.1")
		}
		return v4, dst, nil
	}
	if !block6 && v6.Is6() && (!dst.IsValid() || dst.Is6()) {
		if !dst.IsValid() {
			dst = netip.MustParseAddr("2606:4700:4700::1111")
		}
		return v6, dst, nil
	}
	if dst.IsValid() {
		err = fmt.Errorf("no enabled inner address for pmtu_target %s", dst)
	}
	return
}

func monitorPathMTU(ctx context.Context, conn *connectip.Conn, cfg MaintainTunnelConfig) {
	src, dst, err := cfg.PMTU.EchoPath(cfg.BlockIPv4, cfg.BlockIPv6)
	if err != nil {
		log.Printf("Wire PMTU probe disabled: %v", err)
	}
	tick := time.NewTicker(pmtuRefreshInterval)
	defer tick.Stop()
	var nextCheck, nextGrowth time.Time
	warmupUntil := time.Now().Add(10 * time.Second)
	var verified int
	var unavailable bool
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick.C:
			mtu, changed, err := conn.RefreshPMTU()
			if err != nil {
				if ctx.Err() == nil {
					log.Printf("Unable to refresh QUIC send limit: %v", err)
				}
				continue
			}
			if changed {
				updateDeviceMTU(cfg, mtu)
				log.Printf("Effective inner MTU after QUIC limit update: %d", effectiveTunnelMTU(cfg.MTU, mtu))
			}
			if !src.IsValid() || now.Before(nextCheck) {
				continue
			}
			ceiling := min(cfg.MTU, 65535)
			if verified == 0 {
				// Confirm a useful baseline quickly, so UDP/QUIC needn't wait
				// for the slower search for the final byte of available space.
				ceiling = min(ceiling, 1280)
			} else if now.Before(nextGrowth) {
				ceiling = min(ceiling, verified) // cheap periodic check for a black hole
			} else {
				nextGrowth = now.Add(5 * time.Minute)
			}
			probeCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
			result, err := conn.ProbePathMTU(probeCtx, src, dst, ceiling)
			cancel()
			nextCheck = time.Now().Add(30 * time.Second)
			if time.Now().Before(warmupUntil) {
				nextCheck = time.Now().Add(time.Second)
				nextGrowth = time.Time{}
			}
			if err != nil {
				if !unavailable && ctx.Err() == nil {
					log.Printf("Wire PMTU unavailable via %s: %v (retaining effective MTU %d)", dst, err, effectiveTunnelMTU(cfg.MTU, conn.EffectiveMTU()))
				}
				unavailable = true
				continue
			}
			if result != verified || unavailable {
				log.Printf("Wire-confirmed inner MTU via %s: %d bytes", dst, result)
			}
			verified, unavailable = result, false
			updateDeviceMTU(cfg, conn.EffectiveMTU())
		}
	}
}

func updateDeviceMTU(cfg MaintainTunnelConfig, mtu int) {
	if d, ok := cfg.Device.(interface{ SetMTU(int) }); ok {
		d.SetMTU(effectiveTunnelMTU(cfg.MTU, mtu))
	}
}
