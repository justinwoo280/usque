//go:build windows

package cmd

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/Diniboy1123/usque/config"
)

// Run only from a disposable Windows VM/console. This exercises actual WFP
// filters with manual routing (no Wintun, DNS changes or WARP credentials).
func TestWindowsFamilyGuardWFP(t *testing.T) {
	value := os.Getenv("USQUE_TEST_WFP_PEER")
	if value == "" {
		t.Skip("set USQUE_TEST_WFP_PEER to a reachable IPv4 TCP IP:port to exercise actual WFP")
	}
	peer, err := netip.ParseAddrPort(value)
	if err != nil || !peer.Addr().Is4() || !peer.Addr().IsGlobalUnicast() || peer.Port() == 0 {
		t.Fatalf("expected a non-loopback IPv4 address and port: %q", value)
	}
	dial := func(d *net.Dialer, addr string) (*net.TCPAddr, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		conn, err := d.DialContext(ctx, "tcp4", addr)
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		return conn.LocalAddr().(*net.TCPAddr), nil
	}
	local, err := dial(&net.Dialer{}, peer.String())
	if err != nil {
		t.Fatalf("IPv4 baseline must work before installing WFP: %v", err)
	}
	bound := &net.Dialer{LocalAddr: &net.TCPAddr{IP: local.IP}}
	otherApp := copyWFPTestExecutable(t)
	otherAppDial := func(t *testing.T, expect string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, otherApp, "-test.run=^TestWindowsWFPDialHelper$")
		cmd.Env = append(os.Environ(), "USQUE_TEST_WFP_DIAL="+peer.String(), "USQUE_TEST_WFP_EXPECT="+expect)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("other executable, want %s: %v\n%s", expect, err, out)
		}
	}
	otherAppDial(t, "permit") // prove the helper/endpoint works without filtering
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	t.Run("IPv6 underlay drops IPv4 even when source is bound", func(t *testing.T) {
		guard, err := startTUNFamilyGuard(config.TunInboundSettings{IPv6: true}, &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := guard.Close(); err != nil {
				t.Error(err)
			}
		})
		if _, err := dial(bound, peer.String()); err == nil {
			t.Fatal("IPv4 connected over the physical source address despite the WFP guard")
		}
		if _, err := dial(&net.Dialer{}, l.Addr().String()); err != nil {
			t.Fatalf("IPv4 loopback must continue working: %v", err)
		}
	})

	t.Run("exact outer endpoint remains reachable", func(t *testing.T) {
		p := familyGuardPolicy{block4: true, peer: peer, protocol: uint8(cIPPROTO_TCP)}
		guard, err := installFamilyGuard(p)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := guard.Close(); err != nil {
				t.Error(err)
			}
		})
		if _, err := dial(bound, peer.String()); err != nil {
			t.Fatalf("app-ID + exact peer tuple should be permitted by WFP: %v", err)
		}
		otherAppDial(t, "block")
	})

	if _, err := dial(bound, peer.String()); err != nil {
		t.Fatalf("IPv4 must recover after closing the dynamic WFP session: %v", err)
	}
}

func copyWFPTestExecutable(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	src, err := os.Open(exe)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	path := filepath.Join(t.TempDir(), "other-wfp-app.exe")
	dst, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr := io.Copy(dst, src)
	if closeErr := dst.Close(); closeErr != nil || copyErr != nil {
		t.Fatalf("copy test executable: %v / %v", copyErr, closeErr)
	}
	return path
}

func TestWindowsWFPDialHelper(t *testing.T) {
	addr, expect := os.Getenv("USQUE_TEST_WFP_DIAL"), os.Getenv("USQUE_TEST_WFP_EXPECT")
	if addr == "" || expect == "" {
		t.Skip("helper for TestWindowsFamilyGuardWFP")
	}
	c, err := net.DialTimeout("tcp4", addr, 4*time.Second)
	if err == nil {
		_ = c.Close()
	}
	if (err == nil) != (expect == "permit") {
		t.Fatalf("expected %s; dial error: %v", expect, err)
	}
}
