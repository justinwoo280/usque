//go:build windows

package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Diniboy1123/usque/config"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func TestWindowsTUNAddress(t *testing.T) {
	if p, err := windowsTUNAddress("", false, 4); err != nil || p.IsValid() {
		t.Fatalf("disabled family: got %s, %v", p, err)
	}
	for _, ip := range []string{"", "2001:db8::1", "0.0.0.0", "224.0.0.1", "::ffff:192.0.2.1"} {
		if _, err := windowsTUNAddress(ip, true, 4); err == nil {
			t.Errorf("accepted invalid IPv4 address %q", ip)
		}
	}
	if p, err := windowsTUNAddress("172.16.0.2", true, 4); err != nil || p.String() != "172.16.0.2/32" {
		t.Fatalf("enabled family: got %s, %v", p, err)
	}
}

// Run elevated, with an architecture-matched official wintun.dll next to the
// test binary. This creates an adapter but does not install default routes.
func TestWintunDriverSmoke(t *testing.T) {
	if os.Getenv("USQUE_TEST_WINTUN") != "1" {
		t.Skip("set USQUE_TEST_WINTUN=1 to use the actual Wintun driver")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(exe), "wintun.dll")); err != nil {
		t.Fatalf("place the official wintun.dll next to %s: %v", exe, err)
	}
	d := &tunDevice{
		name: fmt.Sprintf("usque-smoke-%d", os.Getpid()), mtu: 9000, ipv4: true, ipv6: true,
		account: &config.AccountConfig{IPv4: "198.18.0.251", IPv6: "fd27:4cea:1::251"},
	}
	dev, err := d.create()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dev.Close() })
	for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		row, err := winipcfg.LUID(d.luid).IPInterface(family)
		if err != nil {
			t.Fatal(err)
		}
		if row.NLMTU != 9000 {
			t.Errorf("NLMTU = %d for family %d, want 9000", row.NLMTU, family)
		}
	}
	readDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 65535)
		for {
			if _, err := dev.ReadPacket(buf); err != nil {
				readDone <- err
				return
			}
		}
	}()
	if err := dev.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-readDone:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("read after close: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Wintun read did not exit after Close")
	}
}
