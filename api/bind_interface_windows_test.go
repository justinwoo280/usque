//go:build windows

package api

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsBindToDevice(t *testing.T) {
	for _, tc := range []struct {
		network, addr string
		destination   windows.Sockaddr
		level, opt    int
	}{
		{"udp4", "127.0.0.1:0", &windows.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}, windows.IPPROTO_IP, ipUnicastIf},
		{"udp6", "[::1]:0", &windows.SockaddrInet6{Addr: [16]byte{15: 1}}, windows.IPPROTO_IPV6, ipv6UnicastIf},
	} {
		t.Run(tc.network, func(t *testing.T) {
			var idx uint32
			if err := windows.GetBestInterfaceEx(tc.destination, &idx); err != nil || idx == 0 {
				t.Skipf("no %s loopback interface: %v", tc.network, err)
			}
			lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
				var bindErr error
				if err := c.Control(func(fd uintptr) {
					if bindErr = BindToDevice(fd, &net.Interface{Index: int(idx)}); bindErr != nil {
						return
					}
					got, err := windows.GetsockoptInt(windows.Handle(fd), tc.level, tc.opt)
					if err != nil {
						bindErr = err
						return
					}
					// Winsock accepts a network-order IPv4 index for Set but
					// returns a host-order index for Get, for both families.
					if uint32(got) != idx {
						bindErr = fmt.Errorf("socket's interface option = %d, want %d", got, idx)
					}
				}); err != nil {
					return err
				}
				return bindErr
			}}
			c, err := lc.ListenPacket(context.Background(), tc.network, tc.addr)
			if err != nil {
				t.Fatal(err)
			}
			_ = c.Close()
		})
	}
	if err := BindToDevice(uintptr(windows.InvalidHandle), &net.Interface{Index: 1}); err == nil {
		t.Fatal("invalid socket binding silently succeeded")
	}
}
