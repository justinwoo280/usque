//go:build darwin

package api

import (
	"net"

	"golang.org/x/sys/unix"
)

func BindToDevice(fd uintptr, iface *net.Interface) error {
	_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, iface.Index)
	_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, iface.Index)
	return nil
}
