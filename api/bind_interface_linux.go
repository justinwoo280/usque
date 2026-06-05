//go:build linux

package api

import (
	"net"

	"golang.org/x/sys/unix"
)

func BindToDevice(fd uintptr, iface *net.Interface) error {
	return unix.BindToDevice(int(fd), iface.Name)
}
