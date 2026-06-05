//go:build windows

package api

import (
	"encoding/binary"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	ipUnicastIf   = 31
	ipv6UnicastIf = 31
)

func BindToDevice(fd uintptr, iface *net.Interface) error {
	var indexBytes [4]byte
	binary.BigEndian.PutUint32(indexBytes[:], uint32(iface.Index))
	idx := *(*int)(unsafe.Pointer(&indexBytes[0]))
	_ = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, ipUnicastIf, idx)
	_ = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, ipv6UnicastIf, iface.Index)
	return nil
}
