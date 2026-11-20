//go:build windows

package api

import (
	"fmt"
	"math/bits"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	ipUnicastIf     = 31
	ipv6UnicastIf   = 31
	soProtocolInfoW = 0x2005
)

func BindToDevice(fd uintptr, iface *net.Interface) error {
	socket := windows.Handle(fd)
	// The Control hook runs before bind(), when getsockname cannot tell us
	// the family. Query the socket itself and require the right option to work.
	var info windows.WSAProtocolInfo
	size := int32(unsafe.Sizeof(info))
	if err := windows.Getsockopt(socket, windows.SOL_SOCKET, soProtocolInfoW, (*byte)(unsafe.Pointer(&info)), &size); err != nil {
		return fmt.Errorf("get Winsock protocol info: %w", err)
	}
	var err error
	switch info.AddressFamily {
	case windows.AF_INET:
		// IP_UNICAST_IF expects network byte order on Windows, but
		// IPV6_UNICAST_IF expects native byte order.
		err = windows.SetsockoptInt(socket, windows.IPPROTO_IP, ipUnicastIf, int(bits.ReverseBytes32(uint32(iface.Index))))
	case windows.AF_INET6:
		err = windows.SetsockoptInt(socket, windows.IPPROTO_IPV6, ipv6UnicastIf, iface.Index)
	default:
		return fmt.Errorf("cannot bind Winsock address family %d to an interface", info.AddressFamily)
	}
	if err != nil {
		return fmt.Errorf("bind Winsock address family %d to interface %d: %w", info.AddressFamily, iface.Index, err)
	}
	return nil
}
