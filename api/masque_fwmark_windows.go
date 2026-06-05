//go:build windows

package api

import (
	"context"
	"encoding/binary"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	ipUnicastIf   = 31
	ipv6UnicastIf = 31
)

func listenUDPWithMark(ctx context.Context, network string, addr *net.UDPAddr, ifIndex uint32) (*net.UDPConn, error) {
	if ifIndex == 0 {
		return net.ListenUDP(network, addr)
	}
	lc := net.ListenConfig{
		Control: func(net, _ string, c syscall.RawConn) error {
			var opErr error
			err := c.Control(func(fd uintptr) {
				if net == "udp4" || net == "udp" {
					var index [4]byte
					binary.BigEndian.PutUint32(index[:], ifIndex)
					opErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, ipUnicastIf, *(*int)(unsafe.Pointer(&index[0])))
				} else if net == "udp6" {
					opErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, ipv6UnicastIf, int(ifIndex))
				}
			})
			if err != nil {
				return err
			}
			return opErr
		},
	}
	conn, err := lc.ListenPacket(ctx, network, addr.String())
	if err != nil {
		return nil, err
	}
	return conn.(*net.UDPConn), nil
}
