//go:build linux

package api

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func listenUDPWithMark(ctx context.Context, network string, addr *net.UDPAddr, fwmark uint32) (*net.UDPConn, error) {
	if fwmark == 0 {
		return net.ListenUDP(network, addr)
	}
	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var opErr error
			err := c.Control(func(fd uintptr) {
				opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(fwmark))
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
