package api

import (
	"context"
	"net"
	"syscall"
)

// listenUDPWithBind creates a UDP socket optionally bound to a physical interface.
// When updater is non-nil and has a current interface, the socket is bound using
// SO_BINDTODEVICE (Linux), IP_BOUND_IF (macOS), or IP_UNICAST_IF (Windows).
func listenUDPWithBind(ctx context.Context, network string, addr *net.UDPAddr, updater *InterfaceUpdater) (*net.UDPConn, error) {
	if updater == nil {
		return net.ListenUDP(network, addr)
	}

	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			iface := updater.Get()
			if iface == nil {
				return nil
			}
			var opErr error
			err := c.Control(func(fd uintptr) {
				opErr = BindToDevice(fd, iface)
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
