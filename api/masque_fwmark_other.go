//go:build !linux && !windows

package api

import (
	"context"
	"net"
)

func listenUDPWithMark(_ context.Context, network string, addr *net.UDPAddr, _ uint32) (*net.UDPConn, error) {
	return net.ListenUDP(network, addr)
}
