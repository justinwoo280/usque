package mobile

import (
	"net"
	"os"

	"github.com/Diniboy1123/usque/api"
)

func wrapTunFd(fd int) api.TunnelDevice {
	return api.NewFdAdapter(fd)
}

func wrapUDPConn(fd int) *net.UDPConn {
	f := os.NewFile(uintptr(fd), "udp")
	conn, _ := net.FilePacketConn(f)
	_ = f.Close()
	if conn == nil {
		return nil
	}
	return conn.(*net.UDPConn)
}
