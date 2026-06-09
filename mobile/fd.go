//go:build android

package mobile

import (
	"net"
	"os"
	"syscall"

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

// CreateUDPSocket creates a raw IPv4 UDP socket and returns its file descriptor.
// This avoids Java reflection on FileDescriptor which is blocked by hidden API
// restrictions on Android 14+ with targetSdk 34+.
// Returns fd on success, -1 on failure.
func CreateUDPSocket() int {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return -1
	}
	return fd
}

// CloseSocket closes a raw file descriptor.
func CloseSocket(fd int) {
	if fd >= 0 {
		_ = syscall.Close(fd)
	}
}
