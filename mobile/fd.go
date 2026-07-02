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

// wrapUDPConn builds a *net.UDPConn from a caller-owned fd WITHOUT taking
// ownership of that fd.
//
// fd ownership contract (must match the Kotlin side):
//   - The caller (VpnService) created `fd`, called protect() on it, and remains
//     its owner: the caller closes `fd`.
//   - Go needs its own independent fd for the net.UDPConn. We dup() the caller's
//     fd and hand the DUP to os.NewFile; the returned *net.UDPConn owns the dup
//     and closing that conn closes only the dup, never the caller's fd.
//   - Therefore StopTunnel MUST close this udpConn (see StopTunnel) so the dup
//     is released; otherwise the dup leaks and repeated reconnects exhaust fds.
//
// Previous bug: the old code wrapped `fd` directly in os.NewFile and then
// f.Close()'d it, which closed the CALLER's fd; the caller then closed it again
// (double-close / fd-reuse hazard), while the dup created by FilePacketConn
// leaked because MaintainTunnel never closes a caller-supplied UDPConn.
func wrapUDPConn(fd int) *net.UDPConn {
	dup, err := syscall.Dup(fd)
	if err != nil {
		return nil
	}
	f := os.NewFile(uintptr(dup), "udp")
	conn, err := net.FilePacketConn(f)
	// net.FilePacketConn dups again internally; close our os.File wrapper so we
	// don't leak `dup`. The returned conn holds its own fd.
	_ = f.Close()
	if err != nil || conn == nil {
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
