//go:build !windows

package cmd

import (
	"io"
	"net"

	"github.com/Diniboy1123/usque/config"
)

func startTUNFamilyGuard(_ config.TunInboundSettings, _ net.Addr) (io.Closer, error) {
	return nil, nil
}
