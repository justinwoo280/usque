//go:build !linux && !windows && !darwin && !freebsd

package cmd

import (
	"errors"

	"github.com/Diniboy1123/usque/api"
)

func (t *tunDevice) create() (api.TunnelDevice, error) {
	return nil, errors.New("TUN device is not supported on this platform")
}
