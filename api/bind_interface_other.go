//go:build !linux && !darwin && !windows

package api

import "net"

func BindToDevice(_ uintptr, _ *net.Interface) error {
	return nil
}
