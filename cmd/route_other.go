//go:build !linux && !windows && !darwin && !freebsd

package cmd

func newRouteManager(cfg AutoRouteConfig) RouteManager {
	return nil
}
