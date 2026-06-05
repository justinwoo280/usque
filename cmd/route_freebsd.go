//go:build freebsd

package cmd

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
)

type freebsdRouteManager struct {
	cfg            AutoRouteConfig
	defaultGateway string
}

func newRouteManager(cfg AutoRouteConfig) RouteManager {
	cfg.applyDefaults()
	return &freebsdRouteManager{cfg: cfg}
}

func (m *freebsdRouteManager) Setup() error {
	gw, err := findFreeBSDGateway()
	if err != nil {
		return fmt.Errorf("find default gateway: %w", err)
	}
	m.defaultGateway = gw
	log.Printf("Default gateway: %s", gw)

	if m.cfg.EndpointIP != nil && gw != "" {
		mask := "/32"
		if m.cfg.EndpointIP.To4() == nil {
			mask = "/128"
		}
		if err := runRoute("add", m.cfg.EndpointIP.String()+mask, gw); err != nil {
			return fmt.Errorf("add endpoint bypass route: %w", err)
		}
	}

	if m.cfg.EnableIPv4 {
		if err := runRoute("add", "0.0.0.0/1", "-interface", m.cfg.InterfaceName); err != nil {
			return fmt.Errorf("add 0.0.0.0/1: %w", err)
		}
		if err := runRoute("add", "128.0.0.0/1", "-interface", m.cfg.InterfaceName); err != nil {
			return fmt.Errorf("add 128.0.0.0/1: %w", err)
		}
	}

	if m.cfg.EnableIPv6 {
		if err := runRoute("add", "::/1", "-interface", m.cfg.InterfaceName); err != nil {
			return fmt.Errorf("add ::/1: %w", err)
		}
		if err := runRoute("add", "8000::/1", "-interface", m.cfg.InterfaceName); err != nil {
			return fmt.Errorf("add 8000::/1: %w", err)
		}
	}

	log.Println("Auto-route enabled (FreeBSD)")
	return nil
}

func (m *freebsdRouteManager) Cleanup() error {
	if m.cfg.EndpointIP != nil && m.defaultGateway != "" {
		mask := "/32"
		if m.cfg.EndpointIP.To4() == nil {
			mask = "/128"
		}
		_ = runRoute("delete", m.cfg.EndpointIP.String()+mask, m.defaultGateway)
	}

	if m.cfg.EnableIPv4 {
		_ = runRoute("delete", "0.0.0.0/1", "-interface", m.cfg.InterfaceName)
		_ = runRoute("delete", "128.0.0.0/1", "-interface", m.cfg.InterfaceName)
	}
	if m.cfg.EnableIPv6 {
		_ = runRoute("delete", "::/1", "-interface", m.cfg.InterfaceName)
		_ = runRoute("delete", "8000::/1", "-interface", m.cfg.InterfaceName)
	}
	return nil
}

func findFreeBSDGateway() (string, error) {
	out, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return "", fmt.Errorf("route get default: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "gateway:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "gateway:")), nil
		}
	}
	return "", fmt.Errorf("could not find default gateway")
}

func runRoute(args ...string) error {
	cmd := exec.Command("route", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("route %s: %s: %w", strings.Join(args, " "), string(out), err)
	}
	return nil
}
