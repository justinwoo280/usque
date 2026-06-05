//go:build freebsd

package cmd

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

type freebsdRouteManager struct {
	cfg            AutoRouteConfig
	defaultGateway string
	dnsBackup      string
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
			log.Printf("Warning: endpoint bypass failed: %v", err)
		} else {
			log.Printf("Endpoint bypass: %s%s via %s", m.cfg.EndpointIP, mask, gw)
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

	if err := m.setupDNS(); err != nil {
		log.Printf("Warning: DNS setup failed: %v (you may need to configure DNS manually)", err)
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

	m.cleanupDNS()
	return nil
}

func (m *freebsdRouteManager) setupDNS() error {
	if len(m.cfg.DNSServers) == 0 {
		return nil
	}

	const resolvConf = "/etc/resolv.conf"
	backupPath := resolvConf + ".usque.bak"

	data, err := os.ReadFile(resolvConf)
	if err == nil {
		if err := os.WriteFile(backupPath, data, 0644); err != nil {
			log.Printf("Warning: failed to backup %s: %v", resolvConf, err)
		} else {
			m.dnsBackup = backupPath
		}
	}

	var content string
	for _, dns := range m.cfg.DNSServers {
		content += fmt.Sprintf("nameserver %s\n", dns.String())
	}

	if err := os.WriteFile(resolvConf, []byte(content), 0644); err != nil {
		return fmt.Errorf("write %s: %w", resolvConf, err)
	}

	log.Printf("DNS configured: %s", resolvConf)
	return nil
}

func (m *freebsdRouteManager) cleanupDNS() {
	if m.dnsBackup != "" {
		data, err := os.ReadFile(m.dnsBackup)
		if err == nil {
			if err := os.WriteFile("/etc/resolv.conf", data, 0644); err != nil {
				log.Printf("Warning: failed to restore /etc/resolv.conf: %v", err)
			}
		}
		_ = os.Remove(m.dnsBackup)
		m.dnsBackup = ""
	}
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
