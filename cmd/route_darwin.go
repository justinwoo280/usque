//go:build darwin

package cmd

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

type darwinRouteManager struct {
	cfg              AutoRouteConfig
	defaultGateway   string
	defaultIface     string
	dnsBackup        string
	activeService    string
	usedNetworksetup bool
}

func newRouteManager(cfg AutoRouteConfig) RouteManager {
	cfg.applyDefaults()
	return &darwinRouteManager{cfg: cfg}
}

func (m *darwinRouteManager) Setup() error {
	gw, iface, err := findDefaultGateway()
	if err != nil {
		return fmt.Errorf("find default gateway: %w", err)
	}
	m.defaultGateway = gw
	m.defaultIface = iface
	log.Printf("Default gateway: %s via %s", gw, iface)

	if m.cfg.EndpointIP != nil {
		mask := "/32"
		if m.cfg.EndpointIP.To4() == nil {
			mask = "/128"
		}
		if err := runRoute("add", m.cfg.EndpointIP.String()+mask, gw); err != nil {
			return fmt.Errorf("add endpoint bypass route: %w", err)
		}
		log.Printf("Endpoint bypass: %s%s via %s", m.cfg.EndpointIP, mask, gw)
	}

	if m.cfg.EnableIPv4 {
		if err := runRoute("add", "-net", "0.0.0.0/1", "-interface", m.cfg.InterfaceName); err != nil {
			return fmt.Errorf("add 0.0.0.0/1: %w", err)
		}
		if err := runRoute("add", "-net", "128.0.0.0/1", "-interface", m.cfg.InterfaceName); err != nil {
			return fmt.Errorf("add 128.0.0.0/1: %w", err)
		}
	}

	if m.cfg.EnableIPv6 {
		if err := runRoute("add", "-net", "::/1", "-interface", m.cfg.InterfaceName); err != nil {
			return fmt.Errorf("add ::/1: %w", err)
		}
		if err := runRoute("add", "-net", "8000::/1", "-interface", m.cfg.InterfaceName); err != nil {
			return fmt.Errorf("add 8000::/1: %w", err)
		}
	}

	if err := m.setupDNS(); err != nil {
		log.Printf("Warning: DNS setup failed: %v (you may need to configure DNS manually)", err)
	}

	log.Println("Auto-route enabled (macOS)")
	return nil
}

func (m *darwinRouteManager) Cleanup() error {
	if m.cfg.EndpointIP != nil && m.defaultGateway != "" {
		mask := "/32"
		if m.cfg.EndpointIP.To4() == nil {
			mask = "/128"
		}
		_ = runRoute("delete", m.cfg.EndpointIP.String()+mask, m.defaultGateway)
	}

	if m.cfg.EnableIPv4 {
		_ = runRoute("delete", "-net", "0.0.0.0/1", "-interface", m.cfg.InterfaceName)
		_ = runRoute("delete", "-net", "128.0.0.0/1", "-interface", m.cfg.InterfaceName)
	}
	if m.cfg.EnableIPv6 {
		_ = runRoute("delete", "-net", "::/1", "-interface", m.cfg.InterfaceName)
		_ = runRoute("delete", "-net", "8000::/1", "-interface", m.cfg.InterfaceName)
	}

	m.cleanupDNS()
	return nil
}

func (m *darwinRouteManager) setupDNS() error {
	if len(m.cfg.DNSServers) == 0 {
		return nil
	}

	service := findActiveNetworkService()
	if service != "" {
		var dnsArgs []string
		for _, dns := range m.cfg.DNSServers {
			dnsArgs = append(dnsArgs, dns.String())
		}
		args := append([]string{"-setdnsservers", service}, dnsArgs...)
		if err := exec.Command("networksetup", args...).Run(); err == nil {
			m.usedNetworksetup = true
			m.activeService = service
			log.Printf("DNS configured via networksetup for service %q", service)
			flushDNSCache()
			return nil
		}
	}

	return m.setupResolvConf()
}

func (m *darwinRouteManager) setupResolvConf() error {
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

	log.Printf("DNS configured via %s", resolvConf)
	flushDNSCache()
	return nil
}

func (m *darwinRouteManager) cleanupDNS() {
	if m.usedNetworksetup && m.activeService != "" {
		_ = exec.Command("networksetup", "-setdnsservers", m.activeService, "empty").Run()
	}

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

	flushDNSCache()
}

func flushDNSCache() {
	_ = exec.Command("dscacheutil", "-flushcache").Run()
	_ = exec.Command("killall", "-HUP", "mDNSResponder").Run()
}

func findActiveNetworkService() string {
	out, err := exec.Command("networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return ""
	}

	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "*") {
			continue
		}

		dnsOut, err := exec.Command("networksetup", "-getdnsservers", line).Output()
		if err != nil {
			continue
		}
		dnsStr := strings.TrimSpace(string(dnsOut))
		if dnsStr != "" && dnsStr != "There aren't any DNS Servers configured on this port." {
			return line
		}
	}

	return ""
}

func findDefaultGateway() (string, string, error) {
	out, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return "", "", fmt.Errorf("route get default: %w", err)
	}

	var gateway, iface string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "gateway:") {
			gateway = strings.TrimSpace(strings.TrimPrefix(line, "gateway:"))
		}
		if strings.HasPrefix(line, "interface:") {
			iface = strings.TrimSpace(strings.TrimPrefix(line, "interface:"))
		}
	}

	if gateway == "" || iface == "" {
		return "", "", fmt.Errorf("could not parse default gateway (gw=%q iface=%q)", gateway, iface)
	}
	return gateway, iface, nil
}

func runRoute(args ...string) error {
	cmd := exec.Command("route", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("route %s: %s: %w", strings.Join(args, " "), string(out), err)
	}
	return nil
}
