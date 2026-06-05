//go:build linux

package cmd

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type linuxRouteManager struct {
	cfg          AutoRouteConfig
	rules        []*netlink.Rule
	dnsBackup    string
	usedResolved bool
}

func newRouteManager(cfg AutoRouteConfig) RouteManager {
	cfg.applyDefaults()
	return &linuxRouteManager{cfg: cfg}
}

func (m *linuxRouteManager) Setup() error {
	if err := m.setupRoutes(); err != nil {
		return fmt.Errorf("setup routes: %w", err)
	}
	if err := m.setupRules(); err != nil {
		_ = m.cleanupRoutes()
		return fmt.Errorf("setup rules: %w", err)
	}
	if err := m.setupDNS(); err != nil {
		log.Printf("Warning: DNS setup failed: %v (you may need to configure DNS manually)", err)
	}
	log.Printf("Auto-route enabled: table=%d, fwmark=0x%x", m.cfg.TableIndex, m.cfg.Fwmark)
	return nil
}

func (m *linuxRouteManager) Cleanup() error {
	var errs []error
	if err := m.cleanupRules(); err != nil {
		errs = append(errs, fmt.Errorf("cleanup rules: %w", err))
	}
	if err := m.cleanupRoutes(); err != nil {
		errs = append(errs, fmt.Errorf("cleanup routes: %w", err))
	}
	m.cleanupDNS()
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func (m *linuxRouteManager) setupRoutes() error {
	link, err := netlink.LinkByName(m.cfg.InterfaceName)
	if err != nil {
		return fmt.Errorf("find interface %s: %w", m.cfg.InterfaceName, err)
	}

	if m.cfg.EnableIPv4 {
		route := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
			Table:     m.cfg.TableIndex,
		}
		if err := netlink.RouteAdd(route); err != nil && !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("add IPv4 default route: %w", err)
		}
	}

	if m.cfg.EnableIPv6 {
		route := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
			Table:     m.cfg.TableIndex,
			Family:    unix.AF_INET6,
		}
		if err := netlink.RouteAdd(route); err != nil && !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("add IPv6 default route: %w", err)
		}
	}

	return nil
}

func (m *linuxRouteManager) setupRules() error {
	rules := m.buildRules()
	for i, rule := range rules {
		if err := netlink.RuleAdd(rule); err != nil {
			for j := 0; j < i; j++ {
				_ = netlink.RuleDel(rules[j])
			}
			return fmt.Errorf("add rule %d/%d: %w", i+1, len(rules), err)
		}
	}
	m.rules = rules
	return nil
}

func (m *linuxRouteManager) buildRules() []*netlink.Rule {
	var rules []*netlink.Rule
	priority := m.cfg.RuleIndex
	nopPriority := priority + 20

	if m.cfg.EnableIPv4 {
		rule := netlink.NewRule()
		rule.Priority = priority
		rule.Mark = m.cfg.Fwmark
		rule.Table = unix.RT_TABLE_MAIN
		rule.Family = unix.AF_INET
		rules = append(rules, rule)
		priority++

		rule = netlink.NewRule()
		rule.Priority = priority
		rule.Invert = true
		rule.Dport = netlink.NewRulePortRange(53, 53)
		rule.Table = unix.RT_TABLE_MAIN
		rule.SuppressPrefixlen = 0
		rule.Family = unix.AF_INET
		rules = append(rules, rule)
		priority++

		rule = netlink.NewRule()
		rule.Priority = priority
		rule.Table = m.cfg.TableIndex
		rule.SuppressPrefixlen = 0
		rule.Family = unix.AF_INET
		rules = append(rules, rule)
		priority++

		rule = netlink.NewRule()
		rule.Priority = priority
		rule.IifName = m.cfg.InterfaceName
		rule.Goto = nopPriority
		rule.Family = unix.AF_INET
		rules = append(rules, rule)
		priority++

		rule = netlink.NewRule()
		rule.Priority = priority
		rule.Invert = true
		rule.IifName = "lo"
		rule.Table = m.cfg.TableIndex
		rule.Family = unix.AF_INET
		rules = append(rules, rule)
		priority++

		rule = netlink.NewRule()
		rule.Priority = priority
		rule.IifName = "lo"
		rule.Src = &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(32, 32)}
		rule.Table = m.cfg.TableIndex
		rule.Family = unix.AF_INET
		rules = append(rules, rule)

		if m.cfg.IPv4 != nil {
			rule = netlink.NewRule()
			rule.Priority = priority
			rule.IifName = "lo"
			rule.Src = &net.IPNet{IP: m.cfg.IPv4, Mask: net.CIDRMask(32, 32)}
			rule.Table = m.cfg.TableIndex
			rule.Family = unix.AF_INET
			rules = append(rules, rule)
		}
		priority++
	}

	if m.cfg.EnableIPv6 {
		rule := netlink.NewRule()
		rule.Priority = priority
		rule.Mark = m.cfg.Fwmark
		rule.Table = unix.RT_TABLE_MAIN
		rule.Family = unix.AF_INET6
		rules = append(rules, rule)
		priority++

		rule = netlink.NewRule()
		rule.Priority = priority
		rule.Invert = true
		rule.Dport = netlink.NewRulePortRange(53, 53)
		rule.Table = unix.RT_TABLE_MAIN
		rule.SuppressPrefixlen = 0
		rule.Family = unix.AF_INET6
		rules = append(rules, rule)
		priority++

		rule = netlink.NewRule()
		rule.Priority = priority
		rule.Table = m.cfg.TableIndex
		rule.SuppressPrefixlen = 0
		rule.Family = unix.AF_INET6
		rules = append(rules, rule)
		priority++

		rule = netlink.NewRule()
		rule.Priority = priority
		rule.IifName = m.cfg.InterfaceName
		rule.Goto = nopPriority
		rule.Family = unix.AF_INET6
		rules = append(rules, rule)
		priority++

		rule = netlink.NewRule()
		rule.Priority = priority
		rule.IifName = "lo"
		rule.Src = &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(1, 128)}
		rule.Goto = nopPriority
		rule.Family = unix.AF_INET6
		rules = append(rules, rule)

		rule = netlink.NewRule()
		rule.Priority = priority
		rule.IifName = "lo"
		rule.Src = &net.IPNet{IP: net.ParseIP("8000::"), Mask: net.CIDRMask(1, 128)}
		rule.Goto = nopPriority
		rule.Family = unix.AF_INET6
		rules = append(rules, rule)
		priority++

		if m.cfg.IPv6 != nil {
			rule = netlink.NewRule()
			rule.Priority = priority
			rule.IifName = "lo"
			rule.Src = &net.IPNet{IP: m.cfg.IPv6, Mask: net.CIDRMask(128, 128)}
			rule.Table = m.cfg.TableIndex
			rule.Family = unix.AF_INET6
			rules = append(rules, rule)
		}

		rule = netlink.NewRule()
		rule.Priority = priority
		rule.Table = m.cfg.TableIndex
		rule.Family = unix.AF_INET6
		rules = append(rules, rule)
		priority++
	}

	return rules
}

func (m *linuxRouteManager) setupDNS() error {
	if _, err := exec.LookPath("resolvectl"); err == nil {
		return m.setupSystemdResolved()
	}
	return m.setupResolvConf()
}

func (m *linuxRouteManager) setupSystemdResolved() error {
	m.usedResolved = true
	args := []string{"dns", m.cfg.InterfaceName}
	for _, dns := range m.cfg.DNSServers {
		args = append(args, dns.String())
	}
	if err := exec.Command("resolvectl", args...).Run(); err != nil {
		return fmt.Errorf("resolvectl dns: %w", err)
	}
	_ = exec.Command("resolvectl", "domain", m.cfg.InterfaceName, "~.").Run()
	_ = exec.Command("resolvectl", "default-route", m.cfg.InterfaceName, "true").Run()
	return nil
}

func (m *linuxRouteManager) setupResolvConf() error {
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
	return nil
}

func (m *linuxRouteManager) cleanupRules() error {
	if len(m.rules) == 0 {
		ruleList, err := netlink.RuleList(netlink.FAMILY_ALL)
		if err != nil {
			return fmt.Errorf("list rules: %w", err)
		}
		nopPriority := m.cfg.RuleIndex + 20
		minPriority := m.cfg.RuleIndex
		for _, rule := range ruleList {
			if rule.Priority >= minPriority && rule.Priority <= nopPriority {
				toDel := netlink.NewRule()
				toDel.Family = rule.Family
				toDel.Priority = rule.Priority
				if err := netlink.RuleDel(toDel); err != nil {
					log.Printf("Warning: failed to delete rule priority %d: %v", rule.Priority, err)
				}
			}
		}
		return nil
	}

	var errs []error
	for i := len(m.rules) - 1; i >= 0; i-- {
		if err := netlink.RuleDel(m.rules[i]); err != nil {
			errs = append(errs, fmt.Errorf("delete rule %d: %w", i, err))
		}
	}
	m.rules = nil
	return errors.Join(errs...)
}

func (m *linuxRouteManager) cleanupRoutes() error {
	link, err := netlink.LinkByName(m.cfg.InterfaceName)
	if err != nil {
		return nil
	}

	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{
		Table:     m.cfg.TableIndex,
		LinkIndex: link.Attrs().Index,
	}, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_OIF)
	if err != nil {
		return fmt.Errorf("list routes: %w", err)
	}

	var errs []error
	for i := range routes {
		if err := netlink.RouteDel(&routes[i]); err != nil {
			errs = append(errs, fmt.Errorf("delete route: %w", err))
		}
	}
	return errors.Join(errs...)
}

func (m *linuxRouteManager) cleanupDNS() {
	if m.usedResolved {
		_ = exec.Command("resolvectl", "revert", m.cfg.InterfaceName).Run()
		return
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
}
