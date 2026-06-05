package cmd

import "net"

const (
	defaultRouteTableIndex = 2022
	defaultRouteRuleIndex  = 9000
)

// RouteManager handles platform-specific routing setup for the TUN inbound.
type RouteManager interface {
	Setup() error
	Cleanup() error
}

// AutoRouteConfig holds parameters for automatic route/DNS configuration.
type AutoRouteConfig struct {
	InterfaceName string
	IPv4          net.IP
	IPv6          net.IP
	EnableIPv4    bool
	EnableIPv6    bool
	DNSServers    []net.IP
	TableIndex    int
	RuleIndex     int
	EndpointIP    net.IP
}

func defaultDNSServers() []net.IP {
	return []net.IP{
		net.ParseIP("1.1.1.1"),
		net.ParseIP("2606:4700:4700::1111"),
	}
}

func extractEndpointIP(addr net.Addr) net.IP {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.IP
	case *net.TCPAddr:
		return a.IP
	default:
		return nil
	}
}

func (c *AutoRouteConfig) applyDefaults() {
	if c.TableIndex == 0 {
		c.TableIndex = defaultRouteTableIndex
	}
	if c.RuleIndex == 0 {
		c.RuleIndex = defaultRouteRuleIndex
	}
	if len(c.DNSServers) == 0 {
		c.DNSServers = defaultDNSServers()
	}
}
