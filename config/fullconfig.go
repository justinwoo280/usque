package config

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/Diniboy1123/usque/internal"
)

// AccountConfig holds WARP account credentials and assigned addresses.
// This is the same data that register/enroll produces.
type AccountConfig struct {
	PrivateKey     string `json:"private_key"`
	EndpointV4     string `json:"endpoint_v4"`
	EndpointV6     string `json:"endpoint_v6"`
	EndpointH2V4   string `json:"endpoint_h2_v4"`
	EndpointH2V6   string `json:"endpoint_h2_v6"`
	EndpointPubKey string `json:"endpoint_pub_key"`
	License        string `json:"license"`
	ID             string `json:"id"`
	AccessToken    string `json:"access_token"`
	IPv4           string `json:"ipv4"`
	IPv6           string `json:"ipv6"`
}

// FullConfig is the top-level JSON configuration for `run -c`.
// It separates account credentials, inbound listener, and outbound tunnel settings.
type FullConfig struct {
	Account  AccountConfig  `json:"account"`
	Inbound  InboundConfig  `json:"inbound"`
	Outbound OutboundConfig `json:"outbound"`
}

// InboundConfig describes how local traffic enters usque.
type InboundConfig struct {
	Type     string          `json:"type"`
	Settings json.RawMessage `json:"settings"`
}

// TunInboundSettings for inbound type "tun".
type TunInboundSettings struct {
	Name      string   `json:"name"`
	MTU       int      `json:"mtu"`
	IPv4      bool     `json:"ipv4"`
	IPv6      bool     `json:"ipv6"`
	Persist   bool     `json:"persist"`
	TunFd     int      `json:"tun_fd"`
	AutoRoute bool     `json:"auto_route"`
	DNS       []string `json:"dns"`
}

// SocksInboundSettings for inbound type "socks".
type SocksInboundSettings struct {
	Listen     string   `json:"listen"`
	Username   string   `json:"username"`
	Password   string   `json:"password"`
	MTU        int      `json:"mtu"`
	DNS        []string `json:"dns"`
	DNSTimeout string   `json:"dns_timeout"`
	LocalDNS   bool     `json:"local_dns"`
	SystemDNS  bool     `json:"system_dns"`
	UDPTimeout string   `json:"udp_timeout"`
}

// HTTPProxyInboundSettings for inbound type "http_proxy".
type HTTPProxyInboundSettings struct {
	Listen     string   `json:"listen"`
	Username   string   `json:"username"`
	Password   string   `json:"password"`
	MTU        int      `json:"mtu"`
	DNS        []string `json:"dns"`
	DNSTimeout string   `json:"dns_timeout"`
	LocalDNS   bool     `json:"local_dns"`
	SystemDNS  bool     `json:"system_dns"`
}

// PortFwInboundSettings for inbound type "portfw".
type PortFwInboundSettings struct {
	Listen      string   `json:"listen"`
	LocalPorts  []string `json:"local_ports"`
	RemotePorts []string `json:"remote_ports"`
	MTU         int      `json:"mtu"`
	DNS         []string `json:"dns"`
}

// OutboundConfig describes the MASQUE/WARP tunnel connection.
type OutboundConfig struct {
	Tag      string           `json:"tag"`
	Settings OutboundSettings `json:"settings"`
}

// OutboundSettings contains all outbound tunnel parameters.
type OutboundSettings struct {
	Port              int              `json:"port"`
	UseIPv6           bool             `json:"use_ipv6"`
	UseHTTP2          bool             `json:"use_http2"`
	SNIAddress        string           `json:"sni_address"`
	KeepalivePeriod   string           `json:"keepalive_period"`
	InitialPacketSize uint16           `json:"initial_packet_size"`
	ReconnectDelay    string           `json:"reconnect_delay"`
	AlwaysReconnect   bool             `json:"always_reconnect"`
	Insecure          bool             `json:"insecure"`
	OnConnect         string           `json:"on_connect"`
	OnDisconnect      string           `json:"on_disconnect"`
	Congestion        CongestionConfig `json:"congestion"`
	Noise             NoiseJSON        `json:"noise"`
	PreNoise          NoiseJSON        `json:"pre_noise"`
}

// CongestionConfig controls the congestion controller.
type CongestionConfig struct {
	Type       string `json:"type"`
	BrutalBPS  uint64 `json:"brutal_bps"`
	BBRProfile string `json:"bbr_profile"`
}

// Validate checks that the congestion config is consistent: each type only
// accepts its own fields and rejects irrelevant or invalid values.
func (c *CongestionConfig) Validate() error {
	switch c.Type {
	case "reno", "":
		if c.BrutalBPS != 0 {
			return fmt.Errorf("congestion type 'reno' does not accept 'brutal_bps'")
		}
		if c.BBRProfile != "" {
			return fmt.Errorf("congestion type 'reno' does not accept 'bbr_profile'")
		}
	case "brutal":
		if c.BrutalBPS == 0 {
			return fmt.Errorf("congestion type 'brutal' requires 'brutal_bps' > 0")
		}
		if c.BBRProfile != "" {
			return fmt.Errorf("congestion type 'brutal' does not accept 'bbr_profile'")
		}
	case "bbr":
		if c.BrutalBPS != 0 {
			return fmt.Errorf("congestion type 'bbr' does not accept 'brutal_bps'")
		}
		switch c.BBRProfile {
		case "conservative", "standard", "aggressive":
			// valid
		default:
			return fmt.Errorf("congestion type 'bbr' has invalid 'bbr_profile': %q (must be 'conservative', 'standard', or 'aggressive')", c.BBRProfile)
		}
	default:
		return fmt.Errorf("unknown congestion type: %q (must be 'reno', 'brutal', or 'bbr')", c.Type)
	}
	return nil
}

// NoiseJSON is the JSON-serializable noise injection config.
type NoiseJSON struct {
	Enabled  bool   `json:"enabled"`
	Count    int    `json:"count"`
	MinSize  int    `json:"min_size"`
	MaxSize  int    `json:"max_size"`
	DelayMin string `json:"delay_min"`
	DelayMax string `json:"delay_max"`
}

// LoadFullConfig reads and parses a FullConfig from a JSON file.
// It also detects legacy flat account-only configs and auto-migrates them.
func LoadFullConfig(path string) (*FullConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}

	var fc FullConfig
	if err := json.Unmarshal(data, &fc); err == nil && fc.Inbound.Type != "" {
		fc.applyDefaults()
		return &fc, nil
	}

	var old Config
	if err := json.Unmarshal(data, &old); err == nil && old.PrivateKey != "" {
		log.Println("Detected legacy config format; auto-migrating to FullConfig with defaults.")
		fc = FullConfig{
			Account: old,
			Inbound: InboundConfig{
				Type:     "tun",
				Settings: mustMarshal(TunInboundSettings{MTU: 1280, IPv4: true, IPv6: true}),
			},
			Outbound: OutboundConfig{
				Tag: "warp",
				Settings: OutboundSettings{
					Port:            443,
					KeepalivePeriod: "30s",
					ReconnectDelay:  "1s",
					Congestion:      CongestionConfig{Type: "bbr", BBRProfile: "standard"},
					Noise:           defaultNoise(),
					PreNoise:        defaultPreNoise(),
				},
			},
		}
		fc.applyDefaults()
		return &fc, nil
	}

	return nil, fmt.Errorf("config file is not a valid usque config")
}

// SaveFullConfig writes the FullConfig to a prettified JSON file.
func (fc *FullConfig) SaveFullConfig(path string) error {
	data, err := json.MarshalIndent(fc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

// ParseTunSettings decodes inbound.settings as TunInboundSettings.
func (fc *FullConfig) ParseTunSettings() (TunInboundSettings, error) {
	var s TunInboundSettings
	if err := json.Unmarshal(fc.Inbound.Settings, &s); err != nil {
		return s, fmt.Errorf("parse tun settings: %w", err)
	}
	if s.MTU == 0 {
		s.MTU = 1280
	}
	if len(s.DNS) == 0 {
		s.DNS = []string{"1.1.1.1", "2606:4700:4700::1111"}
	}
	// The IPv4/IPv6 fields are plain bools whose zero value (false) is
	// indistinguishable from an absent JSON key. A disabled stack is now
	// black-holed at the TUN, so a missing key must NOT be misread as "disable"
	// (which would black-hole a stack the user never opted out of, or both —
	// killing all connectivity). Detect presence via a pointer-typed probe and
	// default absent keys to enabled (true).
	var probe struct {
		IPv4 *bool `json:"ipv4"`
		IPv6 *bool `json:"ipv6"`
	}
	if err := json.Unmarshal(fc.Inbound.Settings, &probe); err == nil {
		if probe.IPv4 == nil {
			s.IPv4 = true
		}
		if probe.IPv6 == nil {
			s.IPv6 = true
		}
	} else {
		// Malformed settings: fail safe to both stacks enabled rather than
		// black-holing everything.
		s.IPv4 = true
		s.IPv6 = true
	}
	return s, nil
}

// ParseSocksSettings decodes inbound.settings as SocksInboundSettings.
func (fc *FullConfig) ParseSocksSettings() (SocksInboundSettings, error) {
	var s SocksInboundSettings
	if err := json.Unmarshal(fc.Inbound.Settings, &s); err != nil {
		return s, fmt.Errorf("parse socks settings: %w", err)
	}
	if s.Listen == "" {
		s.Listen = "0.0.0.0:1080"
	}
	if s.MTU == 0 {
		s.MTU = 1280
	}
	if s.DNSTimeout == "" {
		s.DNSTimeout = "2s"
	}
	if s.UDPTimeout == "" {
		s.UDPTimeout = "60s"
	}
	if len(s.DNS) == 0 {
		s.DNS = []string{"9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"}
	}
	return s, nil
}

// ParseHTTPProxySettings decodes inbound.settings as HTTPProxyInboundSettings.
func (fc *FullConfig) ParseHTTPProxySettings() (HTTPProxyInboundSettings, error) {
	var s HTTPProxyInboundSettings
	if err := json.Unmarshal(fc.Inbound.Settings, &s); err != nil {
		return s, fmt.Errorf("parse http_proxy settings: %w", err)
	}
	if s.Listen == "" {
		s.Listen = "0.0.0.0:8000"
	}
	if s.MTU == 0 {
		s.MTU = 1280
	}
	if s.DNSTimeout == "" {
		s.DNSTimeout = "2s"
	}
	if len(s.DNS) == 0 {
		s.DNS = []string{"9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"}
	}
	return s, nil
}

// ParsePortFwSettings decodes inbound.settings as PortFwInboundSettings.
func (fc *FullConfig) ParsePortFwSettings() (PortFwInboundSettings, error) {
	var s PortFwInboundSettings
	if err := json.Unmarshal(fc.Inbound.Settings, &s); err != nil {
		return s, fmt.Errorf("parse portfw settings: %w", err)
	}
	if s.MTU == 0 {
		s.MTU = 1280
	}
	if len(s.DNS) == 0 {
		s.DNS = []string{"9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"}
	}
	return s, nil
}

// ParseDuration parses a duration string, returning def on empty or error.
func ParseDuration(s string, def time.Duration) time.Duration {
	if s == "" {
		return def
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return def
	}
	return d
}

// ToNoiseConfig converts NoiseJSON to internal.NoiseConfig.
// Returns a zero config when Enabled is false so no noise is injected.
func (n *NoiseJSON) ToNoiseConfig() internal.NoiseConfig {
	if !n.Enabled {
		return internal.NoiseConfig{}
	}
	return internal.NoiseConfig{
		Count:    n.Count,
		MinSize:  n.MinSize,
		MaxSize:  n.MaxSize,
		DelayMin: ParseDuration(n.DelayMin, 0),
		DelayMax: ParseDuration(n.DelayMax, 0),
	}
}

func (fc *FullConfig) applyDefaults() {
	ob := &fc.Outbound.Settings
	if ob.Port == 0 {
		ob.Port = 443
	}
	if ob.KeepalivePeriod == "" {
		ob.KeepalivePeriod = "30s"
	}
	if ob.ReconnectDelay == "" {
		ob.ReconnectDelay = "1s"
	}
	if ob.Congestion.Type == "" {
		ob.Congestion.Type = "bbr"
	}
	if ob.Congestion.Type == "bbr" && ob.Congestion.BBRProfile == "" {
		ob.Congestion.BBRProfile = "standard"
	}
	if ob.SNIAddress == "" {
		ob.SNIAddress = internal.ConnectSNI
	}
}

func mustMarshal(v interface{}) json.RawMessage {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}

// NewDefaultFullConfig creates a FullConfig with default inbound/outbound for the given account.
func NewDefaultFullConfig(acct AccountConfig) *FullConfig {
	fc := &FullConfig{
		Account: acct,
		Inbound: InboundConfig{
			Type: "tun",
			Settings: mustMarshal(TunInboundSettings{
				MTU:       1280,
				IPv4:      true,
				IPv6:      true,
				AutoRoute: true,
				DNS:       []string{"1.1.1.1", "2606:4700:4700::1111"},
			}),
		},
		Outbound: OutboundConfig{
			Tag: "warp",
			Settings: OutboundSettings{
				Port:            443,
				KeepalivePeriod: "30s",
				ReconnectDelay:  "1s",
				Congestion:      CongestionConfig{Type: "bbr", BBRProfile: "standard"},
				Noise:           defaultNoise(),
				PreNoise:        defaultPreNoise(),
			},
		},
	}
	fc.applyDefaults()
	return fc
}

func defaultNoise() NoiseJSON {
	return NoiseJSON{
		Enabled:  true,
		Count:    5,
		MinSize:  100,
		MaxSize:  400,
		DelayMin: "10ms",
		DelayMax: "50ms",
	}
}

func defaultPreNoise() NoiseJSON {
	return NoiseJSON{
		Enabled:  true,
		Count:    3,
		MinSize:  64,
		MaxSize:  128,
		DelayMin: "5ms",
		DelayMax: "15ms",
	}
}
