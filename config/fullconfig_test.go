package config

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestLoadFullConfig(t *testing.T) {
	data := `{
		"account": {
			"private_key": "dGVzdA==",
			"endpoint_v4": "1.2.3.4",
			"endpoint_v6": "::1",
			"endpoint_h2_v4": "5.6.7.8",
			"endpoint_pub_key": "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
			"license": "lic",
			"id": "id1",
			"access_token": "tok",
			"ipv4": "10.0.0.1",
			"ipv6": "fd00::1"
		},
		"inbound": {
			"type": "tun",
			"settings": {
				"name": "usque0",
				"mtu": 1400,
				"ipv4": true,
				"ipv6": false,
				"auto_route": true,
				"dns": ["1.1.1.1"]
			}
		},
		"outbound": {
			"tag": "warp",
			"settings": {
				"port": 443,
				"use_ipv6": true,
				"use_http2": false,
				"sni_address": "example.com",
				"keepalive_period": "15s",
				"reconnect_delay": "2s",
				"always_reconnect": true,
				"insecure": true,
				"congestion": {
					"type": "bbr",
					"bbr_profile": "aggressive"
				},
				"noise": {
					"count": 5,
					"min_size": 64,
					"max_size": 512,
					"delay_min": "10ms",
					"delay_max": "50ms"
				},
				"pre_noise": {
					"count": 0
				}
			}
		}
	}`

	tmpFile := t.TempDir() + "/config.json"
	if err := os.WriteFile(tmpFile, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}

	fc, err := LoadFullConfig(tmpFile)
	if err != nil {
		t.Fatalf("LoadFullConfig: %v", err)
	}

	// Account
	if fc.Account.EndpointV4 != "1.2.3.4" {
		t.Errorf("endpoint_v4 = %q, want 1.2.3.4", fc.Account.EndpointV4)
	}
	if fc.Account.IPv4 != "10.0.0.1" {
		t.Errorf("ipv4 = %q, want 10.0.0.1", fc.Account.IPv4)
	}

	// Inbound
	if fc.Inbound.Type != "tun" {
		t.Errorf("inbound.type = %q, want tun", fc.Inbound.Type)
	}
	ts, err := fc.ParseTunSettings()
	if err != nil {
		t.Fatalf("ParseTunSettings: %v", err)
	}
	if ts.Name != "usque0" {
		t.Errorf("tun.name = %q, want usque0", ts.Name)
	}
	if ts.MTU != 1400 {
		t.Errorf("tun.mtu = %d, want 1400", ts.MTU)
	}
	if !ts.IPv4 || ts.IPv6 {
		t.Errorf("tun.ipv4=%v ipv6=%v, want true/false", ts.IPv4, ts.IPv6)
	}
	if !ts.AutoRoute {
		t.Error("tun.auto_route should be true")
	}
	if len(ts.DNS) != 1 || ts.DNS[0] != "1.1.1.1" {
		t.Errorf("tun.dns = %v, want [1.1.1.1]", ts.DNS)
	}

	// Outbound
	if fc.Outbound.Tag != "warp" {
		t.Errorf("outbound.tag = %q, want warp", fc.Outbound.Tag)
	}
	ob := fc.Outbound.Settings
	if ob.Port != 443 {
		t.Errorf("port = %d, want 443", ob.Port)
	}
	if !ob.UseIPv6 {
		t.Error("use_ipv6 should be true")
	}
	if ob.SNIAddress != "example.com" {
		t.Errorf("sni_address = %q, want example.com", ob.SNIAddress)
	}
	if !ob.AlwaysReconnect || !ob.Insecure {
		t.Error("always_reconnect and insecure should be true")
	}

	// Congestion
	if ob.Congestion.Type != "bbr" {
		t.Errorf("congestion.type = %q, want bbr", ob.Congestion.Type)
	}
	if ob.Congestion.BBRProfile != "aggressive" {
		t.Errorf("bbr_profile = %q, want aggressive", ob.Congestion.BBRProfile)
	}

	// Noise
	noise := ob.Noise.ToNoiseConfig()
	if noise.Count != 5 {
		t.Errorf("noise.count = %d, want 5", noise.Count)
	}
	if noise.MinSize != 64 || noise.MaxSize != 512 {
		t.Errorf("noise size = [%d,%d], want [64,512]", noise.MinSize, noise.MaxSize)
	}
	if noise.DelayMin != 10*time.Millisecond {
		t.Errorf("noise.delay_min = %v, want 10ms", noise.DelayMin)
	}
}

func TestLoadFullConfigLegacyMigration(t *testing.T) {
	data := `{
		"private_key": "dGVzdA==",
		"endpoint_v4": "1.2.3.4",
		"endpoint_v6": "::1",
		"endpoint_h2_v4": "5.6.7.8",
		"endpoint_pub_key": "pk",
		"license": "lic",
		"id": "id1",
		"access_token": "tok",
		"ipv4": "10.0.0.1",
		"ipv6": "fd00::1"
	}`

	tmpFile := t.TempDir() + "/legacy.json"
	if err := os.WriteFile(tmpFile, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}

	fc, err := LoadFullConfig(tmpFile)
	if err != nil {
		t.Fatalf("LoadFullConfig (legacy): %v", err)
	}

	if fc.Inbound.Type != "tun" {
		t.Errorf("migrated inbound.type = %q, want tun", fc.Inbound.Type)
	}
	if fc.Outbound.Tag != "warp" {
		t.Errorf("migrated outbound.tag = %q, want warp", fc.Outbound.Tag)
	}
	if fc.Account.EndpointV4 != "1.2.3.4" {
		t.Errorf("migrated account.endpoint_v4 = %q, want 1.2.3.4", fc.Account.EndpointV4)
	}
}

func TestLoadFullConfigDefaults(t *testing.T) {
	data := `{
		"account": {"private_key": "dGVzdA=="},
		"inbound": {"type": "socks", "settings": {}},
		"outbound": {"settings": {}}
	}`

	tmpFile := t.TempDir() + "/defaults.json"
	if err := os.WriteFile(tmpFile, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}

	fc, err := LoadFullConfig(tmpFile)
	if err != nil {
		t.Fatalf("LoadFullConfig: %v", err)
	}

	ob := fc.Outbound.Settings
	if ob.Port != 443 {
		t.Errorf("default port = %d, want 443", ob.Port)
	}
	if ob.KeepalivePeriod != "30s" {
		t.Errorf("default keepalive = %q, want 30s", ob.KeepalivePeriod)
	}
	if ob.Congestion.Type != "reno" {
		t.Errorf("default congestion = %q, want reno", ob.Congestion.Type)
	}
	if ob.SNIAddress == "" {
		t.Error("default SNI should not be empty")
	}

	ss, err := fc.ParseSocksSettings()
	if err != nil {
		t.Fatalf("ParseSocksSettings: %v", err)
	}
	if ss.Listen != "0.0.0.0:1080" {
		t.Errorf("default socks.listen = %q, want 0.0.0.0:1080", ss.Listen)
	}
	if ss.MTU != 1280 {
		t.Errorf("default socks.mtu = %d, want 1280", ss.MTU)
	}
}

func TestSaveFullConfig(t *testing.T) {
	fc := &FullConfig{
		Account: AccountConfig{
			PrivateKey: "key",
			EndpointV4: "1.2.3.4",
			IPv4:       "10.0.0.1",
		},
		Inbound: InboundConfig{
			Type:     "tun",
			Settings: mustMarshal(TunInboundSettings{MTU: 1280}),
		},
		Outbound: OutboundConfig{
			Tag: "warp",
			Settings: OutboundSettings{
				Port:            443,
				KeepalivePeriod: "30s",
				ReconnectDelay:  "1s",
			},
		},
	}

	tmpFile := t.TempDir() + "/save.json"
	if err := fc.SaveFullConfig(tmpFile); err != nil {
		t.Fatalf("SaveFullConfig: %v", err)
	}

	loaded, err := LoadFullConfig(tmpFile)
	if err != nil {
		t.Fatalf("LoadFullConfig: %v", err)
	}

	if loaded.Account.PrivateKey != "key" {
		t.Errorf("round-trip private_key = %q, want key", loaded.Account.PrivateKey)
	}
	if loaded.Inbound.Type != "tun" {
		t.Errorf("round-trip inbound.type = %q, want tun", loaded.Inbound.Type)
	}
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		input string
		def   time.Duration
		want  time.Duration
	}{
		{"", 5 * time.Second, 5 * time.Second},
		{"10s", 5 * time.Second, 10 * time.Second},
		{"500ms", 0, 500 * time.Millisecond},
		{"invalid", 3 * time.Second, 3 * time.Second},
	}

	for _, tt := range tests {
		got := ParseDuration(tt.input, tt.def)
		if got != tt.want {
			t.Errorf("ParseDuration(%q, %v) = %v, want %v", tt.input, tt.def, got, tt.want)
		}
	}
}

func TestNoiseJSONToConfig(t *testing.T) {
	n := NoiseJSON{
		Count:    5,
		MinSize:  64,
		MaxSize:  512,
		DelayMin: "10ms",
		DelayMax: "100ms",
	}
	nc := n.ToNoiseConfig()
	if nc.Count != 5 {
		t.Errorf("count = %d, want 5", nc.Count)
	}
	if nc.DelayMin != 10*time.Millisecond {
		t.Errorf("delay_min = %v, want 10ms", nc.DelayMin)
	}
	if nc.DelayMax != 100*time.Millisecond {
		t.Errorf("delay_max = %v, want 100ms", nc.DelayMax)
	}
}

func TestNewDefaultFullConfig(t *testing.T) {
	acct := AccountConfig{
		PrivateKey: "key",
		EndpointV4: "1.2.3.4",
		IPv4:       "10.0.0.1",
	}
	fc := NewDefaultFullConfig(acct)

	if fc.Inbound.Type != "tun" {
		t.Errorf("default inbound.type = %q, want tun", fc.Inbound.Type)
	}
	if fc.Outbound.Tag != "warp" {
		t.Errorf("default outbound.tag = %q, want warp", fc.Outbound.Tag)
	}
	if fc.Outbound.Settings.Port != 443 {
		t.Errorf("default port = %d, want 443", fc.Outbound.Settings.Port)
	}

	// Verify settings are valid JSON
	var ts TunInboundSettings
	if err := json.Unmarshal(fc.Inbound.Settings, &ts); err != nil {
		t.Fatalf("default tun settings invalid JSON: %v", err)
	}
	if ts.MTU != 1280 {
		t.Errorf("default tun.mtu = %d, want 1280", ts.MTU)
	}
}

func TestCongestionValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     CongestionConfig
		wantErr bool
	}{
		// Valid cases
		{"reno default", CongestionConfig{Type: "reno"}, false},
		{"reno empty", CongestionConfig{Type: ""}, false},
		{"brutal valid", CongestionConfig{Type: "brutal", BrutalBPS: 10_000_000}, false},
		{"bbr standard", CongestionConfig{Type: "bbr", BBRProfile: "standard"}, false},
		{"bbr conservative", CongestionConfig{Type: "bbr", BBRProfile: "conservative"}, false},
		{"bbr aggressive", CongestionConfig{Type: "bbr", BBRProfile: "aggressive"}, false},

		// Error cases
		{"reno with brutal_bps", CongestionConfig{Type: "reno", BrutalBPS: 100}, true},
		{"reno with bbr_profile", CongestionConfig{Type: "reno", BBRProfile: "standard"}, true},
		{"brutal missing bps", CongestionConfig{Type: "brutal"}, true},
		{"brutal with bbr_profile", CongestionConfig{Type: "brutal", BrutalBPS: 100, BBRProfile: "standard"}, true},
		{"bbr with brutal_bps", CongestionConfig{Type: "bbr", BrutalBPS: 100, BBRProfile: "standard"}, true},
		{"bbr missing profile", CongestionConfig{Type: "bbr"}, true},
		{"bbr invalid profile", CongestionConfig{Type: "bbr", BBRProfile: "fast"}, true},
		{"unknown type", CongestionConfig{Type: "quic"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}
