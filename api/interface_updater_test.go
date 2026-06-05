package api

import (
	"net"
	"testing"
)

func TestNewInterfaceUpdaterAuto(t *testing.T) {
	u := NewInterfaceUpdater("auto", 0)
	if u.fixedName != "" {
		t.Errorf("auto mode should have empty fixedName, got %q", u.fixedName)
	}
}

func TestNewInterfaceUpdaterFixed(t *testing.T) {
	u := NewInterfaceUpdater("eth0", 5)
	if u.fixedName != "eth0" {
		t.Errorf("fixedName = %q, want eth0", u.fixedName)
	}
	if u.tunIndex != 5 {
		t.Errorf("tunIndex = %d, want 5", u.tunIndex)
	}
}

func TestInterfaceUpdaterGetBeforeUpdate(t *testing.T) {
	u := NewInterfaceUpdater("auto", 0)
	if u.Get() != nil {
		t.Error("Get() before Update() should return nil")
	}
}

func TestInterfaceUpdaterUpdate(t *testing.T) {
	u := NewInterfaceUpdater("auto", 0)
	u.Update()
	iface := u.Get()
	// On most systems there should be at least one up non-loopback interface,
	// but we can't guarantee it in CI, so just verify no panic.
	if iface != nil {
		t.Logf("selected: %s (index %d)", iface.Name, iface.Index)
	}
}

func TestInterfaceUpdaterFixedNonexistent(t *testing.T) {
	u := NewInterfaceUpdater("nonexistent_iface_xyz", 0)
	u.Update()
	if u.Get() != nil {
		t.Error("fixed non-existent interface should return nil")
	}
}

func TestInterfaceUpdaterStableOnReupdate(t *testing.T) {
	u := NewInterfaceUpdater("auto", 0)
	u.Update()
	first := u.Get()
	u.Update()
	second := u.Get()
	if first == nil && second == nil {
		return
	}
	if first != nil && second != nil && first.Index != second.Index {
		t.Errorf("re-update changed interface: %d -> %d", first.Index, second.Index)
	}
}

func TestScoreInterface(t *testing.T) {
	tests := []struct {
		name  string
		addrs []string
		want  int
	}{
		{"wlan0", []string{"192.168.1.5"}, 3},
		{"eth0", []string{"10.0.0.1"}, 3},
		{"docker0", []string{"172.17.0.1"}, 1},
		{"lo", []string{"127.0.0.1"}, 0},
	}

	for _, tt := range tests {
		iface := &net.Interface{Name: tt.name}
		var addrs []net.Addr
		for _, a := range tt.addrs {
			ip := net.ParseIP(a)
			if ip4 := ip.To4(); ip4 != nil {
				ip = ip4
			}
			addrs = append(addrs, &net.IPNet{IP: ip, Mask: net.CIDRMask(24, 32)})
		}
		score := scoreInterface(iface, addrs)
		if score != tt.want {
			t.Errorf("scoreInterface(%q, %v) = %d, want %d", tt.name, tt.addrs, score, tt.want)
		}
	}
}
