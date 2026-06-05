package api

import (
	"log"
	"net"
	"sort"
	"strings"
	"sync"
)

// InterfaceUpdater detects the physical network interface and provides it
// for outbound socket binding. This replaces the fwmark approach: instead of
// marking packets and using policy routing, the QUIC/TCP socket is bound
// directly to the physical NIC via SO_BINDTODEVICE (Linux), IP_BOUND_IF
// (macOS), or IP_UNICAST_IF (Windows).
type InterfaceUpdater struct {
	mu        sync.Mutex
	tunIndex  int
	fixedName string
	iface     *net.Interface
}

// NewInterfaceUpdater creates an updater. If name is "auto" or "", the best
// physical interface is auto-detected. Otherwise the named interface is used.
// tunIndex is excluded from detection to prevent routing loops.
func NewInterfaceUpdater(name string, tunIndex int) *InterfaceUpdater {
	u := &InterfaceUpdater{tunIndex: tunIndex}
	if name != "auto" && name != "" {
		u.fixedName = name
	}
	return u
}

// Get returns the currently selected physical interface (thread-safe).
func (u *InterfaceUpdater) Get() *net.Interface {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.iface
}

// Update re-detects the best physical interface. Safe to call repeatedly
// (e.g. on network change events).
func (u *InterfaceUpdater) Update() {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.iface != nil {
		iface, err := net.InterfaceByIndex(u.iface.Index)
		if err == nil && iface.Name == u.iface.Name {
			return
		}
	}
	u.iface = nil

	interfaces, err := net.Interfaces()
	if err != nil {
		log.Printf("[InterfaceUpdater] failed to list interfaces: %v", err)
		return
	}

	if u.fixedName != "" {
		for _, iface := range interfaces {
			if iface.Index == u.tunIndex {
				continue
			}
			if iface.Name == u.fixedName {
				cp := iface
				u.iface = &cp
				break
			}
		}
	} else {
		type candidate struct {
			index int
			score int
		}
		var candidates []candidate
		for i, iface := range interfaces {
			if iface.Index == u.tunIndex {
				continue
			}
			if strings.Contains(iface.Name, "vEthernet") {
				continue
			}
			if iface.Flags&net.FlagUp == 0 {
				continue
			}
			if iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil || len(addrs) == 0 {
				continue
			}
			candidates = append(candidates, candidate{i, scoreInterface(&iface, addrs)})
		}
		sort.Slice(candidates, func(i, j int) bool {
			if candidates[i].score != candidates[j].score {
				return candidates[i].score > candidates[j].score
			}
			return interfaces[candidates[i].index].Name < interfaces[candidates[j].index].Name
		})
		if len(candidates) > 0 {
			iface := interfaces[candidates[0].index]
			u.iface = &iface
		}
	}

	if u.iface != nil {
		log.Printf("[InterfaceUpdater] selected interface %s (index %d)", u.iface.Name, u.iface.Index)
	} else {
		log.Printf("[InterfaceUpdater] no suitable physical interface found")
	}
}

func scoreInterface(iface *net.Interface, addrs []net.Addr) int {
	s := 0
	name := strings.ToLower(iface.Name)
	if strings.Contains(name, "wlan") || strings.Contains(name, "wi-fi") ||
		strings.Contains(name, "eth") || strings.Contains(name, "en") {
		s += 2
	}
	for _, addr := range addrs {
		a := addr.String()
		if strings.HasPrefix(a, "192.168.") || strings.HasPrefix(a, "10.") || strings.HasPrefix(a, "172.") {
			s++
			break
		}
	}
	return s
}
