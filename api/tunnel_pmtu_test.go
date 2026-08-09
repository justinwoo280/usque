package api

import "testing"

func TestEffectiveTunnelMTU(t *testing.T) {
	tests := []struct {
		name       string
		configured int
		path       int
		want       int
	}{
		{name: "unknown path uses configured MTU", configured: 1420, path: 0, want: 1420},
		{name: "lower path limits configured MTU", configured: 1420, path: 1241, want: 1241},
		{name: "higher path does not exceed configured MTU", configured: 1420, path: 1450, want: 1420},
		{name: "path MTU is usable without configured MTU", configured: 0, path: 1280, want: 1280},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := effectiveTunnelMTU(tt.configured, tt.path); got != tt.want {
				t.Fatalf("effectiveTunnelMTU(%d, %d) = %d, want %d", tt.configured, tt.path, got, tt.want)
			}
		})
	}
}
