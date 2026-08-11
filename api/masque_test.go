package api

import "testing"

func TestNewCloudflareQUICTransportUsesTwentyByteConnectionIDs(t *testing.T) {
	transport := NewCloudflareQUICTransport(nil)
	if transport.ConnectionIDLength != 20 {
		t.Fatalf("ConnectionIDLength = %d, want 20", transport.ConnectionIDLength)
	}
}

func TestTunnelTransportCloseNilSafe(t *testing.T) {
	var transport *TunnelTransport
	if err := transport.Close(); err != nil {
		t.Fatal(err)
	}
}
