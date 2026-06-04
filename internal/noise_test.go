package internal

import (
	"errors"
	"testing"
	"time"
)

type mockPacketWriter struct {
	sent    int
	lastErr error
	packets [][]byte
}

func (m *mockPacketWriter) WritePacket(b []byte) ([]byte, error) {
	if m.lastErr != nil {
		return nil, m.lastErr
	}
	m.sent++
	cp := make([]byte, len(b))
	copy(cp, b)
	m.packets = append(m.packets, cp)
	return nil, nil
}

func TestInjectNoiseZeroCount(t *testing.T) {
	w := &mockPacketWriter{}
	InjectNoise(w, NoiseConfig{Count: 0})
	if w.sent != 0 {
		t.Errorf("expected 0 sends, got %d", w.sent)
	}
}

func TestInjectNoiseBasic(t *testing.T) {
	w := &mockPacketWriter{}
	InjectNoise(w, NoiseConfig{
		Count:   10,
		MinSize: 100,
		MaxSize: 100,
	})
	if w.sent != 10 {
		t.Errorf("expected 10 sends, got %d", w.sent)
	}
	for i, pkt := range w.packets {
		if len(pkt) != 100 {
			t.Errorf("packet %d: expected size 100, got %d", i, len(pkt))
		}
		if pkt[0] != 0x45 {
			t.Errorf("packet %d: not IPv4 (version byte = 0x%02x)", i, pkt[0])
		}
		if pkt[16] != 192 || pkt[17] != 0 || pkt[18] != 2 {
			t.Errorf("packet %d: dst not in TEST-NET-1: %d.%d.%d", i, pkt[16], pkt[17], pkt[18])
		}
	}
}

func TestInjectNoiseStopsOnError(t *testing.T) {
	w := &mockPacketWriter{lastErr: errors.New("send failed")}
	InjectNoise(w, NoiseConfig{
		Count:   10,
		MinSize: 64,
		MaxSize: 64,
	})
	if w.sent != 0 {
		t.Errorf("expected 0 successful sends on error, got %d", w.sent)
	}
}

func TestInjectNoiseSizeRange(t *testing.T) {
	w := &mockPacketWriter{}
	InjectNoise(w, NoiseConfig{
		Count:   50,
		MinSize: 40,
		MaxSize: 200,
	})
	for i, pkt := range w.packets {
		if len(pkt) < 40 || len(pkt) > 200 {
			t.Errorf("packet %d: size %d out of range [40,200]", i, len(pkt))
		}
	}
}

func TestInjectNoiseWithDelay(t *testing.T) {
	w := &mockPacketWriter{}
	start := time.Now()
	InjectNoise(w, NoiseConfig{
		Count:    3,
		MinSize:  64,
		MaxSize:  64,
		DelayMin: 10 * time.Millisecond,
		DelayMax: 10 * time.Millisecond,
	})
	elapsed := time.Since(start)
	if w.sent != 3 {
		t.Errorf("expected 3 sends, got %d", w.sent)
	}
	if elapsed < 20*time.Millisecond {
		t.Errorf("expected at least 20ms delay for 3 packets, got %s", elapsed)
	}
}

func TestMakeIPv4NoisePacket(t *testing.T) {
	pkt := makeIPv4NoisePacket(64)

	if pkt[0] != 0x45 {
		t.Errorf("version/IHL: expected 0x45, got 0x%02x", pkt[0])
	}
	if pkt[8] != 64 {
		t.Errorf("TTL: expected 64, got %d", pkt[8])
	}
	if pkt[16] != 192 || pkt[17] != 0 || pkt[18] != 2 {
		t.Errorf("dst not in 192.0.2.0/24: %d.%d.%d.%d", pkt[16], pkt[17], pkt[18], pkt[19])
	}

	sum := uint32(0)
	for i := 0; i < 20; i += 2 {
		sum += uint32(pkt[i])<<8 | uint32(pkt[i+1])
	}
	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	if sum != 0xFFFF {
		t.Errorf("checksum invalid: folded sum=0x%04x", sum)
	}
}

func TestMakeIPv4NoisePacketMinSize(t *testing.T) {
	pkt := makeIPv4NoisePacket(5)
	if len(pkt) != 20 {
		t.Errorf("expected minimum 20 bytes, got %d", len(pkt))
	}
}
