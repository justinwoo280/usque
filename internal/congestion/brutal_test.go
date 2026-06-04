package congestion

import (
	"testing"
	"time"

	"github.com/apernet/quic-go/congestion"
)

type mockRTTStats struct {
	smoothedRTT time.Duration
}

func (m *mockRTTStats) MinRTT() time.Duration                                       { return m.smoothedRTT }
func (m *mockRTTStats) LatestRTT() time.Duration                                    { return m.smoothedRTT }
func (m *mockRTTStats) SmoothedRTT() time.Duration                                  { return m.smoothedRTT }
func (m *mockRTTStats) MeanDeviation() time.Duration                                { return 0 }
func (m *mockRTTStats) MaxAckDelay() time.Duration                                  { return 0 }
func (m *mockRTTStats) PTO(includeMaxAckDelay bool) time.Duration                   { return m.smoothedRTT * 2 }
func (m *mockRTTStats) UpdateRTT(sendDelta, ackDelay time.Duration)                 {}
func (m *mockRTTStats) SetMaxAckDelay(mad time.Duration)                            {}
func (m *mockRTTStats) SetInitialRTT(t time.Duration)                               {}

func TestBrutalSenderInterface(t *testing.T) {
	var _ congestion.CongestionControl = &BrutalSender{}
	var _ congestion.CongestionControlEx = &BrutalSender{}
}

func TestBrutalSenderCongestionWindow(t *testing.T) {
	bs := NewBrutalSender(10_000_000)
	bs.SetRTTStatsProvider(&mockRTTStats{smoothedRTT: 50 * time.Millisecond})

	cwnd := bs.GetCongestionWindow()
	expected := congestion.ByteCount(10_000_000 * 0.05 * 2 / 1.0)
	if cwnd != expected {
		t.Errorf("cwnd = %d, want %d", cwnd, expected)
	}
}

func TestBrutalSenderZeroRTT(t *testing.T) {
	bs := NewBrutalSender(10_000_000)
	bs.SetRTTStatsProvider(&mockRTTStats{smoothedRTT: 0})

	cwnd := bs.GetCongestionWindow()
	if cwnd != 10240 {
		t.Errorf("cwnd with zero RTT = %d, want 10240", cwnd)
	}
}

func TestBrutalSenderNeverSlowStartOrRecovery(t *testing.T) {
	bs := NewBrutalSender(10_000_000)
	if bs.InSlowStart() {
		t.Error("BrutalSender should never be in slow start")
	}
	if bs.InRecovery() {
		t.Error("BrutalSender should never be in recovery")
	}
}

func TestBrutalSenderIgnoresLoss(t *testing.T) {
	bs := NewBrutalSender(10_000_000)
	bs.SetRTTStatsProvider(&mockRTTStats{smoothedRTT: 50 * time.Millisecond})

	cwndBefore := bs.GetCongestionWindow()
	bs.OnCongestionEvent(1, 1200, 10000)
	bs.OnPacketAcked(2, 1200, 10000, 0)
	cwndAfter := bs.GetCongestionWindow()

	if cwndBefore != cwndAfter {
		t.Errorf("cwnd changed after loss: %d -> %d (should be unchanged)", cwndBefore, cwndAfter)
	}
}

func TestBrutalSenderAckRateClamping(t *testing.T) {
	bs := NewBrutalSender(10_000_000)
	rtt := &mockRTTStats{smoothedRTT: 50 * time.Millisecond}
	bs.SetRTTStatsProvider(rtt)

	cwndNormal := bs.GetCongestionWindow()

	var lost []congestion.LostPacketInfo
	for i := 0; i < 100; i++ {
		lost = append(lost, congestion.LostPacketInfo{PacketNumber: congestion.PacketNumber(i), BytesLost: 1200})
	}
	bs.OnCongestionEventEx(10000, 1, nil, lost)

	cwndAfterLoss := bs.GetCongestionWindow()
	if cwndAfterLoss <= cwndNormal {
		t.Errorf("cwnd should increase after heavy loss (ack rate clamped): normal=%d, after=%d", cwndNormal, cwndAfterLoss)
	}
}

func TestPacerBudget(t *testing.T) {
	p := NewPacer(func() congestion.ByteCount { return 1_000_000 })

	if p.Budget(0) <= 0 {
		t.Error("initial budget should be positive")
	}
}

func TestPacerTimeUntilSend(t *testing.T) {
	p := NewPacer(func() congestion.ByteCount { return 1_000_000 })

	if p.TimeUntilSend() != 0 {
		t.Error("should be able to send immediately with full budget")
	}
}
