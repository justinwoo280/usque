package mobile

import (
	"encoding/json"
	"sync/atomic"
	"time"
)

type tunnelState int

const (
	stateStopped tunnelState = iota
	stateConnecting
	stateConnected
	stateReconnecting
	stateError
)

func (s tunnelState) String() string {
	switch s {
	case stateStopped:
		return "stopped"
	case stateConnecting:
		return "connecting"
	case stateConnected:
		return "connected"
	case stateReconnecting:
		return "reconnecting"
	case stateError:
		return "error"
	default:
		return "unknown"
	}
}

type tunnelStatus struct {
	state     atomic.Int32
	bytesSent atomic.Int64
	bytesRecv atomic.Int64
	startedAt atomic.Int64
	errMsg    atomic.Value
}

func newTunnelStatus() *tunnelStatus {
	s := &tunnelStatus{}
	s.errMsg.Store("")
	return s
}

func (s *tunnelStatus) setState(st tunnelState) {
	s.state.Store(int32(st))
}

func (s *tunnelStatus) setError(msg string) {
	s.state.Store(int32(stateError))
	s.errMsg.Store(msg)
}

func (s *tunnelStatus) addSent(n int64) { s.bytesSent.Add(n) }
func (s *tunnelStatus) addRecv(n int64) { s.bytesRecv.Add(n) }

func (s *tunnelStatus) markStarted() {
	s.startedAt.Store(time.Now().Unix())
}

func (s *tunnelStatus) reset() {
	s.state.Store(int32(stateStopped))
	s.bytesSent.Store(0)
	s.bytesRecv.Store(0)
	s.startedAt.Store(0)
	s.errMsg.Store("")
}

func (s *tunnelStatus) toJSON() string {
	started := s.startedAt.Load()
	var uptime string
	if started > 0 {
		uptime = time.Since(time.Unix(started, 0)).Truncate(time.Second).String()
	}

	errMsg, _ := s.errMsg.Load().(string)

	data := map[string]interface{}{
		"state":      tunnelState(s.state.Load()).String(),
		"bytes_sent": s.bytesSent.Load(),
		"bytes_recv": s.bytesRecv.Load(),
		"uptime":     uptime,
	}
	if errMsg != "" {
		data["message"] = errMsg
	}
	b, _ := json.Marshal(data)
	return string(b)
}
