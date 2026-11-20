//go:build windows

package api

import (
	"errors"
	"io"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

type fakeWintunRing struct {
	read     func() ([]byte, error)
	release  func([]byte)
	allocErr error
	ended    atomic.Int32
	sent     int
}

func (r *fakeWintunRing) ReceivePacket() ([]byte, error) { return r.read() }
func (r *fakeWintunRing) ReleaseReceivePacket(b []byte)  { r.release(b) }
func (r *fakeWintunRing) AllocateSendPacket(n int) ([]byte, error) {
	return make([]byte, n), r.allocErr
}
func (r *fakeWintunRing) SendPacket([]byte) { r.sent++ }
func (r *fakeWintunRing) End()              { r.ended.Add(1) }

type fakeWintunDevice struct{ closed atomic.Int32 }

func (d *fakeWintunDevice) Close() error { d.closed.Add(1); return nil }

func testWintunAdapter(t *testing.T, r *fakeWintunRing) (*WintunAdapter, *fakeWintunDevice) {
	t.Helper()
	readWait, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = windows.CloseHandle(readWait) })
	doneEvt, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	d := new(fakeWintunDevice)
	w := &WintunAdapter{adapter: d, session: r, readWait: readWait, doneEvt: doneEvt}
	t.Cleanup(func() { _ = w.Close() })
	return w, d
}

func TestWintunCloseUnblocksReader(t *testing.T) {
	reading := make(chan struct{})
	r := &fakeWintunRing{read: func() ([]byte, error) {
		close(reading)
		return nil, windows.ERROR_NO_MORE_ITEMS
	}}
	w, d := testWintunAdapter(t, r)
	readDone := make(chan error, 1)
	go func() { _, err := w.ReadPacket(make([]byte, 65535)); readDone <- err }()
	select {
	case <-reading:
	case <-time.After(5 * time.Second):
		t.Fatal("reader did not enter Wintun ring")
	}
	closed := make(chan error, 1)
	go func() { closed <- w.Close() }()
	select {
	case err := <-readDone:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("ReadPacket error = %v, want os.ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("closing Wintun did not wake the reader")
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if r.ended.Load() != 1 || d.closed.Load() != 1 {
		t.Fatal("underlying session and adapter must be closed exactly once")
	}
	if err := w.WritePacket([]byte{1}); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("WritePacket on closed adapter: %v", err)
	}
}

func TestWintunCloseWaitsForPacketRelease(t *testing.T) {
	releasing := make(chan struct{})
	release := make(chan struct{})
	r := &fakeWintunRing{
		read: func() ([]byte, error) { return []byte{1}, nil },
		release: func([]byte) {
			close(releasing)
			<-release
		},
	}
	w, _ := testWintunAdapter(t, r)
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	go func() { _, _ = w.ReadPacket(make([]byte, 1)) }()
	select {
	case <-releasing:
	case <-time.After(5 * time.Second):
		t.Fatal("reader did not get a packet")
	}
	closed := make(chan error, 1)
	go func() { closed <- w.Close() }()
	status, err := windows.WaitForSingleObject(w.doneEvt, 5000)
	ended := r.ended.Load()
	close(release)
	if err != nil || status != windows.WAIT_OBJECT_0 {
		t.Fatalf("close did not signal shutdown: status %#x, error %v", status, err)
	}
	if ended != 0 {
		t.Fatal("Wintun session ended while a ring packet was still borrowed")
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
}

func TestWintunJumboPacketAndRingOverflow(t *testing.T) {
	jumbo := make([]byte, 9000)
	var releases int
	r := &fakeWintunRing{
		read:    func() ([]byte, error) { return jumbo, nil },
		release: func([]byte) { releases++ },
	}
	w, _ := testWintunAdapter(t, r)
	if n, err := w.ReadPacket(make([]byte, 1500)); n != 0 || !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("read jumbo with small buffer = (%d, %v)", n, err)
	}
	if n, err := w.ReadPacket(make([]byte, 65535)); n != len(jumbo) || err != nil || releases != 2 {
		t.Fatalf("read jumbo = (%d, %v), released %d packets", n, err, releases)
	}
	if err := w.WritePacket(jumbo); err != nil || r.sent != 1 {
		t.Fatalf("write jumbo: err=%v, sent=%d", err, r.sent)
	}
	r.allocErr = windows.ERROR_BUFFER_OVERFLOW
	if err := w.WritePacket(jumbo); err != nil || r.sent != 1 {
		t.Fatalf("ring overflow should drop one packet: err=%v, sent=%d", err, r.sent)
	}
}
