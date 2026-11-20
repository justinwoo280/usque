//go:build windows

package api

import (
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

func guidFromName(name string) windows.GUID {
	hash := md5.Sum([]byte(name))
	return *(*windows.GUID)(unsafe.Pointer(&hash[0]))
}

// WintunAdapter wraps a wintun session to satisfy TunnelDevice.
// Unlike NetstackAdapter (which adapts wireguard-go/tun's batch API),
// this directly uses wintun's single-packet ring buffer I/O.
type WintunAdapter struct {
	adapter  io.Closer
	session  wintunRing
	luid     uint64
	readWait windows.Handle
	doneEvt  windows.Handle
	ioMu     sync.RWMutex // holds the ring and both handles alive during I/O
	closing  atomic.Bool
	once     sync.Once
	closeErr error
}

type wintunRing interface {
	ReceivePacket() ([]byte, error)
	ReleaseReceivePacket([]byte)
	AllocateSendPacket(int) ([]byte, error)
	SendPacket([]byte)
	End()
}

func (w *WintunAdapter) ReadPacket(buf []byte) (int, error) {
	w.ioMu.RLock()
	defer w.ioMu.RUnlock()
	for !w.closing.Load() {
		pkt, err := w.session.ReceivePacket()
		if err == nil {
			defer w.session.ReleaseReceivePacket(pkt)
			if len(buf) < len(pkt) {
				return 0, io.ErrShortBuffer
			}
			return copy(buf, pkt), nil
		}

		if errors.Is(err, windows.ERROR_HANDLE_EOF) {
			return 0, os.ErrClosed
		}
		if !errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
			return 0, fmt.Errorf("wintun receive: %w", err)
		}

		ret, waitErr := windows.WaitForMultipleObjects(
			[]windows.Handle{w.doneEvt, w.readWait},
			false,
			windows.INFINITE,
		)
		if waitErr != nil {
			return 0, fmt.Errorf("wintun wait: %w", waitErr)
		}
		switch ret {
		case windows.WAIT_OBJECT_0:
			return 0, os.ErrClosed
		case windows.WAIT_OBJECT_0 + 1:
		default:
			return 0, fmt.Errorf("unexpected Wintun wait status: %#x", ret)
		}
	}
	return 0, os.ErrClosed
}

func (w *WintunAdapter) WritePacket(pkt []byte) error {
	w.ioMu.RLock()
	defer w.ioMu.RUnlock()
	if w.closing.Load() {
		return os.ErrClosed
	}
	if len(pkt) == 0 || len(pkt) > wintun.PacketSizeMax {
		return fmt.Errorf("invalid Wintun packet size %d", len(pkt))
	}
	buf, err := w.session.AllocateSendPacket(len(pkt))
	if errors.Is(err, windows.ERROR_HANDLE_EOF) {
		return os.ErrClosed
	}
	if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
		// Receiver congestion, not a broken TUN or an MTU change. Match
		// wireguard-go: drop this one packet instead of stopping the proxy.
		return nil
	}
	if err != nil {
		return fmt.Errorf("wintun allocate send: %w", err)
	}
	copy(buf, pkt)
	w.session.SendPacket(buf)
	return nil
}

// LUID returns the adapter's locally unique identifier as reported by the
// wintun driver, avoiding a net.InterfaceByName round-trip.
func (w *WintunAdapter) LUID() uint64 {
	return w.luid
}

// Close ends the wintun session and releases the adapter.
// Signals the done event to unblock any goroutine parked in ReadPacket.
func (w *WintunAdapter) Close() error {
	w.once.Do(func() {
		w.closing.Store(true)
		// Wake every pending reader before taking the exclusive lock. Once
		// it is held, no goroutine is waiting on a handle or owns a ring slice.
		if err := windows.SetEvent(w.doneEvt); err != nil {
			w.closeErr = fmt.Errorf("signal Wintun shutdown: %w", err)
			return
		}
		w.ioMu.Lock()
		defer w.ioMu.Unlock()
		w.session.End() // also releases readWait (owned by Wintun)
		w.closeErr = errors.Join(windows.CloseHandle(w.doneEvt), w.adapter.Close())
	})
	return w.closeErr
}

// NewWintunAdapter creates a wintun adapter with the given name, starts an
// 8 MiB ring buffer session, and returns a ready-to-use WintunAdapter.
// The GUID is derived deterministically from the adapter name (MD5) so that
// repeated runs reuse the same network adapter identity.
func NewWintunAdapter(name string) (*WintunAdapter, error) {
	guid := guidFromName(name)
	adapter, err := wintun.CreateAdapter(name, "usque", &guid)
	if err != nil {
		return nil, fmt.Errorf("create wintun adapter: %w", err)
	}

	session, err := adapter.StartSession(0x800000)
	if err != nil {
		_ = adapter.Close()
		return nil, fmt.Errorf("start wintun session: %w", err)
	}

	doneEvt, err := windows.CreateEvent(nil, 1, 0, nil) // manual-reset shutdown broadcast
	if err != nil {
		session.End()
		_ = adapter.Close()
		return nil, fmt.Errorf("create done event: %w", err)
	}

	return &WintunAdapter{
		adapter:  adapter,
		session:  session,
		luid:     adapter.LUID(),
		readWait: session.ReadWaitEvent(),
		doneEvt:  doneEvt,
	}, nil
}
