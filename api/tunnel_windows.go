//go:build windows

package api

import (
	"crypto/md5"
	"errors"
	"fmt"
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
	adapter  *wintun.Adapter
	session  wintun.Session
	readWait windows.Handle
	doneEvt  windows.Handle
}

func (w *WintunAdapter) ReadPacket(buf []byte) (int, error) {
	for {
		pkt, err := w.session.ReceivePacket()
		if err == nil {
			n := copy(buf, pkt)
			w.session.ReleaseReceivePacket(pkt)
			return n, nil
		}

		if !errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
			return 0, fmt.Errorf("wintun receive: %w", err)
		}

		ret, waitErr := windows.WaitForMultipleObjects(
			[]windows.Handle{w.readWait, w.doneEvt},
			false,
			windows.INFINITE,
		)
		if waitErr != nil {
			return 0, fmt.Errorf("wintun wait: %w", waitErr)
		}
		if ret == windows.WAIT_OBJECT_0+1 {
			return 0, fmt.Errorf("wintun adapter closed")
		}
	}
}

func (w *WintunAdapter) WritePacket(pkt []byte) error {
	buf, err := w.session.AllocateSendPacket(len(pkt))
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
	return w.adapter.LUID()
}

// Close ends the wintun session and releases the adapter.
// Signals the done event to unblock any goroutine parked in ReadPacket.
func (w *WintunAdapter) Close() error {
	windows.SetEvent(w.doneEvt)
	w.session.End()
	return w.adapter.Close()
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

	doneEvt, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		session.End()
		_ = adapter.Close()
		return nil, fmt.Errorf("create done event: %w", err)
	}

	return &WintunAdapter{
		adapter:  adapter,
		session:  session,
		readWait: session.ReadWaitEvent(),
		doneEvt:  doneEvt,
	}, nil
}
