//go:build android

package ble

import (
	"context"
	"errors"
	"sync"
)

// androidService is the Android BLE backend — Central + Peripheral +
// GATT server over the platform's android.bluetooth.* stack.
//
// STATUS: scaffold. The Go side of the JNI plumbing lives here; the
// Java callback shim that Android REQUIRES for BluetoothGattCallback
// / ScanCallback / BluetoothGattServerCallback / AdvertiseCallback
// is deliberately left out of this file because writing those
// classes in pure Go from cgo is impractical — see the note under
// "Design note" below.
//
// ┌─ Design note ─────────────────────────────────────────────────┐
// │                                                               │
// │ Android's BLE API is CALLBACK-DRIVEN. Every scan result,      │
// │ every GATT connection state change, every characteristic      │
// │ write comes back through an abstract Java class the caller    │
// │ subclasses. Those subclasses have virtual methods the JVM     │
// │ dispatches to — you can NOT instantiate them from JNI in a    │
// │ way that lets Go receive their events, because Java virtual  │
// │ dispatch needs a real Java class file.                        │
// │                                                               │
// │ Two options that both keep "the BitChat protocol in pure Go": │
// │                                                               │
// │ 1. Ship a ~120-line Kotlin shim (BleShim.kt) with 4 callback  │
// │    classes whose overrides call into `Java_...` native funcs  │
// │    exported from this file. The Go side stays 100 % Go        │
// │    against JNI; the Kotlin is glue that only exists because  │
// │    Android's API demands a class file. `fyne package -os      │
// │    android` accepts a `Kotlin/` sibling directory for exactly │
// │    this — no build-system rewiring needed.                    │
// │                                                               │
// │ 2. Use github.com/tinygo-org/bluetooth as a Go library — it   │
// │    hides the same callback problem behind its own Java shim   │
// │    that ships inside the module. One external dependency, a   │
// │    working BLE stack today, gives up "0 build-time deps".     │
// │                                                               │
// │ The current file compiles as a no-op on the android target so │
// │ we can build the APK, install it, see the UI, and iterate on  │
// │ the BLE layer as its own follow-up. When option 1 or 2 lands  │
// │ everything above (mesh dispatcher / crypto / model / packet   │
// │ processor / fyne UI) plugs in unchanged.                      │
// └───────────────────────────────────────────────────────────────┘
type androidService struct {
	mu     sync.Mutex
	events chan Event
	closed bool
}

// New returns the platform BLE service. On android, that's the
// (currently no-op) android backend; when the Java shim lands it'll
// become a real implementation without touching this signature.
func New() Service {
	return &androidService{events: make(chan Event, 16)}
}

// NewNoop is here so the android build satisfies the same package
// surface as the stub build.
func NewNoop() Service { return New() }

func (s *androidService) Start(context.Context, [8]byte, string) error {
	// TODO: retrieve JavaVM from gomobile, resolve BluetoothManager +
	// BluetoothAdapter, request permissions, kick off scan +
	// advertise. Blocked on the Java shim above.
	return errors.New("ble: android backend pending Java callback shim")
}

func (s *androidService) Send([8]byte, []byte) error {
	return errors.New("ble: android backend pending Java callback shim")
}

func (s *androidService) Broadcast([]byte) {}

func (s *androidService) Events() <-chan Event { return s.events }

func (s *androidService) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	close(s.events)
	s.closed = true
	return nil
}
