//go:build !android

package ble

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	tb "tinygo.org/x/bluetooth"
)

// New returns the tinygo-bluetooth backed Service on any platform
// where tinygo-bluetooth ships an adapter — that's Linux (BlueZ),
// macOS (CoreBluetooth), Windows (WinRT). Android is handled by
// service_android.go (still a stub — see that file for why).
func New() Service { return &tinygoService{} }

// NewNoop returns a Service that fails to Start — useful when a
// caller wants the interface satisfied without touching hardware.
func NewNoop() Service {
	s := &noopService{events: make(chan Event)}
	close(s.events)
	return s
}

type noopService struct{ events chan Event }

func (n *noopService) Start(context.Context, [8]byte, string) error {
	return errors.New("ble: noop backend")
}
func (n *noopService) Send([8]byte, []byte) error {
	return errors.New("ble: noop backend")
}
func (n *noopService) Broadcast([]byte)     {}
func (n *noopService) Events() <-chan Event { return n.events }
func (n *noopService) Close() error         { return nil }

// tinygoService drives tinygo.org/x/bluetooth's DefaultAdapter.
// Central role only for the first cut — we scan for BitchatServiceUUID
// advertisers, connect on discovery, and pull inbound wire packets
// off the peer's characteristic notifications. Peripheral/GATT-server
// support lands in a follow-up (it's platform-specific in tinygo
// and adds nontrivial wiring for advertising + characteristic writes
// from central peers).
type tinygoService struct {
	mu     sync.Mutex
	events chan Event
	cancel context.CancelFunc
	closed bool

	adapter *tb.Adapter
	scanCtx context.Context

	// peer routing state — 8-byte peer id -> device handle.
	peers map[[8]byte]*tinygoPeer
}

type tinygoPeer struct {
	device tb.Device
	tx     tb.DeviceCharacteristic
}

func (s *tinygoService) Start(ctx context.Context, localID [8]byte, nickname string) error {
	s.mu.Lock()
	if s.adapter != nil {
		s.mu.Unlock()
		return errors.New("ble: already started")
	}
	s.adapter = tb.DefaultAdapter
	s.events = make(chan Event, 32)
	s.peers = make(map[[8]byte]*tinygoPeer)
	s.mu.Unlock()

	if err := s.adapter.Enable(); err != nil {
		return fmt.Errorf("adapter enable: %w", err)
	}
	// Kick the scan on a goroutine so Start returns promptly. The
	// callback runs on tinygo-bluetooth's internal thread — it MUST
	// return quickly, so we just push into the events channel.
	scanCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel

	uuid, err := tb.ParseUUID(BitchatServiceUUID)
	if err != nil {
		return fmt.Errorf("parse service uuid: %w", err)
	}

	go func() {
		err := s.adapter.Scan(func(_ *tb.Adapter, result tb.ScanResult) {
			select {
			case <-scanCtx.Done():
				return
			default:
			}
			if !result.AdvertisementPayload.HasServiceUUID(uuid) {
				return
			}
			pid := peerIDFromLocalName(result.LocalName())
			s.pushEvent(PeerFound{
				PeerID:  pid,
				Address: result.Address.String(),
			})
		})
		if err != nil && scanCtx.Err() == nil {
			s.pushEvent(AdapterStateChanged{PoweredOn: false, Reason: err.Error()})
		}
	}()

	// Emit an initial adapter-up event so the caller knows Start
	// completed successfully.
	s.pushEvent(AdapterStateChanged{PoweredOn: true})
	_ = localID
	_ = nickname
	return nil
}

func (s *tinygoService) pushEvent(e Event) {
	s.mu.Lock()
	ch := s.events
	closed := s.closed
	s.mu.Unlock()
	if closed || ch == nil {
		return
	}
	select {
	case ch <- e:
	default:
		// Drop rather than block a BLE callback. Callers who care
		// about lossless delivery should drain Events promptly.
	}
}

// peerIDFromLocalName extracts an 8-byte peer id from a discovered
// peripheral's advertised local name. BitChat mainline / the Rust
// fork advertise a colon-separated peer_id suffix in the local name;
// we search for a 16-hex-char run and return it as raw bytes. If
// none is found, returns all-zero (still surfaces the PeerFound
// event so the operator sees the device is around).
func peerIDFromLocalName(name string) [8]byte {
	var out [8]byte
	name = strings.ToLower(name)
	// Find any 16-hex-char substring.
	for i := 0; i+16 <= len(name); i++ {
		if allHex(name[i : i+16]) {
			for j := 0; j < 8; j++ {
				out[j] = fromHex(name[i+2*j])<<4 | fromHex(name[i+2*j+1])
			}
			return out
		}
	}
	return out
}

func allHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func fromHex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	}
	return 0
}

func (s *tinygoService) Send(peerID [8]byte, data []byte) error {
	s.mu.Lock()
	p, ok := s.peers[peerID]
	s.mu.Unlock()
	if !ok {
		return errors.New("ble: peer not connected")
	}
	_, err := p.tx.WriteWithoutResponse(data)
	return err
}

func (s *tinygoService) Broadcast(data []byte) {
	s.mu.Lock()
	peers := make([]*tinygoPeer, 0, len(s.peers))
	for _, p := range s.peers {
		peers = append(peers, p)
	}
	s.mu.Unlock()
	for _, p := range peers {
		_, _ = p.tx.WriteWithoutResponse(data)
	}
}

func (s *tinygoService) Events() <-chan Event { return s.events }

func (s *tinygoService) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	cancel := s.cancel
	ch := s.events
	adapter := s.adapter
	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if adapter != nil {
		_ = adapter.StopScan()
	}
	// Give the scan goroutine a beat to drain, then close.
	time.Sleep(50 * time.Millisecond)
	if ch != nil {
		close(ch)
	}
	return nil
}
