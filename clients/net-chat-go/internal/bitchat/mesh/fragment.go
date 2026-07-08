// Package mesh — Go port of bitchat-rust's src/mesh/*.rs.
//
// The mesh layer sits between the BLE driver (below) and the app
// (above). It slices packets larger than BLE MTU, reassembles
// fragments, tracks peer state, and dispatches inbound frames by
// message type.
//
// This file: fragment manager.
package mesh

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// MaxFragmentSize is the BLE MTU-safe payload we can push in one
// GATT write. iOS/Android bitchat both settle on 512.
const MaxFragmentSize = 512

// fragmentTimeout drops half-received groups after 30 s so they
// don't leak memory when a peer disappears mid-transfer.
const fragmentTimeout = 30 * time.Second

// FragmentHeader carries the addressing bits that let the manager
// reassemble a group.
type FragmentHeader struct {
	MessageID       string
	FragmentIndex   uint16
	TotalFragments  uint16
}

type fragGroup struct {
	fragments      map[uint16][]byte
	totalFragments uint16
	originalType   byte
	timestamp      time.Time
}

// FragmentManager tracks in-flight reassembly groups keyed by the
// 8-byte fragment_id (hex-encoded).
type FragmentManager struct {
	mu     sync.Mutex
	groups map[string]*fragGroup
}

// NewFragmentManager returns an empty manager.
func NewFragmentManager() *FragmentManager {
	return &FragmentManager{groups: make(map[string]*fragGroup)}
}

// AddFragment stores an inbound fragment. Returns (nil, nil) when
// the group isn't complete yet; the reassembled payload when the
// last fragment lands; an error on protocol violations.
func (m *FragmentManager) AddFragment(h FragmentHeader, originalType byte, data []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanupLocked()

	g, ok := m.groups[h.MessageID]
	if !ok {
		g = &fragGroup{
			fragments:      make(map[uint16][]byte, h.TotalFragments),
			totalFragments: h.TotalFragments,
			originalType:   originalType,
			timestamp:      time.Now().UTC(),
		}
		m.groups[h.MessageID] = g
	}
	if h.TotalFragments != g.totalFragments {
		return nil, errors.New("fragment count mismatch")
	}
	if h.FragmentIndex >= h.TotalFragments {
		return nil, errors.New("invalid fragment index")
	}
	g.fragments[h.FragmentIndex] = data

	if len(g.fragments) != int(g.totalFragments) {
		return nil, nil
	}
	// Reassemble in-order.
	total := 0
	for i := uint16(0); i < g.totalFragments; i++ {
		f, ok := g.fragments[i]
		if !ok {
			return nil, fmt.Errorf("missing fragment %d", i)
		}
		total += len(f)
	}
	out := make([]byte, 0, total)
	for i := uint16(0); i < g.totalFragments; i++ {
		out = append(out, g.fragments[i]...)
	}
	delete(m.groups, h.MessageID)
	return out, nil
}

func (m *FragmentManager) cleanupLocked() {
	cutoff := time.Now().UTC().Add(-fragmentTimeout)
	for id, g := range m.groups {
		if g.timestamp.Before(cutoff) {
			delete(m.groups, id)
		}
	}
}

// EncodeFragmentPayload emits a single fragment payload — the caller
// wraps it in a Packet with MessageType = FragmentStart/Continue/End.
// Layout: 8-byte fragment id + 2-byte index BE + 2-byte total BE +
// 1-byte original type + data.
func EncodeFragmentPayload(fragmentID [8]byte, index, total uint16, originalType byte, data []byte) []byte {
	out := make([]byte, 0, 13+len(data))
	out = append(out, fragmentID[:]...)
	out = binary.BigEndian.AppendUint16(out, index)
	out = binary.BigEndian.AppendUint16(out, total)
	out = append(out, originalType)
	out = append(out, data...)
	return out
}

// DecodeFragmentPayload parses the header off a fragment payload
// and returns the header + wrapped original message type + the raw
// fragment data (a slice into the input — copy before storing).
func DecodeFragmentPayload(data []byte) (FragmentHeader, byte, []byte, error) {
	if len(data) < 13 {
		return FragmentHeader{}, 0, nil, errors.New("fragment payload too small")
	}
	h := FragmentHeader{
		MessageID:      hex.EncodeToString(data[0:8]),
		FragmentIndex:  binary.BigEndian.Uint16(data[8:10]),
		TotalFragments: binary.BigEndian.Uint16(data[10:12]),
	}
	return h, data[12], data[13:], nil
}
