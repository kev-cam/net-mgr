package ble

import (
	"context"
	"testing"
)

func TestConstantsUUIDShape(t *testing.T) {
	// Both UUIDs are the canonical 36-char hyphenated form.
	for _, u := range []string{BitchatServiceUUID, BitchatCharacteristicUUID} {
		if len(u) != 36 {
			t.Errorf("UUID %q length: got %d want 36", u, len(u))
		}
		for _, pos := range []int{8, 13, 18, 23} {
			if u[pos] != '-' {
				t.Errorf("UUID %q char %d: got %c want -", u, pos, u[pos])
			}
		}
	}
}

func TestStubServiceReportsUnavailable(t *testing.T) {
	s := NewNoop()
	if err := s.Start(context.Background(), [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, "test"); err == nil {
		t.Errorf("stub Start should error")
	}
	if err := s.Send([8]byte{}, []byte("x")); err == nil {
		t.Errorf("stub Send should error")
	}
	s.Broadcast([]byte("x")) // no-op
	// Events channel should be closed / drainable without blocking.
	select {
	case _, ok := <-s.Events():
		if ok {
			t.Errorf("stub should return closed events channel")
		}
	default:
	}
	if err := s.Close(); err != nil {
		t.Errorf("stub Close: %v", err)
	}
}

func TestEventTypesAreDistinct(t *testing.T) {
	// Sum-type discipline: the four event types are Events and
	// nothing else can be. Compile-time via method dispatch.
	var _ Event = PeerFound{}
	var _ Event = PeerLost{}
	var _ Event = DataReceived{}
	var _ Event = AdapterStateChanged{}
}
