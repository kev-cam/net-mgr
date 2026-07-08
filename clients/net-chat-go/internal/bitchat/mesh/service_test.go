package mesh

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/kev-cam/net-chat-go/internal/ble"
	"github.com/kev-cam/net-chat-go/internal/bitchat/crypto"
	"github.com/kev-cam/net-chat-go/internal/bitchat/model"
)

// fakeBLE simulates two Services connected by a bidirectional pipe.
// Send / Broadcast on one delivers DataReceived to the other's
// Events channel; PeerFound events fire manually via advertisePresence.
type fakeBLE struct {
	name   string
	events chan ble.Event
	other  *fakeBLE // set after both are constructed

	mu     sync.Mutex
	closed bool
	localID [8]byte
}

func newFakePair() (*fakeBLE, *fakeBLE) {
	a := &fakeBLE{name: "a", events: make(chan ble.Event, 32)}
	b := &fakeBLE{name: "b", events: make(chan ble.Event, 32)}
	a.other = b
	b.other = a
	return a, b
}

func (f *fakeBLE) Start(_ context.Context, id [8]byte, _ string) error {
	f.mu.Lock()
	f.localID = id
	f.mu.Unlock()
	// Tell the other side we exist.
	go func() {
		time.Sleep(5 * time.Millisecond)
		f.other.pushEvent(ble.PeerFound{PeerID: id, Address: f.name})
	}()
	return nil
}

func (f *fakeBLE) Send(peer [8]byte, data []byte) error {
	if f.other == nil {
		return errors.New("no peer wired")
	}
	f.other.pushEvent(ble.DataReceived{PeerID: f.localID, Data: append([]byte(nil), data...)})
	_ = peer
	return nil
}

func (f *fakeBLE) Broadcast(data []byte) {
	if f.other == nil {
		return
	}
	f.other.pushEvent(ble.DataReceived{PeerID: f.localID, Data: append([]byte(nil), data...)})
}

func (f *fakeBLE) Events() <-chan ble.Event { return f.events }

func (f *fakeBLE) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.closed {
		close(f.events)
		f.closed = true
	}
	return nil
}

func (f *fakeBLE) pushEvent(e ble.Event) {
	f.mu.Lock()
	closed := f.closed
	f.mu.Unlock()
	if closed {
		return
	}
	select {
	case f.events <- e:
	default:
	}
}

func makeSeed(byte0 byte) [crypto.SeedLen]byte {
	var s [crypto.SeedLen]byte
	for i := range s {
		s[i] = byte0 + byte(i)
	}
	return s
}

func waitForAppEvent[T AppEvent](t *testing.T, ch <-chan AppEvent, timeout time.Duration, pred func(T) bool) T {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case ev := <-ch:
			if got, ok := ev.(T); ok && pred(got) {
				return got
			}
		case <-deadline:
			var zero T
			t.Fatalf("timeout waiting for AppEvent %T", zero)
			return zero
		}
	}
}

func TestServiceEndToEndAnnounceAndPublicMessage(t *testing.T) {
	// Two identities, two services, a fake BLE pair connecting them.
	fA, fB := newFakePair()
	idA := crypto.NewIdentity(makeSeed(1))
	idB := crypto.NewIdentity(makeSeed(50))
	svcA := NewService(idA, "alice", fA)
	svcB := NewService(idB, "bob", fB)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer svcA.Close()
	defer svcB.Close()

	if err := svcA.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := svcB.Start(ctx); err != nil {
		t.Fatal(err)
	}

	// Alice sends a public chat — Bob should surface it as AppMessage.
	if err := svcA.PostPublic("hello mesh"); err != nil {
		t.Fatal(err)
	}
	m := waitForAppEvent(t, svcB.Events(), 2*time.Second, func(e AppMessage) bool {
		return e.Message != nil && e.Message.Content == "hello mesh"
	})
	if m.Message.Sender != "alice" {
		t.Errorf("sender: got %q want alice", m.Message.Sender)
	}
	if m.FromID != idA.PeerID {
		t.Errorf("from id: got %q want %q", m.FromID, idA.PeerID)
	}
}

func TestServiceEndToEndHandshakeAndDM(t *testing.T) {
	fA, fB := newFakePair()
	idA := crypto.NewIdentity(makeSeed(1))
	idB := crypto.NewIdentity(makeSeed(50))
	svcA := NewService(idA, "alice", fA)
	svcB := NewService(idB, "bob", fB)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer svcA.Close()
	defer svcB.Close()

	if err := svcA.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := svcB.Start(ctx); err != nil {
		t.Fatal(err)
	}

	// Alice initiates a handshake to Bob. First allow the initial
	// Announce broadcasts to settle so any AppPeer events drain.
	time.Sleep(50 * time.Millisecond)

	if err := svcA.InitiateHandshake(idB.PeerID); err != nil {
		t.Fatal(err)
	}
	// The XX handshake needs 3 messages to complete — Bob replies
	// with msg2, Alice sends msg3, both sides transition to
	// Established. Wait for both sides to have an established
	// session. Do this by polling; realistic timing on a fake pipe
	// is <10ms but be generous.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		sA := svcA.sessions.Get(idB.PeerID)
		sB := svcB.sessions.Get(idA.PeerID)
		if sA != nil && sA.Established() && sB != nil && sB.Established() {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	sA := svcA.sessions.Get(idB.PeerID)
	sB := svcB.sessions.Get(idA.PeerID)
	if sA == nil || !sA.Established() || sB == nil || !sB.Established() {
		t.Fatalf("handshake didn't complete: A=%v B=%v",
			sA != nil && sA.Established(), sB != nil && sB.Established())
	}

	// Alice DMs Bob.
	if err := svcA.PostDM(idB.PeerID, "private hi"); err != nil {
		t.Fatal(err)
	}
	m := waitForAppEvent(t, svcB.Events(), 2*time.Second, func(e AppMessage) bool {
		return e.Message != nil && e.Message.Content == "private hi"
	})
	if !m.Message.IsPrivate {
		t.Errorf("IsPrivate: got %v want true", m.Message.IsPrivate)
	}
	if m.FromID != idA.PeerID {
		t.Errorf("from id: got %q", m.FromID)
	}
	// Also verify the round-trip preserves sender identity in the
	// underlying model.
	if m.Message.Sender != "alice" {
		t.Errorf("sender: got %q", m.Message.Sender)
	}
}

func TestServiceEndToEndDMWithoutSessionFails(t *testing.T) {
	fA, fB := newFakePair()
	idA := crypto.NewIdentity(makeSeed(1))
	idB := crypto.NewIdentity(makeSeed(50))
	svcA := NewService(idA, "alice", fA)
	svcB := NewService(idB, "bob", fB)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer svcA.Close()
	defer svcB.Close()

	_ = svcA.Start(ctx)
	_ = svcB.Start(ctx)
	// No InitiateHandshake — PostDM must fail cleanly.
	if err := svcA.PostDM(idB.PeerID, "should fail"); err == nil {
		t.Errorf("PostDM without session should error")
	}
	_ = model.Message{} // keep model import
}

func TestHexHelpersRoundTrip(t *testing.T) {
	in := [8]byte{0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89}
	s := hexEncode8(in)
	if s != "abcdef0123456789" {
		t.Errorf("hexEncode8: got %q", s)
	}
	out, err := hexDecode8(s)
	if err != nil || out != in {
		t.Errorf("hexDecode8 round-trip: got %v/%v", out, err)
	}
	if _, err := hexDecode8("nothex"); err == nil {
		t.Errorf("hexDecode8 of short input should error")
	}
}
