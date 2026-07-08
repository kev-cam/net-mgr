package mesh

import (
	"bytes"
	"testing"
	"time"
)

func TestFragmentEncodeDecodeRoundTrip(t *testing.T) {
	id := [8]byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33}
	payload := EncodeFragmentPayload(id, 3, 7, 0x02, []byte("chunk data"))
	h, ot, data, err := DecodeFragmentPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	if h.FragmentIndex != 3 || h.TotalFragments != 7 {
		t.Errorf("indices: got %d/%d want 3/7", h.FragmentIndex, h.TotalFragments)
	}
	if ot != 0x02 {
		t.Errorf("original_type: got 0x%02x want 0x02", ot)
	}
	if !bytes.Equal(data, []byte("chunk data")) {
		t.Errorf("data: got %q", data)
	}
	if h.MessageID != "deadbeef00112233" {
		t.Errorf("message id: got %q want deadbeef00112233", h.MessageID)
	}
}

func TestFragmentManagerReassemble(t *testing.T) {
	fm := NewFragmentManager()
	body := []byte("the quick brown fox jumps over the lazy dog")
	msgID := "0102030405060708"

	// Slice into 3 fragments manually for the test.
	chunks := [][]byte{body[:15], body[15:30], body[30:]}

	// Feed out of order — 2, 0, 1.
	for _, i := range []uint16{2, 0, 1} {
		full, err := fm.AddFragment(
			FragmentHeader{MessageID: msgID, FragmentIndex: i, TotalFragments: 3},
			0x02, chunks[i],
		)
		if err != nil {
			t.Fatal(err)
		}
		if i != 1 && full != nil {
			t.Errorf("premature completion on frag %d", i)
		}
		if i == 1 { // last fragment fed
			if full == nil {
				t.Fatalf("expected reassembled payload after all 3 fragments")
			}
			if !bytes.Equal(full, body) {
				t.Errorf("reassembled: got %q want %q", full, body)
			}
		}
	}
}

func TestFragmentManagerMismatchedTotal(t *testing.T) {
	fm := NewFragmentManager()
	if _, err := fm.AddFragment(
		FragmentHeader{MessageID: "abcd", FragmentIndex: 0, TotalFragments: 2}, 0x02, []byte("a"),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := fm.AddFragment(
		FragmentHeader{MessageID: "abcd", FragmentIndex: 1, TotalFragments: 3}, 0x02, []byte("b"),
	); err == nil {
		t.Errorf("expected total-mismatch error, got nil")
	}
}

func TestPeerManagerBasics(t *testing.T) {
	pm := NewPeerManager()
	pm.AddPeer("aa11bb22cc33dd44")
	if !pm.Exists("aa11bb22cc33dd44") {
		t.Errorf("Exists after AddPeer: false")
	}
	pm.SetNickname("aa11bb22cc33dd44", "alice")
	pm.SetConnected("aa11bb22cc33dd44", true)
	if got := pm.GetByNickname("alice"); got == nil || got.ID != "aa11bb22cc33dd44" {
		t.Errorf("GetByNickname: %+v", got)
	}
	// "nickname (aa:11:bb)" form.
	if got := pm.GetByNickname("alice (aa:11:bb)"); got == nil || got.ID != "aa11bb22cc33dd44" {
		t.Errorf("GetByNickname with suffix: %+v", got)
	}
	nns := pm.ConnectedNicknames()
	if len(nns) != 1 || nns[0] != "alice (aa:11:bb)" {
		t.Errorf("ConnectedNicknames: %v", nns)
	}
}

func TestPeerManagerFingerprint(t *testing.T) {
	pm := NewPeerManager()
	pm.AddPeer("peer-x")
	pubkey := []byte{0, 1, 2, 3}
	pm.SetStaticKey("peer-x", pubkey)
	p := pm.Get("peer-x")
	if p == nil || p.Fingerprint == "" || len(p.StaticPublicKey) != 4 {
		t.Errorf("fingerprint / key not stored: %+v", p)
	}
}

func TestPeerManagerCleanupStale(t *testing.T) {
	pm := NewPeerManager()
	pm.AddPeer("stale")
	pm.SetConnected("stale", true)
	pm.SetNickname("stale", "old-one")
	// Force old last-seen.
	p := pm.Get("stale")
	p.LastSeen = time.Now().UTC().Add(-time.Hour)
	// Restore into the map (Get returned a copy) by overwriting.
	pm.mu.Lock()
	pm.peers["stale"].LastSeen = time.Now().UTC().Add(-time.Hour)
	pm.mu.Unlock()

	removed := pm.CleanupStale(30 * time.Second)
	if len(removed) != 1 || removed[0] != "stale" {
		t.Errorf("CleanupStale: %v", removed)
	}
	if pm.Get("stale").IsConnected {
		t.Errorf("still connected after CleanupStale")
	}
}
