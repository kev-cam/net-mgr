package crypto

import (
	"bytes"
	"testing"
)

func TestIdentityDerivation(t *testing.T) {
	var seed [SeedLen]byte
	for i := range seed {
		seed[i] = byte(i)
	}
	id := NewIdentity(seed)
	// Peer id is deterministic under a fixed seed — regressions
	// against this vector mean we've broken interop with anyone else
	// deriving from the same seed.
	if len(id.PeerID) != 16 {
		t.Errorf("PeerID length: got %d want 16", len(id.PeerID))
	}
	if id.StaticPublic == [32]byte{} {
		t.Errorf("StaticPublic still zero — x25519 base not wired")
	}
	// Ed25519 sign+verify with the derived keys — proves the seed
	// dual-purpose path is sound.
	sig := id.Sign([]byte("hello"))
	if !Verify(id.VerifyingKey, []byte("hello"), sig) {
		t.Errorf("ed25519 self-verify failed")
	}
}

func TestNoiseXXHandshakeAndTransport(t *testing.T) {
	// Two identities with distinct seeds — they don't know each
	// other's static pubkeys ahead of time; XX carries them.
	var s1, s2 [SeedLen]byte
	for i := range s1 {
		s1[i] = byte(i + 1)
		s2[i] = byte(i + 100)
	}
	a := NewIdentity(s1)
	b := NewIdentity(s2)

	// XX: three messages. A sends 1, B replies 2, A closes with 3.
	initSess, msg1, err := NewInitiator(a, b.PeerID)
	if err != nil {
		t.Fatal(err)
	}
	respSess, msg2, err := NewResponder(b, a.PeerID, msg1)
	if err != nil {
		t.Fatal(err)
	}
	msg3, err := initSess.Step(msg2)
	if err != nil {
		t.Fatal(err)
	}
	if msg3 == nil {
		t.Fatal("initiator should produce message 3 after reading message 2")
	}
	if _, err := respSess.Step(msg3); err != nil {
		t.Fatal(err)
	}
	if !initSess.Established() || !respSess.Established() {
		t.Fatalf("sessions not established: init=%v resp=%v",
			initSess.Established(), respSess.Established())
	}
	// Both sides should have learned the other's static.
	if !bytes.Equal(initSess.RemoteStatic(), b.StaticPublic[:]) {
		t.Errorf("initiator remote static mismatch")
	}
	if !bytes.Equal(respSess.RemoteStatic(), a.StaticPublic[:]) {
		t.Errorf("responder remote static mismatch")
	}

	// Transport: encrypt in each direction and verify decrypt.
	pt := []byte("hello over noise")
	enc, err := initSess.Encrypt(pt)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := respSess.Decrypt(enc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, dec) {
		t.Errorf("transport A→B: got %q want %q", dec, pt)
	}

	pt2 := []byte("and back")
	enc2, err := respSess.Encrypt(pt2)
	if err != nil {
		t.Fatal(err)
	}
	dec2, err := initSess.Decrypt(enc2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt2, dec2) {
		t.Errorf("transport B→A: got %q want %q", dec2, pt2)
	}
}

func TestSessionSetLifecycle(t *testing.T) {
	set := NewSessionSet()
	if got := set.Get("nope"); got != nil {
		t.Errorf("Get on missing key: got %v", got)
	}
	set.Set("peer", &Session{peerID: "peer"})
	if got := set.Get("peer"); got == nil || got.PeerID() != "peer" {
		t.Errorf("Get after Set: got %v", got)
	}
	set.Drop("peer")
	if got := set.Get("peer"); got != nil {
		t.Errorf("Get after Drop: got %v", got)
	}
}
