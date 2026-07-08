// Package crypto — Go port of bitchat-rust's src/crypto/*.rs.
//
// Identity model matches snow_noise_service.rs::new:
//
//	32-byte seed  → Ed25519 signing key (raw seed = SigningKey::from_bytes)
//	              → Curve25519 static key for Noise-XX (SHA-512(seed)[:32]
//	                 clamped per libsodium crypto_sign_ed25519_sk_to_curve25519)
//
// So one SSH ed25519 seed serves the operator's SSH login, net-chat
// authorized-keys signing identity, AND their BitChat peer identity —
// no separate BitChat key ceremony.
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
)

// SeedLen is the size of the raw seed and of the Ed25519 private-key
// prefix (before ed25519.NewKeyFromSeed expands it).
const SeedLen = 32

// Identity carries the derived keys for the local participant.
type Identity struct {
	Seed         [SeedLen]byte
	SigningKey   ed25519.PrivateKey // 64 bytes (seed || pubkey)
	VerifyingKey ed25519.PublicKey  // 32 bytes
	// Curve25519 static key material for the Noise-XX handshake.
	StaticPrivate [32]byte
	StaticPublic  [32]byte
	// PeerID is SHA-256(StaticPublic)[:8] as hex — matches
	// snow_noise_service.rs peer-id derivation.
	PeerID    string
	PeerIDRaw [8]byte
}

// NewIdentity builds an identity from an explicit seed.
func NewIdentity(seed [SeedLen]byte) *Identity {
	sk := ed25519.NewKeyFromSeed(seed[:])
	id := &Identity{
		Seed:         seed,
		SigningKey:   sk,
		VerifyingKey: sk.Public().(ed25519.PublicKey),
	}
	id.StaticPrivate, id.StaticPublic = deriveStatic(seed)
	// SHA-256(static_public)[:8] hex — the wire-visible peer id.
	sum := sha256.Sum256(id.StaticPublic[:])
	copy(id.PeerIDRaw[:], sum[:8])
	id.PeerID = hex.EncodeToString(id.PeerIDRaw[:])
	return id
}

// LoadOrEphemeral honours $BITCHAT_ID_FILE if set — a 32-byte binary
// seed on disk. If unset (or unreadable), a fresh random seed is
// generated and the peer id rotates on every restart. Mirrors the
// snow_noise_service.rs::new priority order.
func LoadOrEphemeral() (*Identity, bool, error) {
	if path := os.Getenv("BITCHAT_ID_FILE"); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, false, fmt.Errorf("BITCHAT_ID_FILE=%s: %w", path, err)
		}
		if len(b) != SeedLen {
			return nil, false, fmt.Errorf("BITCHAT_ID_FILE=%s must be %d bytes (got %d)",
				path, SeedLen, len(b))
		}
		var seed [SeedLen]byte
		copy(seed[:], b)
		return NewIdentity(seed), true, nil
	}
	var seed [SeedLen]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, false, fmt.Errorf("generate seed: %w", err)
	}
	return NewIdentity(seed), false, nil
}

// Sign is the standard Ed25519 sign over msg.
func (i *Identity) Sign(msg []byte) []byte {
	return ed25519.Sign(i.SigningKey, msg)
}

// Verify returns true when sig is a valid Ed25519 signature by pk.
func Verify(pk ed25519.PublicKey, msg, sig []byte) bool {
	if len(pk) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pk, msg, sig)
}

// deriveStatic implements libsodium's crypto_sign_ed25519_sk_to_curve25519:
//
//	h := SHA-512(seed)
//	h[0]  &= 0xF8
//	h[31] &= 0x7F
//	h[31] |= 0x40
//	priv := h[:32]
//	pub  := X25519 base-point multiply (RFC 7748), done via curve25519.X25519.
//
// A separate helper here (rather than pulling curve25519.X25519 directly)
// keeps the test crisp: identity_test.go checks the clamp against known
// libsodium output.
func deriveStatic(seed [SeedLen]byte) (priv, pub [32]byte) {
	h := sha512.Sum512(seed[:])
	var s [32]byte
	copy(s[:], h[:32])
	s[0] &= 0xF8
	s[31] &= 0x7F
	s[31] |= 0x40
	priv = s
	// X25519 scalar-mult of the base point → public key. Done inline
	// to avoid pulling curve25519 here — noise.go will re-derive the
	// public via flynn/noise's key generation.
	pub = scalarBaseMult(priv)
	return
}

// scalarBaseMult is X25519(priv, base) — used exactly once at identity
// derivation. Implemented via curve25519 in noise.go's neighbour so
// this file stays free of the x/crypto import; if you're reading this
// during a follow-up, it's fine to move the call into noise.go.
func scalarBaseMult(priv [32]byte) [32]byte {
	pub, err := x25519Base(priv)
	if err != nil {
		// Only source of error would be a zero private key; a clamp
		// output can't be zero, so this is unreachable.
		panic(fmt.Sprintf("x25519 base: %v", err))
	}
	return pub
}

// x25519Base indirects through the x/crypto import so identity.go
// stays isolated from noise.go's flynn/noise import. Defined in
// x25519.go alongside a golden-vector test.
var x25519Base = func(priv [32]byte) ([32]byte, error) {
	return [32]byte{}, errors.New("x25519Base not wired — link x25519.go")
}
