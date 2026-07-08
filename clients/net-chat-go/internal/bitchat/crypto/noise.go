package crypto

import (
	"errors"
	"fmt"
	"sync"

	"github.com/flynn/noise"
)

// noisePattern is the string form of the bitchat handshake:
// XX / Curve25519 / ChaCha20-Poly1305 / SHA-256. Byte-for-byte
// matches snow's parse target NOISE_PATTERN in snow_noise_service.rs.
var noisePattern = noise.NewCipherSuite(
	noise.DH25519,
	noise.CipherChaChaPoly,
	noise.HashSHA256,
)

// Session holds per-peer Noise state. Zero-value is invalid — build
// via NewInitiator or NewResponder. Concurrent use MUST hold
// SessionSet.mu (or a per-session mutex if the caller wraps).
type Session struct {
	peerID      string
	initiator   bool
	handshake   *noise.HandshakeState
	send        *noise.CipherState
	recv        *noise.CipherState
	remoteStatic []byte // 32-byte curve25519 pubkey once known
	done        bool
}

// PeerID is the wire-visible identifier of the remote endpoint.
func (s *Session) PeerID() string { return s.peerID }

// Established reports whether the handshake has produced transport
// cipherstates.
func (s *Session) Established() bool { return s.done }

// RemoteStatic returns the remote's curve25519 static public key
// once the handshake has revealed it (after XX step 2 for the
// initiator, step 3 for the responder). Empty until then.
func (s *Session) RemoteStatic() []byte { return s.remoteStatic }

// NewInitiator sets up the local side to send the first XX message.
// Returns the session and the first outbound handshake payload — hand
// this to the peer as a NoiseHandshakeInit packet body.
func NewInitiator(id *Identity, peerID string) (*Session, []byte, error) {
	cfg := noise.Config{
		CipherSuite:   noisePattern,
		Pattern:       noise.HandshakeXX,
		Initiator:     true,
		StaticKeypair: noise.DHKey{Public: id.StaticPublic[:], Private: id.StaticPrivate[:]},
	}
	hs, err := noise.NewHandshakeState(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("noise init: %w", err)
	}
	// XX message 1: -> e. No payload from us.
	out, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("noise write msg1: %w", err)
	}
	return &Session{peerID: peerID, initiator: true, handshake: hs}, out, nil
}

// NewResponder consumes the initiator's first message and produces
// message 2. The returned session is not yet Established — one more
// round from the initiator finishes it.
func NewResponder(id *Identity, peerID string, initFrame []byte) (*Session, []byte, error) {
	cfg := noise.Config{
		CipherSuite:   noisePattern,
		Pattern:       noise.HandshakeXX,
		Initiator:     false,
		StaticKeypair: noise.DHKey{Public: id.StaticPublic[:], Private: id.StaticPrivate[:]},
	}
	hs, err := noise.NewHandshakeState(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("noise resp: %w", err)
	}
	if _, _, _, err := hs.ReadMessage(nil, initFrame); err != nil {
		return nil, nil, fmt.Errorf("noise read msg1: %w", err)
	}
	// XX message 2: <- e, ee, s, es
	out, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("noise write msg2: %w", err)
	}
	return &Session{peerID: peerID, initiator: false, handshake: hs}, out, nil
}

// Step consumes an inbound handshake frame and (when applicable)
// produces the next outbound one. Once the handshake completes it
// promotes the internal state to transport ciphers; Established
// starts returning true and Encrypt/Decrypt become available. The
// returned outFrame is nil once the handshake is done.
func (s *Session) Step(inFrame []byte) (outFrame []byte, err error) {
	if s.done {
		return nil, errors.New("session already established")
	}
	if s.handshake == nil {
		return nil, errors.New("no handshake state")
	}
	if _, cs0, cs1, err := s.handshake.ReadMessage(nil, inFrame); err != nil {
		return nil, fmt.Errorf("noise step read: %w", err)
	} else if cs0 != nil && cs1 != nil {
		s.finish(cs0, cs1)
		return nil, nil
	}
	// Not done yet — write our next outbound frame.
	out, cs0, cs1, err := s.handshake.WriteMessage(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("noise step write: %w", err)
	}
	if cs0 != nil && cs1 != nil {
		s.finish(cs0, cs1)
	}
	return out, nil
}

func (s *Session) finish(cs0, cs1 *noise.CipherState) {
	if s.initiator {
		s.send, s.recv = cs0, cs1
	} else {
		s.send, s.recv = cs1, cs0
	}
	s.remoteStatic = append([]byte(nil), s.handshake.PeerStatic()...)
	s.handshake = nil
	s.done = true
}

// Encrypt seals plaintext with our transport cipherstate.
func (s *Session) Encrypt(plaintext []byte) ([]byte, error) {
	if !s.done {
		return nil, errors.New("session not established")
	}
	return s.send.Encrypt(nil, nil, plaintext)
}

// Decrypt opens ciphertext with our transport cipherstate.
func (s *Session) Decrypt(ciphertext []byte) ([]byte, error) {
	if !s.done {
		return nil, errors.New("session not established")
	}
	return s.recv.Decrypt(nil, nil, ciphertext)
}

// SessionSet is a small thread-safe map of peer_id -> Session, matching
// the coarse locking the Rust side uses (Arc<RwLock<HashMap<...>>>).
type SessionSet struct {
	mu sync.RWMutex
	m  map[string]*Session
}

// NewSessionSet returns an empty set.
func NewSessionSet() *SessionSet { return &SessionSet{m: make(map[string]*Session)} }

// Set inserts or replaces a session for peer_id.
func (s *SessionSet) Set(peerID string, sess *Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[peerID] = sess
}

// Get returns the session for peer_id or nil.
func (s *SessionSet) Get(peerID string) *Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.m[peerID]
}

// Drop removes any session for peer_id — used when a peer disconnects
// or the handshake is torn down.
func (s *SessionSet) Drop(peerID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, peerID)
}
