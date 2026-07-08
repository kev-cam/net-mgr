package model

import "time"

// Peer tracks the state we know about a remote BitChat participant.
// Zero-value is invalid — build via NewPeer.
type Peer struct {
	ID              string
	Nickname        string
	Fingerprint     string
	LastSeen        time.Time
	IsConnected     bool
	IsFavorite      bool
	StaticPublicKey []byte // 32-byte curve25519 once known
}

// NewPeer initialises with LastSeen=now.
func NewPeer(id string) *Peer {
	return &Peer{ID: id, LastSeen: time.Now().UTC()}
}

// DisplayName returns the nickname when set, otherwise the peer id.
func (p *Peer) DisplayName() string {
	if p.Nickname != "" {
		return p.Nickname
	}
	return p.ID
}

// Touch bumps LastSeen to now.
func (p *Peer) Touch() { p.LastSeen = time.Now().UTC() }
