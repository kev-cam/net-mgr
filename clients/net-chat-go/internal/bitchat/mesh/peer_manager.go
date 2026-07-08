package mesh

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/kev-cam/net-chat-go/internal/bitchat/model"
)

// PeerManager tracks the peers this node has seen plus a
// nickname→peer_id reverse map, matching peer_manager.rs semantics.
// Coarse-locked (single RWMutex) — matches Rust's Arc<RwLock<...>>.
type PeerManager struct {
	mu        sync.RWMutex
	peers     map[string]*model.Peer
	nicknames map[string]string // nickname -> peer_id
}

// NewPeerManager returns an empty manager.
func NewPeerManager() *PeerManager {
	return &PeerManager{
		peers:     make(map[string]*model.Peer),
		nicknames: make(map[string]string),
	}
}

// AddPeer creates or refreshes an entry for peer_id.
func (m *PeerManager) AddPeer(peerID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.peers[peerID]
	if !ok {
		p = model.NewPeer(peerID)
		m.peers[peerID] = p
	}
	p.Touch()
}

// RemovePeer drops the peer and any nickname mapping.
func (m *PeerManager) RemovePeer(peerID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.peers[peerID]; ok {
		if p.Nickname != "" {
			delete(m.nicknames, p.Nickname)
		}
		delete(m.peers, peerID)
	}
}

// SetConnected updates the connected flag, touching last-seen when
// flipping to true.
func (m *PeerManager) SetConnected(peerID string, connected bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.peers[peerID]; ok {
		p.IsConnected = connected
		if connected {
			p.Touch()
		}
	}
}

// SetNickname assigns / replaces the nickname for peer_id.
func (m *PeerManager) SetNickname(peerID, nickname string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.peers[peerID]
	if !ok {
		return
	}
	if p.Nickname != "" {
		delete(m.nicknames, p.Nickname)
	}
	p.Nickname = nickname
	m.nicknames[nickname] = peerID
}

// SetStaticKey stamps the curve25519 static pubkey and derives a
// SHA-256 fingerprint. Fingerprint is used by the UI's trust view.
func (m *PeerManager) SetStaticKey(peerID string, pubkey []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.peers[peerID]
	if !ok {
		return
	}
	sum := sha256.Sum256(pubkey)
	p.StaticPublicKey = append([]byte(nil), pubkey...)
	p.Fingerprint = hex.EncodeToString(sum[:])
}

// Get returns a copy of the peer entry, or nil.
func (m *PeerManager) Get(peerID string) *model.Peer {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.peers[peerID]
	if !ok {
		return nil
	}
	c := *p
	return &c
}

// GetByNickname supports both "nickname" and "nickname (ID:ID:ID)"
// input forms — the paren suffix is what get_connected_peer_nicknames
// emits for display, so operators paste it back verbatim.
func (m *PeerManager) GetByNickname(nickname string) *model.Peer {
	clean := nickname
	if idx := strings.Index(nickname, " ("); idx >= 0 {
		clean = nickname[:idx]
	}
	m.mu.RLock()
	pid, ok := m.nicknames[clean]
	m.mu.RUnlock()
	if !ok {
		return nil
	}
	return m.Get(pid)
}

// All returns a copy of every known peer.
func (m *PeerManager) All() []*model.Peer {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*model.Peer, 0, len(m.peers))
	for _, p := range m.peers {
		c := *p
		out = append(out, &c)
	}
	return out
}

// Connected returns just the connected peers.
func (m *PeerManager) Connected() []*model.Peer {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*model.Peer, 0)
	for _, p := range m.peers {
		if p.IsConnected {
			c := *p
			out = append(out, &c)
		}
	}
	return out
}

// ConnectedNicknames returns "nickname (ID:ID:ID)" display strings —
// matches get_connected_peer_nicknames.
func (m *PeerManager) ConnectedNicknames() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, 0)
	for _, p := range m.peers {
		if !p.IsConnected {
			continue
		}
		nick := p.Nickname
		if nick == "" {
			// peer_<first 8 chars>
			suffix := p.ID
			if len(suffix) > 8 {
				suffix = suffix[:8]
			}
			nick = "peer_" + suffix
		}
		display := shortIDDisplay(p.ID)
		out = append(out, fmt.Sprintf("%s (%s)", nick, display))
	}
	return out
}

// shortIDDisplay formats the first 6 hex chars as A:B:C — matches Rust.
func shortIDDisplay(id string) string {
	if len(id) < 6 {
		if len(id) > 6 {
			return id[:6]
		}
		return id
	}
	return id[0:2] + ":" + id[2:4] + ":" + id[4:6]
}

// SetFavorite marks/unmarks a peer as a favourite.
func (m *PeerManager) SetFavorite(peerID string, fav bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.peers[peerID]; ok {
		p.IsFavorite = fav
	}
}

// Exists reports whether peer_id is tracked.
func (m *PeerManager) Exists(peerID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.peers[peerID]
	return ok
}

// Count returns the number of tracked peers.
func (m *PeerManager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.peers)
}

// Touch bumps the last-seen timestamp.
func (m *PeerManager) Touch(peerID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.peers[peerID]; ok {
		p.Touch()
	}
}

// CleanupStale marks connected peers whose last-seen is older than
// timeout as disconnected, drops their nickname mapping, and returns
// the affected peer_ids so the caller can notify the UI.
func (m *PeerManager) CleanupStale(timeout time.Duration) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	cutoff := time.Now().UTC().Add(-timeout)
	var removed []string
	for pid, p := range m.peers {
		if !p.IsConnected || !p.LastSeen.Before(cutoff) {
			continue
		}
		p.IsConnected = false
		if p.Nickname != "" {
			delete(m.nicknames, p.Nickname)
		}
		removed = append(removed, pid)
	}
	return removed
}
