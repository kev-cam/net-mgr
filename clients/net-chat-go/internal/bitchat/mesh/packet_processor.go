package mesh

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/kev-cam/net-chat-go/internal/bitchat/crypto"
	"github.com/kev-cam/net-chat-go/internal/bitchat/model"
	"github.com/kev-cam/net-chat-go/internal/bitchat/protocol"
)

// dedupeCap caps the seen-packet-hash set to bound memory. The Rust
// side uses a bloom filter tuned for ~10k entries; we approximate
// with a bounded LRU-ish set (FIFO eviction once past the cap).
const dedupeCap = 10000

// PacketProcessor is the mesh dispatcher — it consumes framed Packets
// from the BLE driver, dedupes, hands off to type-specific handlers,
// and surfaces app-level events via the Delegate. Lean port of
// packet_processor.rs: relay logic, delivery-ack, and channel_* are
// deferred; the client-side subset is what a phone actually needs.
type PacketProcessor struct {
	delegate  Delegate
	peers     *PeerManager
	fragments *FragmentManager
	sessions  *crypto.SessionSet

	mu       sync.Mutex
	seen     map[string]struct{}
	seenList []string // FIFO for eviction

	announces map[string]time.Time // peer_id -> last-seen announce
}

// NewPacketProcessor wires a processor to its collaborators.
func NewPacketProcessor(delegate Delegate, peers *PeerManager,
	fragments *FragmentManager, sessions *crypto.SessionSet) *PacketProcessor {
	return &PacketProcessor{
		delegate:  delegate,
		peers:     peers,
		fragments: fragments,
		sessions:  sessions,
		seen:      make(map[string]struct{}),
		announces: make(map[string]time.Time),
	}
}

// Process consumes one inbound packet. fromAddr is the BLE peer
// address (or any transport-level identifier) — surfaced to the
// delegate but not required for dispatch.
func (p *PacketProcessor) Process(pkt *protocol.Packet, fromAddr string) error {
	if pkt == nil {
		return errors.New("nil packet")
	}
	if p.isDuplicate(pkt) {
		return nil
	}
	p.markSeen(pkt)

	// Ignore anything we ourselves sent that bounced back off a
	// relay. LocalPeerID is stable, so string compare is enough.
	if pkt.SenderIDHex() == p.delegate.LocalPeerID() {
		return nil
	}

	switch pkt.MessageType {
	case protocol.MTAnnounce:
		return p.handleAnnounce(pkt, fromAddr)
	case protocol.MTMessage:
		return p.handleMessage(pkt)
	case protocol.MTLeave:
		return p.handleLeave(pkt)
	case protocol.MTNoiseHandshakeInit:
		p.delegate.OnHandshakeInit(pkt.SenderIDHex(), pkt)
		return nil
	case protocol.MTNoiseHandshakeResp, protocol.MTNoiseHandshakeFinal:
		p.delegate.OnHandshakeResponse(pkt.SenderIDHex(), pkt)
		return nil
	case protocol.MTNoiseEncrypted:
		return p.handleNoiseEncrypted(pkt)
	case protocol.MTNoiseIdentityAnnounce:
		return p.handleIdentityAnnounce(pkt)
	case protocol.MTFragmentStart,
		protocol.MTFragmentContinue,
		protocol.MTFragmentEnd:
		return p.handleFragment(pkt, fromAddr)
	}
	// Any other MT the phone client doesn't care about (channel_*,
	// delivery_ack, favorited, version_hello) is a silent no-op.
	return nil
}

// isDuplicate reports whether we've already seen this packet by
// hashing its wire form. Uses a SHA-256 of the encoded bytes — same
// stability guarantee as an id would give without adding a field.
func (p *PacketProcessor) isDuplicate(pkt *protocol.Packet) bool {
	key := packetKey(pkt)
	p.mu.Lock()
	_, seen := p.seen[key]
	p.mu.Unlock()
	return seen
}

func (p *PacketProcessor) markSeen(pkt *protocol.Packet) {
	key := packetKey(pkt)
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, seen := p.seen[key]; seen {
		return
	}
	p.seen[key] = struct{}{}
	p.seenList = append(p.seenList, key)
	// FIFO eviction once past the cap.
	if len(p.seenList) > dedupeCap {
		drop := p.seenList[0]
		p.seenList = p.seenList[1:]
		delete(p.seen, drop)
	}
}

func packetKey(pkt *protocol.Packet) string {
	enc, err := protocol.Encode(pkt)
	if err != nil {
		return pkt.SenderIDHex() + "\x00" + string(pkt.Payload)
	}
	sum := sha256.Sum256(enc)
	return hex.EncodeToString(sum[:])
}

// extractAnnounceNickname parses the TLV Announce payload for the
// nickname field (0x01), falling back to a bare UTF-8 nickname for
// pre-TLV senders. Straight port of the Rust top-level helper.
func extractAnnounceNickname(payload []byte) string {
	if len(payload) == 0 {
		return ""
	}
	// TLV fast path: field IDs 0x01..0x04.
	if payload[0] >= 0x01 && payload[0] <= 0x04 {
		i := 0
		for i+2 <= len(payload) {
			ftype := payload[i]
			flen := int(payload[i+1])
			start := i + 2
			end := start + flen
			if end > len(payload) {
				break
			}
			if ftype == 0x01 {
				s := string(payload[start:end])
				s = strings.TrimSpace(s)
				return s
			}
			i = end
		}
	}
	// Fallback: bare-nickname sender.
	return strings.TrimSpace(string(payload))
}

// handleAnnounce parses nickname off the payload, marks the peer
// connected, and notifies the delegate on the connect edge. Rate
// duplicates by peer_id so a talkative peer doesn't spam the UI.
func (p *PacketProcessor) handleAnnounce(pkt *protocol.Packet, fromAddr string) error {
	peerID := pkt.SenderIDHex()
	nick := extractAnnounceNickname(pkt.Payload)

	p.peers.AddPeer(peerID)
	if nick != "" {
		p.peers.SetNickname(peerID, nick)
	}
	// Announce debounce: 5 s per peer.
	p.mu.Lock()
	last, ok := p.announces[peerID]
	fresh := !ok || time.Since(last) > 5*time.Second
	if fresh {
		p.announces[peerID] = time.Now().UTC()
	}
	p.mu.Unlock()

	if fresh {
		existing := p.peers.Get(peerID)
		wasConnected := existing != nil && existing.IsConnected
		p.peers.SetConnected(peerID, true)
		if !wasConnected {
			p.delegate.OnPeerConnected(peerID)
		}
	}
	_ = fromAddr
	return nil
}

// handleMessage decodes the BitchatMessage body and delivers.
func (p *PacketProcessor) handleMessage(pkt *protocol.Packet) error {
	m, err := model.FromBinaryPayload(pkt.Payload)
	if err != nil {
		return err
	}
	if m.SenderPeerID == "" {
		m.SenderPeerID = pkt.SenderIDHex()
	}
	p.delegate.OnMessage(m)
	return nil
}

// handleLeave marks the peer disconnected and notifies.
func (p *PacketProcessor) handleLeave(pkt *protocol.Packet) error {
	peerID := pkt.SenderIDHex()
	existing := p.peers.Get(peerID)
	wasConnected := existing != nil && existing.IsConnected
	p.peers.SetConnected(peerID, false)
	if wasConnected {
		p.delegate.OnPeerDisconnected(peerID)
	}
	return nil
}

// handleNoiseEncrypted opens the ciphertext via the peer's session
// and, on success, RE-DISPATCHES the inner Packet — so a MTMessage
// inside a MTNoiseEncrypted still flows through OnMessage.
func (p *PacketProcessor) handleNoiseEncrypted(pkt *protocol.Packet) error {
	peerID := pkt.SenderIDHex()
	sess := p.sessions.Get(peerID)
	if sess == nil || !sess.Established() {
		return errors.New("no established session for " + peerID)
	}
	pt, err := sess.Decrypt(pkt.Payload)
	if err != nil {
		return err
	}
	inner, err := protocol.Decode(pt)
	if err != nil {
		return err
	}
	// Deliver the inner via the raw callback for callers that want
	// pre-dispatch access (e.g. persistence), then also re-process
	// via the normal path so OnMessage etc. fire.
	p.delegate.OnEncryptedInner(peerID, inner)
	return p.Process(inner, "encrypted")
}

// handleIdentityAnnounce parses the payload as an IdentityAnnouncement,
// registers the static key with the peer manager, and notifies.
func (p *PacketProcessor) handleIdentityAnnounce(pkt *protocol.Packet) error {
	ann, err := protocol.DecodeIdentityAnnouncement(pkt.Payload)
	if err != nil {
		return err
	}
	peerID := ann.PeerID
	if peerID == "" {
		peerID = pkt.SenderIDHex()
	}
	p.peers.AddPeer(peerID)
	if ann.Nickname != "" {
		p.peers.SetNickname(peerID, ann.Nickname)
	}
	if len(ann.PublicKey) == 32 {
		p.peers.SetStaticKey(peerID, ann.PublicKey)
	}
	p.delegate.OnIdentityAnnounce(peerID, ann)
	return nil
}

// handleFragment feeds the FragmentManager and, on completion,
// decodes and re-processes the reassembled packet.
func (p *PacketProcessor) handleFragment(pkt *protocol.Packet, fromAddr string) error {
	h, origType, body, err := DecodeFragmentPayload(pkt.Payload)
	if err != nil {
		return err
	}
	full, err := p.fragments.AddFragment(h, origType, body)
	if err != nil {
		return err
	}
	if full == nil {
		return nil
	}
	inner, err := protocol.Decode(full)
	if err != nil {
		return err
	}
	return p.Process(inner, fromAddr)
}
