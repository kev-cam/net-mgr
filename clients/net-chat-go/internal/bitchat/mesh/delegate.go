package mesh

import (
	"github.com/kev-cam/net-chat-go/internal/bitchat/model"
	"github.com/kev-cam/net-chat-go/internal/bitchat/protocol"
)

// Delegate is the callback surface the caller implements to hook into
// mesh events. Reduced from bitchat-rust's BluetoothMeshDelegate to
// the subset an edge client needs — channel management, delivery
// receipts, and version negotiation are deferred to a follow-up.
//
// All methods MAY be called from a goroutine other than the caller
// that fed the inbound packet. Implementations must be thread-safe.
type Delegate interface {
	// OnMessage fires for each successfully-decoded MTMessage.
	OnMessage(m *model.Message)

	// OnPeerConnected / OnPeerDisconnected reflect peer roster
	// changes discovered from Announce / Leave frames.
	OnPeerConnected(peerID string)
	OnPeerDisconnected(peerID string)

	// OnHandshakeInit / OnHandshakeResponse hand the raw packet
	// back to the caller so it can drive the crypto.Session state
	// machine (NewResponder / Session.Step).
	OnHandshakeInit(peerID string, packet *protocol.Packet)
	OnHandshakeResponse(peerID string, packet *protocol.Packet)

	// OnIdentityAnnounce lets the caller bind peer_id ⇄ static key ⇄
	// nickname. The processor has already stamped the peer manager;
	// callers typically use this to persist "trust on first use"
	// records.
	OnIdentityAnnounce(peerID string, ann *protocol.IdentityAnnouncement)

	// OnEncryptedInner is fired after a NoiseEncrypted packet has
	// been decrypted and the inner packet re-processed — this is
	// the natural callback for private DMs.
	OnEncryptedInner(peerID string, inner *protocol.Packet)

	// LocalPeerID / LocalNickname let the processor tag outbound
	// packets and filter self-echoes. Should return stable values
	// for the lifetime of the processor.
	LocalPeerID() string
	LocalNickname() string
}
