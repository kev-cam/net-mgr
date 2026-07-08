package mesh

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/kev-cam/net-chat-go/internal/ble"
	"github.com/kev-cam/net-chat-go/internal/bitchat/crypto"
	"github.com/kev-cam/net-chat-go/internal/bitchat/model"
	"github.com/kev-cam/net-chat-go/internal/bitchat/protocol"
)

// AnnounceInterval — how often we broadcast our Announce so peers
// know we're alive. Matches the fork's default cadence.
const AnnounceInterval = 30 * time.Second

// AppEvent is the app-facing sum type — the UI subscribes to this
// instead of raw BLE events. Reduces the surface the caller has to
// know about.
type AppEvent interface{ isAppEvent() }

// AppMessage — a decoded chat message arrived, either public or
// after DM decryption.
type AppMessage struct {
	Message *model.Message
	FromID  string // peer_id in hex
}

// AppPeer — the peer roster changed. `Peer` is nil on disconnect.
type AppPeer struct {
	PeerID     string
	Nickname   string
	Connected  bool
}

// AppAdapter — BLE adapter state changed (BT toggle, permission
// revoked, etc). Surfaced verbatim from ble.AdapterStateChanged so
// the UI can show "BT off" without decoding a nested type.
type AppAdapter struct {
	PoweredOn bool
	Reason    string
}

func (AppMessage) isAppEvent() {}
func (AppPeer) isAppEvent()    {}
func (AppAdapter) isAppEvent() {}

// Service is the top-level bitchat mesh — it owns the crypto identity,
// the peer state, the packet processor, and the BLE driver, and
// exposes a small app surface (Start, Broadcast, Events).
//
// Implements the Delegate contract itself, so the wiring stays tight:
// PacketProcessor → Service (delegate methods) → out on AppEvent
// channel and back through the BLE driver for handshake replies.
type Service struct {
	identity  *crypto.Identity
	nickname  string
	peers     *PeerManager
	sessions  *crypto.SessionSet
	fragments *FragmentManager
	processor *PacketProcessor
	ble       ble.Service

	mu     sync.Mutex
	events chan AppEvent
	cancel context.CancelFunc
	closed bool
}

// NewService wires all the collaborators. Caller supplies the BLE
// service (typically ble.New()) so tests can inject a fake.
func NewService(id *crypto.Identity, nickname string, bleSvc ble.Service) *Service {
	s := &Service{
		identity:  id,
		nickname:  nickname,
		peers:     NewPeerManager(),
		sessions:  crypto.NewSessionSet(),
		fragments: NewFragmentManager(),
		ble:       bleSvc,
		events:    make(chan AppEvent, 64),
	}
	s.processor = NewPacketProcessor(s, s.peers, s.fragments, s.sessions)
	return s
}

// Events is the channel of app-level events for the UI.
func (s *Service) Events() <-chan AppEvent { return s.events }

// Start powers up BLE and kicks off the reader + announce loops.
// Blocks until BLE.Start returns (adapter enable + scan kickoff).
func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.cancel != nil {
		s.mu.Unlock()
		return errors.New("mesh: already started")
	}
	ctx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.mu.Unlock()

	if err := s.ble.Start(ctx, s.identity.PeerIDRaw, s.nickname); err != nil {
		return fmt.Errorf("mesh: ble start: %w", err)
	}
	go s.readLoop(ctx)
	go s.announceLoop(ctx)
	return nil
}

// Close tears down the announce + read loops and the BLE stack.
// Safe to call multiple times.
func (s *Service) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	cancel := s.cancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	err := s.ble.Close()
	// Give loops a beat to exit before closing events so a late
	// pushEvent doesn't panic.
	time.Sleep(50 * time.Millisecond)
	close(s.events)
	return err
}

// readLoop drains ble.Events and translates them into
// PacketProcessor input.
func (s *Service) readLoop(ctx context.Context) {
	events := s.ble.Events()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			s.onBLEEvent(ev)
		}
	}
}

func (s *Service) onBLEEvent(ev ble.Event) {
	switch e := ev.(type) {
	case ble.PeerFound:
		pid := hexEncode8(e.PeerID)
		s.peers.AddPeer(pid)
		s.peers.SetConnected(pid, true)
		s.pushEvent(AppPeer{PeerID: pid, Connected: true})
	case ble.PeerLost:
		pid := hexEncode8(e.PeerID)
		s.peers.SetConnected(pid, false)
		s.pushEvent(AppPeer{PeerID: pid, Connected: false})
	case ble.DataReceived:
		pkt, err := protocol.Decode(e.Data)
		if err != nil {
			return
		}
		_ = s.processor.Process(pkt, hexEncode8(e.PeerID))
	case ble.AdapterStateChanged:
		s.pushEvent(AppAdapter{PoweredOn: e.PoweredOn, Reason: e.Reason})
	}
}

// announceLoop periodically broadcasts a fresh Announce so peers
// discover / re-anchor us. First fire is immediate.
func (s *Service) announceLoop(ctx context.Context) {
	t := time.NewTicker(AnnounceInterval)
	defer t.Stop()
	s.sendAnnounce()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.sendAnnounce()
		}
	}
}

// sendAnnounce builds an Announce packet (TLV nickname payload) and
// broadcasts it over BLE.
func (s *Service) sendAnnounce() {
	nickBytes := []byte(s.nickname)
	if len(nickBytes) > 255 {
		nickBytes = nickBytes[:255]
	}
	// TLV: 0x01 (type=nickname) + len + bytes.
	payload := make([]byte, 0, 2+len(nickBytes))
	payload = append(payload, 0x01, byte(len(nickBytes)))
	payload = append(payload, nickBytes...)
	pkt := protocol.New(protocol.MTAnnounce, s.identity.PeerIDRaw, payload)
	if bytes, err := protocol.Encode(pkt); err == nil {
		s.ble.Broadcast(bytes)
	}
}

// PostPublic broadcasts a plain-text chat message to all peers.
func (s *Service) PostPublic(content string) error {
	m := model.New(s.nickname, content, time.Now().UTC())
	m.SenderPeerID = s.identity.PeerID
	body, err := m.ToBinaryPayload()
	if err != nil {
		return err
	}
	pkt := protocol.New(protocol.MTMessage, s.identity.PeerIDRaw, body)
	enc, err := protocol.Encode(pkt)
	if err != nil {
		return err
	}
	s.ble.Broadcast(enc)
	return nil
}

// PostDM sends a private message to peer_id (16 hex chars). Fails if
// no Noise session is established with that peer yet.
func (s *Service) PostDM(peerHex, content string) error {
	sess := s.sessions.Get(peerHex)
	if sess == nil || !sess.Established() {
		return errors.New("no established session — call InitiateHandshake first")
	}
	m := model.NewPrivate(s.nickname, content, time.Now().UTC(), "")
	m.SenderPeerID = s.identity.PeerID
	body, err := m.ToBinaryPayload()
	if err != nil {
		return err
	}
	// Wrap as an inner Message packet, then encrypt as a
	// NoiseEncrypted packet whose payload is the ciphertext.
	inner := protocol.New(protocol.MTMessage, s.identity.PeerIDRaw, body)
	innerBytes, err := protocol.Encode(inner)
	if err != nil {
		return err
	}
	ct, err := sess.Encrypt(innerBytes)
	if err != nil {
		return err
	}
	outer := protocol.New(protocol.MTNoiseEncrypted, s.identity.PeerIDRaw, ct)
	rid, err := hexDecode8(peerHex)
	if err != nil {
		return err
	}
	outer.WithRecipient(rid)
	enc, err := protocol.Encode(outer)
	if err != nil {
		return err
	}
	return s.ble.Send(rid, enc)
}

// InitiateHandshake kicks off a Noise-XX exchange with peer_id. The
// caller receives handshake progress via subsequent
// OnHandshakeResponse callbacks routed through processor → delegate.
func (s *Service) InitiateHandshake(peerHex string) error {
	sess, msg1, err := crypto.NewInitiator(s.identity, peerHex)
	if err != nil {
		return err
	}
	s.sessions.Set(peerHex, sess)
	// Wrap message 1 as a NoiseHandshakeInit packet body.
	pkt := protocol.New(protocol.MTNoiseHandshakeInit, s.identity.PeerIDRaw, msg1)
	rid, err := hexDecode8(peerHex)
	if err != nil {
		return err
	}
	pkt.WithRecipient(rid)
	enc, err := protocol.Encode(pkt)
	if err != nil {
		return err
	}
	return s.ble.Send(rid, enc)
}

func (s *Service) pushEvent(e AppEvent) {
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return
	}
	select {
	case s.events <- e:
	default:
		// Drop rather than block a BLE reader loop.
	}
}

// ---- Delegate implementation ------------------------------------

// OnMessage — a public / broadcast Message arrived. Emit as an
// AppMessage; no BLE action needed.
func (s *Service) OnMessage(m *model.Message) {
	s.pushEvent(AppMessage{Message: m, FromID: m.SenderPeerID})
}

// OnPeerConnected mirrors the packet-level Announce into an
// AppPeer edge event.
func (s *Service) OnPeerConnected(peerID string) {
	p := s.peers.Get(peerID)
	nick := ""
	if p != nil {
		nick = p.Nickname
	}
	s.pushEvent(AppPeer{PeerID: peerID, Nickname: nick, Connected: true})
}

// OnPeerDisconnected mirrors Leave into an AppPeer edge event.
func (s *Service) OnPeerDisconnected(peerID string) {
	s.pushEvent(AppPeer{PeerID: peerID, Connected: false})
}

// OnHandshakeInit — someone else initiated toward us. Build a
// responder session, send back message 2.
func (s *Service) OnHandshakeInit(peerID string, pkt *protocol.Packet) {
	sess, msg2, err := crypto.NewResponder(s.identity, peerID, pkt.Payload)
	if err != nil {
		return
	}
	s.sessions.Set(peerID, sess)
	out := protocol.New(protocol.MTNoiseHandshakeResp, s.identity.PeerIDRaw, msg2)
	rid, err := hexDecode8(peerID)
	if err != nil {
		return
	}
	out.WithRecipient(rid)
	if enc, err := protocol.Encode(out); err == nil {
		_ = s.ble.Send(rid, enc)
	}
}

// OnHandshakeResponse — we're the initiator; feed the response into
// the session state machine. If it produces message 3, send it.
func (s *Service) OnHandshakeResponse(peerID string, pkt *protocol.Packet) {
	sess := s.sessions.Get(peerID)
	if sess == nil {
		return
	}
	out, err := sess.Step(pkt.Payload)
	if err != nil {
		return
	}
	if out == nil {
		return // handshake complete
	}
	// One more outbound frame needed.
	// The responder ALSO reaches this branch on its message-3 read;
	// Session.Step is idempotent about producing nil when done.
	frame := protocol.New(protocol.MTNoiseHandshakeFinal, s.identity.PeerIDRaw, out)
	rid, err := hexDecode8(peerID)
	if err != nil {
		return
	}
	frame.WithRecipient(rid)
	if enc, err := protocol.Encode(frame); err == nil {
		_ = s.ble.Send(rid, enc)
	}
}

// OnIdentityAnnounce — stamp peer state (already done by the
// processor); nothing extra here yet.
func (s *Service) OnIdentityAnnounce(peerID string, _ *protocol.IdentityAnnouncement) {
	p := s.peers.Get(peerID)
	if p == nil {
		return
	}
	s.pushEvent(AppPeer{PeerID: peerID, Nickname: p.Nickname, Connected: true})
}

// OnEncryptedInner — inner packet already re-processed by the
// processor's Process call; nothing needed here.
func (s *Service) OnEncryptedInner(string, *protocol.Packet) {}

// LocalPeerID returns our 16-hex peer id — used by the processor's
// self-echo filter.
func (s *Service) LocalPeerID() string { return s.identity.PeerID }

// LocalNickname is what Announces + Messages tag as our sender.
func (s *Service) LocalNickname() string { return s.nickname }

// ---- tiny hex helpers -------------------------------------------

const hexchars = "0123456789abcdef"

func hexEncode8(b [8]byte) string {
	out := make([]byte, 16)
	for i := 0; i < 8; i++ {
		out[i*2] = hexchars[b[i]>>4]
		out[i*2+1] = hexchars[b[i]&0x0F]
	}
	return string(out)
}

func hexDecode8(s string) ([8]byte, error) {
	var out [8]byte
	s = strings.ToLower(s)
	if len(s) != 16 {
		return out, fmt.Errorf("expected 16 hex chars, got %d", len(s))
	}
	for i := 0; i < 8; i++ {
		hi, lo := fromHexChar(s[i*2]), fromHexChar(s[i*2+1])
		if hi > 15 || lo > 15 {
			return out, fmt.Errorf("bad hex at %d", i*2)
		}
		out[i] = (hi << 4) | lo
	}
	return out, nil
}

func fromHexChar(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	}
	return 0xFF
}
