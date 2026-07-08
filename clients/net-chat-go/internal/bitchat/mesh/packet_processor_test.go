package mesh

import (
	"sync"
	"testing"
	"time"

	"github.com/kev-cam/net-chat-go/internal/bitchat/crypto"
	"github.com/kev-cam/net-chat-go/internal/bitchat/model"
	"github.com/kev-cam/net-chat-go/internal/bitchat/protocol"
)

// captureDelegate records callbacks in-order for tests.
type captureDelegate struct {
	mu   sync.Mutex
	msgs []*model.Message
	conn []string
	disc []string
	init []string
	resp []string
	idAnn []string
	inner []string
}

func (c *captureDelegate) OnMessage(m *model.Message) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.msgs = append(c.msgs, m)
}
func (c *captureDelegate) OnPeerConnected(peerID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.conn = append(c.conn, peerID)
}
func (c *captureDelegate) OnPeerDisconnected(peerID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.disc = append(c.disc, peerID)
}
func (c *captureDelegate) OnHandshakeInit(peerID string, _ *protocol.Packet) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.init = append(c.init, peerID)
}
func (c *captureDelegate) OnHandshakeResponse(peerID string, _ *protocol.Packet) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.resp = append(c.resp, peerID)
}
func (c *captureDelegate) OnIdentityAnnounce(peerID string, _ *protocol.IdentityAnnouncement) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.idAnn = append(c.idAnn, peerID)
}
func (c *captureDelegate) OnEncryptedInner(peerID string, _ *protocol.Packet) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.inner = append(c.inner, peerID)
}
func (c *captureDelegate) LocalPeerID() string  { return "0000000000000000" }
func (c *captureDelegate) LocalNickname() string { return "test" }

func newProcessor() (*PacketProcessor, *captureDelegate) {
	d := &captureDelegate{}
	p := NewPacketProcessor(d, NewPeerManager(), NewFragmentManager(), crypto.NewSessionSet())
	return p, d
}

func makeAnnounce(sender [8]byte, nickname string) *protocol.Packet {
	// TLV form: 0x01 (type) 0x0N (len) N bytes UTF-8 nickname.
	nickBytes := []byte(nickname)
	payload := make([]byte, 0, 2+len(nickBytes))
	payload = append(payload, 0x01, byte(len(nickBytes)))
	payload = append(payload, nickBytes...)
	return protocol.New(protocol.MTAnnounce, sender, payload)
}

func TestAnnounceRegistersPeerAndFiresConnect(t *testing.T) {
	p, d := newProcessor()
	sender := [8]byte{0xAA, 0x11, 0xBB, 0x22, 0xCC, 0x33, 0xDD, 0x44}
	if err := p.Process(makeAnnounce(sender, "alice"), "addr:1"); err != nil {
		t.Fatal(err)
	}
	peers := d.conn
	if len(peers) != 1 || peers[0] != "aa11bb22cc33dd44" {
		t.Errorf("OnPeerConnected: got %v", peers)
	}
	got := p.peers.Get("aa11bb22cc33dd44")
	if got == nil || got.Nickname != "alice" {
		t.Errorf("peer nickname: %+v", got)
	}
}

func TestDuplicateAnnouncesDedupe(t *testing.T) {
	p, d := newProcessor()
	sender := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	pk := makeAnnounce(sender, "b")
	_ = p.Process(pk, "a")
	// Same packet again → dedupe by encoded hash → no second callback.
	_ = p.Process(pk, "a")
	if len(d.conn) != 1 {
		t.Errorf("connect callbacks: got %d want 1", len(d.conn))
	}
}

func TestSelfSenderFilter(t *testing.T) {
	p, d := newProcessor()
	// LocalPeerID = 0000...00 — sender that matches must be dropped.
	pk := makeAnnounce([8]byte{}, "me")
	_ = p.Process(pk, "a")
	if len(d.conn) != 0 {
		t.Errorf("self packet leaked to callback: %v", d.conn)
	}
}

func TestMessageDeliversToDelegate(t *testing.T) {
	p, d := newProcessor()
	m := model.New("carol", "hi mesh", time.UnixMilli(1700000000000).UTC())
	body, err := m.ToBinaryPayload()
	if err != nil {
		t.Fatal(err)
	}
	sender := [8]byte{9, 9, 9, 9, 9, 9, 9, 9}
	pk := protocol.New(protocol.MTMessage, sender, body)
	if err := p.Process(pk, "a"); err != nil {
		t.Fatal(err)
	}
	if len(d.msgs) != 1 || d.msgs[0].Content != "hi mesh" {
		t.Errorf("OnMessage: %v", d.msgs)
	}
	if d.msgs[0].SenderPeerID != "0909090909090909" {
		t.Errorf("SenderPeerID auto-fill: got %q", d.msgs[0].SenderPeerID)
	}
}

func TestLeaveFiresDisconnect(t *testing.T) {
	p, d := newProcessor()
	sender := [8]byte{7, 7, 7, 7, 7, 7, 7, 7}
	// Announce first so the peer is connected.
	_ = p.Process(makeAnnounce(sender, "peer7"), "a")
	if len(d.conn) != 1 {
		t.Fatalf("prep failed: %v", d.conn)
	}
	// Now a Leave packet.
	leave := protocol.New(protocol.MTLeave, sender, nil)
	if err := p.Process(leave, "a"); err != nil {
		t.Fatal(err)
	}
	if len(d.disc) != 1 || d.disc[0] != "0707070707070707" {
		t.Errorf("OnPeerDisconnected: %v", d.disc)
	}
}

func TestHandshakeInitAndRespPassThrough(t *testing.T) {
	p, d := newProcessor()
	sender := [8]byte{0xB, 0xB, 0xB, 0xB, 0xB, 0xB, 0xB, 0xB}
	init := protocol.New(protocol.MTNoiseHandshakeInit, sender, []byte{0x01, 0x02})
	if err := p.Process(init, "a"); err != nil {
		t.Fatal(err)
	}
	resp := protocol.New(protocol.MTNoiseHandshakeResp, sender, []byte{0x03, 0x04})
	if err := p.Process(resp, "a"); err != nil {
		t.Fatal(err)
	}
	if len(d.init) != 1 || len(d.resp) != 1 {
		t.Errorf("handshake pass-through: init=%v resp=%v", d.init, d.resp)
	}
}

func TestFragmentReassemblyDispatchesInner(t *testing.T) {
	p, d := newProcessor()
	m := model.New("frag", "assembled body", time.UnixMilli(0).UTC())
	body, err := m.ToBinaryPayload()
	if err != nil {
		t.Fatal(err)
	}
	sender := [8]byte{5, 5, 5, 5, 5, 5, 5, 5}
	inner := protocol.New(protocol.MTMessage, sender, body)
	innerBytes, err := protocol.Encode(inner)
	if err != nil {
		t.Fatal(err)
	}
	// Cut the encoded inner into two chunks and wrap each in a
	// Fragment packet.
	fragID := [8]byte{0xF, 0xA, 0xC, 0xE, 0x00, 0x01, 0x02, 0x03}
	half := len(innerBytes) / 2
	chunks := [][]byte{innerBytes[:half], innerBytes[half:]}
	for i, c := range chunks {
		payload := EncodeFragmentPayload(fragID, uint16(i), 2, byte(protocol.MTMessage), c)
		var mt protocol.MessageType = protocol.MTFragmentStart
		if i == len(chunks)-1 {
			mt = protocol.MTFragmentEnd
		} else if i > 0 {
			mt = protocol.MTFragmentContinue
		}
		pk := protocol.New(mt, sender, payload)
		if err := p.Process(pk, "a"); err != nil {
			t.Fatal(err)
		}
	}
	if len(d.msgs) != 1 || d.msgs[0].Content != "assembled body" {
		t.Errorf("reassembled message not delivered: %+v", d.msgs)
	}
}

func TestIdentityAnnounceRegistersStaticKey(t *testing.T) {
	p, d := newProcessor()
	ann := &protocol.IdentityAnnouncement{
		PeerID:           "aabbccddeeff0011",
		PublicKey:        make([]byte, 32),
		SigningPublicKey: make([]byte, 32),
		Nickname:         "eve",
		Timestamp:        time.UnixMilli(1700000000000).UTC(),
		Signature:        make([]byte, 64),
	}
	for i := range ann.PublicKey {
		ann.PublicKey[i] = byte(i)
	}
	body := ann.Encode()
	sender := [8]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}
	pk := protocol.New(protocol.MTNoiseIdentityAnnounce, sender, body)
	if err := p.Process(pk, "a"); err != nil {
		t.Fatal(err)
	}
	if len(d.idAnn) != 1 {
		t.Errorf("OnIdentityAnnounce: %v", d.idAnn)
	}
	got := p.peers.Get("aabbccddeeff0011")
	if got == nil || len(got.StaticPublicKey) != 32 || got.Nickname != "eve" {
		t.Errorf("peer state: %+v", got)
	}
}
