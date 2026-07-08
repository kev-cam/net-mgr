package protocol

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestIdentityAnnouncementRoundTrip(t *testing.T) {
	a := &IdentityAnnouncement{
		PeerID:           "0102030405060708",
		PublicKey:        bytes.Repeat([]byte{0xAA}, 32),
		SigningPublicKey: bytes.Repeat([]byte{0xBB}, 32),
		Nickname:         "alice",
		Timestamp:        time.UnixMilli(1700000000123).UTC(),
		Signature:        bytes.Repeat([]byte{0xCC}, 64),
	}
	enc := a.Encode()
	dec, err := DecodeIdentityAnnouncement(enc)
	if err != nil {
		t.Fatal(err)
	}
	if dec.PeerID != a.PeerID || dec.Nickname != a.Nickname {
		t.Errorf("basics lost: %+v", dec)
	}
	if !bytes.Equal(dec.PublicKey, a.PublicKey) ||
		!bytes.Equal(dec.SigningPublicKey, a.SigningPublicKey) ||
		!bytes.Equal(dec.Signature, a.Signature) {
		t.Errorf("bytes fields lost")
	}
	if !dec.Timestamp.Equal(a.Timestamp) {
		t.Errorf("timestamp: got %v want %v", dec.Timestamp, a.Timestamp)
	}
	if dec.PreviousPeerID != "" {
		t.Errorf("unexpected previous peer id: %q", dec.PreviousPeerID)
	}
}

func TestIdentityAnnouncementWithPreviousPeerID(t *testing.T) {
	a := &IdentityAnnouncement{
		PeerID:           "aaaaaaaaaaaaaaaa",
		PublicKey:        bytes.Repeat([]byte{0x01}, 32),
		SigningPublicKey: bytes.Repeat([]byte{0x02}, 32),
		Nickname:         "bob",
		Timestamp:        time.UnixMilli(1700000000000).UTC(),
		PreviousPeerID:   "bbbbbbbbbbbbbbbb",
		Signature:        bytes.Repeat([]byte{0x03}, 64),
	}
	enc := a.Encode()
	dec, err := DecodeIdentityAnnouncement(enc)
	if err != nil {
		t.Fatal(err)
	}
	if dec.PreviousPeerID != a.PreviousPeerID {
		t.Errorf("prev peer id: got %q want %q", dec.PreviousPeerID, a.PreviousPeerID)
	}
}

func TestHandshakeRequestRoundTrip(t *testing.T) {
	r := NewHandshakeRequest(
		"aaaaaaaaaaaaaaaa",
		"requester-nick",
		"bbbbbbbbbbbbbbbb",
		7,
	)
	enc := r.Encode()
	dec, err := DecodeHandshakeRequest(enc)
	if err != nil {
		t.Fatal(err)
	}
	if dec.RequesterID != r.RequesterID || dec.TargetID != r.TargetID {
		t.Errorf("ids lost: %+v", dec)
	}
	if dec.PendingMessageCount != r.PendingMessageCount {
		t.Errorf("count: got %d want %d", dec.PendingMessageCount, r.PendingMessageCount)
	}
	if dec.RequesterNickname != r.RequesterNickname {
		t.Errorf("nick: got %q want %q", dec.RequesterNickname, r.RequesterNickname)
	}
	if dec.RequestID != r.RequestID {
		t.Errorf("request_id round-trip: got %q want %q", dec.RequestID, r.RequestID)
	}
}

func TestUUIDGenerationShape(t *testing.T) {
	id := newUUIDv4()
	// 36 chars, "-" at positions 8,13,18,23.
	if len(id) != 36 {
		t.Errorf("uuid length: got %d want 36 (%q)", len(id), id)
	}
	for _, pos := range []int{8, 13, 18, 23} {
		if id[pos] != '-' {
			t.Errorf("uuid[%d] = %c want -", pos, id[pos])
		}
	}
	// Version nibble is 4, variant top bits are 10.
	if id[14] != '4' {
		t.Errorf("uuid version nibble: got %c want 4", id[14])
	}
	if !strings.ContainsRune("89ab", rune(id[19])) {
		t.Errorf("uuid variant nibble: got %c want 8/9/a/b", id[19])
	}
}

func TestProtocolNackRoundTrip(t *testing.T) {
	n := &ProtocolNack{
		OriginalPacketID: bytes.Repeat([]byte{0xDE}, 16),
		SenderID:         "0102030405060708",
		ReceiverID:       "090a0b0c0d0e0f10",
		PacketType:       0x12,
		Reason:           "handshake gave up",
		ErrorCode:        NackHandshakeFailed,
	}
	enc := n.Encode()
	dec, err := DecodeProtocolNack(enc)
	if err != nil {
		t.Fatal(err)
	}
	if dec.SenderID != n.SenderID || dec.ReceiverID != n.ReceiverID {
		t.Errorf("ids lost: %+v", dec)
	}
	if dec.PacketType != n.PacketType || dec.ErrorCode != n.ErrorCode {
		t.Errorf("type/code lost: %+v", dec)
	}
	if dec.Reason != n.Reason {
		t.Errorf("reason: got %q want %q", dec.Reason, n.Reason)
	}
	if !bytes.Equal(dec.OriginalPacketID, n.OriginalPacketID) {
		t.Errorf("orig packet id: got %x want %x",
			dec.OriginalPacketID, n.OriginalPacketID)
	}
}

func TestNackErrorCodeFromByteUnknownFallback(t *testing.T) {
	if got := NackErrorCodeFromByte(0x99); got != NackUnknownError {
		t.Errorf("unknown byte 0x99: got %d want %d", got, NackUnknownError)
	}
	if got := NackErrorCodeFromByte(0x01); got != NackDecryptionFailed {
		t.Errorf("0x01: got %d", got)
	}
}

func TestBroadcastRecipient(t *testing.T) {
	for i, b := range BroadcastRecipient {
		if b != 0xFF {
			t.Errorf("BroadcastRecipient[%d]: got 0x%02x want 0xFF", i, b)
		}
	}
}
