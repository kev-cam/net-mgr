package model

import (
	"bytes"
	"testing"
	"time"
)

func TestBinaryRoundTripBasic(t *testing.T) {
	m := New("alice", "hello world", time.UnixMilli(1700000000123).UTC())
	b, err := m.ToBinaryPayload()
	if err != nil {
		t.Fatal(err)
	}
	got, err := FromBinaryPayload(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Sender != m.Sender || got.Content != m.Content || got.ID != m.ID {
		t.Errorf("core fields lost: got %+v want %+v", got, m)
	}
	if !got.Timestamp.Equal(m.Timestamp) {
		t.Errorf("timestamp: got %v want %v", got.Timestamp, m.Timestamp)
	}
}

func TestBinaryRoundTripAllOptionals(t *testing.T) {
	m := New("carol", "greetings", time.UnixMilli(1700000000000).UTC())
	m.IsRelay = true
	m.IsPrivate = true
	m.OriginalSender = "bob"
	m.RecipientNickname = "dave"
	m.SenderPeerID = "0102030405060708"
	m.Mentions = []string{"eve", "frank", "gina"}
	m.Channel = "#control"
	b, err := m.ToBinaryPayload()
	if err != nil {
		t.Fatal(err)
	}
	got, err := FromBinaryPayload(b)
	if err != nil {
		t.Fatal(err)
	}
	if !got.IsRelay || !got.IsPrivate {
		t.Errorf("flags lost: relay=%v private=%v", got.IsRelay, got.IsPrivate)
	}
	if got.OriginalSender != m.OriginalSender ||
		got.RecipientNickname != m.RecipientNickname ||
		got.SenderPeerID != m.SenderPeerID ||
		got.Channel != m.Channel {
		t.Errorf("optional strings lost: %+v", got)
	}
	if len(got.Mentions) != len(m.Mentions) {
		t.Errorf("mention count: got %d want %d", len(got.Mentions), len(m.Mentions))
	}
	for i, m0 := range m.Mentions {
		if got.Mentions[i] != m0 {
			t.Errorf("mention[%d]: got %q want %q", i, got.Mentions[i], m0)
		}
	}
}

func TestBinaryRoundTripEncrypted(t *testing.T) {
	m := New("alice", "unused-when-encrypted", time.UnixMilli(0).UTC())
	m.IsEncrypted = true
	m.EncryptedContent = []byte{0x00, 0x01, 0xFF, 0xFE}
	b, err := m.ToBinaryPayload()
	if err != nil {
		t.Fatal(err)
	}
	got, err := FromBinaryPayload(b)
	if err != nil {
		t.Fatal(err)
	}
	if !got.IsEncrypted {
		t.Errorf("IsEncrypted lost")
	}
	if !bytes.Equal(got.EncryptedContent, m.EncryptedContent) {
		t.Errorf("encrypted content: got %x want %x", got.EncryptedContent, m.EncryptedContent)
	}
	if got.Content != "" {
		t.Errorf("Content should be empty on encrypted round-trip, got %q", got.Content)
	}
}

func TestNoOptionalsSetsNoFlags(t *testing.T) {
	m := New("solo", "no extras", time.UnixMilli(0).UTC())
	b, err := m.ToBinaryPayload()
	if err != nil {
		t.Fatal(err)
	}
	if b[0] != 0 {
		t.Errorf("flags byte: got 0x%02x want 0x00", b[0])
	}
}
