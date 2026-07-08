// Package model — Go port of bitchat-rust's src/model/*.rs.
package model

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Message is the app-level chat message that travels inside a Packet
// payload of type MTMessage. On-wire layout matches iOS/Android
// bitchat_message binary payload — see model/bitchat_message.rs.
type Message struct {
	ID                string
	Sender            string
	Content           string
	Timestamp         time.Time
	IsRelay           bool
	OriginalSender    string   // "" ⇒ not set
	IsPrivate         bool
	RecipientNickname string   // "" ⇒ not set
	SenderPeerID      string   // "" ⇒ not set
	Mentions          []string // nil ⇒ not set (empty slice writes zero mentions)
	Channel           string   // "" ⇒ not set
	EncryptedContent  []byte
	IsEncrypted       bool
}

// New builds a fresh chat message with a random UUID-v4-ish id.
// The id doesn't need to be RFC-4122; iOS/Android just check that
// it's a printable ASCII string. We emit 32 lowercase hex chars.
func New(sender, content string, ts time.Time) *Message {
	return &Message{ID: newID(), Sender: sender, Content: content, Timestamp: ts}
}

// NewPrivate is New with is_private + recipient_nickname set.
func NewPrivate(sender, content string, ts time.Time, recipientNick string) *Message {
	m := New(sender, content, ts)
	m.IsPrivate = true
	m.RecipientNickname = recipientNick
	return m
}

// NewInChannel is New with a channel tag set. (Named to avoid
// clashing with NewChannel in channel.go.)
func NewInChannel(sender, content string, ts time.Time, channel string) *Message {
	m := New(sender, content, ts)
	m.Channel = channel
	return m
}

func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Flag bits — MUST match bitchat_message.rs::to_binary_payload.
const (
	flagIsRelay             = 1 << 0
	flagIsPrivate           = 1 << 1
	flagHasOriginalSender   = 1 << 2
	flagHasRecipientNick    = 1 << 3
	flagHasSenderPeerID     = 1 << 4
	flagHasMentions         = 1 << 5
	flagHasChannel          = 1 << 6
	flagIsEncrypted         = 1 << 7
)

// ToBinaryPayload emits the on-wire message body — the thing that
// goes into a Packet.Payload for MTMessage.
func (m *Message) ToBinaryPayload() ([]byte, error) {
	var flags byte
	if m.IsRelay {
		flags |= flagIsRelay
	}
	if m.IsPrivate {
		flags |= flagIsPrivate
	}
	if m.OriginalSender != "" {
		flags |= flagHasOriginalSender
	}
	if m.RecipientNickname != "" {
		flags |= flagHasRecipientNick
	}
	if m.SenderPeerID != "" {
		flags |= flagHasSenderPeerID
	}
	if len(m.Mentions) > 0 {
		flags |= flagHasMentions
	}
	if m.Channel != "" {
		flags |= flagHasChannel
	}
	if m.IsEncrypted {
		flags |= flagIsEncrypted
	}

	buf := make([]byte, 0, 4096)
	buf = append(buf, flags)
	buf = binary.BigEndian.AppendUint64(buf, uint64(m.Timestamp.UnixMilli()))
	buf = appendString1(buf, m.ID)
	buf = appendString1(buf, m.Sender)

	if m.IsEncrypted {
		buf = appendBytes2(buf, m.EncryptedContent)
	} else {
		buf = appendBytes2(buf, []byte(m.Content))
	}

	if flags&flagHasOriginalSender != 0 {
		buf = appendString1(buf, m.OriginalSender)
	}
	if flags&flagHasRecipientNick != 0 {
		buf = appendString1(buf, m.RecipientNickname)
	}
	if flags&flagHasSenderPeerID != 0 {
		buf = appendString1(buf, m.SenderPeerID)
	}
	if flags&flagHasMentions != 0 {
		n := len(m.Mentions)
		if n > 255 {
			n = 255
		}
		buf = append(buf, byte(n))
		for i := 0; i < n; i++ {
			buf = appendString1(buf, m.Mentions[i])
		}
	}
	if flags&flagHasChannel != 0 {
		buf = appendString1(buf, m.Channel)
	}
	return buf, nil
}

// FromBinaryPayload parses a message body.
func FromBinaryPayload(data []byte) (*Message, error) {
	if len(data) < 13 {
		return nil, errors.New("message too small")
	}
	i := 0
	flags := data[i]
	i++
	ts := time.UnixMilli(int64(binary.BigEndian.Uint64(data[i : i+8]))).UTC()
	i += 8

	id, ni, err := readString1(data, i)
	if err != nil {
		return nil, fmt.Errorf("id: %w", err)
	}
	i = ni

	sender, ni, err := readString1(data, i)
	if err != nil {
		return nil, fmt.Errorf("sender: %w", err)
	}
	i = ni

	if i+2 > len(data) {
		return nil, errors.New("content length truncated")
	}
	contentLen := int(binary.BigEndian.Uint16(data[i : i+2]))
	i += 2
	if i+contentLen > len(data) {
		return nil, errors.New("content truncated")
	}
	content := data[i : i+contentLen]
	i += contentLen

	m := &Message{
		ID:          id,
		Sender:      sender,
		Timestamp:   ts,
		IsRelay:     flags&flagIsRelay != 0,
		IsPrivate:   flags&flagIsPrivate != 0,
		IsEncrypted: flags&flagIsEncrypted != 0,
	}
	if m.IsEncrypted {
		m.EncryptedContent = append([]byte(nil), content...)
	} else {
		m.Content = string(content)
	}

	if flags&flagHasOriginalSender != 0 {
		m.OriginalSender, i, err = readString1(data, i)
		if err != nil {
			return nil, fmt.Errorf("original_sender: %w", err)
		}
	}
	if flags&flagHasRecipientNick != 0 {
		m.RecipientNickname, i, err = readString1(data, i)
		if err != nil {
			return nil, fmt.Errorf("recipient_nickname: %w", err)
		}
	}
	if flags&flagHasSenderPeerID != 0 {
		m.SenderPeerID, i, err = readString1(data, i)
		if err != nil {
			return nil, fmt.Errorf("sender_peer_id: %w", err)
		}
	}
	if flags&flagHasMentions != 0 {
		if i >= len(data) {
			return nil, errors.New("mention count truncated")
		}
		n := int(data[i])
		i++
		m.Mentions = make([]string, 0, n)
		for k := 0; k < n; k++ {
			var s string
			s, i, err = readString1(data, i)
			if err != nil {
				return nil, fmt.Errorf("mention[%d]: %w", k, err)
			}
			m.Mentions = append(m.Mentions, s)
		}
	}
	if flags&flagHasChannel != 0 {
		m.Channel, i, err = readString1(data, i)
		if err != nil {
			return nil, fmt.Errorf("channel: %w", err)
		}
	}
	_ = i
	return m, nil
}

// appendString1 writes a 1-byte length prefix + UTF-8 bytes, capping
// at 255 bytes (matches the Rust `.min(255) as u8` truncation).
func appendString1(buf []byte, s string) []byte {
	b := []byte(s)
	n := len(b)
	if n > 255 {
		n = 255
	}
	buf = append(buf, byte(n))
	buf = append(buf, b[:n]...)
	return buf
}

// appendBytes2 writes a 2-byte BE length prefix + bytes, capping at
// 65535 (matches the Rust `.min(65535) as u16` truncation).
func appendBytes2(buf, b []byte) []byte {
	n := len(b)
	if n > 65535 {
		n = 65535
	}
	buf = binary.BigEndian.AppendUint16(buf, uint16(n))
	buf = append(buf, b[:n]...)
	return buf
}

// readString1 reads a 1-byte length + UTF-8 bytes, returning the
// string and the byte offset after it.
func readString1(data []byte, i int) (string, int, error) {
	if i >= len(data) {
		return "", i, errors.New("string length truncated")
	}
	n := int(data[i])
	i++
	if i+n > len(data) {
		return "", i, errors.New("string truncated")
	}
	return string(data[i : i+n]), i + n, nil
}
