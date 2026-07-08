package protocol

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// IdentityAnnouncement is the noise_identity_announcement TLV — the
// payload of an MTNoiseIdentityAnnounce packet. iOS/Android look at
// this to bind peer_id ⇄ static key + nickname and (optionally)
// migrate from a previous peer_id.
type IdentityAnnouncement struct {
	PeerID           string    // 16 hex chars
	PublicKey        []byte    // curve25519 static pubkey (32 bytes)
	SigningPublicKey []byte    // ed25519 signing pubkey (32 bytes)
	Nickname         string    // ≤ 255 bytes
	Timestamp        time.Time // ms precision
	PreviousPeerID   string    // "" ⇒ absent
	Signature        []byte    // ed25519 signature over the tuple
}

// hexTo8 decodes a 16-hex-char peer id to raw bytes.
func hexTo8(s string) ([8]byte, error) {
	var out [8]byte
	b, err := hex.DecodeString(s)
	if err != nil {
		return out, fmt.Errorf("invalid hex: %w", err)
	}
	if len(b) != 8 {
		return out, errors.New("peer id must be 8 bytes")
	}
	copy(out[:], b)
	return out, nil
}

// EncodeIdentityAnnouncement serialises to the wire form.
func (a *IdentityAnnouncement) Encode() []byte {
	var flags byte
	if a.PreviousPeerID != "" {
		flags = 0x01
	}
	buf := make([]byte, 0, 128+len(a.PublicKey)+len(a.SigningPublicKey)+len(a.Nickname)+len(a.Signature))
	buf = append(buf, flags)

	// PeerID: 8 raw bytes, no length prefix. Fallback to zeros if
	// the string isn't valid hex — matches Rust's silent fallback.
	if b, err := hexTo8(a.PeerID); err == nil {
		buf = append(buf, b[:]...)
	} else {
		buf = append(buf, make([]byte, 8)...)
	}

	// Public key: 2-byte len + bytes.
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(a.PublicKey)))
	buf = append(buf, a.PublicKey...)

	// Signing public key: 2-byte len + bytes.
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(a.SigningPublicKey)))
	buf = append(buf, a.SigningPublicKey...)

	// Nickname: 1-byte len + UTF-8 (iOS compatibility on the byte
	// width, capped at 255).
	nick := []byte(a.Nickname)
	if len(nick) > 255 {
		nick = nick[:255]
	}
	buf = append(buf, byte(len(nick)))
	buf = append(buf, nick...)

	// Timestamp: 8-byte BE u64 (ms).
	buf = binary.BigEndian.AppendUint64(buf, uint64(a.Timestamp.UnixMilli()))

	// Previous peer id — 8 raw bytes, only when the flag is set.
	if flags&0x01 != 0 {
		if b, err := hexTo8(a.PreviousPeerID); err == nil {
			buf = append(buf, b[:]...)
		}
	}

	// Signature: 2-byte len + bytes.
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(a.Signature)))
	buf = append(buf, a.Signature...)

	return buf
}

// DecodeIdentityAnnouncement parses the wire form.
func DecodeIdentityAnnouncement(data []byte) (*IdentityAnnouncement, error) {
	if len(data) < 10 {
		return nil, errors.New("data too small for identity announcement")
	}
	i := 0
	flags := data[i]
	i++
	hasPrev := flags&0x01 != 0

	if i+8 > len(data) {
		return nil, errors.New("invalid peer id length")
	}
	peerID := hex.EncodeToString(data[i : i+8])
	i += 8

	pk, ni, err := readBytes2(data, i)
	if err != nil {
		return nil, fmt.Errorf("public_key: %w", err)
	}
	i = ni

	spk, ni, err := readBytes2(data, i)
	if err != nil {
		return nil, fmt.Errorf("signing_public_key: %w", err)
	}
	i = ni

	nick, ni, err := readString1(data, i)
	if err != nil {
		return nil, fmt.Errorf("nickname: %w", err)
	}
	i = ni

	if i+8 > len(data) {
		return nil, errors.New("invalid timestamp")
	}
	ts := time.UnixMilli(int64(binary.BigEndian.Uint64(data[i : i+8]))).UTC()
	i += 8

	var prev string
	if hasPrev {
		if i+8 > len(data) {
			return nil, errors.New("invalid previous peer id")
		}
		prev = hex.EncodeToString(data[i : i+8])
		i += 8
	}

	sig, _, err := readBytes2(data, i)
	if err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}

	return &IdentityAnnouncement{
		PeerID:           peerID,
		PublicKey:        append([]byte(nil), pk...),
		SigningPublicKey: append([]byte(nil), spk...),
		Nickname:         nick,
		Timestamp:        ts,
		PreviousPeerID:   prev,
		Signature:        append([]byte(nil), sig...),
	}, nil
}

// readBytes2 reads a 2-byte BE length prefix + bytes, returning a
// slice into the input (not a copy — caller copies if it needs to
// outlive the input buffer).
func readBytes2(data []byte, i int) ([]byte, int, error) {
	if i+2 > len(data) {
		return nil, i, errors.New("length field truncated")
	}
	n := int(binary.BigEndian.Uint16(data[i : i+2]))
	i += 2
	if i+n > len(data) {
		return nil, i, errors.New("data truncated")
	}
	return data[i : i+n], i + n, nil
}

// readString1 mirrors the model helper for 1-byte-len UTF-8 strings.
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
