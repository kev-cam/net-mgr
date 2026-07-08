package protocol

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// HandshakeRequest is the MTHandshakeRequest payload. Requester asks
// target to initiate a Noise handshake so the queued pending_message
// count can be delivered encrypted.
//
// On-wire byte order surprise: nickname length is LITTLE-endian
// (matches iOS which uses .littleEndian in Data.append). Everything
// else is big-endian.
type HandshakeRequest struct {
	RequestID           string    // UUID string form (36 chars with dashes)
	RequesterID         string    // 16 hex peer id
	RequesterNickname   string
	TargetID            string    // 16 hex peer id
	PendingMessageCount uint8
	Timestamp           time.Time
}

// NewHandshakeRequest builds with fresh id + now().
func NewHandshakeRequest(requesterID, requesterNickname, targetID string, pending uint8) *HandshakeRequest {
	return &HandshakeRequest{
		RequestID:           newUUIDv4(),
		RequesterID:         requesterID,
		RequesterNickname:   requesterNickname,
		TargetID:            targetID,
		PendingMessageCount: pending,
		Timestamp:           time.Now().UTC(),
	}
}

// Encode serialises to the wire form.
func (r *HandshakeRequest) Encode() []byte {
	buf := make([]byte, 0, 43+len(r.RequesterNickname))

	// Request ID: 16 raw UUID bytes. Fall back to zeros on parse error.
	rid := uuidToBytes(r.RequestID)
	buf = append(buf, rid[:]...)

	// Requester ID: 8 raw bytes, padded with zeros on short hex.
	req := hexTo8Pad(r.RequesterID)
	buf = append(buf, req[:]...)
	// Target ID: same.
	tgt := hexTo8Pad(r.TargetID)
	buf = append(buf, tgt[:]...)

	buf = append(buf, r.PendingMessageCount)
	buf = binary.BigEndian.AppendUint64(buf, uint64(r.Timestamp.UnixMilli()))

	// Nickname length is LITTLE-endian (iOS quirk), then UTF-8 bytes.
	nick := []byte(r.RequesterNickname)
	if len(nick) > 65535 {
		nick = nick[:65535]
	}
	buf = binary.LittleEndian.AppendUint16(buf, uint16(len(nick)))
	buf = append(buf, nick...)
	return buf
}

// DecodeHandshakeRequest parses the wire form. Minimum length 43 bytes.
func DecodeHandshakeRequest(data []byte) (*HandshakeRequest, error) {
	if len(data) < 43 {
		return nil, errors.New("handshake request too short")
	}
	i := 0
	requestID := uuidFromBytes(data[i : i+16])
	i += 16
	requesterID := hex.EncodeToString(data[i : i+8])
	i += 8
	targetID := hex.EncodeToString(data[i : i+8])
	i += 8
	pending := data[i]
	i++
	ts := time.UnixMilli(int64(binary.BigEndian.Uint64(data[i : i+8]))).UTC()
	i += 8
	// LITTLE-endian nickname length.
	nickLen := int(binary.LittleEndian.Uint16(data[i : i+2]))
	i += 2
	if i+nickLen > len(data) {
		return nil, errors.New("nickname truncated")
	}
	nickname := string(data[i : i+nickLen])

	return &HandshakeRequest{
		RequestID:           requestID,
		RequesterID:         requesterID,
		RequesterNickname:   nickname,
		TargetID:            targetID,
		PendingMessageCount: pending,
		Timestamp:           ts,
	}, nil
}

// hexTo8Pad returns 8 raw bytes: hex-decodes s, truncates to 8, or
// zero-pads short decodes. Matches Rust's "silent fallback" pattern.
func hexTo8Pad(s string) [8]byte {
	var out [8]byte
	b, err := hex.DecodeString(s)
	if err != nil {
		return out
	}
	if len(b) >= 8 {
		copy(out[:], b[:8])
	} else {
		copy(out[:], b)
	}
	return out
}

// newUUIDv4 emits a random RFC-4122 v4 UUID string.
func newUUIDv4() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	// Set version (4) and variant (RFC-4122).
	b[6] = (b[6] & 0x0F) | 0x40
	b[8] = (b[8] & 0x3F) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// uuidToBytes parses a 36-char UUID string to raw bytes. Falls back
// to zeros on parse failure — matches Rust silent fallback.
func uuidToBytes(s string) [16]byte {
	var out [16]byte
	// Strip dashes then hex-decode.
	stripped := make([]byte, 0, 32)
	for i := 0; i < len(s); i++ {
		if s[i] == '-' {
			continue
		}
		stripped = append(stripped, s[i])
	}
	if len(stripped) != 32 {
		return out
	}
	b, err := hex.DecodeString(string(stripped))
	if err != nil {
		return out
	}
	copy(out[:], b)
	return out
}

// uuidFromBytes formats 16 raw bytes as RFC-4122 UUID string.
func uuidFromBytes(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
