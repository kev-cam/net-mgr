package protocol

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"time"
)

// NackErrorCode is the 1-byte reason code in a ProtocolNack payload.
type NackErrorCode uint8

const (
	NackDecryptionFailed       NackErrorCode = 0x01
	NackInvalidSignature       NackErrorCode = 0x02
	NackSystemValidationFailed NackErrorCode = 0x03
	NackInvalidPacketFormat    NackErrorCode = 0x04
	NackSessionNotFound        NackErrorCode = 0x05
	NackHandshakeFailed        NackErrorCode = 0x06
	NackUnsupportedVersion     NackErrorCode = 0x07
	NackUnknownError           NackErrorCode = 0xFF
)

// NackErrorCodeFromByte parses a wire byte; any unknown value maps
// to NackUnknownError, matching Rust's from_u8.
func NackErrorCodeFromByte(b byte) NackErrorCode {
	switch NackErrorCode(b) {
	case NackDecryptionFailed, NackInvalidSignature, NackSystemValidationFailed,
		NackInvalidPacketFormat, NackSessionNotFound, NackHandshakeFailed,
		NackUnsupportedVersion:
		return NackErrorCode(b)
	}
	return NackUnknownError
}

// ProtocolNack is the payload of MTProtocolNack — a per-packet
// negative ack sent when a peer can't process a specific inbound.
// Rejection reason travels as both a machine-readable ErrorCode and
// a human-readable Reason string.
type ProtocolNack struct {
	OriginalPacketID []byte // 16-byte UUID of the packet being NACK'd
	SenderID         string // 16 hex peer id (of the NACK sender)
	ReceiverID       string // 16 hex peer id (of the NACK target)
	PacketType       byte
	Reason           string
	ErrorCode        NackErrorCode
}

// Encode serialises to the Mac-client-compatible wire form:
//
//	16 bytes original_packet_id
//	16 bytes nack_id (fresh UUIDv4 — receiver ignores it)
//	 8 bytes sender_id (hex-decoded to raw)
//	 8 bytes receiver_id (hex-decoded to raw)
//	 1 byte packet_type
//	 1 byte error_code
//	 8 bytes timestamp (ms, BE)
//	 1 byte reason len
//	 N bytes reason
func (n *ProtocolNack) Encode() []byte {
	buf := make([]byte, 0, 58+len(n.Reason))

	// Original packet id (pad/truncate to 16 bytes).
	if len(n.OriginalPacketID) >= 16 {
		buf = append(buf, n.OriginalPacketID[:16]...)
	} else {
		buf = append(buf, n.OriginalPacketID...)
		buf = append(buf, make([]byte, 16-len(n.OriginalPacketID))...)
	}

	// Fresh NACK id (UUID v4).
	var nackID [16]byte
	_, _ = rand.Read(nackID[:])
	nackID[6] = (nackID[6] & 0x0F) | 0x40
	nackID[8] = (nackID[8] & 0x3F) | 0x80
	buf = append(buf, nackID[:]...)

	snd := hexTo8Pad(n.SenderID)
	buf = append(buf, snd[:]...)
	rcv := hexTo8Pad(n.ReceiverID)
	buf = append(buf, rcv[:]...)
	buf = append(buf, n.PacketType, byte(n.ErrorCode))
	buf = binary.BigEndian.AppendUint64(buf, uint64(time.Now().UTC().UnixMilli()))

	// Reason: 1-byte length + UTF-8 (Mac's default 1-byte encoding).
	rb := []byte(n.Reason)
	if len(rb) > 255 {
		rb = rb[:255]
	}
	buf = append(buf, byte(len(rb)))
	buf = append(buf, rb...)
	return buf
}

// DecodeProtocolNack parses the wire form. Minimum length 58 bytes.
func DecodeProtocolNack(data []byte) (*ProtocolNack, error) {
	if len(data) < 58 {
		return nil, errors.New("nack data too short")
	}
	i := 0
	orig := make([]byte, 16)
	copy(orig, data[i:i+16])
	i += 16
	i += 16 // skip nack_id — not used by iOS/Android either
	senderID := hex.EncodeToString(data[i : i+8])
	i += 8
	receiverID := hex.EncodeToString(data[i : i+8])
	i += 8
	packetType := data[i]
	i++
	errCode := NackErrorCodeFromByte(data[i])
	i++
	i += 8 // timestamp — not surfaced by Rust either
	if i >= len(data) {
		return nil, errors.New("nack reason length missing")
	}
	rlen := int(data[i])
	i++
	if i+rlen > len(data) {
		return nil, errors.New("nack reason truncated")
	}
	reason := string(data[i : i+rlen])
	return &ProtocolNack{
		OriginalPacketID: orig,
		SenderID:         senderID,
		ReceiverID:       receiverID,
		PacketType:       packetType,
		Reason:           reason,
		ErrorCode:        errCode,
	}, nil
}
