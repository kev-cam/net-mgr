package protocol

import (
	"encoding/hex"
	"time"
)

// PacketFlags is the 1-byte flags word in the header. Bits mirror
// mainline packet.rs. Fields are exported so the sign/verify helpers
// in higher layers can clear has_signature before hashing.
type PacketFlags struct {
	HasRecipient bool
	HasSignature bool
	IsCompressed bool
}

// PacketFlagsFromByte decodes a flags byte.
func PacketFlagsFromByte(b byte) PacketFlags {
	return PacketFlags{
		HasRecipient: b&0x01 != 0,
		HasSignature: b&0x02 != 0,
		IsCompressed: b&0x04 != 0,
	}
}

// ToByte encodes flags for the wire.
func (f PacketFlags) ToByte() byte {
	var b byte
	if f.HasRecipient {
		b |= 0x01
	}
	if f.HasSignature {
		b |= 0x02
	}
	if f.IsCompressed {
		b |= 0x04
	}
	return b
}

// Packet is the on-wire packet framed by BinaryProtocol. Nil recipient
// / signature slices signal "not present"; the encoder consults the
// flag AND the slice — matches Rust's Option<[u8; N]> shape.
type Packet struct {
	Version     byte
	MessageType MessageType
	TTL         byte
	Timestamp   time.Time
	Flags       PacketFlags
	SenderID    [8]byte
	RecipientID *[8]byte // nil ⇒ not present
	Payload     []byte
	Signature   *[64]byte // nil ⇒ not present
}

const (
	// HeaderSize is the fixed header prefix: version + type + ttl +
	// timestamp(8) + flags + payload_len(2) = 13 bytes.
	HeaderSize = 13
	// MaxPayloadSize is the 2-byte payload length upper bound.
	MaxPayloadSize = 65535
)

// New builds a fresh outbound packet with defaults matching packet.rs::new.
func New(mt MessageType, sender [8]byte, payload []byte) *Packet {
	return &Packet{
		Version:     1,
		MessageType: mt,
		TTL:         3,
		Timestamp:   time.Now().UTC(),
		SenderID:    sender,
		Payload:     payload,
	}
}

// WithRecipient sets the recipient and lifts the has_recipient flag.
func (p *Packet) WithRecipient(rid [8]byte) *Packet {
	p.RecipientID = &rid
	p.Flags.HasRecipient = true
	return p
}

// WithSignature stamps a signature and lifts the has_signature flag.
func (p *Packet) WithSignature(sig [64]byte) *Packet {
	p.Signature = &sig
	p.Flags.HasSignature = true
	return p
}

// SenderIDHex returns the 16-char lowercase-hex form.
func (p *Packet) SenderIDHex() string { return hex.EncodeToString(p.SenderID[:]) }

// RecipientIDHex returns the 16-char lowercase-hex form of the
// recipient if present, empty string otherwise.
func (p *Packet) RecipientIDHex() string {
	if p.RecipientID == nil {
		return ""
	}
	return hex.EncodeToString(p.RecipientID[:])
}
