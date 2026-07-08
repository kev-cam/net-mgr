package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// Encode serializes a packet to the on-wire form: header + optional
// recipient + payload (with optional 2-byte pre-length when compressed)
// + optional signature, then PKCS#7 padded to the next block size.
// Straight port of binary_protocol.rs::encode; byte order is BigEndian.
func Encode(p *Packet) ([]byte, error) {
	payload := p.Payload
	var originalPayloadSize uint16
	isCompressed := false

	if ShouldCompress(p.Payload) {
		if c, err := Compress(p.Payload); err != nil {
			return nil, err
		} else if c != nil {
			originalPayloadSize = uint16(len(p.Payload))
			payload = c
			isCompressed = true
		}
	}

	flags := p.Flags
	flags.IsCompressed = isCompressed

	// Payload data size includes the 2-byte original-length prefix
	// when the payload is compressed.
	payloadDataSize := len(payload)
	if isCompressed {
		payloadDataSize += 2
	}
	if payloadDataSize > MaxPayloadSize {
		return nil, fmt.Errorf("message too large: %d > %d", payloadDataSize, MaxPayloadSize)
	}

	// Header + sender + optional recipient + payload + optional signature.
	tail := 0
	if flags.HasRecipient {
		tail += 8
	}
	if flags.HasSignature {
		tail += 64
	}
	buf := make([]byte, 0, HeaderSize+8+payloadDataSize+tail)

	buf = append(buf, p.Version, byte(p.MessageType), p.TTL)
	buf = binary.BigEndian.AppendUint64(buf, uint64(p.Timestamp.UnixMilli()))
	buf = append(buf, flags.ToByte())
	buf = binary.BigEndian.AppendUint16(buf, uint16(payloadDataSize))
	buf = append(buf, p.SenderID[:]...)

	if flags.HasRecipient {
		if p.RecipientID == nil {
			return nil, errors.New("has_recipient set but recipient_id is nil")
		}
		buf = append(buf, p.RecipientID[:]...)
	}

	if isCompressed {
		buf = binary.BigEndian.AppendUint16(buf, originalPayloadSize)
	}
	buf = append(buf, payload...)

	if flags.HasSignature {
		if p.Signature == nil {
			return nil, errors.New("has_signature set but signature is nil")
		}
		buf = append(buf, p.Signature[:]...)
	}

	optimal := OptimalBlockSize(len(buf))
	return Pad(buf, optimal), nil
}

// Decode is the inverse of Encode: strip padding, read header + fields,
// decompress if flagged. Errors reported as plain error strings —
// higher layers decide whether to warn-and-drop or bubble up.
func Decode(data []byte) (*Packet, error) {
	un := Unpad(data)
	// header + sender_id
	if len(un) < HeaderSize+8 {
		return nil, fmt.Errorf("packet too small: len=%d min=%d", len(un), HeaderSize+8)
	}
	i := 0
	version := un[i]
	i++
	if version != 1 {
		return nil, fmt.Errorf("unsupported version %d", version)
	}
	rawType := un[i]
	i++
	mt, err := MessageTypeFromByte(rawType)
	if err != nil {
		return nil, err
	}
	ttl := un[i]
	i++
	ts := binary.BigEndian.Uint64(un[i : i+8])
	i += 8
	flags := PacketFlagsFromByte(un[i])
	i++
	payloadLen := int(binary.BigEndian.Uint16(un[i : i+2]))
	i += 2

	expected := HeaderSize + 8 + payloadLen
	if flags.HasRecipient {
		expected += 8
	}
	if flags.HasSignature {
		expected += 64
	}
	if len(un) < expected {
		return nil, fmt.Errorf("packet size mismatch: expected>=%d got=%d type=0x%02x payload_len=%d has_recipient=%v has_signature=%v",
			expected, len(un), rawType, payloadLen, flags.HasRecipient, flags.HasSignature)
	}

	var sender [8]byte
	copy(sender[:], un[i:i+8])
	i += 8

	var recipient *[8]byte
	if flags.HasRecipient {
		var r [8]byte
		copy(r[:], un[i:i+8])
		i += 8
		recipient = &r
	}

	var payload []byte
	if flags.IsCompressed {
		if payloadLen < 2 {
			return nil, errors.New("compressed payload too small")
		}
		originalSize := int(binary.BigEndian.Uint16(un[i : i+2]))
		i += 2
		compressed := un[i : i+payloadLen-2]
		i += payloadLen - 2
		p, err := Decompress(compressed, originalSize)
		if err != nil {
			return nil, fmt.Errorf("decompress: %w", err)
		}
		payload = p
	} else {
		payload = make([]byte, payloadLen)
		copy(payload, un[i:i+payloadLen])
		i += payloadLen
	}

	var signature *[64]byte
	if flags.HasSignature {
		var s [64]byte
		copy(s[:], un[i:i+64])
		i += 64
		signature = &s
	}

	return &Packet{
		Version:     version,
		MessageType: mt,
		TTL:         ttl,
		Timestamp:   time.UnixMilli(int64(ts)).UTC(),
		Flags:       flags,
		SenderID:    sender,
		RecipientID: recipient,
		Payload:     payload,
		Signature:   signature,
	}, nil
}

// EncodeForSigning renders the canonical bytes that go into the
// Ed25519 signature. The verifier reproduces these by encoding the
// received packet with ttl=0 and signature=None; the rebuild MUST
// match byte-for-byte — see packet.rs::to_binary_for_signing.
func EncodeForSigning(p *Packet) ([]byte, error) {
	// Shallow copy is enough — we don't mutate the payload slice.
	q := *p
	q.TTL = 0
	q.Signature = nil
	q.Flags.HasSignature = false
	return Encode(&q)
}

// PacketSize inspects a header prefix and returns the on-wire size of
// the packet (excluding padding). Straight port of get_packet_size.
func PacketSize(data []byte) (int, error) {
	if len(data) < HeaderSize {
		return 0, errors.New("insufficient data for header")
	}
	// NOTE: preserves the (buggy?) Rust behaviour of pulling flags
	// from byte 11 and payload_len from bytes 11..13 — the Rust
	// source does the same. Mainline clients don't call this on
	// mixed streams so the bug is dormant.
	flags := PacketFlagsFromByte(data[11])
	payloadLen := int(binary.BigEndian.Uint16(data[11:13]))
	size := HeaderSize + 8 + payloadLen
	if flags.HasRecipient {
		size += 8
	}
	if flags.HasSignature {
		size += 64
	}
	return size, nil
}
