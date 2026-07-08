package protocol

import (
	"bytes"
	"testing"
	"time"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	p := New(MTMessage, [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, []byte("Hello, world!"))
	enc, err := Encode(p)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := Decode(enc)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Version != p.Version {
		t.Errorf("version: got %d want %d", dec.Version, p.Version)
	}
	if dec.MessageType != p.MessageType {
		t.Errorf("mt: got 0x%02x want 0x%02x", dec.MessageType, p.MessageType)
	}
	if dec.SenderID != p.SenderID {
		t.Errorf("sender: got %v want %v", dec.SenderID, p.SenderID)
	}
	if !bytes.Equal(dec.Payload, p.Payload) {
		t.Errorf("payload: got %q want %q", dec.Payload, p.Payload)
	}
}

func TestEncodeDecodeWithRecipientAndSignature(t *testing.T) {
	sig := [64]byte{}
	for i := range sig {
		sig[i] = byte(i)
	}
	rid := [8]byte{9, 10, 11, 12, 13, 14, 15, 16}
	p := New(MTNoiseEncrypted, [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, []byte("payload"))
	p.WithRecipient(rid).WithSignature(sig)
	enc, err := Encode(p)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := Decode(enc)
	if err != nil {
		t.Fatal(err)
	}
	if dec.RecipientID == nil || *dec.RecipientID != rid {
		t.Errorf("recipient: got %v want %v", dec.RecipientID, rid)
	}
	if dec.Signature == nil || *dec.Signature != sig {
		t.Errorf("signature mismatch")
	}
	if !dec.Flags.HasRecipient || !dec.Flags.HasSignature {
		t.Errorf("flags lost: %+v", dec.Flags)
	}
}

func TestTimestampRoundTrip(t *testing.T) {
	// Millisecond precision only — Rust encodes .timestamp_millis().
	when := time.UnixMilli(1700000000123).UTC()
	p := New(MTMessage, [8]byte{}, []byte("t"))
	p.Timestamp = when
	enc, err := Encode(p)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := Decode(enc)
	if err != nil {
		t.Fatal(err)
	}
	if !dec.Timestamp.Equal(when) {
		t.Errorf("ts: got %v want %v", dec.Timestamp, when)
	}
}

func TestPaddingRoundTrip(t *testing.T) {
	cases := [][]byte{
		{},
		{1},
		make([]byte, 100),
		make([]byte, 200),
		make([]byte, 250), // near PKCS#7 boundary
	}
	for _, in := range cases {
		out := Unpad(Pad(in, OptimalBlockSize(len(in))))
		if !bytes.Equal(out, in) {
			t.Errorf("pad/unpad(%d): mismatch", len(in))
		}
	}
}

func TestMessageTypeAliases(t *testing.T) {
	if mt, err := MessageTypeFromByte(0x04); err != nil || mt != MTMessage {
		t.Errorf("0x04 legacy Message: got %v/%v", mt, err)
	}
	if mt, err := MessageTypeFromByte(0x02); err != nil || mt != MTMessage {
		t.Errorf("0x02 mainline Message: got %v/%v", mt, err)
	}
	if _, err := MessageTypeFromByte(0xFF); err == nil {
		t.Errorf("0xFF should be unknown, got no error")
	}
}

func TestEncodeForSigningClearsTTLAndSig(t *testing.T) {
	sig := [64]byte{}
	p := New(MTAnnounce, [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, []byte("hi"))
	p.TTL = 7
	p.WithSignature(sig)
	// Sign-bytes should decode with ttl=0 and no signature.
	sb, err := EncodeForSigning(p)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := Decode(sb)
	if err != nil {
		t.Fatal(err)
	}
	if dec.TTL != 0 {
		t.Errorf("sign-bytes TTL: got %d want 0", dec.TTL)
	}
	if dec.Flags.HasSignature || dec.Signature != nil {
		t.Errorf("sign-bytes should have no signature")
	}
}
