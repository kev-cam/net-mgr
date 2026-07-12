package io.grfx.netchat.protocol;

import java.io.ByteArrayOutputStream;

/**
 * Encoder/decoder for BitChat packets. Big-endian throughout;
 * mirrors bitchat-rust binary_protocol.rs and the Go port
 * internal/bitchat/protocol/binary_protocol.go byte-for-byte.
 *
 * <p>Compression is deliberately not implemented — matches Rust's
 * {@code should_compress = false} for iOS/Android compatibility. The
 * has_compressed flag is respected on decode but never set on encode.
 */
public final class BinaryProtocol {
    private BinaryProtocol() {}

    /** Encode a packet to on-wire bytes (padded, no compression). */
    public static byte[] encode(Packet p) throws ProtocolException {
        if (p.senderId == null || p.senderId.length != 8) {
            throw new ProtocolException("sender_id must be 8 bytes");
        }
        if (p.flags.hasRecipient
                && (p.recipientId == null || p.recipientId.length != 8)) {
            throw new ProtocolException("has_recipient set but recipient_id absent or wrong length");
        }
        if (p.flags.hasSignature
                && (p.signature == null || p.signature.length != 64)) {
            throw new ProtocolException("has_signature set but signature absent or wrong length");
        }
        int payloadLen = p.payload == null ? 0 : p.payload.length;
        if (payloadLen > Packet.MAX_PAYLOAD_SIZE) {
            throw new ProtocolException("payload too large: " + payloadLen
                    + " > " + Packet.MAX_PAYLOAD_SIZE);
        }

        ByteArrayOutputStream buf = new ByteArrayOutputStream(
                Packet.HEADER_SIZE + 8 + payloadLen + 64);
        buf.write(p.version & 0xFF);
        buf.write(p.messageType.value & 0xFF);
        buf.write(p.ttl & 0xFF);
        writeU64BE(buf, p.timestampMillis);
        buf.write(p.flags.toByte() & 0xFF);
        writeU16BE(buf, payloadLen);
        writeAll(buf, p.senderId);
        if (p.flags.hasRecipient) writeAll(buf, p.recipientId);
        if (payloadLen > 0) writeAll(buf, p.payload);
        if (p.flags.hasSignature) writeAll(buf, p.signature);

        byte[] raw = buf.toByteArray();
        return Padding.pad(raw, Padding.optimalBlockSize(raw.length));
    }

    /** Decode on-wire bytes (padded) into a Packet. */
    public static Packet decode(byte[] data)
            throws ProtocolException, MessageType.UnknownMessageTypeException {
        byte[] un = Padding.unpad(data);
        if (un.length < Packet.HEADER_SIZE + 8) {
            throw new ProtocolException("packet too small: " + un.length);
        }
        int i = 0;
        Packet p = new Packet();
        p.version = un[i++];
        if (p.version != 1) {
            throw new ProtocolException("unsupported version " + (p.version & 0xFF));
        }
        p.messageType = MessageType.fromByte(un[i++]);
        p.ttl = un[i++];
        p.timestampMillis = readU64BE(un, i); i += 8;
        Packet.Flags flags = Packet.Flags.fromByte(un[i++]);
        p.flags.hasRecipient = flags.hasRecipient;
        p.flags.hasSignature = flags.hasSignature;
        p.flags.isCompressed = flags.isCompressed;
        int payloadLen = readU16BE(un, i); i += 2;

        int expected = Packet.HEADER_SIZE + 8 + payloadLen;
        if (flags.hasRecipient) expected += 8;
        if (flags.hasSignature) expected += 64;
        if (un.length < expected) {
            throw new ProtocolException("packet size mismatch: expected >= "
                    + expected + " got " + un.length);
        }

        p.senderId = new byte[8];
        System.arraycopy(un, i, p.senderId, 0, 8);
        i += 8;

        if (flags.hasRecipient) {
            p.recipientId = new byte[8];
            System.arraycopy(un, i, p.recipientId, 0, 8);
            i += 8;
        }

        // Compression: we don't emit it but we tolerate reading it —
        // the payload prefix is a u16 BE original-length, then the
        // compressed bytes. We simply refuse (no zlib bundled to
        // decompress). Matches Rust's iOS-compat behaviour: real
        // clients never set this.
        if (flags.isCompressed) {
            throw new ProtocolException("compressed payload not supported");
        }
        p.payload = new byte[payloadLen];
        System.arraycopy(un, i, p.payload, 0, payloadLen);
        i += payloadLen;

        if (flags.hasSignature) {
            p.signature = new byte[64];
            System.arraycopy(un, i, p.signature, 0, 64);
            i += 64;
        }
        return p;
    }

    /** Canonical bytes for Ed25519 signing: TTL=0, no signature.
     *  Verifier reconstructs these from the wire packet + zeroing the
     *  same fields and expects a byte-for-byte match. */
    public static byte[] encodeForSigning(Packet p) throws ProtocolException {
        Packet q = new Packet();
        q.version = p.version;
        q.messageType = p.messageType;
        q.ttl = 0;
        q.timestampMillis = p.timestampMillis;
        q.flags.hasRecipient = p.flags.hasRecipient;
        q.flags.hasSignature = false;
        q.flags.isCompressed = p.flags.isCompressed;
        q.senderId = p.senderId;
        q.recipientId = p.recipientId;
        q.payload = p.payload;
        q.signature = null;
        return encode(q);
    }

    // ---- primitive I/O helpers ------------------------------------------

    private static void writeAll(ByteArrayOutputStream b, byte[] a) {
        b.write(a, 0, a.length);
    }

    private static void writeU16BE(ByteArrayOutputStream b, int v) {
        b.write((v >>> 8) & 0xFF);
        b.write(v & 0xFF);
    }

    private static void writeU64BE(ByteArrayOutputStream b, long v) {
        for (int shift = 56; shift >= 0; shift -= 8) {
            b.write((int) ((v >>> shift) & 0xFF));
        }
    }

    private static int readU16BE(byte[] a, int off) {
        return ((a[off] & 0xFF) << 8) | (a[off + 1] & 0xFF);
    }

    private static long readU64BE(byte[] a, int off) {
        long v = 0;
        for (int i = 0; i < 8; i++) {
            v = (v << 8) | (a[off + i] & 0xFFL);
        }
        return v;
    }

    /** Thrown by encode/decode on any structural error. */
    public static final class ProtocolException extends Exception {
        public ProtocolException(String msg) { super(msg); }
    }
}
