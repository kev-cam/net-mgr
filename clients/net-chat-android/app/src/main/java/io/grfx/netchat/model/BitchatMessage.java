package io.grfx.netchat.model;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * App-level chat message that travels inside a Packet payload of type
 * MESSAGE (0x02). On-wire layout matches iOS/Android mainline
 * bitchat_message binary payload — see bitchat-rust
 * src/model/bitchat_message.rs and the Go port under
 * internal/bitchat/model/message.go.
 *
 * <p>Rendering into UTF-8: strings that overflow their 1-byte length
 * prefix are truncated (matches the Rust {@code .min(255) as u8}
 * fallback). Content overflowing the 2-byte length is truncated too
 * (matches {@code .min(65535) as u16}).
 */
public final class BitchatMessage {

    // Flag bits — MUST match bitchat_message.rs::to_binary_payload.
    private static final int F_IS_RELAY               = 1 << 0;
    private static final int F_IS_PRIVATE             = 1 << 1;
    private static final int F_HAS_ORIGINAL_SENDER    = 1 << 2;
    private static final int F_HAS_RECIPIENT_NICK     = 1 << 3;
    private static final int F_HAS_SENDER_PEER_ID     = 1 << 4;
    private static final int F_HAS_MENTIONS           = 1 << 5;
    private static final int F_HAS_CHANNEL            = 1 << 6;
    private static final int F_IS_ENCRYPTED           = 1 << 7;

    public String id;                       // random hex, 32 chars
    public String sender;                   // display name
    public String content;                  // plaintext body
    public long timestampMillis;            // BE u64 on wire
    public boolean isRelay;
    public String originalSender;           // null ⇒ not set
    public boolean isPrivate;
    public String recipientNickname;        // null ⇒ not set
    public String senderPeerId;             // null ⇒ not set (16 hex chars when set)
    public List<String> mentions;           // null ⇒ not set; empty ⇒ zero mentions
    public String channel;                  // null ⇒ not set
    public byte[] encryptedContent;         // null ⇒ not set
    public boolean isEncrypted;

    /** Fresh outbound message with a random UUID-shaped id and now(). */
    public static BitchatMessage now(String sender, String content) {
        BitchatMessage m = new BitchatMessage();
        m.id = randomId();
        m.sender = sender;
        m.content = content;
        m.timestampMillis = System.currentTimeMillis();
        return m;
    }

    private static String randomId() {
        byte[] b = new byte[16];
        new java.security.SecureRandom().nextBytes(b);
        StringBuilder sb = new StringBuilder(32);
        for (byte v : b) sb.append(String.format("%02x", v));
        return sb.toString();
    }

    /** Encode to the wire body — the byte[] that goes into
     *  Packet.payload for MESSAGE. Never returns null. */
    public byte[] toBinaryPayload() {
        int flags = 0;
        if (isRelay)                              flags |= F_IS_RELAY;
        if (isPrivate)                            flags |= F_IS_PRIVATE;
        if (originalSender != null)               flags |= F_HAS_ORIGINAL_SENDER;
        if (recipientNickname != null)            flags |= F_HAS_RECIPIENT_NICK;
        if (senderPeerId != null)                 flags |= F_HAS_SENDER_PEER_ID;
        if (mentions != null && !mentions.isEmpty()) flags |= F_HAS_MENTIONS;
        if (channel != null)                      flags |= F_HAS_CHANNEL;
        if (isEncrypted)                          flags |= F_IS_ENCRYPTED;

        java.io.ByteArrayOutputStream buf = new java.io.ByteArrayOutputStream(4096);
        buf.write(flags);
        writeU64BE(buf, timestampMillis);
        writeString1(buf, id == null ? "" : id);
        writeString1(buf, sender == null ? "" : sender);
        if (isEncrypted) {
            writeBytes2(buf, encryptedContent == null ? new byte[0] : encryptedContent);
        } else {
            writeBytes2(buf, (content == null ? "" : content).getBytes(StandardCharsets.UTF_8));
        }
        if ((flags & F_HAS_ORIGINAL_SENDER) != 0)  writeString1(buf, originalSender);
        if ((flags & F_HAS_RECIPIENT_NICK) != 0)   writeString1(buf, recipientNickname);
        if ((flags & F_HAS_SENDER_PEER_ID) != 0)   writeString1(buf, senderPeerId);
        if ((flags & F_HAS_MENTIONS) != 0) {
            int n = Math.min(mentions.size(), 255);
            buf.write(n);
            for (int i = 0; i < n; i++) writeString1(buf, mentions.get(i));
        }
        if ((flags & F_HAS_CHANNEL) != 0) writeString1(buf, channel);
        return buf.toByteArray();
    }

    /** Parse the wire body — throws on truncation. */
    public static BitchatMessage fromBinaryPayload(byte[] data) throws ProtocolException {
        if (data == null || data.length < 13) {
            throw new ProtocolException("message too small (" + (data == null ? 0 : data.length) + " bytes)");
        }
        Cursor cur = new Cursor(data);
        int flags = cur.u8();
        long ts = cur.u64BE();
        String id = cur.string1();
        String sender = cur.string1();
        byte[] content = cur.bytes2();

        BitchatMessage m = new BitchatMessage();
        m.id = id;
        m.sender = sender;
        m.timestampMillis = ts;
        m.isRelay      = (flags & F_IS_RELAY)      != 0;
        m.isPrivate    = (flags & F_IS_PRIVATE)    != 0;
        m.isEncrypted  = (flags & F_IS_ENCRYPTED)  != 0;
        if (m.isEncrypted) {
            m.encryptedContent = content;
        } else {
            m.content = new String(content, StandardCharsets.UTF_8);
        }
        if ((flags & F_HAS_ORIGINAL_SENDER) != 0) m.originalSender = cur.string1();
        if ((flags & F_HAS_RECIPIENT_NICK) != 0)  m.recipientNickname = cur.string1();
        if ((flags & F_HAS_SENDER_PEER_ID) != 0)  m.senderPeerId = cur.string1();
        if ((flags & F_HAS_MENTIONS) != 0) {
            int n = cur.u8();
            m.mentions = new ArrayList<>(n);
            for (int i = 0; i < n; i++) m.mentions.add(cur.string1());
        }
        if ((flags & F_HAS_CHANNEL) != 0) m.channel = cur.string1();
        return m;
    }

    public static final class ProtocolException extends Exception {
        public ProtocolException(String msg) { super(msg); }
    }

    // ---- wire primitives ------------------------------------------------

    private static void writeU64BE(java.io.ByteArrayOutputStream b, long v) {
        for (int shift = 56; shift >= 0; shift -= 8) {
            b.write((int) ((v >>> shift) & 0xFF));
        }
    }

    private static void writeString1(java.io.ByteArrayOutputStream b, String s) {
        byte[] bytes = (s == null ? "" : s).getBytes(StandardCharsets.UTF_8);
        int n = Math.min(bytes.length, 255);
        b.write(n);
        b.write(bytes, 0, n);
    }

    private static void writeBytes2(java.io.ByteArrayOutputStream b, byte[] bytes) {
        int n = Math.min(bytes.length, 65535);
        b.write((n >>> 8) & 0xFF);
        b.write(n & 0xFF);
        b.write(bytes, 0, n);
    }

    /** Fluent-ish cursor for the parser — avoids passing (data, offset)
     *  through every helper. */
    private static final class Cursor {
        final byte[] a;
        int i;
        Cursor(byte[] a) { this.a = a; }

        int u8() throws ProtocolException {
            need(1);
            return a[i++] & 0xFF;
        }

        int u16BE() throws ProtocolException {
            need(2);
            int v = ((a[i] & 0xFF) << 8) | (a[i + 1] & 0xFF);
            i += 2;
            return v;
        }

        long u64BE() throws ProtocolException {
            need(8);
            long v = 0;
            for (int k = 0; k < 8; k++) v = (v << 8) | (a[i + k] & 0xFFL);
            i += 8;
            return v;
        }

        String string1() throws ProtocolException {
            int n = u8();
            need(n);
            String s = new String(a, i, n, StandardCharsets.UTF_8);
            i += n;
            return s;
        }

        byte[] bytes2() throws ProtocolException {
            int n = u16BE();
            need(n);
            byte[] out = new byte[n];
            System.arraycopy(a, i, out, 0, n);
            i += n;
            return out;
        }

        private void need(int n) throws ProtocolException {
            if (i + n > a.length) {
                throw new ProtocolException("truncated at offset " + i + " (need " + n + " bytes)");
            }
        }
    }
}
