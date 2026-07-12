package io.grfx.netchat.protocol;

/**
 * BitChat wire packet. Encoder/decoder in {@link BinaryProtocol}.
 *
 * <p>{@link #recipientId} and {@link #signature} are optional — null
 * signals "not present". The flag bits in {@link Flags} MUST agree
 * with the null-ness of these fields; {@link BinaryProtocol#encode}
 * checks this.
 */
public final class Packet {

    /** 1-byte flags word: has_recipient (bit 0), has_signature (bit 1), is_compressed (bit 2). */
    public static final class Flags {
        public boolean hasRecipient;
        public boolean hasSignature;
        public boolean isCompressed;

        public static Flags fromByte(byte b) {
            Flags f = new Flags();
            f.hasRecipient = (b & 0x01) != 0;
            f.hasSignature = (b & 0x02) != 0;
            f.isCompressed = (b & 0x04) != 0;
            return f;
        }

        public byte toByte() {
            int v = 0;
            if (hasRecipient) v |= 0x01;
            if (hasSignature) v |= 0x02;
            if (isCompressed) v |= 0x04;
            return (byte) v;
        }
    }

    public static final int HEADER_SIZE = 13;      // version + type + ttl + ts(8) + flags + len(2)
    public static final int MAX_PAYLOAD_SIZE = 65535;

    public byte version = 1;
    public MessageType messageType;
    public byte ttl = 3;
    public long timestampMillis;                   // ms since epoch (BE u64 on wire)
    public final Flags flags = new Flags();
    public byte[] senderId;                        // exactly 8 bytes
    public byte[] recipientId;                     // 8 bytes, or null
    public byte[] payload;                         // arbitrary length; ≤ MAX_PAYLOAD_SIZE encoded
    public byte[] signature;                       // 64 bytes, or null

    public Packet() {}

    /** Convenience builder — sets timestamp to now, ttl=3. */
    public static Packet outbound(MessageType type, byte[] senderId, byte[] payload) {
        Packet p = new Packet();
        p.messageType = type;
        p.senderId = senderId;
        p.payload = payload;
        p.timestampMillis = System.currentTimeMillis();
        return p;
    }

    /** Set recipient AND lift the has_recipient flag in one step. */
    public Packet withRecipient(byte[] rid) {
        this.recipientId = rid;
        this.flags.hasRecipient = true;
        return this;
    }

    /** Set signature AND lift the has_signature flag in one step. */
    public Packet withSignature(byte[] sig) {
        this.signature = sig;
        this.flags.hasSignature = true;
        return this;
    }
}
