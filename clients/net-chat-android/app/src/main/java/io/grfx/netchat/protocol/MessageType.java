package io.grfx.netchat.protocol;

/**
 * BitChat message type byte. Numeric values MUST match mainline
 * permissionlesstech/bitchat + the Rust fork so we interop with
 * iOS/Android clients out of the box. See bitchat-rust
 * src/protocol/message_type.rs for the same table.
 *
 * <p>Note the 0x02 / 0x04 dual mapping for Message: mainline uses 0x02,
 * the older fork used 0x04. From-byte accepts either → Message.
 */
public enum MessageType {
    ANNOUNCE(0x01),
    MESSAGE(0x02),
    LEAVE(0x03),
    FRAGMENT_START(0x05),
    FRAGMENT_CONTINUE(0x06),
    FRAGMENT_END(0x07),
    CHANNEL_ANNOUNCE(0x08),
    CHANNEL_RETENTION(0x09),
    DELIVERY_ACK(0x0A),
    DELIVERY_STATUS_REQUEST(0x0B),
    READ_RECEIPT(0x0C),
    NOISE_HANDSHAKE_INIT(0x10),
    NOISE_HANDSHAKE_RESP(0x11),
    NOISE_ENCRYPTED(0x12),
    NOISE_IDENTITY_ANNOUNCE(0x13),
    CHANNEL_KEY_VERIFY_REQUEST(0x14),
    CHANNEL_KEY_VERIFY_RESPONSE(0x15),
    CHANNEL_PASSWORD_UPDATE(0x16),
    CHANNEL_METADATA(0x17),
    NOISE_HANDSHAKE_FINAL(0x18),
    VERSION_HELLO(0x20),
    VERSION_ACK(0x21),
    PROTOCOL_ACK(0x22),
    PROTOCOL_NACK(0x23),
    SYSTEM_VALIDATION(0x24),
    HANDSHAKE_REQUEST(0x25),
    FAVORITED(0x30),
    UNFAVORITED(0x31);

    public final byte value;

    MessageType(int v) { this.value = (byte) v; }

    /**
     * Decode a wire byte to a MessageType. Legacy 0x04 aliases to
     * MESSAGE so a rolling upgrade across the fork doesn't strand
     * older nodes.
     *
     * @throws UnknownMessageTypeException on any value not in the table.
     */
    public static MessageType fromByte(byte b) throws UnknownMessageTypeException {
        int i = b & 0xFF;
        switch (i) {
            case 0x01: return ANNOUNCE;
            case 0x02: case 0x04: return MESSAGE;
            case 0x03: return LEAVE;
            case 0x05: return FRAGMENT_START;
            case 0x06: return FRAGMENT_CONTINUE;
            case 0x07: return FRAGMENT_END;
            case 0x08: return CHANNEL_ANNOUNCE;
            case 0x09: return CHANNEL_RETENTION;
            case 0x0A: return DELIVERY_ACK;
            case 0x0B: return DELIVERY_STATUS_REQUEST;
            case 0x0C: return READ_RECEIPT;
            case 0x10: return NOISE_HANDSHAKE_INIT;
            case 0x11: return NOISE_HANDSHAKE_RESP;
            case 0x12: return NOISE_ENCRYPTED;
            case 0x13: return NOISE_IDENTITY_ANNOUNCE;
            case 0x14: return CHANNEL_KEY_VERIFY_REQUEST;
            case 0x15: return CHANNEL_KEY_VERIFY_RESPONSE;
            case 0x16: return CHANNEL_PASSWORD_UPDATE;
            case 0x17: return CHANNEL_METADATA;
            case 0x18: return NOISE_HANDSHAKE_FINAL;
            case 0x20: return VERSION_HELLO;
            case 0x21: return VERSION_ACK;
            case 0x22: return PROTOCOL_ACK;
            case 0x23: return PROTOCOL_NACK;
            case 0x24: return SYSTEM_VALIDATION;
            case 0x25: return HANDSHAKE_REQUEST;
            case 0x30: return FAVORITED;
            case 0x31: return UNFAVORITED;
        }
        throw new UnknownMessageTypeException(b);
    }

    public static final class UnknownMessageTypeException extends Exception {
        public final byte value;
        UnknownMessageTypeException(byte v) {
            super(String.format("unknown message type 0x%02x", v & 0xFF));
            this.value = v;
        }
    }
}
