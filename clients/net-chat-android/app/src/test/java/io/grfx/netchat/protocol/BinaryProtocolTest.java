package io.grfx.netchat.protocol;

import org.junit.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.Assert.*;

/**
 * Byte-for-byte round-trip: encode a Packet and decode it back,
 * verifying every wire field survives. Covers every MessageType so an
 * enum-table mismatch would fail loud.
 */
public class BinaryProtocolTest {

    @Test
    public void roundtrip_every_message_type() throws Exception {
        for (MessageType type : MessageType.values()) {
            Packet p = Packet.outbound(type, senderId(), payloadFor(type));
            p.ttl = 3;
            byte[] wire = BinaryProtocol.encode(p);
            Packet q = BinaryProtocol.decode(wire);

            assertEquals("version " + type, p.version, q.version);
            assertEquals("type " + type, p.messageType, q.messageType);
            assertEquals("ttl " + type, p.ttl, q.ttl);
            assertEquals("ts " + type, p.timestampMillis, q.timestampMillis);
            assertArrayEquals("sender " + type, p.senderId, q.senderId);
            assertArrayEquals("payload " + type, p.payload, q.payload);
        }
    }

    @Test
    public void roundtrip_with_recipient() throws Exception {
        Packet p = Packet.outbound(MessageType.NOISE_ENCRYPTED, senderId(), new byte[]{1, 2, 3});
        p.withRecipient(new byte[]{10, 11, 12, 13, 14, 15, 16, 17});
        byte[] wire = BinaryProtocol.encode(p);
        Packet q = BinaryProtocol.decode(wire);

        assertTrue("has_recipient decoded", q.flags.hasRecipient);
        assertArrayEquals("recipient", p.recipientId, q.recipientId);
        assertArrayEquals("payload", p.payload, q.payload);
    }

    @Test
    public void roundtrip_with_signature() throws Exception {
        Packet p = Packet.outbound(MessageType.ANNOUNCE, senderId(), "hi".getBytes(StandardCharsets.UTF_8));
        byte[] sig = new byte[64];
        for (int i = 0; i < 64; i++) sig[i] = (byte) i;
        p.withSignature(sig);
        byte[] wire = BinaryProtocol.encode(p);
        Packet q = BinaryProtocol.decode(wire);

        assertTrue("has_signature decoded", q.flags.hasSignature);
        assertArrayEquals("signature bytes", sig, q.signature);
    }

    @Test
    public void encode_padded_to_optimal_block() throws Exception {
        Packet p = Packet.outbound(MessageType.ANNOUNCE, senderId(), new byte[]{0x01, 0x03, 'b', 'o', 'b'});
        byte[] wire = BinaryProtocol.encode(p);
        // header 13 + sender 8 + payload 5 = 26 → padded to 256
        assertEquals("padded to 256-byte block", 256, wire.length);
    }

    @Test
    public void encodeForSigning_zeroes_ttl_and_drops_signature() throws Exception {
        Packet p = Packet.outbound(MessageType.ANNOUNCE, senderId(), new byte[]{0x01, 0x03, 'b', 'o', 'b'});
        p.ttl = 7;
        byte[] sig = new byte[64];
        p.withSignature(sig);
        byte[] canonical = BinaryProtocol.encodeForSigning(p);
        Packet q = BinaryProtocol.decode(canonical);
        assertEquals("ttl zeroed", 0, q.ttl);
        assertFalse("signature flag cleared", q.flags.hasSignature);
        assertNull("signature dropped", q.signature);
    }

    @Test(expected = BinaryProtocol.ProtocolException.class)
    public void bad_sender_length_rejected() throws Exception {
        Packet p = new Packet();
        p.messageType = MessageType.ANNOUNCE;
        p.senderId = new byte[7];                       // wrong length
        p.payload = new byte[0];
        BinaryProtocol.encode(p);
    }

    private static byte[] senderId() {
        return new byte[]{(byte) 0xAA, (byte) 0xBB, (byte) 0xCC, (byte) 0xDD,
                          (byte) 0xEE, (byte) 0xFF, 0x00, 0x11};
    }

    private static byte[] payloadFor(MessageType t) {
        // A tiny distinctive payload per type so decode returns the same bytes.
        return new byte[]{(byte) (t.value & 0xFF), 0x01, 0x02, 0x03};
    }
}
