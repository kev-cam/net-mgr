package io.grfx.netchat.model;

import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.*;

/**
 * Payload round-trip with all optional-field combinations.
 */
public class BitchatMessageTest {

    @Test
    public void minimal_roundtrip() throws Exception {
        BitchatMessage m = BitchatMessage.now("alice", "hello world");
        BitchatMessage r = BitchatMessage.fromBinaryPayload(m.toBinaryPayload());
        assertEquals(m.id, r.id);
        assertEquals(m.sender, r.sender);
        assertEquals(m.content, r.content);
        assertEquals(m.timestampMillis, r.timestampMillis);
        assertFalse(r.isPrivate);
        assertFalse(r.isRelay);
        assertNull(r.channel);
        assertNull(r.mentions);
    }

    @Test
    public void private_flag_survives() throws Exception {
        BitchatMessage m = BitchatMessage.now("alice", "shh");
        m.isPrivate = true;
        m.senderPeerId = "aabbccddeeff0011";
        BitchatMessage r = BitchatMessage.fromBinaryPayload(m.toBinaryPayload());
        assertTrue(r.isPrivate);
        assertEquals(m.senderPeerId, r.senderPeerId);
    }

    @Test
    public void relay_and_original_sender() throws Exception {
        BitchatMessage m = BitchatMessage.now("relay-bob", "forwarded");
        m.isRelay = true;
        m.originalSender = "alice";
        BitchatMessage r = BitchatMessage.fromBinaryPayload(m.toBinaryPayload());
        assertTrue(r.isRelay);
        assertEquals("alice", r.originalSender);
    }

    @Test
    public void mentions_channel_and_recipient() throws Exception {
        BitchatMessage m = BitchatMessage.now("alice", "@bob look #general");
        m.channel = "#general";
        m.recipientNickname = "bob";
        m.mentions = Arrays.asList("bob", "carol");
        BitchatMessage r = BitchatMessage.fromBinaryPayload(m.toBinaryPayload());
        assertEquals("#general", r.channel);
        assertEquals("bob", r.recipientNickname);
        assertEquals(Arrays.asList("bob", "carol"), r.mentions);
    }

    @Test
    public void utf8_content_survives() throws Exception {
        BitchatMessage m = BitchatMessage.now("alice", "hallo 🌍 привет");
        BitchatMessage r = BitchatMessage.fromBinaryPayload(m.toBinaryPayload());
        assertEquals("hallo 🌍 привет", r.content);
    }
}
