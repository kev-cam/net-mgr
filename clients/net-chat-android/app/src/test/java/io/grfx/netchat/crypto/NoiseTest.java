package io.grfx.netchat.crypto;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.Assert.*;

/**
 * Loopback tests for the Noise-XX state machine. If these pass, the
 * initiator/responder halves at least agree with themselves —
 * cross-implementation compatibility with Rust/iOS still needs a
 * hardware run, but this catches every bug I could catch on-box.
 */
public class NoiseTest {

    @Test
    public void handshake_completes_and_reveals_static_keys() throws Exception {
        Identity a = Identity.ephemeral();
        Identity b = Identity.ephemeral();

        Noise.Initiator init = new Noise.Initiator(a.staticPrivateKey, a.staticPublicKey);
        Noise.Responder resp = new Noise.Responder(b.staticPrivateKey, b.staticPublicKey);

        // -> e
        byte[] msg1 = init.writeMessage(new byte[0]);
        byte[] pl1  = resp.readMessage(msg1);
        assertEquals("payload on msg1", 0, pl1.length);

        // <- e, ee, s, es
        byte[] msg2 = resp.writeMessage(new byte[0]);
        byte[] pl2  = init.readMessage(msg2);
        assertEquals("payload on msg2", 0, pl2.length);

        // -> s, se
        byte[] msg3 = init.writeMessage(new byte[0]);
        byte[] pl3  = resp.readMessage(msg3);
        assertEquals("payload on msg3", 0, pl3.length);

        assertTrue("initiator established", init.isEstablished());
        assertTrue("responder established", resp.isEstablished());

        // Static keys must have been revealed to each side and match.
        assertArrayEquals("initiator sees b's static",
                b.staticPublicKey, init.remoteStaticPublicKey());
        assertArrayEquals("responder sees a's static",
                a.staticPublicKey, resp.remoteStaticPublicKey());
    }

    @Test
    public void transport_encrypt_decrypt_roundtrip() throws Exception {
        Noise.Initiator init = new Noise.Initiator(new byte[32], new byte[32]);
        Noise.Responder resp = new Noise.Responder(new byte[32], new byte[32]);
        // We need real static keys — the dummy zeros above would still
        // "work" for the handshake proper because the DH result is
        // deterministic, but Tink's X25519 rejects an all-zero pubkey.
        // Rebuild with fresh identities:
        Identity a = Identity.ephemeral();
        Identity b = Identity.ephemeral();
        init = new Noise.Initiator(a.staticPrivateKey, a.staticPublicKey);
        resp = new Noise.Responder(b.staticPrivateKey, b.staticPublicKey);
        runHandshake(init, resp);

        // Initiator → Responder
        for (int i = 0; i < 10; i++) {
            byte[] pt = ("hello #" + i).getBytes(StandardCharsets.UTF_8);
            byte[] ct = init.encrypt(pt);
            assertFalse("ciphertext != plaintext", Arrays.equals(pt, ct));
            byte[] roundTrip = resp.decrypt(ct);
            assertArrayEquals("roundtrip[" + i + "]", pt, roundTrip);
        }
        // Responder → Initiator
        for (int i = 0; i < 10; i++) {
            byte[] pt = ("reply #" + i).getBytes(StandardCharsets.UTF_8);
            byte[] ct = resp.encrypt(pt);
            byte[] roundTrip = init.decrypt(ct);
            assertArrayEquals("reply roundtrip[" + i + "]", pt, roundTrip);
        }
    }

    @Test
    public void handshake_payloads_travel_through() throws Exception {
        Identity a = Identity.ephemeral();
        Identity b = Identity.ephemeral();
        Noise.Initiator init = new Noise.Initiator(a.staticPrivateKey, a.staticPublicKey);
        Noise.Responder resp = new Noise.Responder(b.staticPrivateKey, b.staticPublicKey);

        byte[] p1 = "msg1 payload".getBytes(StandardCharsets.UTF_8);
        byte[] p2 = "msg2 payload".getBytes(StandardCharsets.UTF_8);
        byte[] p3 = "msg3 payload".getBytes(StandardCharsets.UTF_8);

        assertArrayEquals(p1, resp.readMessage(init.writeMessage(p1)));
        assertArrayEquals(p2, init.readMessage(resp.writeMessage(p2)));
        assertArrayEquals(p3, resp.readMessage(init.writeMessage(p3)));
    }

    @Test(expected = java.security.GeneralSecurityException.class)
    public void tampered_ciphertext_fails_decrypt() throws Exception {
        Identity a = Identity.ephemeral();
        Identity b = Identity.ephemeral();
        Noise.Initiator init = new Noise.Initiator(a.staticPrivateKey, a.staticPublicKey);
        Noise.Responder resp = new Noise.Responder(b.staticPrivateKey, b.staticPublicKey);
        runHandshake(init, resp);

        byte[] ct = init.encrypt("secret".getBytes(StandardCharsets.UTF_8));
        ct[0] ^= 0x01;                                  // flip one bit
        resp.decrypt(ct);                               // AEAD auth must fail
    }

    private static void runHandshake(Noise.Initiator init, Noise.Responder resp) throws Exception {
        resp.readMessage(init.writeMessage(new byte[0]));
        init.readMessage(resp.writeMessage(new byte[0]));
        resp.readMessage(init.writeMessage(new byte[0]));
    }
}
