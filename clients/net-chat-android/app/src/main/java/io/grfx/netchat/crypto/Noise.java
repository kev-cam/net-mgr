package io.grfx.netchat.crypto;

import com.google.crypto.tink.subtle.Hkdf;
import com.google.crypto.tink.subtle.X25519;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Noise Protocol Framework — pattern {@code Noise_XX_25519_ChaChaPoly_SHA256}.
 * The pattern:
 *
 * <pre>
 *   XX:
 *     -&gt; e
 *     &lt;- e, ee, s, es
 *     -&gt; s, se
 * </pre>
 *
 * <p>This class holds one side's state — call {@link Initiator} or
 * {@link Responder} to build one, hand inbound frames via
 * {@link Session#readMessage(byte[])} and pull outbound frames via
 * {@link Session#writeMessage(byte[])}. When {@link Session#isEstablished()}
 * flips true the transport ciphers are ready — encrypt via
 * {@link Session#encrypt(byte[])}, decrypt via {@link Session#decrypt(byte[])}.
 *
 * <p>Wire-compatible with {@code snow} (Rust) and {@code flynn/noise}
 * (Go) — those are the libraries bitchat-rust and our earlier Go port
 * used, so a Java initiator can complete a handshake against a Rust
 * responder byte-for-byte.
 */
public final class Noise {
    private Noise() {}

    private static final byte[] PROTOCOL_NAME =
            "Noise_XX_25519_ChaChaPoly_SHA256".getBytes();

    private static final int DHLEN = 32;
    private static final int HASHLEN = 32;
    private static final int KEYLEN = 32;
    private static final int TAGLEN = 16;

    // ---- SymmetricState -------------------------------------------------
    private static final class SymmetricState {
        byte[] ck = new byte[HASHLEN];
        byte[] h  = new byte[HASHLEN];
        CipherState cipher = new CipherState();

        SymmetricState() {
            byte[] name = PROTOCOL_NAME;
            if (name.length <= HASHLEN) {
                h = Arrays.copyOf(name, HASHLEN);         // right-pad with zeros
            } else {
                h = sha256(name);
            }
            ck = h.clone();
        }

        void mixHash(byte[] data) {
            byte[] cat = concat(h, data);
            h = sha256(cat);
        }

        void mixKey(byte[] input) {
            byte[][] out = hkdf(ck, input, 2);
            ck = out[0];
            cipher.initializeKey(truncateOrPad(out[1]));
        }

        byte[] encryptAndHash(byte[] plaintext) throws GeneralSecurityException {
            byte[] ct = cipher.encryptWithAd(h, plaintext);
            mixHash(ct);
            return ct;
        }

        byte[] decryptAndHash(byte[] ciphertext) throws GeneralSecurityException {
            byte[] pt = cipher.decryptWithAd(h, ciphertext);
            mixHash(ciphertext);
            return pt;
        }

        /** Split at handshake end into two transport CipherStates. */
        CipherState[] split() {
            byte[][] out = hkdf(ck, new byte[0], 2);
            CipherState c1 = new CipherState();
            CipherState c2 = new CipherState();
            c1.initializeKey(truncateOrPad(out[0]));
            c2.initializeKey(truncateOrPad(out[1]));
            return new CipherState[]{c1, c2};
        }
    }

    // ---- CipherState ----------------------------------------------------
    private static final class CipherState {
        byte[] key;                     // 32 bytes when set
        long nonce;                     // little-endian 64-bit counter

        void initializeKey(byte[] k) { this.key = k; this.nonce = 0; }
        boolean hasKey() { return key != null; }

        byte[] encryptWithAd(byte[] ad, byte[] plaintext) throws GeneralSecurityException {
            if (!hasKey()) return plaintext.clone();      // pre-key stage — passthrough
            byte[] ct = chachaPolyOp(Cipher.ENCRYPT_MODE, key, nonce12(), ad, plaintext);
            nonce++;
            return ct;
        }

        byte[] decryptWithAd(byte[] ad, byte[] ciphertext) throws GeneralSecurityException {
            if (!hasKey()) return ciphertext.clone();
            byte[] pt = chachaPolyOp(Cipher.DECRYPT_MODE, key, nonce12(), ad, ciphertext);
            nonce++;
            return pt;
        }

        private byte[] nonce12() {
            // ChaChaPoly nonce = 4 zero bytes || 8-byte LE counter.
            byte[] n = new byte[12];
            for (int i = 0; i < 8; i++) n[4 + i] = (byte) ((nonce >>> (8 * i)) & 0xFF);
            return n;
        }
    }

    // ---- Handshake state, exposed to callers via Session ----------------

    public static abstract class Session {
        final SymmetricState sym = new SymmetricState();
        byte[] ephPriv;                 // local ephemeral
        byte[] ephPub;
        byte[] staticPriv;              // local static
        byte[] staticPub;
        byte[] remoteEphPub;
        byte[] remoteStaticPub;
        int msgIndex;                   // number of handshake messages processed
        boolean established;
        CipherState send, recv;

        Session(byte[] staticPriv, byte[] staticPub, byte[] prologue) {
            this.staticPriv = staticPriv;
            this.staticPub = staticPub;
            if (prologue != null && prologue.length > 0) sym.mixHash(prologue);
        }

        /** True once the handshake produced transport CipherStates. */
        public boolean isEstablished() { return established; }

        /** Remote's static public key — only valid after the handshake
         *  has revealed it. Returns null pre-reveal. */
        public byte[] remoteStaticPublicKey() {
            return remoteStaticPub == null ? null : remoteStaticPub.clone();
        }

        /** Called by subclasses when the handshake pattern reaches the
         *  end. Splits ck into two CipherStates and clears interim
         *  state. */
        void promoteToTransport(boolean initiator) {
            CipherState[] pair = sym.split();
            if (initiator) {
                send = pair[0]; recv = pair[1];
            } else {
                send = pair[1]; recv = pair[0];
            }
            established = true;
            // Wipe handshake material we don't need any more.
            ephPriv = null;
        }

        /** Transport encrypt for post-handshake sending. */
        public byte[] encrypt(byte[] plaintext) throws GeneralSecurityException {
            if (!established) throw new IllegalStateException("handshake not complete");
            return send.encryptWithAd(new byte[0], plaintext);
        }

        /** Transport decrypt for post-handshake receiving. */
        public byte[] decrypt(byte[] ciphertext) throws GeneralSecurityException {
            if (!established) throw new IllegalStateException("handshake not complete");
            return recv.decryptWithAd(new byte[0], ciphertext);
        }

        /** Produce the next outbound handshake frame. Returns null if
         *  it's not our turn (or if the handshake is done). */
        public abstract byte[] writeMessage(byte[] payload) throws GeneralSecurityException;

        /** Consume an inbound handshake frame. Returns the (possibly
         *  empty) plaintext payload the peer sent along. */
        public abstract byte[] readMessage(byte[] frame) throws GeneralSecurityException;
    }

    // ---- Initiator (XX pattern) ----------------------------------------
    public static final class Initiator extends Session {
        public Initiator(byte[] staticPriv, byte[] staticPub) {
            this(staticPriv, staticPub, null);
        }
        public Initiator(byte[] staticPriv, byte[] staticPub, byte[] prologue) {
            super(staticPriv, staticPub, prologue);
        }

        @Override
        public byte[] writeMessage(byte[] payload) throws GeneralSecurityException {
            if (payload == null) payload = new byte[0];
            switch (msgIndex) {
                case 0: {
                    // -> e
                    genEphemeral();
                    sym.mixHash(ephPub);
                    byte[] pt = sym.encryptAndHash(payload);
                    msgIndex++;
                    return concat(ephPub, pt);
                }
                case 2: {
                    // -> s, se
                    byte[] encStatic = sym.encryptAndHash(staticPub);
                    sym.mixKey(dh(staticPriv, remoteEphPub));
                    byte[] pt = sym.encryptAndHash(payload);
                    msgIndex++;
                    promoteToTransport(true);
                    return concat(encStatic, pt);
                }
                default:
                    return null;
            }
        }

        @Override
        public byte[] readMessage(byte[] frame) throws GeneralSecurityException {
            switch (msgIndex) {
                case 1: {
                    // <- e, ee, s, es
                    int off = 0;
                    remoteEphPub = Arrays.copyOfRange(frame, off, off + DHLEN); off += DHLEN;
                    sym.mixHash(remoteEphPub);
                    sym.mixKey(dh(ephPriv, remoteEphPub));

                    int sEncLen = DHLEN + TAGLEN;
                    byte[] encRs = Arrays.copyOfRange(frame, off, off + sEncLen); off += sEncLen;
                    remoteStaticPub = sym.decryptAndHash(encRs);
                    sym.mixKey(dh(ephPriv, remoteStaticPub));

                    byte[] payloadCt = Arrays.copyOfRange(frame, off, frame.length);
                    byte[] payload = sym.decryptAndHash(payloadCt);
                    msgIndex++;
                    return payload;
                }
                default:
                    throw new IllegalStateException("initiator has no read at msg " + msgIndex);
            }
        }

        private void genEphemeral() throws GeneralSecurityException {
            byte[] priv = randomBytes(32);
            // RFC 7748 clamp for X25519.
            priv[0]  &= (byte) 0xF8;
            priv[31] &= (byte) 0x7F;
            priv[31] |= (byte) 0x40;
            ephPriv = priv;
            ephPub  = X25519.publicFromPrivate(priv);
        }
    }

    // ---- Responder (XX pattern) ----------------------------------------
    public static final class Responder extends Session {
        public Responder(byte[] staticPriv, byte[] staticPub) {
            this(staticPriv, staticPub, null);
        }
        public Responder(byte[] staticPriv, byte[] staticPub, byte[] prologue) {
            super(staticPriv, staticPub, prologue);
        }

        @Override
        public byte[] readMessage(byte[] frame) throws GeneralSecurityException {
            switch (msgIndex) {
                case 0: {
                    // <- e (from initiator)
                    remoteEphPub = Arrays.copyOfRange(frame, 0, DHLEN);
                    sym.mixHash(remoteEphPub);
                    byte[] payload = sym.decryptAndHash(
                            Arrays.copyOfRange(frame, DHLEN, frame.length));
                    msgIndex++;
                    return payload;
                }
                case 2: {
                    // <- s, se (last handshake frame from initiator)
                    int sEncLen = DHLEN + TAGLEN;
                    byte[] encRs = Arrays.copyOfRange(frame, 0, sEncLen);
                    remoteStaticPub = sym.decryptAndHash(encRs);
                    sym.mixKey(dh(ephPriv, remoteStaticPub));

                    byte[] payload = sym.decryptAndHash(
                            Arrays.copyOfRange(frame, sEncLen, frame.length));
                    msgIndex++;
                    promoteToTransport(false);
                    return payload;
                }
                default:
                    throw new IllegalStateException("responder has no read at msg " + msgIndex);
            }
        }

        @Override
        public byte[] writeMessage(byte[] payload) throws GeneralSecurityException {
            if (payload == null) payload = new byte[0];
            switch (msgIndex) {
                case 1: {
                    // -> e, ee, s, es
                    genEphemeral();
                    sym.mixHash(ephPub);
                    sym.mixKey(dh(ephPriv, remoteEphPub));

                    byte[] encStatic = sym.encryptAndHash(staticPub);
                    sym.mixKey(dh(staticPriv, remoteEphPub));

                    byte[] pt = sym.encryptAndHash(payload);
                    msgIndex++;
                    return concat(ephPub, encStatic, pt);
                }
                default:
                    return null;
            }
        }

        private void genEphemeral() throws GeneralSecurityException {
            byte[] priv = randomBytes(32);
            priv[0]  &= (byte) 0xF8;
            priv[31] &= (byte) 0x7F;
            priv[31] |= (byte) 0x40;
            ephPriv = priv;
            ephPub  = X25519.publicFromPrivate(priv);
        }
    }

    // ---- primitives -----------------------------------------------------

    private static byte[] dh(byte[] priv, byte[] pub) throws GeneralSecurityException {
        return X25519.computeSharedSecret(priv, pub);
    }

    /** ChaCha20-Poly1305 via JDK Cipher API (Android API 28+ / Java 11+).
     *  Output on encrypt is {@code ct || tag} (no leading nonce); input on
     *  decrypt expects the same. That's the Noise-Framework on-wire format. */
    private static byte[] chachaPolyOp(int mode, byte[] key, byte[] nonce,
                                       byte[] ad, byte[] data)
            throws GeneralSecurityException {
        Cipher c = Cipher.getInstance("ChaCha20-Poly1305");
        c.init(mode,
                new SecretKeySpec(key, "ChaCha20"),
                new IvParameterSpec(nonce));
        if (ad != null && ad.length > 0) c.updateAAD(ad);
        try {
            return c.doFinal(data);
        } catch (javax.crypto.IllegalBlockSizeException | javax.crypto.BadPaddingException e) {
            throw new GeneralSecurityException(e);
        }
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** HKDF-SHA-256 producing {@code n} 32-byte outputs. */
    private static byte[][] hkdf(byte[] salt, byte[] ikm, int n) {
        try {
            byte[] full = Hkdf.computeHkdf("HMACSHA256", ikm, salt, new byte[0], n * HASHLEN);
            byte[][] out = new byte[n][HASHLEN];
            for (int i = 0; i < n; i++) {
                System.arraycopy(full, i * HASHLEN, out[i], 0, HASHLEN);
            }
            return out;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HKDF failure", e);
        }
    }

    private static byte[] truncateOrPad(byte[] a) {
        if (a.length == KEYLEN) return a;
        byte[] out = new byte[KEYLEN];
        System.arraycopy(a, 0, out, 0, Math.min(a.length, KEYLEN));
        return out;
    }

    private static byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] p : parts) total += p.length;
        byte[] out = new byte[total];
        int off = 0;
        for (byte[] p : parts) { System.arraycopy(p, 0, out, off, p.length); off += p.length; }
        return out;
    }

    private static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        new SecureRandom().nextBytes(b);
        return b;
    }
}
