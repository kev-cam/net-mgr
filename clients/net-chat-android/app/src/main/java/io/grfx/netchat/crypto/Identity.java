package io.grfx.netchat.crypto;

import com.google.crypto.tink.subtle.Ed25519Sign;
import com.google.crypto.tink.subtle.Ed25519Verify;
import com.google.crypto.tink.subtle.X25519;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;

/**
 * BitChat identity. One 32-byte seed drives both:
 *
 * <ul>
 *   <li>Ed25519 signing (seed = Ed25519 private key)</li>
 *   <li>Curve25519 static key for Noise-XX, derived per libsodium's
 *       {@code crypto_sign_ed25519_sk_to_curve25519}:
 *       SHA-512(seed)[0..32], clamped, then scalar-mult with the
 *       base point to get the pubkey.</li>
 * </ul>
 *
 * <p>Matches bitchat-rust src/crypto/snow_noise_service.rs::new and the
 * Go port under internal/bitchat/crypto/identity.go byte-for-byte, so
 * the same seed on any platform produces the same peer_id.
 */
public final class Identity {

    public static final int SEED_LEN = 32;
    public static final int PEER_ID_LEN = 8;

    public final byte[] seed;                       // 32 bytes
    public final byte[] signingPublicKey;           // 32 bytes (Ed25519)
    public final byte[] staticPrivateKey;           // 32 bytes (X25519 clamped)
    public final byte[] staticPublicKey;            // 32 bytes (X25519)
    public final byte[] peerIdRaw;                  // 8 bytes = SHA-256(staticPublic)[:8]
    public final String peerIdHex;                  // 16 lowercase hex chars

    private final Ed25519Sign signer;

    private Identity(byte[] seed, byte[] signingPublic,
                     byte[] staticPriv, byte[] staticPub,
                     Ed25519Sign signer) {
        this.seed = seed;
        this.signingPublicKey = signingPublic;
        this.staticPrivateKey = staticPriv;
        this.staticPublicKey = staticPub;
        this.signer = signer;
        try {
            byte[] sum = MessageDigest.getInstance("SHA-256").digest(staticPub);
            this.peerIdRaw = new byte[PEER_ID_LEN];
            System.arraycopy(sum, 0, this.peerIdRaw, 0, PEER_ID_LEN);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
        StringBuilder sb = new StringBuilder(PEER_ID_LEN * 2);
        for (byte b : this.peerIdRaw) sb.append(String.format("%02x", b & 0xFF));
        this.peerIdHex = sb.toString();
    }

    /** Build from an explicit seed. */
    public static Identity fromSeed(byte[] seed) throws GeneralSecurityException {
        if (seed == null || seed.length != SEED_LEN) {
            throw new IllegalArgumentException("seed must be " + SEED_LEN + " bytes");
        }
        // Ed25519: seed IS the private key material in Tink's API.
        Ed25519Sign.KeyPair edKp = Ed25519Sign.KeyPair.newKeyPairFromSeed(seed);
        byte[] edPub = edKp.getPublicKey();
        Ed25519Sign signer = new Ed25519Sign(seed);

        // Curve25519 static: SHA-512(seed)[0..32], then RFC 7748 clamp.
        byte[] hash = MessageDigest.getInstance("SHA-512").digest(seed);
        byte[] staticPriv = new byte[32];
        System.arraycopy(hash, 0, staticPriv, 0, 32);
        staticPriv[0]  &= (byte) 0xF8;
        staticPriv[31] &= (byte) 0x7F;
        staticPriv[31] |= (byte) 0x40;
        byte[] staticPub = X25519.publicFromPrivate(staticPriv);

        return new Identity(seed.clone(), edPub, staticPriv, staticPub, signer);
    }

    /** Fresh ephemeral identity for boxes that don't persist state. */
    public static Identity ephemeral() throws GeneralSecurityException {
        byte[] seed = new byte[SEED_LEN];
        new SecureRandom().nextBytes(seed);
        return fromSeed(seed);
    }

    public byte[] sign(byte[] message) throws GeneralSecurityException {
        return signer.sign(message);
    }

    public static boolean verify(byte[] publicKey, byte[] message, byte[] signature) {
        try {
            new Ed25519Verify(publicKey).verify(signature, message);
            return true;
        } catch (GeneralSecurityException e) {
            return false;
        }
    }
}
