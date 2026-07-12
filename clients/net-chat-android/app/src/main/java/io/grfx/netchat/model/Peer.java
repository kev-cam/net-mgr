package io.grfx.netchat.model;

/**
 * Roster entry for a remote BitChat participant. Mutable POJO — the
 * peer manager owns instances and updates them in place when new
 * announces arrive.
 */
public final class Peer {
    public final String peerIdHex;          // 16 chars lowercase hex
    public String nickname;                 // null ⇒ never announced one
    public long lastSeenMillis;
    public boolean connected;               // true while GATT link is up
    public byte[] staticPublicKey;          // curve25519, null until IdentityAnnounce
    public String fingerprint;              // SHA-256(static_pk) hex, null until keyed

    public Peer(String peerIdHex) {
        this.peerIdHex = peerIdHex;
        this.lastSeenMillis = System.currentTimeMillis();
    }

    public String displayName() {
        return nickname == null || nickname.isEmpty() ? peerIdHex : nickname;
    }

    public void touch() { this.lastSeenMillis = System.currentTimeMillis(); }
}
