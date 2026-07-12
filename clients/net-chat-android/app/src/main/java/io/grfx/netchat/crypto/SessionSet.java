package io.grfx.netchat.crypto;

import java.util.HashMap;
import java.util.Map;

/**
 * Thread-safe registry of Noise sessions keyed by peer_id (16 hex chars).
 * Callers hand out session references; the set owns lifetime.
 */
public final class SessionSet {
    private final Map<String, Noise.Session> byPeer = new HashMap<>();

    public synchronized void set(String peerIdHex, Noise.Session session) {
        byPeer.put(peerIdHex, session);
    }

    public synchronized Noise.Session get(String peerIdHex) {
        return byPeer.get(peerIdHex);
    }

    public synchronized void drop(String peerIdHex) {
        byPeer.remove(peerIdHex);
    }

    public synchronized boolean isEstablished(String peerIdHex) {
        Noise.Session s = byPeer.get(peerIdHex);
        return s != null && s.isEstablished();
    }
}
