package io.grfx.netchat.mesh;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import io.grfx.netchat.model.Peer;

/**
 * Tracks known peers keyed by 16-hex peer_id. Emits change events to a
 * single {@link Listener} — the UI subscribes and re-renders the
 * roster whenever anything moves.
 *
 * <p>Thread-safe via one coarse lock; the peer set is small enough
 * (dozens, not thousands) that finer locking would be overkill.
 */
public final class PeerManager {

    public interface Listener {
        void onPeerChanged(Peer peer);
        void onPeerRemoved(String peerIdHex);
    }

    private final Map<String, Peer> byId = new HashMap<>();
    private Listener listener;

    public synchronized void setListener(Listener l) { this.listener = l; }

    /** Insert or refresh a peer, touching last-seen. */
    public void addOrTouch(String peerIdHex) {
        Peer p;
        synchronized (this) {
            p = byId.get(peerIdHex);
            if (p == null) {
                p = new Peer(peerIdHex);
                byId.put(peerIdHex, p);
            } else {
                p.touch();
            }
        }
        fire(p);
    }

    public void setConnected(String peerIdHex, boolean connected) {
        Peer p;
        synchronized (this) {
            p = byId.get(peerIdHex);
            if (p == null) return;
            p.connected = connected;
            if (connected) p.touch();
        }
        fire(p);
    }

    public void setNickname(String peerIdHex, String nickname) {
        Peer p;
        synchronized (this) {
            p = byId.get(peerIdHex);
            if (p == null) return;
            if (nickname == null || nickname.isEmpty()) return;
            p.nickname = nickname;
        }
        fire(p);
    }

    /**
     * Stamp the curve25519 static pubkey and derive a SHA-256
     * fingerprint. Used by the UI's trust view.
     */
    public void setStaticKey(String peerIdHex, byte[] pubkey) {
        Peer p;
        synchronized (this) {
            p = byId.get(peerIdHex);
            if (p == null || pubkey == null) return;
            p.staticPublicKey = pubkey.clone();
            try {
                byte[] fp = MessageDigest.getInstance("SHA-256").digest(pubkey);
                StringBuilder sb = new StringBuilder(fp.length * 2);
                for (byte b : fp) sb.append(String.format("%02x", b));
                p.fingerprint = sb.toString();
            } catch (java.security.NoSuchAlgorithmException ignored) {
                // SHA-256 is a JDK guarantee; if it's missing we have
                // bigger problems than a null fingerprint.
            }
        }
        fire(p);
    }

    public synchronized Peer get(String peerIdHex) {
        Peer p = byId.get(peerIdHex);
        return p == null ? null : snapshot(p);
    }

    public synchronized List<Peer> all() {
        List<Peer> out = new ArrayList<>(byId.size());
        for (Peer p : byId.values()) out.add(snapshot(p));
        out.sort(Comparator
                .comparing((Peer p) -> !p.connected)                        // connected first
                .thenComparing(p -> p.displayName().toLowerCase()));
        return out;
    }

    /**
     * Mark connected peers we haven't heard from in {@code timeoutMillis}
     * as disconnected. Returns the affected peer ids so the caller can
     * fire UI updates.
     */
    public List<String> pruneStale(long timeoutMillis) {
        List<Peer> changed = new ArrayList<>();
        long cutoff = System.currentTimeMillis() - timeoutMillis;
        synchronized (this) {
            for (Iterator<Peer> it = byId.values().iterator(); it.hasNext(); ) {
                Peer p = it.next();
                if (p.connected && p.lastSeenMillis < cutoff) {
                    p.connected = false;
                    changed.add(p);
                }
            }
        }
        List<String> ids = new ArrayList<>(changed.size());
        for (Peer p : changed) { fire(p); ids.add(p.peerIdHex); }
        return ids;
    }

    private void fire(Peer p) {
        Listener l;
        Peer snap;
        synchronized (this) {
            l = listener;
            snap = snapshot(p);
        }
        if (l != null) l.onPeerChanged(snap);
    }

    private static Peer snapshot(Peer p) {
        Peer copy = new Peer(p.peerIdHex);
        copy.nickname = p.nickname;
        copy.lastSeenMillis = p.lastSeenMillis;
        copy.connected = p.connected;
        copy.staticPublicKey = p.staticPublicKey;
        copy.fingerprint = p.fingerprint;
        return copy;
    }
}
