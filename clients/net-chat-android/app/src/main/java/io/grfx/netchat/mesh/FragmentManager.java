package io.grfx.netchat.mesh;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * Reassembles fragmented packets. iOS/Android + bitchat-rust all
 * slice packets larger than the BLE MTU into pieces of at most
 * {@value #MAX_FRAGMENT_SIZE} bytes. Wire layout of each fragment
 * payload:
 *
 * <pre>
 *   0..7   fragment id      (8 bytes; hex form = "message id")
 *   8..9   fragment index   (BE u16)
 *  10..11  total fragments  (BE u16)
 *  12      original type    (u8)
 *  13..N   fragment data
 * </pre>
 *
 * <p>Groups older than {@link #TIMEOUT_MILLIS} are evicted whenever a
 * new fragment is added.
 */
public final class FragmentManager {
    public static final int MAX_FRAGMENT_SIZE = 512;
    private static final long TIMEOUT_MILLIS = 30_000L;

    public static final class Header {
        public final String messageId;
        public final int fragmentIndex;
        public final int totalFragments;

        public Header(String id, int idx, int total) {
            this.messageId = id;
            this.fragmentIndex = idx;
            this.totalFragments = total;
        }
    }

    private static final class Group {
        final Map<Integer, byte[]> pieces = new HashMap<>();
        final int total;
        final byte originalType;
        final long addedAtMillis;

        Group(int total, byte originalType) {
            this.total = total;
            this.originalType = originalType;
            this.addedAtMillis = System.currentTimeMillis();
        }
    }

    private final Map<String, Group> groups = new HashMap<>();

    /**
     * Store one fragment. Returns the reassembled full payload once
     * the last fragment lands; otherwise null.
     *
     * @throws ProtocolException on total mismatch / bad index /
     *                           missing fragment during reassembly.
     */
    public synchronized byte[] addFragment(Header h, byte originalType, byte[] data)
            throws ProtocolException {
        cleanupExpiredLocked();
        Group g = groups.get(h.messageId);
        if (g == null) {
            g = new Group(h.totalFragments, originalType);
            groups.put(h.messageId, g);
        }
        if (h.totalFragments != g.total) {
            throw new ProtocolException("fragment count mismatch");
        }
        if (h.fragmentIndex < 0 || h.fragmentIndex >= h.totalFragments) {
            throw new ProtocolException("invalid fragment index");
        }
        g.pieces.put(h.fragmentIndex, data);
        if (g.pieces.size() != g.total) return null;

        // All present — reassemble in-order.
        int total = 0;
        for (int i = 0; i < g.total; i++) {
            byte[] p = g.pieces.get(i);
            if (p == null) throw new ProtocolException("missing fragment " + i);
            total += p.length;
        }
        ByteArrayOutputStream buf = new ByteArrayOutputStream(total);
        for (int i = 0; i < g.total; i++) buf.write(g.pieces.get(i), 0, g.pieces.get(i).length);
        groups.remove(h.messageId);
        return buf.toByteArray();
    }

    private void cleanupExpiredLocked() {
        long cutoff = System.currentTimeMillis() - TIMEOUT_MILLIS;
        for (Iterator<Map.Entry<String, Group>> it = groups.entrySet().iterator(); it.hasNext(); ) {
            if (it.next().getValue().addedAtMillis < cutoff) it.remove();
        }
    }

    // ---- codec helpers (also used to build outbound fragments) ----------

    /** Wrap one fragment's data in the 13-byte header. */
    public static byte[] encodePayload(byte[] fragmentId8, int index, int total,
                                       byte originalType, byte[] data) {
        if (fragmentId8.length != 8) throw new IllegalArgumentException("fragment id must be 8 bytes");
        byte[] out = new byte[13 + data.length];
        System.arraycopy(fragmentId8, 0, out, 0, 8);
        out[8]  = (byte) ((index >>> 8) & 0xFF);
        out[9]  = (byte) (index & 0xFF);
        out[10] = (byte) ((total >>> 8) & 0xFF);
        out[11] = (byte) (total & 0xFF);
        out[12] = originalType;
        System.arraycopy(data, 0, out, 13, data.length);
        return out;
    }

    /** Parse the 13-byte header off a fragment payload. */
    public static Decoded decodePayload(byte[] data) throws ProtocolException {
        if (data.length < 13) throw new ProtocolException("fragment payload too small");
        StringBuilder sb = new StringBuilder(16);
        for (int i = 0; i < 8; i++) sb.append(String.format("%02x", data[i] & 0xFF));
        int idx   = ((data[8]  & 0xFF) << 8) | (data[9]  & 0xFF);
        int total = ((data[10] & 0xFF) << 8) | (data[11] & 0xFF);
        byte origType = data[12];
        byte[] body = new byte[data.length - 13];
        System.arraycopy(data, 13, body, 0, body.length);
        return new Decoded(new Header(sb.toString(), idx, total), origType, body);
    }

    public static final class Decoded {
        public final Header header;
        public final byte originalType;
        public final byte[] data;

        Decoded(Header header, byte originalType, byte[] data) {
            this.header = header;
            this.originalType = originalType;
            this.data = data;
        }
    }

    /** Slice a large wire packet into fragments the peer can Reassemble. */
    public static List<byte[]> slice(byte[] fragmentId8, byte originalType, byte[] wholeWire) {
        List<byte[]> parts = new ArrayList<>();
        int chunk = MAX_FRAGMENT_SIZE - 13;
        int total = (wholeWire.length + chunk - 1) / chunk;
        for (int i = 0; i < total; i++) {
            int start = i * chunk;
            int end = Math.min(start + chunk, wholeWire.length);
            byte[] piece = new byte[end - start];
            System.arraycopy(wholeWire, start, piece, 0, piece.length);
            parts.add(encodePayload(fragmentId8, i, total, originalType, piece));
        }
        return parts;
    }

    public static final class ProtocolException extends Exception {
        public ProtocolException(String msg) { super(msg); }
    }
}
