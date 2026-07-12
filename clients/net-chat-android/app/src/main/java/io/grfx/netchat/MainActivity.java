package io.grfx.netchat;

import android.Manifest;
import android.annotation.SuppressLint;
import android.bluetooth.BluetoothDevice;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.method.ScrollingMovementMethod;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import io.grfx.netchat.crypto.Identity;
import io.grfx.netchat.crypto.Noise;
import io.grfx.netchat.crypto.SessionSet;
import io.grfx.netchat.mesh.FragmentManager;
import io.grfx.netchat.mesh.PeerManager;
import io.grfx.netchat.model.BitchatMessage;
import io.grfx.netchat.model.Peer;
import io.grfx.netchat.protocol.BinaryProtocol;
import io.grfx.netchat.protocol.MessageType;
import io.grfx.netchat.protocol.Packet;

/**
 * End-to-end wiring:
 * <ol>
 *   <li>Request BLE + notification perms, then start
 *       {@link BitChatService} as a foreground service.</li>
 *   <li>Bring up GATT server, scanner, central. 30 s Announce ticker.</li>
 *   <li>Public messages: proper {@link BitchatMessage} wire form,
 *       auto-fragmented if the packet exceeds the BLE MTU.</li>
 *   <li>DMs: type {@code @<16hex> body}. First DM to a peer starts a
 *       Noise-XX handshake ({@link Noise.Initiator}); subsequent DMs
 *       encrypt via the established session.</li>
 * </ol>
 */
public class MainActivity extends AppCompatActivity
        implements BitChatService.Bridge {

    private static final int REQ_PERMISSIONS = 42;
    private static final long ANNOUNCE_INTERVAL_MS = 30_000L;

    private TextView log;
    private TextView peersView;
    private EditText compose;
    private BitChatGattServer peripheral;
    private BitChatScanner scanner;
    private BitChatCentral central;
    private ScheduledExecutorService ticker;

    private final PeerManager peers = new PeerManager();
    private final FragmentManager fragments = new FragmentManager();
    private final SessionSet sessions = new SessionSet();
    private final Map<String, List<String>> pendingDMs = new HashMap<>();
    private Identity identity;
    private String nickname;

    private final Handler ui = new Handler(Looper.getMainLooper());
    private final SimpleDateFormat ts = new SimpleDateFormat("HH:mm:ss", Locale.US);

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        log = findViewById(R.id.log);
        log.setMovementMethod(new ScrollingMovementMethod());
        peersView = findViewById(R.id.peers);
        peersView.setMovementMethod(new ScrollingMovementMethod());
        compose = findViewById(R.id.compose);

        Button startBtn = findViewById(R.id.start);
        Button stopBtn = findViewById(R.id.stop);
        Button postBtn = findViewById(R.id.post);
        startBtn.setOnClickListener(v -> requestAndStart());
        stopBtn.setOnClickListener(v -> stopService());
        postBtn.setOnClickListener(v -> {
            String txt = compose.getText().toString().trim();
            if (!txt.isEmpty()) {
                dispatchCompose(txt);
                compose.setText("");
            }
        });

        try {
            identity = Identity.ephemeral();
        } catch (Throwable t) {
            append("identity error: " + t.getMessage());
        }
        nickname = "android-" + (identity != null ? identity.peerIdHex.substring(0, 4) : "?");
        append("peer_id=" + (identity != null ? identity.peerIdHex : "?")
                + "  nick=" + nickname);

        peers.setListener(new PeerManager.Listener() {
            @Override public void onPeerChanged(Peer peer) { renderPeers(); }
            @Override public void onPeerRemoved(String peerIdHex) { renderPeers(); }
        });
    }

    // ---- Service lifecycle -------------------------------------

    private void requestAndStart() {
        String[] perms;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            perms = new String[]{
                    Manifest.permission.BLUETOOTH_SCAN,
                    Manifest.permission.BLUETOOTH_ADVERTISE,
                    Manifest.permission.BLUETOOTH_CONNECT,
                    Manifest.permission.POST_NOTIFICATIONS,
            };
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            perms = new String[]{
                    Manifest.permission.BLUETOOTH_SCAN,
                    Manifest.permission.BLUETOOTH_ADVERTISE,
                    Manifest.permission.BLUETOOTH_CONNECT,
            };
        } else {
            perms = new String[]{Manifest.permission.ACCESS_FINE_LOCATION};
        }
        if (haveAll(perms)) { startBleService(); return; }
        ActivityCompat.requestPermissions(this, perms, REQ_PERMISSIONS);
    }

    private boolean haveAll(String[] perms) {
        for (String p : perms) {
            if (ContextCompat.checkSelfPermission(this, p)
                    != PackageManager.PERMISSION_GRANTED) return false;
        }
        return true;
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions,
                                           int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode != REQ_PERMISSIONS) return;
        for (int r : grantResults) {
            if (r != PackageManager.PERMISSION_GRANTED) {
                append("permission denied");
                return;
            }
        }
        startBleService();
    }

    private void startBleService() {
        BitChatService.setBridge(this);
        Intent i = new Intent(this, BitChatService.class);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(i);
        } else {
            startService(i);
        }
    }

    private void stopService() {
        stopService(new Intent(this, BitChatService.class));
    }

    @Override
    public void onServiceStarted(Context ctx) { ui.post(() -> startAll(ctx)); }
    @Override
    public void onServiceStopped() { ui.post(this::stopAll); }

    // ---- BLE bring-up -------------------------------------------

    @SuppressLint("MissingPermission")
    private void startAll(Context ctx) {
        stopAll();
        central = new BitChatCentral(ctx, new BitChatCentral.Sink() {
            @Override public void onConnected(byte[] pid) {
                peers.setConnected(hex(pid), true);
                append("connected " + hex(pid));
            }
            @Override public void onDisconnected(byte[] pid) {
                peers.setConnected(hex(pid), false);
                append("disconnected " + hex(pid));
            }
            @Override public void onInbound(byte[] pid, byte[] data) { handleInbound(data); }
        });

        peripheral = new BitChatGattServer(ctx, new BitChatGattServer.EventSink() {
            @Override public void onInbound(BluetoothDevice from, byte[] data) { handleInbound(data); }
            @Override public void onSubscribed(BluetoothDevice device) {
                append("subscribed by " + device.getAddress());
            }
            @Override public void onUnsubscribed(BluetoothDevice device) {
                append("unsubscribed by " + device.getAddress());
            }
        });
        String err = peripheral.start(BitChatConstants.LOCAL_NAME_PREFIX + identity.peerIdHex);
        if (err != null) { append("peripheral start: " + err); peripheral = null; }
        else { append("peripheral up"); }

        scanner = new BitChatScanner(ctx, (device, pid, name, rssi) -> {
            String pidHex = hex(pid);
            if (pidHex.equals(identity.peerIdHex)) return;
            peers.addOrTouch(pidHex);
            central.connectTo(device, pid);
        });
        String scanErr = scanner.start();
        if (scanErr != null) { append("scanner start: " + scanErr); scanner = null; }
        else { append("scanner up"); }

        ticker = new ScheduledThreadPoolExecutor(1);
        ticker.scheduleAtFixedRate(this::sendAnnounce,
                500, ANNOUNCE_INTERVAL_MS, TimeUnit.MILLISECONDS);
        ticker.scheduleAtFixedRate(() -> peers.pruneStale(120_000L),
                30_000, 30_000, TimeUnit.MILLISECONDS);
    }

    private void stopAll() {
        if (ticker != null) { ticker.shutdownNow(); ticker = null; }
        if (peripheral != null) { peripheral.stop(); peripheral = null; }
        if (scanner != null) { scanner.stop(); scanner = null; }
        if (central != null) { central.closeAll(); central = null; }
        append("stopped");
    }

    // ---- Compose dispatch --------------------------------------

    /** {@code @<16hex> body} → DM; anything else → public broadcast. */
    private void dispatchCompose(String text) {
        if (text.startsWith("@") && text.length() > 17 && text.charAt(17) == ' ') {
            String pidHex = text.substring(1, 17).toLowerCase();
            if (isHex(pidHex)) {
                String body = text.substring(18);
                sendDM(pidHex, body);
                return;
            }
        }
        broadcastText(text);
    }

    // ---- Wire helpers ------------------------------------------

    private byte[] buildAnnouncePayload() {
        byte[] nick = nickname.getBytes(StandardCharsets.UTF_8);
        int n = Math.min(nick.length, 255);
        byte[] out = new byte[2 + n];
        out[0] = 0x01;
        out[1] = (byte) n;
        System.arraycopy(nick, 0, out, 2, n);
        return out;
    }

    private void sendAnnounce() {
        try {
            Packet p = Packet.outbound(MessageType.ANNOUNCE, identity.peerIdRaw, buildAnnouncePayload());
            sendWire(BinaryProtocol.encode(p), p.messageType.value);
        } catch (Throwable t) {
            append("announce error: " + t.getMessage());
        }
    }

    private void broadcastText(String text) {
        try {
            BitchatMessage m = BitchatMessage.now(nickname, text);
            m.senderPeerId = identity.peerIdHex;
            Packet p = Packet.outbound(MessageType.MESSAGE, identity.peerIdRaw, m.toBinaryPayload());
            sendWire(BinaryProtocol.encode(p), p.messageType.value);
            append("(you) " + text);
        } catch (Throwable t) {
            append("post error: " + t.getMessage());
        }
    }

    /** DM to a specific peer_id. Initiates a Noise-XX handshake if
     *  no session exists; enqueues the message body inside the last
     *  handshake payload — matches the {@code snow} behaviour where
     *  payloads ride the handshake for free. */
    private void sendDM(String peerHex, String body) {
        try {
            Noise.Session sess = sessions.get(peerHex);
            if (sess != null && sess.isEstablished()) {
                sendEncryptedInner(peerHex, sess, body);
                append("(you → " + peerHex.substring(0, 6) + ") " + body);
                return;
            }
            // No live established session. Enqueue the body. If the
            // existing session isn't ours to drive (null, or a stalled
            // Responder from an inbound INIT they never followed
            // through on), start a fresh Initiator handshake — this
            // overwrites a stalled Responder, which is fine: their
            // orphan responder times out on their side and they retry.
            synchronized (pendingDMs) {
                pendingDMs.computeIfAbsent(peerHex, k -> new ArrayList<>()).add(body);
            }
            boolean needFreshInitiator = sess == null || !(sess instanceof Noise.Initiator);
            if (needFreshInitiator) {
                Noise.Initiator init = new Noise.Initiator(
                        identity.staticPrivateKey, identity.staticPublicKey);
                sessions.set(peerHex, init);
                byte[] frame = init.writeMessage(new byte[0]);
                sendHandshake(peerHex, MessageType.NOISE_HANDSHAKE_INIT, frame);
                append("(handshake init → " + peerHex.substring(0, 6) + ")");
            }
            append("(queued DM to " + peerHex.substring(0, 6)
                    + " — will flush after handshake)");
        } catch (Throwable t) {
            append("dm error: " + t.getMessage());
        }
    }

    private void flushPending(String peerHex, Noise.Session sess) {
        List<String> queue;
        synchronized (pendingDMs) {
            queue = pendingDMs.remove(peerHex);
        }
        if (queue == null || queue.isEmpty()) return;
        for (String body : queue) {
            try {
                sendEncryptedInner(peerHex, sess, body);
                append("(you → " + peerHex.substring(0, 6) + ") " + body);
            } catch (Throwable t) {
                append("dm flush error: " + t.getMessage());
            }
        }
    }

    private void sendHandshake(String peerHex, MessageType type, byte[] frame) throws Throwable {
        Packet p = Packet.outbound(type, identity.peerIdRaw, frame);
        p.withRecipient(hexTo8(peerHex));
        sendWire(BinaryProtocol.encode(p), p.messageType.value);
    }

    private void sendEncryptedInner(String peerHex, Noise.Session sess, String body)
            throws Throwable {
        BitchatMessage m = BitchatMessage.now(nickname, body);
        m.isPrivate = true;
        m.senderPeerId = identity.peerIdHex;
        Packet inner = Packet.outbound(MessageType.MESSAGE, identity.peerIdRaw, m.toBinaryPayload());
        byte[] innerWire = BinaryProtocol.encode(inner);
        byte[] ct = sess.encrypt(innerWire);
        Packet outer = Packet.outbound(MessageType.NOISE_ENCRYPTED, identity.peerIdRaw, ct);
        outer.withRecipient(hexTo8(peerHex));
        sendWire(BinaryProtocol.encode(outer), outer.messageType.value);
    }

    /** Blast one packet out. Fragments if larger than MTU-safe. */
    private void sendWire(byte[] wire, byte originalType) {
        if (wire.length <= FragmentManager.MAX_FRAGMENT_SIZE) {
            if (peripheral != null) peripheral.notify(wire);
            if (central != null) central.broadcast(wire);
            return;
        }
        byte[] fragmentId = new byte[8];
        new SecureRandom().nextBytes(fragmentId);
        List<byte[]> parts = FragmentManager.slice(fragmentId, originalType, wire);
        for (int i = 0; i < parts.size(); i++) {
            MessageType wrap = MessageType.FRAGMENT_CONTINUE;
            if (i == 0) wrap = MessageType.FRAGMENT_START;
            else if (i == parts.size() - 1) wrap = MessageType.FRAGMENT_END;
            try {
                Packet frag = Packet.outbound(wrap, identity.peerIdRaw, parts.get(i));
                byte[] fragWire = BinaryProtocol.encode(frag);
                if (peripheral != null) peripheral.notify(fragWire);
                if (central != null) central.broadcast(fragWire);
            } catch (Throwable t) {
                append("fragment " + i + " error: " + t.getMessage());
                return;
            }
        }
    }

    // ---- Inbound handling --------------------------------------

    private void handleInbound(byte[] data) {
        try {
            Packet p = BinaryProtocol.decode(data);
            String senderHex = hex(p.senderId);
            if (senderHex.equals(identity.peerIdHex)) return;                // self-echo
            peers.addOrTouch(senderHex);
            switch (p.messageType) {
                case ANNOUNCE:
                    peers.setNickname(senderHex, extractAnnounceNickname(p.payload));
                    break;
                case MESSAGE:
                    try {
                        BitchatMessage m = BitchatMessage.fromBinaryPayload(p.payload);
                        append(senderHex.substring(0, 6) + " (" + m.sender + "): " + m.content);
                    } catch (BitchatMessage.ProtocolException e) {
                        append(senderHex.substring(0, 6) + ": "
                                + new String(p.payload, StandardCharsets.UTF_8));
                    }
                    break;
                case NOISE_HANDSHAKE_INIT:
                    if (!addressedToUs(p)) break;
                    handleHandshakeInit(senderHex, p);
                    break;
                case NOISE_HANDSHAKE_RESP:
                    if (!addressedToUs(p)) break;
                    // Mainline (bitchat-rust) reuses NOISE_HANDSHAKE_RESP
                    // (0x11) as BOTH msg 2 (responder → initiator) AND
                    // msg 3 (initiator → responder). Dispatch on our own
                    // session state.
                    handleHandshakeResp(senderHex, p);
                    break;
                case NOISE_HANDSHAKE_FINAL:
                    if (!addressedToUs(p)) break;
                    // Vestigial in mainline. Accept for back-compat with
                    // any client that still emits 0x18 (our earlier build,
                    // some third-party ports).
                    handleHandshakeFinal(senderHex, p);
                    break;
                case NOISE_ENCRYPTED:
                    if (!addressedToUs(p)) break;
                    handleEncrypted(senderHex, p);
                    break;
                case FRAGMENT_START:
                case FRAGMENT_CONTINUE:
                case FRAGMENT_END: {
                    FragmentManager.Decoded d = FragmentManager.decodePayload(p.payload);
                    byte[] full = fragments.addFragment(d.header, d.originalType, d.data);
                    if (full != null) handleInbound(full);
                    break;
                }
                default:
                    // Silent skip — future crypto verbs land here.
                    break;
            }
        } catch (Throwable t) {
            append("decode error: " + t.getMessage() + " (" + data.length + " bytes)");
            append("  hex: " + hexPreview(data, 64));
        }
    }

    private static String hexPreview(byte[] b, int max) {
        if (b == null) return "";
        int n = Math.min(b.length, max);
        StringBuilder sb = new StringBuilder(n * 2 + 4);
        for (int i = 0; i < n; i++) sb.append(String.format("%02x", b[i] & 0xFF));
        if (b.length > max) sb.append("…+").append(b.length - max);
        return sb.toString();
    }

    private void handleHandshakeInit(String senderHex, Packet p) throws Throwable {
        // Peer wants to talk to us. Build a responder, feed the frame,
        // reply with message 2 (e, ee, s, es).
        Noise.Responder resp = new Noise.Responder(
                identity.staticPrivateKey, identity.staticPublicKey);
        resp.readMessage(p.payload);                    // consumes message 1
        byte[] out = resp.writeMessage(new byte[0]);    // produces message 2
        sessions.set(senderHex, resp);
        sendHandshake(senderHex, MessageType.NOISE_HANDSHAKE_RESP, out);
        append("(handshake responded → " + senderHex.substring(0, 6) + ")");
    }

    private void handleHandshakeResp(String senderHex, Packet p) throws Throwable {
        Noise.Session sess = sessions.get(senderHex);
        if (sess == null) return;
        if (sess instanceof Noise.Initiator) {
            // Initiator side: this is msg 2. Consume it, produce msg 3,
            // and ship msg 3 back — ALSO as NOISE_HANDSHAKE_RESP (0x11)
            // to match mainline bitchat-rust (see snow_noise_service.rs:411).
            sess.readMessage(p.payload);
            byte[] out = sess.writeMessage(new byte[0]);
            sendHandshake(senderHex, MessageType.NOISE_HANDSHAKE_RESP, out);
            peers.setStaticKey(senderHex, sess.remoteStaticPublicKey());
            append("(handshake complete with " + senderHex.substring(0, 6) + ")");
            flushPending(senderHex, sess);
        } else if (sess instanceof Noise.Responder) {
            // Responder side: this is msg 3. Consume it — the session
            // promotes to transport inside readMessage.
            sess.readMessage(p.payload);
            peers.setStaticKey(senderHex, sess.remoteStaticPublicKey());
            append("(handshake complete with " + senderHex.substring(0, 6) + ")");
            flushPending(senderHex, sess);
        }
    }

    private void handleHandshakeFinal(String senderHex, Packet p) throws Throwable {
        // Responder consuming message 3.
        Noise.Session sess = sessions.get(senderHex);
        if (!(sess instanceof Noise.Responder)) return;
        sess.readMessage(p.payload);
        peers.setStaticKey(senderHex, sess.remoteStaticPublicKey());
        append("(handshake complete with " + senderHex.substring(0, 6) + ")");
        flushPending(senderHex, sess);
    }

    private void handleEncrypted(String senderHex, Packet p) throws Throwable {
        Noise.Session sess = sessions.get(senderHex);
        if (sess == null || !sess.isEstablished()) {
            append("(dropped encrypted from " + senderHex.substring(0, 6) + " — no session)");
            return;
        }
        byte[] innerWire = sess.decrypt(p.payload);
        // Feed the inner packet back through handleInbound so
        // MESSAGE bodies etc. reuse the same rendering path.
        handleInbound(innerWire);
    }

    /** True iff this frame either has no recipient (broadcast) OR is
     *  addressed specifically to our peer_id. Announces are always
     *  broadcast; noise-* frames MUST carry a recipient and we should
     *  only feed them to our sessions when we're the target — otherwise
     *  we AEAD-decrypt with the wrong session and blow up with a bogus
     *  BAD_DECRYPT in the log for every noise frame that sailed by. */
    private boolean addressedToUs(Packet p) {
        if (!p.flags.hasRecipient || p.recipientId == null) return true;
        return java.util.Arrays.equals(p.recipientId, identity.peerIdRaw);
    }

    private static String extractAnnounceNickname(byte[] payload) {
        if (payload == null || payload.length == 0) return "";
        int first = payload[0] & 0xFF;
        if (first >= 0x01 && first <= 0x04) {
            int i = 0;
            while (i + 2 <= payload.length) {
                int type = payload[i] & 0xFF;
                int len  = payload[i + 1] & 0xFF;
                int start = i + 2;
                int end   = start + len;
                if (end > payload.length) break;
                if (type == 0x01) {
                    return new String(payload, start, len, StandardCharsets.UTF_8).trim();
                }
                i = end;
            }
        }
        return new String(payload, StandardCharsets.UTF_8).trim();
    }

    // ---- UI helpers --------------------------------------------

    private void renderPeers() {
        List<Peer> roster = peers.all();
        StringBuilder sb = new StringBuilder();
        for (Peer p : roster) {
            sb.append(p.connected ? "● " : "  ");
            boolean hasNick = p.nickname != null && !p.nickname.isEmpty();
            if (hasNick) {
                sb.append(p.nickname);
                if (sessions.isEstablished(p.peerIdHex)) sb.append(" 🔒");
                sb.append('\n');
                sb.append("  ").append(p.peerIdHex).append('\n');
            } else {
                sb.append(p.peerIdHex);
                if (sessions.isEstablished(p.peerIdHex)) sb.append(" 🔒");
                sb.append('\n');
            }
        }
        if (sb.length() == 0) sb.append("(no peers yet)");
        String out = sb.toString();
        ui.post(() -> peersView.setText(out));
    }

    private void append(String line) {
        String stamp = ts.format(new Date());
        String out = stamp + "  " + line + "\n";
        Runnable r = () -> {
            log.append(out);
            // Auto-scroll to the last line. TextView.append() moves the
            // buffer end but not the scroll offset — without this the
            // visible viewport stays anchored to whatever old line was
            // at the top and new events scroll off the bottom.
            if (log.getLayout() == null) return;
            int y = log.getLayout().getLineTop(log.getLineCount())
                    - log.getHeight();
            log.scrollTo(0, Math.max(0, y));
        };
        if (Looper.myLooper() == Looper.getMainLooper()) r.run();
        else ui.post(r);
    }

    // ---- Hex helpers -------------------------------------------

    private static String hex(byte[] b) {
        if (b == null) return "";
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte v : b) sb.append(String.format("%02x", v));
        return sb.toString();
    }

    private static byte[] hexTo8(String s) {
        byte[] out = new byte[8];
        for (int i = 0; i < 8; i++) {
            out[i] = (byte) (
                    (Character.digit(s.charAt(i * 2), 16) << 4)
                            | Character.digit(s.charAt(i * 2 + 1), 16));
        }
        return out;
    }

    private static boolean isHex(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
        }
        return true;
    }
}
