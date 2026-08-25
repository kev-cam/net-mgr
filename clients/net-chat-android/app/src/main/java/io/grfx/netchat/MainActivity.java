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
    /** Location is requested separately, and late — see shareLocation(). */
    private static final int REQ_LOCATION = 43;
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
    private LocationShare locationShare;

    /**
     * Position sharing. Movement-driven, not scheduled: the platform emits a
     * fix only when the device has actually moved minDistance, subject to a
     * minTime floor. A stationary phone therefore costs nothing.
     *
     * OFF at every app start, still deliberately — a device must not resume
     * reporting its position because of something switched on weeks ago. What
     * changed is that the state is now VISIBLE: the button is colour-coded, so
     * "it stopped" is legible at a glance instead of buried in the log, which
     * is how the old /loc beacon kept dying unnoticed.
     *
     * The thresholds DO persist (they are configuration, not consent); the
     * on/off state does not.
     */
    private Button  locBtn;
    private boolean locOn;
    private long    locMinTimeMs  = 5 * 60_000L;   // never more often than this
    private float   locMinDistM   = 25f;           // must move this far first
    private long    locLastFixAt;

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

        locBtn = findViewById(R.id.loc);
        loadLocPrefs();
        locBtn.setOnClickListener(v -> toggleLocation());
        paintLocButton();
        Button startBtn = findViewById(R.id.start);
        Button stopBtn = findViewById(R.id.stop);
        Button postBtn = findViewById(R.id.post);
        Button locBtn = findViewById(R.id.loc);
        startBtn.setOnClickListener(v -> requestAndStart());
        stopBtn.setOnClickListener(v -> stopService());
        locBtn.setOnClickListener(v -> shareLocation());
        postBtn.setOnClickListener(v -> {
            String txt = compose.getText().toString().trim();
            if (!txt.isEmpty()) {
                dispatchCompose(txt);
                compose.setText("");
            }
        });

        // Wire the Noise trace sink to logcat. Filter with:
        //   adb logcat -s NoiseTrace
        // for the full state-transition trace of every handshake.
        // DEBUG-only: the trace dumps DH shared secrets, chaining/cipher
        // keys and handshake plaintext — never leave it enabled in a
        // release build (readable via adb/bugreport).
        if (BuildConfig.DEBUG) {
            io.grfx.netchat.crypto.Noise.TRACER = (label, data) -> {
                StringBuilder sb = new StringBuilder(label).append("=");
                if (data == null) sb.append("(null)");
                else for (byte b : data) sb.append(String.format("%02x", b));
                android.util.Log.i("NoiseTrace", sb.toString());
            };
        }

        try {
            identity = loadOrCreateIdentity();
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

    // Persisted identity: one seed per install, so peer_id survives
    // activity recreation and app restarts (the bridge-side equivalent is
    // BITCHAT_ID_FILE). SharedPreferences, not Keystore: the seed must be
    // the raw Ed25519 input (see Identity's cross-platform derivation),
    // and Keystore won't release raw private key bytes.
    private Identity loadOrCreateIdentity() throws Exception {
        android.content.SharedPreferences sp =
                getSharedPreferences("identity", MODE_PRIVATE);
        String hex = sp.getString("seed", null);
        if (hex != null && hex.length() == Identity.SEED_LEN * 2) {
            // Guard the parse: a stored value that is the right LENGTH but
            // contains a non-hex char (corruption/tampering of app-private
            // prefs) must self-heal by regenerating, not throw out of here
            // and leave identity == null (which then NPEs in startAll).
            try {
                byte[] seed = new byte[Identity.SEED_LEN];
                for (int i = 0; i < seed.length; i++) {
                    seed[i] = (byte) Integer.parseInt(
                            hex.substring(i * 2, i * 2 + 2), 16);
                }
                return Identity.fromSeed(seed);
            } catch (NumberFormatException e) {
                append("stored seed unparseable; regenerating identity");
                // fall through to regenerate + overwrite
            }
        }
        Identity id = Identity.ephemeral();
        StringBuilder sb = new StringBuilder(Identity.SEED_LEN * 2);
        for (byte b : id.seed) sb.append(String.format("%02x", b & 0xFF));
        sp.edit().putString("seed", sb.toString()).apply();
        return id;
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
        if (requestCode == REQ_LOCATION) {
            boolean granted = grantResults.length > 0
                    && grantResults[0] == PackageManager.PERMISSION_GRANTED;
            if (granted) {
                if (locOn) startLocation();   // the button asked for this
                else shareLocation();         // a bare /loc asked for one fix
            } else {
                // Disarm rather than let an armed beacon re-prompt on every
                // tick — a repeating permission dialog is worse than no beacon.
                append("location: permission denied");
                locOn = false;
                paintLocButton();
            }
            return;
        }
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
            @Override public void onAdvertiseResult(boolean ok, int errorCode) {
                // Asynchronous verdict — "peripheral up" below only means the
                // request was accepted. Say plainly when we are NOT advertising,
                // because an undiscoverable peripheral looks identical to a
                // healthy one from this screen.
                runOnUiThread(() -> append(ok
                        ? "advertising"
                        : "NOT ADVERTISING — " + BitChatGattServer.advertiseError(errorCode)));
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
        if (locOn) stopLocation("off (mesh stopped)");          // an armed beacon must not outlive the mesh
        if (ticker != null) { ticker.shutdownNow(); ticker = null; }
        if (peripheral != null) { peripheral.stop(); peripheral = null; }
        if (scanner != null) { scanner.stop(); scanner = null; }
        if (central != null) { central.closeAll(); central = null; }
        append("stopped");
    }

    // ---- Compose dispatch --------------------------------------

    /** {@code @<16hex> body} → DM; anything else → public broadcast. */
    /**
     * Share this device's position with the mesh, as an ordinary broadcast.
     *
     * Deliberately not a new MessageType: a location is just text that happens
     * to parse, so it rides the existing MESSAGE path and therefore reaches
     * every bridge, net-chat and roster that already handles chat — no protocol
     * version bump, no bridge-side change, and older peers still see something
     * readable rather than dropping an unknown type.
     *
     * One-shot: an explicit tap or a bare /loc. Continuous sharing does NOT
     * come through here — startLocation() registers a movement-filtered
     * listener with the platform instead, so nothing in this path is on a
     * timer.
     */
    private void shareLocation() {
        // On Android 12+ this app holds no location permission by design —
        // BLUETOOTH_SCAN declares neverForLocation precisely so BLE does not
        // drag one in. Sharing a position is the single feature that genuinely
        // needs it, so the grant is asked for HERE, when the operator asks to
        // be located, rather than at startup where it would put a location
        // prompt in front of people who only ever wanted chat.
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION)
                != PackageManager.PERMISSION_GRANTED) {
            append("location: requesting permission …");
            ActivityCompat.requestPermissions(this,
                    new String[]{ Manifest.permission.ACCESS_FINE_LOCATION }, REQ_LOCATION);
            return;                     // resumes in onRequestPermissionsResult
        }
        if (locationShare == null) locationShare = new LocationShare(this);
        append("(you) requesting location …");
        locationShare.request(new LocationShare.Sink() {
            @Override public void onStatus(String msg) { ui.post(() -> append(msg)); }
            @Override public void onFix(String line, android.location.Location loc) {
                if (line == null) return;          // status already explained why
                ui.post(() -> broadcastText(line));
            }
        });
    }

    /**
     * Below this, a beacon costs a GNSS wake plus a mesh broadcast to re-report
     * a position that has not meaningfully changed. Two tablets reporting every
     * few minutes is enough to fix the survey frame; faster only spends battery.
     */
    // Colour IS the state. Grey = off, amber = on but no fix yet, green = on
    // with a recent fix, red = wanted but blocked (permission or provider).
    private static final int LOC_OFF     = 0xFF555555;
    private static final int LOC_WAITING = 0xFFB8860B;
    private static final int LOC_LIVE    = 0xFF2E7D32;
    private static final int LOC_BLOCKED = 0xFFB71C1C;
    /** A fix older than this stops counting as "live" on the button. */
    private static final long LOC_FRESH_MS = 15 * 60_000L;

    private void paintLocButton() {
        if (locBtn == null) return;
        int c; String t;
        if (!locOn)                                              { c = LOC_OFF;     t = "Loc off"; }
        else if (locationShare == null || !locationShare.isRunning()) { c = LOC_BLOCKED; t = "Loc !"; }
        else if (locLastFixAt == 0)                              { c = LOC_WAITING; t = "Loc …"; }
        else if (System.currentTimeMillis() - locLastFixAt > LOC_FRESH_MS) { c = LOC_WAITING; t = "Loc ~"; }
        else                                                     { c = LOC_LIVE;    t = "Loc on"; }
        locBtn.setBackgroundColor(c);
        locBtn.setText(t);
    }

    /** Toggle from the button. */
    private void toggleLocation() {
        if (locOn) { stopLocation("off (button)"); return; }
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION)
                != PackageManager.PERMISSION_GRANTED) {
            append("location: requesting permission …");
            locOn = true;                 // remember the intent across the prompt
            paintLocButton();
            ActivityCompat.requestPermissions(this,
                    new String[]{ Manifest.permission.ACCESS_FINE_LOCATION }, REQ_LOCATION);
            return;
        }
        startLocation();
    }

    private void startLocation() {
        if (locationShare == null) locationShare = new LocationShare(this);
        locOn = true;
        locLastFixAt = 0;
        boolean ok = locationShare.startUpdates(locMinTimeMs, locMinDistM, new LocationShare.Sink() {
            @Override public void onStatus(String msg) { ui.post(() -> append(msg)); }
            @Override public void onFix(String line, android.location.Location loc) {
                if (line == null) return;
                ui.post(() -> {
                    locLastFixAt = System.currentTimeMillis();
                    paintLocButton();
                    broadcastText(line);
                });
            }
        });
        append(ok ? "location: sharing on movement (min " + (locMinTimeMs / 60_000L)
                    + "m, " + (int) locMinDistM + "m)"
                  : "location: could not start");
        if (!ok) locOn = false;
        paintLocButton();
    }

    private void stopLocation(String why) {
        if (locationShare != null) locationShare.stopUpdates();
        locOn = false;
        locLastFixAt = 0;
        append("location: " + why);
        paintLocButton();
    }

    /** "5m" / "90s" / bare "5" (minutes). 0 when unparseable. */
    private static long parseInterval(String s) {
        if (s == null) return 0L;
        s = s.trim().toLowerCase(Locale.US);
        if (s.isEmpty()) return 0L;
        long mult = 60_000L;
        if (s.endsWith("s"))      { mult = 1_000L;  s = s.substring(0, s.length() - 1); }
        else if (s.endsWith("m")) { mult = 60_000L; s = s.substring(0, s.length() - 1); }
        try { return Long.parseLong(s.trim()) * mult; }
        catch (NumberFormatException e) { return 0L; }
    }

    private void dispatchCompose(String text) {
        if (text.regionMatches(true, 0, "/loc", 0, 4)
            && (text.length() == 4 || text.charAt(4) == ' ')) {
            String arg = text.length() > 4 ? text.substring(4).trim() : "";
            String low = arg.toLowerCase(Locale.US);
            if (arg.isEmpty())                       { shareLocation(); return; }
            if (low.equals("on"))                    { if (!locOn) toggleLocation(); return; }
            if (low.equals("off") || low.equals("stop")) { if (locOn) stopLocation("off"); return; }
            if (low.startsWith("every")) {            // minimum interval
                long ms = parseInterval(arg.substring(5));
                if (ms <= 0) { append("usage: /loc every <n>[s|m]"); return; }
                locMinTimeMs = ms;
                saveLocPrefs();
                append("location: min interval " + (ms / 60_000L) + "m"
                       + (locOn ? " (restarting)" : ""));
                if (locOn) startLocation();
                return;
            }
            if (low.startsWith("move")) {             // minimum distance
                String d = arg.substring(4).trim().replaceAll("(?i)m$", "");
                try {
                    float m = Float.parseFloat(d);
                    if (m <= 0) throw new NumberFormatException();
                    locMinDistM = m;
                    saveLocPrefs();
                    // Say so rather than silently accepting a useless value: a
                    // threshold under the fix accuracy makes a stationary phone
                    // emit continuously as the position jitters.
                    if (m < 20f) append("location: " + (int) m
                            + "m is below typical fix accuracy — expect jitter");
                    append("location: move threshold " + (int) m + "m"
                           + (locOn ? " (restarting)" : ""));
                    if (locOn) startLocation();
                } catch (NumberFormatException e) { append("usage: /loc move <metres>"); }
                return;
            }
            append("usage: /loc | /loc on | /loc off | /loc every <n>[s|m] | /loc move <m>");
            return;
        }
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

    // Thresholds persist; the on/off state deliberately does not.
    private static final String LOC_PREFS = "loc";
    private void saveLocPrefs() {
        getSharedPreferences(LOC_PREFS, MODE_PRIVATE).edit()
            .putLong("minTimeMs", locMinTimeMs)
            .putFloat("minDistM", locMinDistM)
            .apply();
    }
    private void loadLocPrefs() {
        android.content.SharedPreferences p = getSharedPreferences(LOC_PREFS, MODE_PRIVATE);
        locMinTimeMs = p.getLong("minTimeMs", locMinTimeMs);
        locMinDistM  = p.getFloat("minDistM",  locMinDistM);
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
