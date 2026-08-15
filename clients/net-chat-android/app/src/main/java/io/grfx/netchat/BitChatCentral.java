package io.grfx.netchat;

import android.annotation.SuppressLint;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCallback;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattDescriptor;
import android.bluetooth.BluetoothGattService;
import android.content.Context;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.util.Log;

import java.util.HashMap;
import java.util.Map;

/**
 * Central-role plumbing. Given a device discovered by
 * {@link BitChatScanner}, this manages the connect → discover services
 * → find characteristic → enable notifications lifecycle.
 *
 * <p>Public API:
 * <ul>
 *   <li>{@link #connectTo(BluetoothDevice, byte[])} — start the chain</li>
 *   <li>{@link #send(byte[], byte[])} — WriteWithoutResponse to a specific peer</li>
 *   <li>{@link #broadcast(byte[])} — write to every currently-subscribed peer</li>
 *   <li>{@link Sink#onInbound} — fires on notifications from a subscribed peer</li>
 * </ul>
 */
public final class BitChatCentral {
    private static final String TAG = "BitChatCentral";

    public interface Sink {
        void onConnected(byte[] peerId);
        void onDisconnected(byte[] peerId);
        void onInbound(byte[] peerId, byte[] data);
    }

    /** Give up on a direct connect that never calls back (stack usually
     *  reports 133 near 30s; be a little more patient than that). */
    private static final long CONNECT_TIMEOUT_MS = 35_000L;

    /** Backoff before re-attempting a peer, indexed by consecutive failures. */
    private static final long[] RETRY_BACKOFF_MS = { 2_000L, 5_000L, 15_000L, 60_000L };

    private final Context context;
    private final Sink sink;
    private final Map<String, PeerConn> byAddress = new HashMap<>();
    private final Handler handler = new Handler(Looper.getMainLooper());

    public BitChatCentral(Context context, Sink sink) {
        this.context = context;
        this.sink = sink;
    }

    private static final class PeerConn {
        final BluetoothDevice device;
        final byte[] peerId;
        BluetoothGatt gatt;
        BluetoothGattCharacteristic tx;
        volatile boolean subscribed;
        /** A connectGatt() is in flight (no CONNECTED/DISCONNECTED callback yet). */
        volatile boolean connecting;
        /** elapsedRealtime of the last connectGatt(), for the backoff gate. */
        volatile long lastAttemptMs;
        /** Consecutive failed attempts; reset to 0 once connected. */
        volatile int failures;

        PeerConn(BluetoothDevice d, byte[] pid) { this.device = d; this.peerId = pid; }
    }

    private static long backoffFor(int failures) {
        if (failures <= 0) return 0L;
        int i = Math.min(failures - 1, RETRY_BACKOFF_MS.length - 1);
        return RETRY_BACKOFF_MS[i];
    }

    /**
     * Start (or retry) the connect chain for a scanned device.
     *
     * <p>Called on every matching scan hit, so it must be cheap and idempotent:
     * it returns immediately when the peer is already connected, when an attempt
     * is still in flight, or when the peer is inside its failure backoff.
     */
    @SuppressLint("MissingPermission")
    public void connectTo(BluetoothDevice device, byte[] peerId) {
        if (device == null) return;
        String addr = device.getAddress();
        PeerConn pc;
        BluetoothGatt stale = null;
        long now = SystemClock.elapsedRealtime();
        synchronized (byAddress) {
            pc = byAddress.get(addr);
            if (pc != null) {
                if (pc.subscribed || pc.connecting) return;     // healthy, or in flight
                long wait = backoffFor(pc.failures) - (now - pc.lastAttemptMs);
                if (wait > 0) return;                           // still cooling down
                // Retrying: the previous client interface must go. With
                // autoConnect=false a dead BluetoothGatt is NOT reusable, and
                // Android has only a handful of client interfaces — leaking them
                // eventually breaks connecting to anything at all.
                stale = pc.gatt;
                pc.gatt = null;
                pc.tx = null;
            } else {
                pc = new PeerConn(device, peerId);
                byAddress.put(addr, pc);
            }
            pc.connecting = true;
            pc.lastAttemptMs = now;
        }
        closeQuietly(stale);        // outside the monitor — see markFailed()
        // autoConnect=false — a DIRECT connect. autoConnect=true looks tempting
        // (the OS holds the intent across brief absences) but it is a background
        // "acceptlist" connect, and in this app it simply never completed:
        //   * the stack refuses it outright for peers using a resolvable private
        //     address — "Can't add RPA to background connection" — and BLE
        //     privacy means most peers, including our own Android peripheral,
        //     rotate exactly such an address; and
        //   * for the rest, the controller's initiating scan is starved by our
        //     own SCAN_MODE_LOW_LATENCY scan, so requests sat in the acceptlist
        //     for many minutes with zero connections.
        // Reconnect-after-drop is now our job instead: the scanner re-reports the
        // peer within seconds and we retry here under the backoff above.
        BluetoothGatt g = device.connectGatt(context, false /*autoConnect*/,
                gattCallback, BluetoothDevice.TRANSPORT_LE);
        synchronized (byAddress) { pc.gatt = g; }
        Log.i(TAG, "connect → " + addr + " direct attempt=" + (pc.failures + 1)
                + (g == null ? " FAILED (connectGatt returned null)" : ""));
        if (g == null) { markFailed(addr, "connectGatt returned null", true); return; }
        // Watchdog: a direct connect that never calls back would otherwise pin
        // this peer in `connecting` forever and it would never be retried.
        final String watchAddr = addr;
        handler.postDelayed(() -> {
            PeerConn p;
            synchronized (byAddress) { p = byAddress.get(watchAddr); }
            if (p != null && p.connecting && !p.subscribed) {
                Log.w(TAG, "connect timeout after " + CONNECT_TIMEOUT_MS + "ms: " + watchAddr);
                markFailed(watchAddr, "timeout", true);
            }
        }, CONNECT_TIMEOUT_MS);
    }

    /**
     * Release the GATT client for a peer so a later scan hit can retry.
     *
     * @param countAsFailure true for a genuine connect failure (advances the
     *        backoff); false when a peer we were happily talking to simply went
     *        away, which should be retried promptly rather than penalised.
     */
    private void markFailed(String addr, String why, boolean countAsFailure) {
        BluetoothGatt doomed;
        int failures;
        synchronized (byAddress) {
            PeerConn pc = byAddress.get(addr);
            if (pc == null) return;
            pc.connecting = false;
            pc.subscribed = false;
            pc.tx = null;
            if (countAsFailure) pc.failures++; else pc.failures = 0;
            doomed = pc.gatt;
            pc.gatt = null;
            failures = pc.failures;
        }
        // Close OUTSIDE the monitor: BluetoothGatt calls reach into the stack,
        // and holding our lock across them risks deadlocking against a callback
        // thread that wants the same lock.
        closeQuietly(doomed);
        Log.i(TAG, "released " + addr + " (" + why + ") failures=" + failures
                + " next attempt allowed in " + backoffFor(failures) + "ms");
    }

    @SuppressLint("MissingPermission")
    private static void closeQuietly(BluetoothGatt g) {
        if (g == null) return;
        try { g.disconnect(); } catch (Throwable ignored) {}
        try { g.close(); } catch (Throwable ignored) {}
    }

    @SuppressLint("MissingPermission")
    public boolean send(byte[] peerId, byte[] data) {
        PeerConn pc = findByPeerId(peerId);
        if (pc == null || pc.gatt == null || pc.tx == null) {
            Log.i(TAG, "send skipped (peer not tracked/tx null): "
                    + (pc == null ? "no PeerConn" : (pc.tx == null ? "no tx" : "no gatt")));
            return false;
        }
        int type = BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE;
        boolean ok;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            int rc = pc.gatt.writeCharacteristic(pc.tx, data, type);
            ok = rc == BluetoothGatt.GATT_SUCCESS;
        } else {
            pc.tx.setWriteType(type);
            pc.tx.setValue(data);
            ok = pc.gatt.writeCharacteristic(pc.tx);
        }
        Log.i(TAG, "send " + data.length + "B → " + pc.device.getAddress()
                + " ok=" + ok + " subscribed=" + pc.subscribed);
        return ok;
    }

    public void broadcast(byte[] data) {
        PeerConn[] snapshot;
        synchronized (byAddress) {
            snapshot = byAddress.values().toArray(new PeerConn[0]);
        }
        int candidates = 0, sent = 0;
        for (PeerConn pc : snapshot) {
            if (pc.tx != null && pc.subscribed) {
                candidates++;
                if (send(pc.peerId, data)) sent++;
            }
        }
        Log.i(TAG, "broadcast " + data.length + "B → " + sent + "/" + candidates
                + " (tracked=" + snapshot.length + ")");
    }

    @SuppressLint("MissingPermission")
    public void closeAll() {
        // Explicit user-driven teardown (STOP). Drop any pending connect
        // watchdogs too, or a retry could fire after the user stopped BLE.
        handler.removeCallbacksAndMessages(null);
        synchronized (byAddress) {
            for (PeerConn pc : byAddress.values()) {
                pc.connecting = false;
                pc.subscribed = false;
                pc.tx = null;
                closeQuietly(pc.gatt);
                pc.gatt = null;
            }
            byAddress.clear();
        }
    }

    private PeerConn findByPeerId(byte[] peerId) {
        if (peerId == null) return null;
        synchronized (byAddress) {
            for (PeerConn pc : byAddress.values()) {
                if (java.util.Arrays.equals(pc.peerId, peerId)) return pc;
            }
        }
        return null;
    }

    private PeerConn findByGatt(BluetoothGatt gatt) {
        synchronized (byAddress) {
            for (PeerConn pc : byAddress.values()) {
                if (pc.gatt == gatt) return pc;
            }
        }
        return null;
    }

    private final BluetoothGattCallback gattCallback = new BluetoothGattCallback() {
        @Override
        @SuppressLint("MissingPermission")
        public void onConnectionStateChange(BluetoothGatt gatt, int status, int newState) {
            PeerConn pc = findByGatt(gatt);
            // status was previously ignored entirely, which made every GATT
            // error (133 no-response, 8 timeout, 22 terminated locally, 62
            // failed-to-establish) completely invisible — the single biggest
            // reason this path could not be diagnosed from logcat.
            Log.i(TAG, "onConnectionStateChange status=" + status
                    + " newState=" + newState
                    + " peer=" + (pc == null ? "?" : pc.device.getAddress()));
            if (pc == null) {
                // Callback for a GATT we already replaced/closed — release it.
                closeQuietly(gatt);
                return;
            }
            if (newState == BluetoothGatt.STATE_CONNECTED
                    && status == BluetoothGatt.GATT_SUCCESS) {
                pc.connecting = false;
                pc.failures = 0;                    // a good connect clears the backoff
                // Request the biggest MTU BLE allows (517) BEFORE discovering
                // services — default 23-byte MTU truncates BitChat frames to
                // 20 bytes and every packet fails to decode. onMtuChanged
                // triggers discoverServices().
                gatt.requestMtu(517);
            } else if (newState == BluetoothGatt.STATE_DISCONNECTED) {
                // Fire onDisconnected only if we previously fired onConnected —
                // keeps the sink's connect/disconnect pairs balanced.
                boolean wasSubscribed = pc.subscribed;
                if (wasSubscribed && sink != null) sink.onDisconnected(pc.peerId);
                // With autoConnect=false the OS will NOT reconnect for us, and a
                // disconnected BluetoothGatt still holds a client interface until
                // close(). Release it and let the next scan hit retry under the
                // backoff. A drop after we were subscribed isn't a connect
                // failure — the peer simply left — so it doesn't advance it.
                markFailed(pc.device.getAddress(), "disconnected status=" + status,
                        !wasSubscribed);
            } else if (status != BluetoothGatt.GATT_SUCCESS) {
                markFailed(pc.device.getAddress(), "status=" + status, true);
            }
        }

        @Override
        @SuppressLint("MissingPermission")
        public void onMtuChanged(BluetoothGatt gatt, int mtu, int status) {
            // Whether or not the peer accepted 517, kick off service
            // discovery. Even the fallback (usually ~185 or ~247) is
            // enough for a padded 256-byte Announce.
            gatt.discoverServices();
        }

        @Override
        @SuppressLint("MissingPermission")
        public void onServicesDiscovered(BluetoothGatt gatt, int status) {
            PeerConn pc = findByGatt(gatt);
            if (pc == null) return;
            if (status != BluetoothGatt.GATT_SUCCESS) {
                Log.w(TAG, "service discovery failed status=" + status
                        + " peer=" + pc.device.getAddress());
                gatt.disconnect();          // onConnectionStateChange cleans up
                return;
            }
            BluetoothGattService svc = gatt.getService(BitChatConstants.SERVICE_UUID);
            if (svc == null) {
                Log.w(TAG, "peer has no BitChat service: " + pc.device.getAddress());
                gatt.disconnect();
                return;
            }
            BluetoothGattCharacteristic ch = svc.getCharacteristic(
                    BitChatConstants.CHARACTERISTIC_UUID);
            if (ch == null) {
                Log.w(TAG, "peer has no BitChat characteristic");
                gatt.disconnect();
                return;
            }
            pc.tx = ch;
            // Enable local notification routing.
            gatt.setCharacteristicNotification(ch, true);
            // Write 0x0001 to the CCCD to tell the peer we want notifications.
            BluetoothGattDescriptor cccd = ch.getDescriptor(BitChatConstants.CCCD_UUID);
            if (cccd != null) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    gatt.writeDescriptor(cccd,
                            BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE);
                } else {
                    cccd.setValue(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE);
                    gatt.writeDescriptor(cccd);
                }
            }
        }

        @Override
        public void onDescriptorWrite(BluetoothGatt gatt,
                                      BluetoothGattDescriptor descriptor, int status) {
            PeerConn pc = findByGatt(gatt);
            Log.i(TAG, "onDescriptorWrite status=" + status
                    + " uuid=" + descriptor.getUuid()
                    + " peer=" + (pc == null ? "?" : pc.device.getAddress()));
            if (pc != null && status == BluetoothGatt.GATT_SUCCESS
                    && BitChatConstants.CCCD_UUID.equals(descriptor.getUuid())) {
                pc.subscribed = true;
                if (sink != null) sink.onConnected(pc.peerId);
            }
        }

        @Override
        public void onCharacteristicChanged(BluetoothGatt gatt,
                                            BluetoothGattCharacteristic characteristic) {
            handleNotification(gatt, characteristic, characteristic.getValue());
        }

        // Android 13+ callback variant carries the value directly.
        @Override
        public void onCharacteristicChanged(BluetoothGatt gatt,
                                            BluetoothGattCharacteristic characteristic,
                                            byte[] value) {
            handleNotification(gatt, characteristic, value);
        }

        private void handleNotification(BluetoothGatt gatt,
                                        BluetoothGattCharacteristic characteristic,
                                        byte[] value) {
            if (!BitChatConstants.CHARACTERISTIC_UUID.equals(characteristic.getUuid())) return;
            PeerConn pc = findByGatt(gatt);
            if (pc == null || value == null || sink == null) return;
            sink.onInbound(pc.peerId, value.clone());
        }
    };
}
