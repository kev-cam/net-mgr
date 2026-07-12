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

    private final Context context;
    private final Sink sink;
    private final Map<String, PeerConn> byAddress = new HashMap<>();

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

        PeerConn(BluetoothDevice d, byte[] pid) { this.device = d; this.peerId = pid; }
    }

    @SuppressLint("MissingPermission")
    public void connectTo(BluetoothDevice device, byte[] peerId) {
        if (device == null) return;
        String addr = device.getAddress();
        synchronized (byAddress) {
            if (byAddress.containsKey(addr)) return;                // already tracked
            PeerConn pc = new PeerConn(device, peerId);
            byAddress.put(addr, pc);
            // autoConnect=true: the OS holds the connection intent even
            // when the peer briefly leaves range and re-fires CONNECTED
            // when it comes back. Cuts the connect/disconnect churn we
            // used to see with autoConnect=false where every scan hit
            // opened a fresh GATT.
            pc.gatt = device.connectGatt(context, true /*autoConnect*/,
                    gattCallback, BluetoothDevice.TRANSPORT_LE);
        }
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
        // Explicit user-driven teardown — closing here CANCELS the
        // autoConnect intent so the OS stops trying to reconnect.
        synchronized (byAddress) {
            for (PeerConn pc : byAddress.values()) {
                if (pc.gatt != null) {
                    try { pc.gatt.disconnect(); } catch (Throwable ignored) {}
                    try { pc.gatt.close(); } catch (Throwable ignored) {}
                }
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
            if (pc == null) return;
            if (newState == BluetoothGatt.STATE_CONNECTED) {
                // Request the biggest MTU BLE allows (517) BEFORE discovering
                // services — default 23-byte MTU truncates BitChat frames to
                // 20 bytes and every packet fails to decode. onMtuChanged
                // triggers discoverServices().
                gatt.requestMtu(517);
            } else if (newState == BluetoothGatt.STATE_DISCONNECTED) {
                // Do NOT close(): with autoConnect=true, holding the gatt
                // alive lets the OS reconnect the SAME peer without a
                // second connectTo() from us. Fire onDisconnected only if
                // we previously fired onConnected — keeps the sink's
                // connect/disconnect pairs balanced.
                boolean wasSubscribed = pc.subscribed;
                pc.subscribed = false;
                pc.tx = null;
                if (wasSubscribed && sink != null) sink.onDisconnected(pc.peerId);
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
            if (pc == null || status != BluetoothGatt.GATT_SUCCESS) return;
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
