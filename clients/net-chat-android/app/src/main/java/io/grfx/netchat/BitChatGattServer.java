package io.grfx.netchat;

import android.annotation.SuppressLint;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattDescriptor;
import android.bluetooth.BluetoothGattServer;
import android.bluetooth.BluetoothGattServerCallback;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.BluetoothManager;
import android.bluetooth.le.AdvertiseCallback;
import android.bluetooth.le.AdvertiseData;
import android.bluetooth.le.AdvertiseSettings;
import android.bluetooth.le.BluetoothLeAdvertiser;
import android.content.Context;
import android.util.Log;

/**
 * Peripheral role. Hosts a GATT service with one Read+Write+Notify
 * characteristic, and starts advertising the service UUID so other
 * BitChat centrals can find us.
 *
 * <p>Inbound writes fire {@link EventSink#onInbound(BluetoothDevice, byte[])};
 * outbound Notify goes through {@link #notify(byte[])} which pushes the
 * value to every subscribed central.
 */
public final class BitChatGattServer {
    private static final String TAG = "BitChatGattServer";

    /** Callback surface the caller wires up to receive events. */
    public interface EventSink {
        void onInbound(BluetoothDevice from, byte[] data);
        void onSubscribed(BluetoothDevice device);
        void onUnsubscribed(BluetoothDevice device);
    }

    private final Context context;
    private final EventSink sink;
    private BluetoothGattServer server;
    private BluetoothGattCharacteristic char_;
    private BluetoothLeAdvertiser advertiser;
    private final java.util.List<BluetoothDevice> subscribers = new java.util.ArrayList<>();

    public BitChatGattServer(Context context, EventSink sink) {
        this.context = context;
        this.sink = sink;
    }

    /**
     * Boot the peripheral. Returns null on success; otherwise an
     * error message the caller can surface to the operator.
     */
    @SuppressLint("MissingPermission")
    public String start(String localName) {
        BluetoothManager mgr = (BluetoothManager) context.getSystemService(Context.BLUETOOTH_SERVICE);
        if (mgr == null) return "no BluetoothManager";
        if (mgr.getAdapter() == null) return "no BT adapter on this device";
        if (!mgr.getAdapter().isEnabled()) return "Bluetooth is off";
        advertiser = mgr.getAdapter().getBluetoothLeAdvertiser();
        if (advertiser == null) return "device doesn't support BLE advertising (Peripheral)";

        // --- GATT server -------------------------------------------------
        server = mgr.openGattServer(context, gattServerCallback);
        if (server == null) return "openGattServer failed";

        char_ = new BluetoothGattCharacteristic(
                BitChatConstants.CHARACTERISTIC_UUID,
                BluetoothGattCharacteristic.PROPERTY_READ
                        | BluetoothGattCharacteristic.PROPERTY_WRITE
                        | BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE
                        | BluetoothGattCharacteristic.PROPERTY_NOTIFY,
                BluetoothGattCharacteristic.PERMISSION_READ
                        | BluetoothGattCharacteristic.PERMISSION_WRITE);

        // CCCD — Notify needs it. Central writes 0x0001 here to subscribe.
        BluetoothGattDescriptor cccd = new BluetoothGattDescriptor(
                BitChatConstants.CCCD_UUID,
                BluetoothGattDescriptor.PERMISSION_READ
                        | BluetoothGattDescriptor.PERMISSION_WRITE);
        char_.addDescriptor(cccd);

        BluetoothGattService svc = new BluetoothGattService(
                BitChatConstants.SERVICE_UUID,
                BluetoothGattService.SERVICE_TYPE_PRIMARY);
        svc.addCharacteristic(char_);
        if (!server.addService(svc)) {
            return "addService returned false";
        }

        // --- Advertise --------------------------------------------------
        AdvertiseSettings settings = new AdvertiseSettings.Builder()
                .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
                .setConnectable(true)
                .setTimeout(0)                // indefinite
                .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM)
                .build();
        // The BLE advertisement packet is ~31 bytes; the local name can
        // eat all of it, so put service UUID in the primary packet and
        // the local name in the scan response.
        AdvertiseData data = new AdvertiseData.Builder()
                .setIncludeDeviceName(false)
                .addServiceUuid(BitChatConstants.SERVICE_PARCEL_UUID)
                .build();
        AdvertiseData scanResponse = new AdvertiseData.Builder()
                .setIncludeDeviceName(false)
                // "bc-" + 16 hex = 19 bytes; comfortably fits scan response.
                .addServiceData(BitChatConstants.SERVICE_PARCEL_UUID,
                        localName.getBytes())
                .build();
        advertiser.startAdvertising(settings, data, scanResponse, advertiseCallback);
        Log.i(TAG, "BitChat peripheral started, localName=" + localName);
        return null;
    }

    /** Push data to every subscribed central via Notify. Returns the
     *  number of subscribers actually notified (0 = frame dropped
     *  silently — the case we want to catch when the bridge stops
     *  reading and we can't tell locally). */
    @SuppressLint("MissingPermission")
    public int notify(byte[] data) {
        if (char_ == null || server == null) {
            Log.i(TAG, "notify subscribers=0 bytes=" + data.length + " (server not up)");
            return 0;
        }
        char_.setValue(data);
        int total = subscribers.size();
        int ok = 0;
        for (BluetoothDevice d : subscribers) {
            try {
                if (server.notifyCharacteristicChanged(d, char_, false)) ok++;
            } catch (SecurityException ignored) {
                // BLUETOOTH_CONNECT was revoked; keep going.
            }
        }
        // Log every send. In logcat we can grep by tag "BitChatGattServer"
        // to correlate with bridge-side timestamps. subs= is what
        // OUR list thinks; ok/= counts how many notifyCharacteristicChanged
        // actually returned true (false = queue full / device gone).
        Log.i(TAG, "notify subs=" + total + " ok=" + ok + " bytes=" + data.length);
        return ok;
    }

    /** Tear down advertising + GATT server. Safe to call twice. */
    @SuppressLint("MissingPermission")
    public void stop() {
        if (advertiser != null) {
            try { advertiser.stopAdvertising(advertiseCallback); } catch (Throwable ignored) {}
            advertiser = null;
        }
        if (server != null) {
            try { server.close(); } catch (Throwable ignored) {}
            server = null;
        }
        subscribers.clear();
    }

    private final AdvertiseCallback advertiseCallback = new AdvertiseCallback() {
        @Override public void onStartSuccess(AdvertiseSettings settingsInEffect) {
            Log.i(TAG, "advertise: onStartSuccess");
        }
        @Override public void onStartFailure(int errorCode) {
            Log.w(TAG, "advertise: onStartFailure code=" + errorCode);
        }
    };

    private final BluetoothGattServerCallback gattServerCallback = new BluetoothGattServerCallback() {
        @Override
        @SuppressLint("MissingPermission")
        public void onCharacteristicWriteRequest(BluetoothDevice device, int requestId,
                BluetoothGattCharacteristic characteristic, boolean preparedWrite,
                boolean responseNeeded, int offset, byte[] value) {
            if (!BitChatConstants.CHARACTERISTIC_UUID.equals(characteristic.getUuid())) {
                if (responseNeeded && server != null) {
                    server.sendResponse(device, requestId,
                            BluetoothGatt.GATT_INVALID_ATTRIBUTE_LENGTH, offset, null);
                }
                return;
            }
            if (sink != null && value != null) {
                sink.onInbound(device, value);
            }
            if (responseNeeded && server != null) {
                server.sendResponse(device, requestId,
                        BluetoothGatt.GATT_SUCCESS, offset, value);
            }
        }

        @Override
        @SuppressLint("MissingPermission")
        public void onDescriptorWriteRequest(BluetoothDevice device, int requestId,
                BluetoothGattDescriptor descriptor, boolean preparedWrite,
                boolean responseNeeded, int offset, byte[] value) {
            if (BitChatConstants.CCCD_UUID.equals(descriptor.getUuid()) && value != null) {
                boolean enable = value.length >= 2
                        && value[0] == BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE[0]
                        && value[1] == BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE[1];
                boolean disable = value.length >= 2
                        && value[0] == BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE[0]
                        && value[1] == BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE[1];
                if (enable && !subscribers.contains(device)) {
                    subscribers.add(device);
                    if (sink != null) sink.onSubscribed(device);
                } else if (disable) {
                    if (subscribers.remove(device) && sink != null) {
                        sink.onUnsubscribed(device);
                    }
                }
            }
            if (responseNeeded && server != null) {
                server.sendResponse(device, requestId,
                        BluetoothGatt.GATT_SUCCESS, offset, value);
            }
        }
    };
}
