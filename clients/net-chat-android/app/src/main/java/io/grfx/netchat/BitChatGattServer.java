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
        /**
         * Advertising settled. startAdvertising() is ASYNCHRONOUS: start()
         * returning null only means the request was accepted, so without this
         * the UI reported "peripheral up" even when the controller went on to
         * reject the advertisement and the device never became discoverable.
         * Default no-op so existing implementors keep compiling.
         */
        default void onAdvertiseResult(boolean ok, int errorCode) {}
    }

    /** Human-readable form of the AdvertiseCallback.ADVERTISE_FAILED_* codes. */
    static String advertiseError(int code) {
        switch (code) {
            case AdvertiseCallback.ADVERTISE_FAILED_DATA_TOO_LARGE:
                return "data too large (advert + scan response must each fit 31 bytes)";
            case AdvertiseCallback.ADVERTISE_FAILED_TOO_MANY_ADVERTISERS:
                return "too many advertisers (LE advertising slots exhausted)";
            case AdvertiseCallback.ADVERTISE_FAILED_ALREADY_STARTED:
                return "already started";
            case AdvertiseCallback.ADVERTISE_FAILED_INTERNAL_ERROR:
                return "internal error";
            case AdvertiseCallback.ADVERTISE_FAILED_FEATURE_UNSUPPORTED:
                return "feature unsupported on this adapter";
            default:
                return "unknown code " + code;
        }
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
        // Both the primary advertisement and the scan response are hard-capped
        // at 31 bytes of AD payload each, and a 128-bit service UUID is 16 of
        // them. Budget per packet:
        //     primary: flags(3, added by the stack) + UUID AD(2 + 16)      = 21
        //     scan rsp: service-data AD(2 + 16 UUID + 8 peer-id)           = 26
        // The scan response previously carried the "bc-<16 hex>" string (19
        // bytes) as service data: 2 + 16 + 19 = 37 > 31, so the controller
        // rejected the WHOLE advertisement with ADVERTISE_FAILED_DATA_TOO_LARGE
        // (code 1) and this peripheral never advertised at all — it was simply
        // undiscoverable, which went unnoticed because the app also works as a
        // central (it connects out to bridges, which is how the round-trip was
        // demonstrated). Send the peer id as its 8 RAW bytes instead: same
        // information, 11 bytes cheaper, and it fits.
        AdvertiseData data = new AdvertiseData.Builder()
                .setIncludeDeviceName(false)
                .addServiceUuid(BitChatConstants.SERVICE_PARCEL_UUID)
                .build();
        byte[] pidRaw = BitChatScanner.peerIdFromName(localName);   // 8 bytes
        // Capability HINT, one byte appended to the peer id (2 + 16 + 8 + 1 = 27,
        // still inside the 31-byte limit that this advertisement has already been
        // burned by once).
        //
        // A hint, deliberately, not a description: 31 bytes cannot hold "xpra on
        // 14501" and should not try. It says only WHAT KIND of thing this is, so
        // a viewer can rank and filter what is nearby without a round trip; the
        // actual connection details are resolved from the peer id through
        // net-mgr (net-connect already emits proto/host/port/label per target).
        // That split is what keeps discovery working away from infrastructure -
        // the advert is a pointer, and the mesh carries the resolution when the
        // network cannot.
        byte[] sd = new byte[pidRaw.length + 1];
        System.arraycopy(pidRaw, 0, sd, 0, pidRaw.length);
        sd[pidRaw.length] = BitChatConstants.CAP_SELF;
        AdvertiseData scanResponse = new AdvertiseData.Builder()
                .setIncludeDeviceName(false)
                .addServiceData(BitChatConstants.SERVICE_PARCEL_UUID, sd)
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
            if (sink != null) sink.onAdvertiseResult(true, 0);
        }
        @Override public void onStartFailure(int errorCode) {
            Log.w(TAG, "advertise: onStartFailure code=" + errorCode
                    + " (" + advertiseError(errorCode) + ")");
            if (sink != null) sink.onAdvertiseResult(false, errorCode);
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
