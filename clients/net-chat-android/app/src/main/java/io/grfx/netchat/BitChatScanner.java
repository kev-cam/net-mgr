package io.grfx.netchat;

import android.annotation.SuppressLint;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothManager;
import android.bluetooth.le.BluetoothLeScanner;
import android.bluetooth.le.ScanCallback;
import android.bluetooth.le.ScanFilter;
import android.bluetooth.le.ScanRecord;
import android.bluetooth.le.ScanResult;
import android.bluetooth.le.ScanSettings;
import android.content.Context;
import android.util.Log;

import java.util.Arrays;
import java.util.Collections;

/**
 * Central role. Scans for peripherals advertising the BitChat service
 * UUID; forwards each hit to the caller via {@link Sink#onPeerFound}.
 * Connect + GATT discovery + characteristic subscribe are the next
 * pieces — deliberately separated from this class so scanning stays
 * simple and callback-only.
 */
public final class BitChatScanner {
    private static final String TAG = "BitChatScanner";

    public interface Sink {
        /** peerId is 8 bytes decoded from the local name (all-zero when absent). */
        void onPeerFound(BluetoothDevice device, byte[] peerId, String localName, int rssi);
    }

    private final Context context;
    private final Sink sink;
    private BluetoothLeScanner scanner;

    public BitChatScanner(Context context, Sink sink) {
        this.context = context;
        this.sink = sink;
    }

    @SuppressLint("MissingPermission")
    public String start() {
        BluetoothManager mgr = (BluetoothManager) context.getSystemService(Context.BLUETOOTH_SERVICE);
        if (mgr == null || mgr.getAdapter() == null) return "no BT adapter";
        scanner = mgr.getAdapter().getBluetoothLeScanner();
        if (scanner == null) return "no BLE scanner (adapter off?)";

        // Two filters — peers may advertise the UUID in either the
        // "complete/incomplete list of service UUIDs" AD OR as a
        // service-data AD (mainline bitchat-rust does the latter).
        // A single setServiceUuid() filter misses the service-data
        // variant, which is why we couldn't see bigsony's bitchat-jsonl
        // instances from the tablet.
        ScanFilter uuidFilter = new ScanFilter.Builder()
                .setServiceUuid(BitChatConstants.SERVICE_PARCEL_UUID)
                .build();
        ScanFilter dataFilter = new ScanFilter.Builder()
                .setServiceData(BitChatConstants.SERVICE_PARCEL_UUID,
                        new byte[0], new byte[0])
                .build();
        ScanSettings settings = new ScanSettings.Builder()
                .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
                .setCallbackType(ScanSettings.CALLBACK_TYPE_ALL_MATCHES)
                .build();
        scanner.startScan(Arrays.asList(uuidFilter, dataFilter), settings, scanCallback);
        Log.i(TAG, "BitChat scanner started");
        return null;
    }

    @SuppressLint("MissingPermission")
    public void stop() {
        if (scanner != null) {
            try { scanner.stopScan(scanCallback); } catch (Throwable ignored) {}
            scanner = null;
        }
    }

    private final ScanCallback scanCallback = new ScanCallback() {
        @Override public void onScanResult(int callbackType, ScanResult result) {
            handleResult(result);
        }
        @Override public void onBatchScanResults(java.util.List<ScanResult> results) {
            for (ScanResult r : results) handleResult(r);
        }
        @Override public void onScanFailed(int errorCode) {
            Log.w(TAG, "scan failed code=" + errorCode);
        }
    };

    private void handleResult(ScanResult result) {
        if (result == null || result.getDevice() == null) return;
        ScanRecord rec = result.getScanRecord();
        // LocalName may live in the primary advertisement OR the scan
        // response; ScanRecord.getDeviceName pulls whichever is
        // present. Advertisers who put it in ServiceData carry
        // it in a per-service byte array — check that too.
        String name = rec == null ? null : rec.getDeviceName();
        byte[] sd = rec == null ? null
                : rec.getServiceData(BitChatConstants.SERVICE_PARCEL_UUID);
        if (name == null && sd != null) name = new String(sd);
        byte[] pid = peerIdFromName(name);
        // Raw-bytes form: a 128-bit service UUID already consumes 16 of the 31
        // advertisable bytes, so we publish the peer id as its 8 RAW bytes —
        // 16 hex characters cannot fit alongside the UUID (see
        // BitChatGattServer). Only used when the string path found nothing, so
        // an advertiser that does send hex keeps its existing interpretation.
        // Accept 8 (peer id alone) or 9 (peer id + capability hint) bytes. The
        // exact-8 test this replaces would have rejected every advert from a
        // newer peer outright, losing the peer id as well as the hint.
        if (sd != null && sd.length >= 8 && isZero(pid)) {
            pid = java.util.Arrays.copyOfRange(sd, 0, 8);
        }
        int caps = (sd != null && sd.length >= 9) ? (sd[8] & 0xff) : 0;
        Log.i(TAG, "scan hit: addr=" + result.getDevice().getAddress()
                + " name=" + (name == null ? "(none)" : name)
                + " rssi=" + result.getRssi());
        if (sink != null) {
            sink.onPeerFound(result.getDevice(), pid,
                    name == null ? "" : name, result.getRssi());
        }
    }

    /**
     * Extract 8 raw bytes from any 16-hex substring inside name.
     * Matches our "bc-<16hex>" convention plus iOS/Android mainline
     * variants that embed hex without the "bc-" prefix.
     */
    static byte[] peerIdFromName(String name) {
        byte[] out = new byte[8];
        if (name == null) return out;
        String s = name.toLowerCase();
        for (int i = 0; i + 16 <= s.length(); i++) {
            if (allHex(s, i, i + 16)) {
                for (int j = 0; j < 8; j++) {
                    out[j] = (byte) ((fromHex(s.charAt(i + 2 * j)) << 4)
                            | fromHex(s.charAt(i + 2 * j + 1)));
                }
                return out;
            }
        }
        return out;
    }

    /** True when peerIdFromName() found no hex and returned all zeroes. */
    private static boolean isZero(byte[] b) {
        if (b == null) return true;
        for (byte x : b) if (x != 0) return false;
        return true;
    }

    private static boolean allHex(String s, int start, int end) {
        for (int i = start; i < end; i++) {
            char c = s.charAt(i);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
        }
        return true;
    }

    private static int fromHex(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return 0;
    }
}
