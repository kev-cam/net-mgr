package io.grfx.netchat;

import android.os.ParcelUuid;

import java.util.UUID;

/**
 * BitChat wire constants shared between the GATT server (Peripheral)
 * and the scanner (Central). Both UUIDs come straight from the
 * Rust reference (bitchat-rust: SERVICE_UUID = 0xF47B5E2D_4A9E_...),
 * matching iOS/Android mainline so we can interop.
 */
public final class BitChatConstants {
    /** Advertised service UUID. Peers scan for this. */
    public static final UUID SERVICE_UUID =
            UUID.fromString("F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C");

    /** Read/Write/Notify characteristic that carries wire packets both directions. */
    public static final UUID CHARACTERISTIC_UUID =
            UUID.fromString("A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D");

    /** Client Characteristic Configuration Descriptor — required by the
     *  Bluetooth SIG spec for any characteristic supporting Notify. Central
     *  writes 0x0001 here to enable notifications. */
    public static final UUID CCCD_UUID =
            UUID.fromString("00002902-0000-1000-8000-00805f9b34fb");

    /** ParcelUuid form for the scan/advertise APIs. */
    public static final ParcelUuid SERVICE_PARCEL_UUID = new ParcelUuid(SERVICE_UUID);

    /** Local-name prefix so we can recognise our own advertisements
     *  (and cheap peer_id transport) without collision with random BLE
     *  gear. Format: "bc-<16 hex>". */
    public static final String LOCAL_NAME_PREFIX = "bc-";

    private BitChatConstants() {}
}
