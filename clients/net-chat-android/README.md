# net-chat-android

Pure-Java Android BitChat client. First cut: BLE Peripheral + Central
proof-of-life. Advertises the BitChat service UUID, scans for other
advertisers, logs every event to an on-screen console.

## Why Java and not Kotlin / Go / Rust

- Android's BLE Peripheral APIs are Java classes with subclassable
  callback types (`BluetoothGattServerCallback`, `AdvertiseCallback`,
  `ScanCallback`). Every other language has to reach them through JNI
  plus a real `.class` file, which is the wall that stopped the Go and
  Rust attempts. Java skips that wall entirely.
- No new build tooling — Android Studio + Gradle handle everything.

## Layout

```
app/src/main/
├── AndroidManifest.xml          BLE permissions + activity
├── java/io/grfx/netchat/
│   ├── MainActivity.java        UI + permission dance + wiring
│   ├── BitChatConstants.java    Wire-compatible UUIDs
│   ├── BitChatGattServer.java   Peripheral role
│   └── BitChatScanner.java      Central role
└── res/
    ├── layout/activity_main.xml Start/Stop buttons + scrolling log
    └── values/strings.xml
```

## Build + install

```
cd clients/net-chat-android
./gradlew installDebug           # phone connected via ADB, USB debugging on
```

If there's no `./gradlew` wrapper yet, run once from Android Studio
(File → Open → this directory) or install the Gradle CLI and run
`gradle wrapper` first.

## What works today

- Requests BLUETOOTH_SCAN / _ADVERTISE / _CONNECT (Android 12+) or
  ACCESS_FINE_LOCATION (Android 8-11) at Start.
- Registers a GATT service with one Read+Write+Notify characteristic
  and a CCCD descriptor (0x2902).
- Advertises SERVICE_UUID with local name `bc-<16 hex peer_id>` in
  the scan response.
- Scans for peers advertising SERVICE_UUID, prints each hit with
  peer_id + name + RSSI + MAC.

## What's next

- Connect back to discovered peers (`BluetoothGatt.connectGatt`) and
  subscribe to their characteristic for incoming Notify.
- Port bitchat-rust's `protocol/`, `crypto/` (Noise-XX), `mesh/`,
  `model/` packages to Java under `io.grfx.netchat.protocol`, etc.
  Straight port; the Go side is already done and can be transliterated.
- Background Service + foreground notification so BLE keeps running
  when the operator swipes the activity away.
- Optional local socket for a companion Go/Fyne UI to connect to
  (matches the "helper subprocess" model discussed in the plan).

## Wire compatibility

`SERVICE_UUID` and `CHARACTERISTIC_UUID` are taken verbatim from
`bitchat-rust::mesh::bluetooth_connection_manager` (which took them
from mainline iOS/Android BitChat), so this app should peer with
iOS/Android BitChat clients out of the box once the protocol port
lands.
