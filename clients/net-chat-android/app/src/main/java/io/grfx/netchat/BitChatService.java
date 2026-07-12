package io.grfx.netchat;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;

/**
 * Foreground service that owns the BLE peripheral, scanner, and
 * central objects. Runs with a persistent notification so Android
 * doesn't kill it when the activity backgrounds.
 *
 * <p>Wiring is deliberately thin — the activity subclass {@link Bridge}
 * exposes the actual BitChat objects. The service just owns lifecycle.
 */
public final class BitChatService extends Service {

    private static final String CHANNEL_ID = "netchat_ble";
    private static final int NOTIFICATION_ID = 1;

    /** Simple hook the activity implements so we can call back into it
     *  for start/stop of BLE state. Set once via {@link #setBridge}. */
    public interface Bridge {
        void onServiceStarted(Context ctx);
        void onServiceStopped();
    }

    private static Bridge bridge;

    /** Called by MainActivity before startForegroundService. */
    public static void setBridge(Bridge b) { bridge = b; }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        ensureChannel();
        Notification n = new Notification.Builder(this, CHANNEL_ID)
                .setContentTitle("net-chat")
                .setContentText("BitChat mesh running")
                .setSmallIcon(android.R.drawable.stat_sys_data_bluetooth)
                .setOngoing(true)
                .build();
        // Type-tagged on Android 14+ so the OS knows this is a
        // connectedDevice service (Bluetooth foreground use case).
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, n,
                    android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE);
        } else {
            startForeground(NOTIFICATION_ID, n);
        }
        if (bridge != null) bridge.onServiceStarted(this);
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        if (bridge != null) bridge.onServiceStopped();
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) { return null; }

    private void ensureChannel() {
        NotificationManager mgr = getSystemService(NotificationManager.class);
        if (mgr == null) return;
        if (mgr.getNotificationChannel(CHANNEL_ID) != null) return;
        NotificationChannel ch = new NotificationChannel(
                CHANNEL_ID, "BitChat mesh", NotificationManager.IMPORTANCE_LOW);
        ch.setDescription("Keeps BitChat BLE active in the background");
        mgr.createNotificationChannel(ch);
    }
}
