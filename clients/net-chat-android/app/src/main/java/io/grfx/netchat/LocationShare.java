package io.grfx.netchat;

import android.Manifest;
import android.content.Context;
import android.content.pm.PackageManager;
import android.location.Location;
import android.location.LocationListener;
import android.location.LocationManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;

import java.util.Locale;

/**
 * One-shot location fix for "share my position" in the mesh.
 *
 * Deliberately built on the platform {@link LocationManager} rather than the
 * fused provider: this app has no Google Play services dependency (see
 * app/build.gradle) and adding one to read a single coordinate would be a poor
 * trade. The tablet reports both {@code gps} and {@code network} providers
 * enabled, which is all this needs.
 *
 * NOTHING HERE RUNS UNTIL THE OPERATOR ASKS. There is no periodic sampling and
 * no background registration: a fix is acquired per explicit request and the
 * listener is torn down immediately afterwards. Position is the one thing a
 * chat client should never emit on a timer that the user did not set.
 *
 * The permission is already held for an unrelated reason — Android 11 requires
 * ACCESS_FINE_LOCATION to *scan* for BLE peers, so the manifest declares it and
 * the app is granted it. That makes this free to add, and is also why the code
 * still re-checks the grant: a user can revoke it in Settings while BLE keeps
 * working from a previously-cached grant.
 */
public final class LocationShare {

    /** How stale a cached fix may be before we bother powering up the radio. */
    private static final long FRESH_ENOUGH_MS = 60_000L;
    /** Give the GNSS engine this long before falling back to whatever we have. */
    private static final long LIVE_FIX_TIMEOUT_MS = 20_000L;

    public interface Sink {
        /** @param line human-readable, ready to broadcast; null if unavailable */
        void onFix(String line, Location loc);
        void onStatus(String msg);
    }

    private final Context ctx;
    private final Handler ui = new Handler(Looper.getMainLooper());
    private LocationListener live;

    public LocationShare(Context ctx) { this.ctx = ctx.getApplicationContext(); }

    private boolean granted() {
        return ctx.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION)
                == PackageManager.PERMISSION_GRANTED;
    }

    /**
     * Get a position and hand it to {@code sink}.
     *
     * Strategy is cheapest-first: a cached fix that is recent enough is used as
     * is, because waking the GNSS engine to re-derive a position the device
     * already knows costs seconds and battery for no accuracy gain. Otherwise we
     * ask for one live update and, if the sky view is poor (which indoors it
     * usually is), fall back to the best cached fix rather than reporting
     * nothing — a stale position with its age stated is more useful than
     * silence, provided the age travels with it.
     */
    public void request(Sink sink) {
        if (!granted()) {
            sink.onStatus("location: permission not granted "
                        + "(pm grant io.grfx.netchat android.permission.ACCESS_FINE_LOCATION)");
            sink.onFix(null, null);
            return;
        }
        LocationManager lm = (LocationManager) ctx.getSystemService(Context.LOCATION_SERVICE);
        if (lm == null) { sink.onStatus("location: no LocationManager"); sink.onFix(null, null); return; }

        Location best = bestCached(lm);
        if (best != null && ageMs(best) <= FRESH_ENOUGH_MS) {
            sink.onFix(format(best), best);
            return;
        }

        String provider = lm.isProviderEnabled(LocationManager.GPS_PROVIDER)
                ? LocationManager.GPS_PROVIDER
                : (lm.isProviderEnabled(LocationManager.NETWORK_PROVIDER)
                        ? LocationManager.NETWORK_PROVIDER : null);
        if (provider == null) {
            if (best != null) { sink.onStatus("location: providers off, using cached"); sink.onFix(format(best), best); }
            else { sink.onStatus("location: no provider enabled"); sink.onFix(null, null); }
            return;
        }

        sink.onStatus("location: acquiring via " + provider + " …");
        final Location fallback = best;
        final boolean[] done = { false };

        live = new LocationListener() {
            @Override public void onLocationChanged(Location location) {
                if (done[0]) return;
                done[0] = true;
                stopLive(lm);
                sink.onFix(format(location), location);
            }
            // Required by the pre-API-29 interface; a provider going quiet is
            // handled by the timeout below rather than here, since a disabled
            // provider mid-request is indistinguishable from a slow one.
            @Override public void onStatusChanged(String p, int s, Bundle e) { }
            @Override public void onProviderEnabled(String p) { }
            @Override public void onProviderDisabled(String p) { }
        };

        try {
            lm.requestLocationUpdates(provider, 0L, 0f, live, Looper.getMainLooper());
        } catch (SecurityException se) {
            sink.onStatus("location: denied at request time: " + se.getMessage());
            sink.onFix(fallback == null ? null : format(fallback), fallback);
            return;
        }

        ui.postDelayed(() -> {
            if (done[0]) return;
            done[0] = true;
            stopLive(lm);
            if (fallback != null) {
                sink.onStatus("location: no live fix in " + (LIVE_FIX_TIMEOUT_MS / 1000)
                            + "s, using cached");
                sink.onFix(format(fallback), fallback);
            } else {
                sink.onStatus("location: no fix (indoors? try near a window)");
                sink.onFix(null, null);
            }
        }, LIVE_FIX_TIMEOUT_MS);
    }

    private void stopLive(LocationManager lm) {
        if (live == null) return;
        try { lm.removeUpdates(live); } catch (SecurityException ignored) { }
        live = null;
    }

    private Location bestCached(LocationManager lm) {
        Location best = null;
        for (String p : new String[] { LocationManager.GPS_PROVIDER, LocationManager.NETWORK_PROVIDER }) {
            Location l;
            try { l = lm.getLastKnownLocation(p); } catch (SecurityException se) { continue; }
            if (l == null) continue;
            if (best == null || l.getTime() > best.getTime()) best = l;
        }
        return best;
    }

    private static long ageMs(Location l) { return Math.max(0L, System.currentTimeMillis() - l.getTime()); }

    /**
     * Locale.US is not optional: the default locale formats a decimal point as
     * a comma in much of the world, which would emit "37,42" inside a
     * comma-separated coordinate pair and silently corrupt every consumer.
     *
     * Six decimal places is ~0.1 m — far finer than any fix this will carry,
     * and short enough to stay well inside a BLE message.
     */
    static String format(Location l) {
        StringBuilder sb = new StringBuilder("LOC ");
        sb.append(String.format(Locale.US, "%.6f,%.6f", l.getLatitude(), l.getLongitude()));
        if (l.hasAccuracy()) sb.append(String.format(Locale.US, " acc=%.0fm", l.getAccuracy()));
        if (l.hasAltitude()) sb.append(String.format(Locale.US, " alt=%.0fm", l.getAltitude()));
        sb.append(" src=").append(l.getProvider());
        long age = ageMs(l) / 1000L;
        if (age > 5) sb.append(" age=").append(age).append("s");
        return sb.toString();
    }
}
