package io.grfx.netchat.protocol;

/**
 * PKCS#7 padding to one of the fixed block sizes iOS + Android +
 * bitchat-rust all agree on. Any change here breaks Announce
 * signature verification against mainline clients — the signed bytes
 * MUST reproduce byte-for-byte.
 */
public final class Padding {
    private Padding() {}

    private static final int[] BLOCKS = {256, 512, 1024, 2048};

    /** Smallest block from {@link #BLOCKS} that fits dataSize; else dataSize itself. */
    public static int optimalBlockSize(int dataSize) {
        for (int b : BLOCKS) if (dataSize <= b) return b;
        return dataSize;
    }

    /** PKCS#7 pad to targetSize. If padding needed > 255 (byte-count limit)
     *  or data is already at/over target, returns data unchanged. */
    public static byte[] pad(byte[] data, int targetSize) {
        if (data.length >= targetSize) return data.clone();
        int need = targetSize - data.length;
        if (need > 255) return data.clone();
        byte[] out = new byte[targetSize];
        System.arraycopy(data, 0, out, 0, data.length);
        byte fill = (byte) need;
        for (int i = data.length; i < targetSize; i++) out[i] = fill;
        return out;
    }

    /** Reverse PKCS#7. Invalid padding (0 or > length) → return input unchanged. */
    public static byte[] unpad(byte[] data) {
        if (data.length == 0) return data;
        int n = data[data.length - 1] & 0xFF;
        if (n == 0 || n > data.length) return data;
        byte[] out = new byte[data.length - n];
        System.arraycopy(data, 0, out, 0, out.length);
        return out;
    }
}
