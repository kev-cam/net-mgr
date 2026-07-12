package io.grfx.netchat.protocol;

import org.junit.Test;

import static org.junit.Assert.*;

public class PaddingTest {

    @Test
    public void optimal_block_size_picks_smallest_fit() {
        assertEquals(256, Padding.optimalBlockSize(1));
        assertEquals(256, Padding.optimalBlockSize(256));
        assertEquals(512, Padding.optimalBlockSize(257));
        assertEquals(1024, Padding.optimalBlockSize(600));
        assertEquals(2048, Padding.optimalBlockSize(1500));
    }

    @Test
    public void oversized_data_is_returned_untouched() {
        assertEquals(5000, Padding.optimalBlockSize(5000));
    }

    @Test
    public void pad_unpad_roundtrip() {
        byte[] in = {1, 2, 3, 4, 5};
        byte[] padded = Padding.pad(in, 256);
        assertEquals(256, padded.length);
        byte[] back = Padding.unpad(padded);
        assertArrayEquals(in, back);
    }

    @Test
    public void pad_at_or_over_target_no_op() {
        byte[] in = new byte[300];
        byte[] padded = Padding.pad(in, 256);
        assertArrayEquals(in, padded);
    }

    @Test
    public void unpad_invalid_returns_input() {
        byte[] junk = {1, 2, 3, 0};                     // trailing 0 → invalid PKCS#7
        assertArrayEquals(junk, Padding.unpad(junk));
    }
}
