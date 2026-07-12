package io.grfx.netchat.mesh;

import org.junit.Test;

import java.security.SecureRandom;
import java.util.List;

import static org.junit.Assert.*;

/**
 * Slice a large payload, feed the fragments back through the manager
 * (in and out of order), verify byte-perfect reassembly.
 */
public class FragmentManagerTest {

    @Test
    public void slice_and_reassemble_in_order() throws Exception {
        byte[] fragmentId = new byte[8];
        new SecureRandom().nextBytes(fragmentId);
        byte[] original = new byte[2500];
        for (int i = 0; i < original.length; i++) original[i] = (byte) (i & 0xFF);

        List<byte[]> parts = FragmentManager.slice(fragmentId, (byte) 0x02, original);
        assertTrue("more than one fragment", parts.size() > 1);

        FragmentManager m = new FragmentManager();
        byte[] result = null;
        for (int i = 0; i < parts.size(); i++) {
            FragmentManager.Decoded d = FragmentManager.decodePayload(parts.get(i));
            result = m.addFragment(d.header, d.originalType, d.data);
            if (i < parts.size() - 1) assertNull("still fragmented", result);
        }
        assertNotNull("reassembled", result);
        assertArrayEquals("byte-perfect", original, result);
    }

    @Test
    public void reassembles_out_of_order() throws Exception {
        byte[] fragmentId = new byte[8];
        new SecureRandom().nextBytes(fragmentId);
        byte[] original = new byte[4096];
        for (int i = 0; i < original.length; i++) original[i] = (byte) (i * 3 & 0xFF);

        List<byte[]> parts = FragmentManager.slice(fragmentId, (byte) 0x02, original);
        FragmentManager m = new FragmentManager();

        // Feed in reverse — reassembly must still work.
        byte[] result = null;
        for (int i = parts.size() - 1; i >= 0; i--) {
            FragmentManager.Decoded d = FragmentManager.decodePayload(parts.get(i));
            result = m.addFragment(d.header, d.originalType, d.data);
        }
        assertNotNull("reassembled from reverse order", result);
        assertArrayEquals(original, result);
    }

    @Test(expected = FragmentManager.ProtocolException.class)
    public void mismatched_total_rejected() throws Exception {
        FragmentManager m = new FragmentManager();
        FragmentManager.Header h1 = new FragmentManager.Header("aabbccddeeff0011", 0, 3);
        FragmentManager.Header h2 = new FragmentManager.Header("aabbccddeeff0011", 1, 4);
        m.addFragment(h1, (byte) 0x02, new byte[]{1, 2, 3});
        m.addFragment(h2, (byte) 0x02, new byte[]{4, 5, 6});
    }
}
