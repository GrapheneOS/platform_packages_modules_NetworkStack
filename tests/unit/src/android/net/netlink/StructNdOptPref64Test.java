/*
 * Copyright (C) 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.net.netlink;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import android.net.IpPrefix;

import androidx.test.filters.SmallTest;
import androidx.test.runner.AndroidJUnit4;

import libcore.util.HexEncoding;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.net.InetAddress;
import java.nio.ByteBuffer;

@RunWith(AndroidJUnit4.class)
@SmallTest
public class StructNdOptPref64Test {

    private static final String PREFIX1 = "64:ff9b::";
    private static final String PREFIX2 = "2001:db8:1:2:3:64::";

    private static byte[] prefixBytes(String addrString) throws Exception {
        InetAddress addr = InetAddress.getByName(addrString);
        byte[] prefixBytes = new byte[12];
        System.arraycopy(addr.getAddress(), 0, prefixBytes, 0, 12);
        return prefixBytes;
    }

    private static IpPrefix prefix(String addrString, int prefixLength) throws Exception {
        return new IpPrefix(InetAddress.getByName(addrString), prefixLength);
    }

    private void assertPref64OptMatches(int lifetime, IpPrefix prefix, StructNdOptPref64 opt) {
        assertEquals(StructNdOptPref64.TYPE, opt.type);
        assertEquals(2, opt.length);
        assertEquals(lifetime, opt.lifetime);
        assertEquals(prefix, opt.prefix);
    }

    /**
     * Returns the 2-byte "scaled lifetime and prefix length code" field: 13-bit lifetime, 3-bit PLC
     */
    private short getPref64ScaledLifetimePlc(int lifetime, int prefixLengthCode) {
        return (short) ((lifetime & 0xfff8) | (prefixLengthCode & 0x7));
    }

    private ByteBuffer makeNdOptPref64(int lifetime, byte[] prefix, int prefixLengthCode) {
        if (prefix.length != 12) throw new IllegalArgumentException("Prefix must be 12 bytes");

        ByteBuffer buf = ByteBuffer.allocate(16)
                .put((byte) StructNdOptPref64.TYPE)
                .put((byte) 2)  // len=2 (16 bytes)
                .putShort(getPref64ScaledLifetimePlc(lifetime, prefixLengthCode))
                .put(prefix, 0, 12);

        buf.flip();
        return buf;
    }

    @Test
    public void testParseCannedOption() throws Exception {
        String hexBytes = "2602"               // type=38, len=2 (16 bytes)
                + "0088"                       // lifetime=136, PLC=0 (/96)
                + "20010db80003000400050006";  // 2001:db8:3:4:5:6/96
        byte[] rawBytes = HexEncoding.decode(hexBytes);
        StructNdOptPref64 opt = StructNdOptPref64.parse(ByteBuffer.wrap(rawBytes));
        assertPref64OptMatches(136, prefix("2001:db8:3:4:5:6::", 96), opt);

        hexBytes = "2602"                      // type=38, len=2 (16 bytes)
                + "2752"                       // lifetime=10064, PLC=2 (/56)
                + "0064ff9b0000000000000000";  // 64:ff9b::/56
        rawBytes = HexEncoding.decode(hexBytes);
        opt = StructNdOptPref64.parse(ByteBuffer.wrap(rawBytes));
        assertPref64OptMatches(10064, prefix("64:ff9b::", 56), opt);
    }

    @Test
    public void testParsing() throws Exception {
        // Valid.
        ByteBuffer buf = makeNdOptPref64(600, prefixBytes(PREFIX1), 0);
        StructNdOptPref64 opt = StructNdOptPref64.parse(buf);
        assertPref64OptMatches(600, prefix(PREFIX1, 96), opt);

        // Valid, zero lifetime, /64.
        buf = makeNdOptPref64(0, prefixBytes(PREFIX1), 1);
        opt = StructNdOptPref64.parse(buf);
        assertPref64OptMatches(0, prefix(PREFIX1, 64), opt);

        // Valid, low lifetime, /56.
        buf = makeNdOptPref64(8, prefixBytes(PREFIX2), 2);
        opt = StructNdOptPref64.parse(buf);
        assertPref64OptMatches(8, prefix(PREFIX2, 56), opt);
        assertEquals(new IpPrefix("2001:db8:1::/56"), opt.prefix);  // Prefix is truncated.

        // Valid, maximum lifetime, /32.
        buf = makeNdOptPref64(65528, prefixBytes(PREFIX2), 5);
        opt = StructNdOptPref64.parse(buf);
        assertPref64OptMatches(65528, prefix(PREFIX2, 32), opt);
        assertEquals(new IpPrefix("2001:db8::/32"), opt.prefix);  // Prefix is truncated.

        // Lifetime not divisible by 8.
        buf = makeNdOptPref64(300, prefixBytes(PREFIX2), 0);
        opt = StructNdOptPref64.parse(buf);
        assertPref64OptMatches(296, prefix(PREFIX2, 96), opt);

        // Invalid prefix length codes.
        buf = makeNdOptPref64(600, prefixBytes(PREFIX1), 6);
        assertNull(StructNdOptPref64.parse(buf));
        buf = makeNdOptPref64(600, prefixBytes(PREFIX1), 7);
        assertNull(StructNdOptPref64.parse(buf));

        // Truncated to varying lengths...
        buf = makeNdOptPref64(600, prefixBytes(PREFIX1), 3);
        final int len = buf.limit();
        for (int i = 0; i < buf.limit() - 1; i++) {
            buf.flip();
            buf.limit(i);
            assertNull("Option truncated to " + i + " bytes, should have returned null",
                    StructNdOptPref64.parse(buf));
        }
        buf.flip();
        buf.limit(len);
        // ... but otherwise OK.
        opt = StructNdOptPref64.parse(buf);
        assertPref64OptMatches(600, prefix(PREFIX1, 48), opt);
    }

    @Test
    public void testToString() throws Exception {
        ByteBuffer buf = makeNdOptPref64(600, prefixBytes(PREFIX1), 4);
        StructNdOptPref64 opt = StructNdOptPref64.parse(buf);
        assertPref64OptMatches(600, prefix(PREFIX1, 40), opt);
        assertEquals("NdOptPref64(64:ff9b::/40, 600)", opt.toString());
    }
}
