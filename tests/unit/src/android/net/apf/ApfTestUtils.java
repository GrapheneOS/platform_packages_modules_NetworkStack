/*
 * Copyright (C) 2023 The Android Open Source Project
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
package android.net.apf;

import static android.net.apf.ApfJniUtils.apfSimulate;

import static org.junit.Assert.assertEquals;

import com.android.internal.util.HexDump;

import java.util.Arrays;

/**
 * The util class for calling the APF interpreter and check the return value
 */
public class ApfTestUtils {
    public static final int PASS = 1;
    public static final int DROP = 0;
    // Interpreter will just accept packets without link layer headers, so pad fake packet to at
    // least the minimum packet size.
    public static final int MIN_PKT_SIZE = 15;

    private ApfTestUtils() {
    }

    private static String label(int code) {
        switch (code) {
            case PASS:
                return "PASS";
            case DROP:
                return "DROP";
            default:
                return "UNKNOWN";
        }
    }

    private static void assertReturnCodesEqual(String msg, int expected, int got) {
        assertEquals(msg, label(expected), label(got));
    }

    private static void assertReturnCodesEqual(int expected, int got) {
        assertEquals(label(expected), label(got));
    }

    private static void assertVerdict(int apfVersion, int expected, byte[] program, byte[] packet,
            int filterAge) {
        final String msg = "Unexpected APF verdict. To debug:\n" + "  apf_run --program "
                + HexDump.toHexString(program) + " --packet " + HexDump.toHexString(packet)
                + " --trace | less\n  ";
        assertReturnCodesEqual(msg, expected,
                apfSimulate(apfVersion, program, packet, null, filterAge));
    }

    /**
     * Runs the APF program and checks the return code is equals to expected value. If not, the
     * customized message is printed.
     */
    public static void assertVerdict(int apfVersion, String msg, int expected, byte[] program,
            byte[] packet, int filterAge) {
        assertReturnCodesEqual(msg, expected,
                apfSimulate(apfVersion, program, packet, null, filterAge));
    }

    /**
     * Runs the APF program and checks the return code is equals to expected value.
     */
    public static void assertVerdict(int apfVersion, int expected, byte[] program, byte[] packet) {
        assertVerdict(apfVersion, expected, program, packet, 0);
    }

    /**
     * Runs the APF program and checks the return code is PASS.
     */
    public static void assertPass(int apfVersion, byte[] program, byte[] packet, int filterAge) {
        assertVerdict(apfVersion, PASS, program, packet, filterAge);
    }

    /**
     * Runs the APF program and checks the return code is PASS.
     */
    public static void assertPass(int apfVersion, byte[] program, byte[] packet) {
        assertVerdict(apfVersion, PASS, program, packet);
    }

    /**
     * Runs the APF program and checks the return code is DROP.
     */
    public static void assertDrop(int apfVersion, byte[] program, byte[] packet, int filterAge) {
        assertVerdict(apfVersion, DROP, program, packet, filterAge);
    }

    /**
     * Runs the APF program and checks the return code is DROP.
     */
    public static void assertDrop(int apfVersion, byte[] program, byte[] packet) {
        assertVerdict(apfVersion, DROP, program, packet);
    }

    /**
     * Checks the generated APF program equals to the expected value.
     */
    public static void assertProgramEquals(byte[] expected, byte[] program) throws AssertionError {
        // assertArrayEquals() would only print one byte, making debugging difficult.
        if (!Arrays.equals(expected, program)) {
            throw new AssertionError("\nexpected: " + HexDump.toHexString(expected) + "\nactual:   "
                    + HexDump.toHexString(program));
        }
    }

    /**
     * Runs the APF program and checks the return code and data regions equals to expected value.
     */
    public static void assertDataMemoryContents(int apfVersion, int expected, byte[] program,
            byte[] packet, byte[] data, byte[] expectedData)
            throws ApfGenerator.IllegalInstructionException, Exception {
        assertReturnCodesEqual(expected,
                apfSimulate(apfVersion, program, packet, data, 0 /* filterAge */));

        // assertArrayEquals() would only print one byte, making debugging difficult.
        if (!Arrays.equals(expectedData, data)) {
            throw new Exception("\nprogram:     " + HexDump.toHexString(program) + "\ndata memory: "
                    + HexDump.toHexString(data) + "\nexpected:    " + HexDump.toHexString(
                    expectedData));
        }
    }

    private static void assertVerdict(int apfVersion, int expected, ApfGenerator gen, byte[] packet,
            int filterAge) throws ApfGenerator.IllegalInstructionException {
        assertReturnCodesEqual(expected,
                apfSimulate(apfVersion, gen.generate(), packet, null, filterAge));
    }

    /**
     * Runs the APF program and checks the return code is PASS.
     */
    public static void assertPass(int apfVersion, ApfGenerator gen, byte[] packet, int filterAge)
            throws ApfGenerator.IllegalInstructionException {
        assertVerdict(apfVersion, PASS, gen, packet, filterAge);
    }

    /**
     * Runs the APF program and checks the return code is DROP.
     */
    public static void assertDrop(int apfVersion, ApfGenerator gen, byte[] packet, int filterAge)
            throws ApfGenerator.IllegalInstructionException {
        assertVerdict(apfVersion, DROP, gen, packet, filterAge);
    }

    /**
     * Runs the APF program and checks the return code is PASS.
     */
    public static void assertPass(int apfVersion, ApfGenerator gen)
            throws ApfGenerator.IllegalInstructionException {
        assertVerdict(apfVersion, PASS, gen, new byte[MIN_PKT_SIZE], 0);
    }

    /**
     * Runs the APF program and checks the return code is DROP.
     */
    public static void assertDrop(int apfVersion, ApfGenerator gen)
            throws ApfGenerator.IllegalInstructionException {
        assertVerdict(apfVersion, DROP, gen, new byte[MIN_PKT_SIZE], 0);
    }
}
