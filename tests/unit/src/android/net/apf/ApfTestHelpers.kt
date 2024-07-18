/*
 * Copyright (C) 2024 The Android Open Source Project
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
package android.net.apf

import android.net.apf.ApfCounterTracker.Counter
import android.net.apf.ApfCounterTracker.Counter.APF_PROGRAM_ID
import android.net.apf.ApfCounterTracker.Counter.APF_VERSION
import android.net.apf.ApfCounterTracker.Counter.TOTAL_PACKETS
import android.net.apf.BaseApfGenerator.APF_VERSION_6
import android.net.ip.IpClient
import com.android.net.module.util.HexDump
import kotlin.test.assertEquals
import org.mockito.ArgumentCaptor
import org.mockito.Mockito.clearInvocations
import org.mockito.Mockito.timeout
import org.mockito.Mockito.verify

class ApfTestHelpers private constructor() {
    companion object {
        const val TIMEOUT_MS: Long = 1000
        const val PASS: Int = 1
        const val DROP: Int = 0

        // Interpreter will just accept packets without link layer headers, so pad fake packet to at
        // least the minimum packet size.
        const val MIN_PKT_SIZE: Int = 15
        private fun label(code: Int): String {
            return when (code) {
                PASS -> "PASS"
                DROP -> "DROP"
                else -> "UNKNOWN"
            }
        }

        private fun assertReturnCodesEqual(msg: String, expected: Int, got: Int) {
            assertEquals(label(expected), label(got), msg)
        }

        private fun assertReturnCodesEqual(expected: Int, got: Int) {
            assertEquals(label(expected), label(got))
        }

        private fun assertVerdict(
            apfVersion: Int,
            expected: Int,
            program: ByteArray,
            packet: ByteArray,
            filterAge: Int
        ) {
            val msg = """Unexpected APF verdict. To debug:
                apf_run
                    --program ${HexDump.toHexString(program)}
                    --packet ${HexDump.toHexString(packet)}
                    --age $filterAge
                    ${if (apfVersion > 4) " --v6" else ""}
                    --trace " + " | less\n
            """
            assertReturnCodesEqual(
                msg,
                expected,
                ApfJniUtils.apfSimulate(apfVersion, program, packet, null, filterAge)
            )
        }

        @Throws(BaseApfGenerator.IllegalInstructionException::class)
        private fun assertVerdict(
            apfVersion: Int,
            expected: Int,
            gen: ApfV4Generator,
            packet: ByteArray,
            filterAge: Int
        ) {
            assertVerdict(apfVersion, expected, gen.generate(), packet, null, filterAge)
        }

        private fun assertVerdict(
            apfVersion: Int,
            expected: Int,
            program: ByteArray,
            packet: ByteArray,
            data: ByteArray?,
            filterAge: Int
        ) {
            val msg = """Unexpected APF verdict. To debug:
                apf_run
                    --program ${HexDump.toHexString(program)}
                    --packet ${HexDump.toHexString(packet)}
                    ${if (data != null) "--data ${HexDump.toHexString(data)}" else ""}
                    --age $filterAge
                    ${if (apfVersion > 4) "--v6" else ""}
                    --trace | less
            """
            assertReturnCodesEqual(
                msg,
                expected,
                ApfJniUtils.apfSimulate(apfVersion, program, packet, data, filterAge)
            )
        }

        /**
         * Runs the APF program with customized data region and checks the return code.
         */
        fun assertVerdict(
            apfVersion: Int,
            expected: Int,
            program: ByteArray,
            packet: ByteArray,
            data: ByteArray?
        ) {
            assertVerdict(apfVersion, expected, program, packet, data, filterAge = 0)
        }

        /**
         * Runs the APF program and checks the return code is equals to expected value. If not, the
         * customized message is printed.
         */
        @JvmStatic
        fun assertVerdict(
            apfVersion: Int,
            msg: String,
            expected: Int,
            program: ByteArray?,
            packet: ByteArray?,
            filterAge: Int
        ) {
            assertReturnCodesEqual(
                msg,
                expected,
                ApfJniUtils.apfSimulate(apfVersion, program, packet, null, filterAge)
            )
        }

        /**
         * Runs the APF program and checks the return code is equals to expected value.
         */
        @JvmStatic
        fun assertVerdict(apfVersion: Int, expected: Int, program: ByteArray, packet: ByteArray) {
            assertVerdict(apfVersion, expected, program, packet, 0)
        }

        /**
         * Runs the APF program and checks the return code is PASS.
         */
        @JvmStatic
        fun assertPass(apfVersion: Int, program: ByteArray, packet: ByteArray, filterAge: Int) {
            assertVerdict(apfVersion, PASS, program, packet, filterAge)
        }

        /**
         * Runs the APF program and checks the return code is PASS.
         */
        @JvmStatic
        fun assertPass(apfVersion: Int, program: ByteArray, packet: ByteArray) {
            assertVerdict(apfVersion, PASS, program, packet)
        }

        /**
         * Runs the APF program and checks the return code is DROP.
         */
        @JvmStatic
        fun assertDrop(apfVersion: Int, program: ByteArray, packet: ByteArray, filterAge: Int) {
            assertVerdict(apfVersion, DROP, program, packet, filterAge)
        }

        /**
         * Runs the APF program and checks the return code is DROP.
         */
        @JvmStatic
        fun assertDrop(apfVersion: Int, program: ByteArray, packet: ByteArray) {
            assertVerdict(apfVersion, DROP, program, packet)
        }

        /**
         * Runs the APF program and checks the return code is PASS.
         */
        @Throws(BaseApfGenerator.IllegalInstructionException::class)
        @JvmStatic
        fun assertPass(apfVersion: Int, gen: ApfV4Generator, packet: ByteArray, filterAge: Int) {
            assertVerdict(apfVersion, PASS, gen, packet, filterAge)
        }

        /**
         * Runs the APF program and checks the return code is DROP.
         */
        @Throws(BaseApfGenerator.IllegalInstructionException::class)
        @JvmStatic
        fun assertDrop(apfVersion: Int, gen: ApfV4Generator, packet: ByteArray, filterAge: Int) {
            assertVerdict(apfVersion, DROP, gen, packet, filterAge)
        }

        /**
         * Runs the APF program and checks the return code is PASS.
         */
        @Throws(BaseApfGenerator.IllegalInstructionException::class)
        @JvmStatic
        fun assertPass(apfVersion: Int, gen: ApfV4Generator) {
            assertVerdict(apfVersion, PASS, gen, ByteArray(MIN_PKT_SIZE), 0)
        }

        /**
         * Runs the APF program and checks the return code is DROP.
         */
        @Throws(BaseApfGenerator.IllegalInstructionException::class)
        @JvmStatic
        fun assertDrop(apfVersion: Int, gen: ApfV4Generator) {
            assertVerdict(apfVersion, DROP, gen, ByteArray(MIN_PKT_SIZE), 0)
        }

        /**
         * Checks the generated APF program equals to the expected value.
         */
        @Throws(AssertionError::class)
        @JvmStatic
        fun assertProgramEquals(expected: ByteArray, program: ByteArray?) {
            // assertArrayEquals() would only print one byte, making debugging difficult.
            if (!expected.contentEquals(program)) {
                throw AssertionError(
                    "\nexpected: " + HexDump.toHexString(expected) +
                    "\nactual:   " + HexDump.toHexString(program)
                )
            }
        }

        /**
         * Runs the APF program and checks the return code and data regions
         * equals to expected value.
         */
        @Throws(BaseApfGenerator.IllegalInstructionException::class, Exception::class)
        @JvmStatic
        fun assertDataMemoryContents(
            apfVersion: Int,
            expected: Int,
            program: ByteArray?,
            packet: ByteArray?,
            data: ByteArray,
            expectedData: ByteArray,
            ignoreInterpreterVersion: Boolean
        ) {
            assertReturnCodesEqual(
                expected,
                ApfJniUtils.apfSimulate(apfVersion, program, packet, data, 0)
            )

            if (ignoreInterpreterVersion) {
                val apfVersionIdx = (Counter.totalSize() +
                        APF_VERSION.offset())
                val apfProgramIdIdx = (Counter.totalSize() +
                        APF_PROGRAM_ID.offset())
                for (i in 0..3) {
                    data[apfVersionIdx + i] = 0
                    data[apfProgramIdIdx + i] = 0
                }
            }
            // assertArrayEquals() would only print one byte, making debugging difficult.
            if (!expectedData.contentEquals(data)) {
                throw Exception(
                    ("\nprogram:     " + HexDump.toHexString(program) +
                     "\ndata memory: " + HexDump.toHexString(data) +
                     "\nexpected:    " + HexDump.toHexString(expectedData))
                )
            }
        }

        fun verifyProgramRun(
            version: Int,
            program: ByteArray,
            pkt: ByteArray,
            targetCnt: Counter,
            cntMap: MutableMap<Counter, Long> = mutableMapOf(),
            dataRegion: ByteArray = ByteArray(Counter.totalSize()) { 0 },
            incTotal: Boolean = true,
            result: Int = if (targetCnt.name.startsWith("PASSED")) PASS else DROP
        ) {
            assertVerdict(version, result, program, pkt, dataRegion)
            cntMap[targetCnt] = cntMap.getOrDefault(targetCnt, 0) + 1
            if (incTotal) {
                cntMap[TOTAL_PACKETS] = cntMap.getOrDefault(TOTAL_PACKETS, 0) + 1
            }
            val errMsg = "Counter is not increased properly. To debug: \n" +
                    " apf_run --program ${HexDump.toHexString(program)} " +
                    "--packet ${HexDump.toHexString(pkt)} " +
                    "--data ${HexDump.toHexString(dataRegion)} --age 0 " +
                    "${if (version == APF_VERSION_6) "--v6" else "" } --trace  | less \n"
            assertEquals(cntMap, decodeCountersIntoMap(dataRegion), errMsg)
        }

        fun decodeCountersIntoMap(counterBytes: ByteArray): Map<Counter, Long> {
            val counters = Counter::class.java.enumConstants
            val ret = HashMap<Counter, Long>()
            val skippedCounters = setOf(APF_PROGRAM_ID, APF_VERSION)
            // starting from index 2 to skip the endianness mark
            if (counters != null) {
                for (c in listOf(*counters).subList(2, counters.size)) {
                    if (c in skippedCounters) continue
                    val value = ApfCounterTracker.getCounterValue(counterBytes, c)
                    if (value != 0L) {
                        ret[c] = value
                    }
                }
            }
            return ret
        }

        @JvmStatic
        fun consumeInstalledProgram(
            ipClientCb: IpClient.IpClientCallbacksWrapper,
            installCnt: Int
        ): ByteArray {
            val programCaptor = ArgumentCaptor.forClass(
                ByteArray::class.java
            )

            verify(ipClientCb, timeout(TIMEOUT_MS).times(installCnt)).installPacketFilter(
                programCaptor.capture()
            )

            clearInvocations<Any>(ipClientCb)
            return programCaptor.value
        }
    }
}
