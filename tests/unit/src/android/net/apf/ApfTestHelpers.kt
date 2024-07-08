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
import android.net.apf.ApfTestUtils.DROP
import android.net.apf.ApfTestUtils.PASS
import android.net.apf.ApfTestUtils.assertVerdict
import android.net.apf.BaseApfGenerator.APF_VERSION_6
import com.android.net.module.util.HexDump
import kotlin.test.assertEquals

class ApfTestHelpers private constructor() {
    companion object {
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
    }
}
