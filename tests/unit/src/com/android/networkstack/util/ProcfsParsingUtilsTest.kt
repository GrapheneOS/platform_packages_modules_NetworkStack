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
package com.android.networkstack.util

import android.net.apf.ProcfsParsingUtils
import androidx.test.filters.SmallTest
import com.android.internal.util.HexDump
import java.net.Inet6Address
import java.net.InetAddress
import kotlin.test.assertEquals
import org.junit.Test

@SmallTest
class ProcfsParsingUtilsTest {
    @Test
    fun testParseNdTrafficClass() {
        val inputString = listOf("25")
        val expectedResult = 25

        assertEquals(
            expectedResult,
            ProcfsParsingUtils.parseNdTrafficClass(inputString)
        )
    }

    @Test
    fun testParseAnycast6Address() {
        val inputString = listOf(
            "41 eth0  2a0034e2abc1334591a733387s2e322e 2",
            "47 wlan0 2a0079e10abc15391ba735397a2e311f 1",
            "48 wlan1 2a004591a733387s2e334e2abc13322e 3"
        )

        val expectedResult = InetAddress.getByAddress(
            HexDump.hexStringToByteArray("2a0079e10abc15391ba735397a2e311f")
        ) as Inet6Address

        assertEquals(
            expectedResult,
            ProcfsParsingUtils.parseAnycast6Address(inputString, "wlan0")
        )
    }
}
