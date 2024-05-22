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

import android.net.MacAddress
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
            "42 wlan0 2a0012e2abcddee459123738456e134a 4",
            "47 wlan0 2a0079e10abc15391ba735397a2e311f 1",
            "48 wlan1 2a004591a733387s2e334e2abc13322e 3"
        )

        val expectedResult = listOf(
            InetAddress.getByAddress(
                HexDump.hexStringToByteArray("2a0012e2abcddee459123738456e134a")
            ) as Inet6Address,
            InetAddress.getByAddress(
                HexDump.hexStringToByteArray("2a0079e10abc15391ba735397a2e311f")
            ) as Inet6Address
        )

        assertEquals(
            expectedResult,
            ProcfsParsingUtils.parseAnycast6Addresses(inputString, "wlan0")
        )
    }

    @Test
    fun testParseEtherMulticastAddress() {
        val inputString = listOf(
            "2    dummy0          1     0     333300000001",
            "2    dummy0          1     0     01005e000001",
            "3    ifb0            1     0     333300000001",
            "4    ifb1            1     0     333300000001",
            "7    gretap0         1     0     333300000001",
            "8    erspan0         1     0     333300000001",
            "47   wlan0           1     0     01005e000001",
            "47   wlan0           1     0     333300000001",
            "47   wlan0           1     0     3333ff8a3667",
            "47   wlan0           1     0     3333ff59c632",
            "47   wlan0           1     0     3333ff574870",
            "48   wlan1           1     0     333300000001"
        )

        val expectedResult = listOf(
            MacAddress.fromBytes(HexDump.hexStringToByteArray("01005e000001")),
            MacAddress.fromBytes(HexDump.hexStringToByteArray("333300000001")),
            MacAddress.fromBytes(HexDump.hexStringToByteArray("3333ff8a3667")),
            MacAddress.fromBytes(HexDump.hexStringToByteArray("3333ff59c632")),
            MacAddress.fromBytes(HexDump.hexStringToByteArray("3333ff574870"))
        )

        assertEquals(
            expectedResult,
            ProcfsParsingUtils.parseEtherMulticastAddresses(inputString, "wlan0")
        )
    }

    @Test
    fun testParseIpv6MulticastAddress() {
        val inputString = listOf(
            "44   umts_dummy      ff020000000000000000000000000001     1 0000000C 0",
            "44   umts_dummy      ff010000000000000000000000000001     1 00000008 0",
            "46   aware_nmi0      ff020000000000000000000000000001     1 00000008 0",
            "46   aware_nmi0      ff010000000000000000000000000001     1 00000008 0",
            "47   wlan0           ff0200000000000000000001ff574870     1 00000004 0",
            "47   wlan0           ff0200000000000000000001ff59c632     1 00000004 0",
            "47   wlan0           ff0200000000000000000001ff8a3667     2 00000004 0",
            "47   wlan0           ff020000000000000000000000000001     1 0000000C 0",
            "47   wlan0           ff010000000000000000000000000001     1 00000008 0",
            "48   wlan1           ff020000000000000000000000000001     1 0000000C 0",
            "48   wlan1           ff010000000000000000000000000001     1 00000008 0",
            "49   radiotap0       ff020000000000000000000000000001     1 0000000C 0",
            "49   radiotap0       ff010000000000000000000000000001     1 00000008 0",
            "50   v4-wlan0        ff020000000000000000000000000001     1 0000000C 0",
            "50   v4-wlan0        ff010000000000000000000000000001     1 00000008 0"
        )

        val expectedResult = listOf(
            InetAddress.getByAddress(
                HexDump.hexStringToByteArray("ff0200000000000000000001ff574870")
            ) as Inet6Address,
            InetAddress.getByAddress(
                HexDump.hexStringToByteArray("ff0200000000000000000001ff59c632")
            ) as Inet6Address,
            InetAddress.getByAddress(
                HexDump.hexStringToByteArray("ff0200000000000000000001ff8a3667")
            ) as Inet6Address,
            InetAddress.getByAddress(
                HexDump.hexStringToByteArray("ff020000000000000000000000000001")
            ) as Inet6Address,
            InetAddress.getByAddress(
                HexDump.hexStringToByteArray("ff010000000000000000000000000001")
            ) as Inet6Address
        )

        assertEquals(
            expectedResult,
            ProcfsParsingUtils.parseIPv6MulticastAddresses(inputString, "wlan0")
        )
    }
}
