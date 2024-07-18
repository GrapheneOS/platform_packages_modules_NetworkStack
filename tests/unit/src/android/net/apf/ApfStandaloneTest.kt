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

import android.net.apf.ApfConstants.DHCP_SERVER_PORT
import android.net.apf.ApfConstants.ETH_HEADER_LEN
import android.net.apf.ApfConstants.ICMP6_TYPE_OFFSET
import android.net.apf.ApfConstants.IPV4_BROADCAST_ADDRESS
import android.net.apf.ApfConstants.IPV4_DEST_ADDR_OFFSET
import android.net.apf.ApfConstants.IPV4_PROTOCOL_OFFSET
import android.net.apf.ApfConstants.IPV4_SRC_ADDR_OFFSET
import android.net.apf.ApfConstants.IPV6_NEXT_HEADER_OFFSET
import android.net.apf.ApfConstants.TCP_UDP_DESTINATION_PORT_OFFSET
import android.net.apf.BaseApfGenerator.APF_VERSION_4
import android.net.apf.BaseApfGenerator.MemorySlot
import android.net.apf.BaseApfGenerator.Register.R0
import android.net.apf.BaseApfGenerator.Register.R1
import android.system.OsConstants
import android.system.OsConstants.ETH_P_IP
import android.system.OsConstants.IPPROTO_ICMPV6
import android.util.Log
import androidx.test.filters.SmallTest
import com.android.net.module.util.HexDump
import com.android.net.module.util.NetworkStackConstants.ETHER_TYPE_OFFSET
import com.android.net.module.util.NetworkStackConstants.ICMPV6_ROUTER_SOLICITATION
import com.android.testutils.DevSdkIgnoreRunner
import kotlin.test.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

/**
 * This class generate ApfStandaloneTest programs for side-loading into firmware without needing the
 * ApfFilter.java dependency. Its bytecode facilitates Wi-Fi chipset vendor regression tests,
 * preventing issues caused by APF interpreter integration.
 *
 * Note: Code size optimization is not a priority for these test programs, so some redundancy may
 * exist.
 */
@RunWith(DevSdkIgnoreRunner::class)
@SmallTest
class ApfStandaloneTest {

    private val etherTypeDenyList = listOf(0x88A2, 0x88A4, 0x88B8, 0x88CD, 0x88E1, 0x88E3)
    private val ramSize = 1024
    private val clampSize = 1024

    fun runApfTest(isSuspendMode: Boolean) {
        val program = generateApfV4Program(isSuspendMode)
        Log.w(
            TAG,
            "Program should be run in SETSUSPENDMODE $isSuspendMode: " +
                HexDump.toHexString(program)
        )
        // packet that in ethertype denylist:
        // ###[ Ethernet ]###
        //   dst       = ff:ff:ff:ff:ff:ff
        //   src       = 04:7b:cb:46:3f:b5
        //   type      = 0x88a2
        // ###[ Raw ]###
        //   load      = '01'
        //
        // raw bytes:
        // ffffffffffff047bcb463fb588a21

        val packetBadEtherType =
                HexDump.hexStringToByteArray("ffffffffffff047bcb463fb588a201")
        val dataRegion = ByteArray(Counter.totalSize()) { 0 }
        ApfTestHelpers.assertVerdict(
            APF_VERSION_4,
            ApfTestHelpers.DROP,
            program,
            packetBadEtherType,
            dataRegion
        )
        assertEquals(mapOf<Counter, Long>(
                Counter.TOTAL_PACKETS to 1,
                Counter.DROPPED_ETHERTYPE_DENYLISTED to 1
        ), decodeCountersIntoMap(dataRegion))

        // dhcp request packet.
        // ###[ Ethernet ]###
        //   dst       = ff:ff:ff:ff:ff:ff
        //   src       = 04:7b:cb:46:3f:b5
        //   type      = IPv4
        // ###[ IP ]###
        //      version   = 4
        //      ihl       = None
        //      tos       = 0x0
        //      len       = None
        //      id        = 1
        //      flags     =
        //      frag      = 0
        //      ttl       = 64
        //      proto     = udp
        //      chksum    = None
        //      src       = 0.0.0.0
        //      dst       = 255.255.255.255
        //      \options   \
        // ###[ UDP ]###
        //         sport     = bootpc
        //         dport     = bootps
        //         len       = None
        //         chksum    = None
        // ###[ BOOTP ]###
        //            op        = BOOTREQUEST
        //            htype     = Ethernet (10Mb)
        //            hlen      = 6
        //            hops      = 0
        //            xid       = 0x1020304
        //            secs      = 0
        //            flags     =
        //            ciaddr    = 0.0.0.0
        //            yiaddr    = 0.0.0.0
        //            siaddr    = 0.0.0.0
        //            giaddr    = 0.0.0.0
        //            chaddr    = 30:34:3a:37:62:3a (pad: b'cb:46:3f:b5')
        //            sname     = ''
        //            file      = ''
        //            options   = b'c\x82Sc' (DHCP magic)
        // ###[ DHCP options ]###
        //               options   = [message-type='request' server_id=192.168.1.1
        //                            requested_addr=192.168.1.100 end]
        //
        // raw bytes:
        // ffffffffffff047bcb463fb508004500011c00010000401179d100000000ffffffff004400430108393
        // b010106000000000b000000000000000000000000000000000000000030343a37623a63623a34363a33
        // 663a6200000000000000000000000000000000000000000000000000000000000000000000000000000
        // 00000000000000000000000000000000000000000000000000000000000000000000000000000000000
        // 00000000000000000000000000000000000000000000000000000000000000000000000000000000000
        // 00000000000000000000000000000000000000000000000000000000000000000000000000000000000
        // 0000000000000000000000000000000000000000000000000000000000638253633501033604c0a8010
        // 13204c0a80164ff
        val dhcpRequestPktRawBytes = """
            ffffffffffff047bcb463fb508004500011c00010000401179d100000000ffffffff00440043010839
            3b010106000000000b000000000000000000000000000000000000000030343a37623a63623a34363a
            33663a6200000000000000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000638253633501033604
            c0a801013204c0a80164ff
        """.replace("\\s+".toRegex(), "").trim()
        val dhcpRequestPkt = HexDump.hexStringToByteArray(dhcpRequestPktRawBytes)
        ApfTestHelpers.assertVerdict(
            APF_VERSION_4,
            ApfTestHelpers.DROP,
            program,
            dhcpRequestPkt,
            dataRegion
        )
        assertEquals(mapOf<Counter, Long>(
                Counter.TOTAL_PACKETS to 2,
                Counter.DROPPED_ETHERTYPE_DENYLISTED to 1,
                Counter.DROPPED_DHCP_REQUEST_DISCOVERY to 1
        ), decodeCountersIntoMap(dataRegion))

        // RS packet:
        // ###[ Ethernet ]###
        //   dst       = ff:ff:ff:ff:ff:ff
        //   src       = 04:7b:cb:46:3f:b5
        //   type      = IPv6
        // ###[ IPv6 ]###
        //      version   = 6
        //      tc        = 0
        //      fl        = 0
        //      plen      = None
        //      nh        = ICMPv6
        //      hlim      = 255
        //      src       = fe80::30b4:5e42:ef3d:36e5
        //      dst       = ff02::2
        // ###[ ICMPv6 Neighbor Discovery - Router Solicitation ]###
        //         type      = Router Solicitation
        //         code      = 0
        //         cksum     = None
        //         res       = 0
        //
        // raw bytes:
        // ffffffffffff047bcb463fb586dd6000000000083afffe8000000000000030b45e42ef3d36e5ff0200000
        // 000000000000000000000028500c81d00000000
        val rsPktRawBytes = """
            ffffffffffff047bcb463fb586dd6000000000083afffe8000000000000030b45e42ef3d36e5ff020000
            0000000000000000000000028500c81d00000000
        """.replace("\\s+".toRegex(), "").trim()
        val rsPkt = HexDump.hexStringToByteArray(rsPktRawBytes)
        ApfTestHelpers.assertVerdict(APF_VERSION_4, ApfTestHelpers.DROP, program, rsPkt, dataRegion)
        assertEquals(mapOf<Counter, Long>(
                Counter.TOTAL_PACKETS to 3,
                Counter.DROPPED_RS to 1,
                Counter.DROPPED_ETHERTYPE_DENYLISTED to 1,
                Counter.DROPPED_DHCP_REQUEST_DISCOVERY to 1
        ), decodeCountersIntoMap(dataRegion))
        if (isSuspendMode) {
            // Ping request packet
            // ###[ Ethernet ]###
            //  dst       = ff:ff:ff:ff:ff:ff
            //  src       = 04:7b:cb:46:3f:b5
            //  type      = IPv4
            // ###[ IP ]###
            //      version   = 4
            //      ihl       = None
            //      tos       = 0x0
            //      len       = None
            //      id        = 1
            //      flags     =
            //      frag      = 0
            //      ttl       = 64
            //      proto     = icmp
            //      chksum    = None
            //      src       = 100.79.97.84
            //      dst       = 8.8.8.8
            //      \options   \
            // ###[ ICMP ]###
            //         type      = echo-request
            //         code      = 0
            //         chksum    = None
            //         id        = 0x0
            //         seq       = 0x0
            //         unused    = ''
            //
            // raw bytes: 84
            // ffffffffffff047bcb463fb508004500001c000100004001a52d644f6154080808080800f7ff
            // 00000000
            val pingRequestPktRawBytes = """
                ffffffffffff047bcb463fb508004500001c000100004001a52d644f6154080808080800f7ff
                00000000
            """.replace("\\s+".toRegex(), "").trim()
            val pingRequestPkt = HexDump.hexStringToByteArray(pingRequestPktRawBytes)
            ApfTestHelpers.assertVerdict(
                APF_VERSION_4,
                ApfTestHelpers.DROP,
                program,
                pingRequestPkt,
                dataRegion
            )
            assertEquals(mapOf<Counter, Long>(
                    Counter.TOTAL_PACKETS to 4,
                    Counter.DROPPED_RS to 1,
                    Counter.DROPPED_ICMP4_ECHO_REQUEST to 1,
                    Counter.DROPPED_ETHERTYPE_DENYLISTED to 1,
                    Counter.DROPPED_DHCP_REQUEST_DISCOVERY to 1
            ), decodeCountersIntoMap(dataRegion))
        }
    }

    @Test
    fun testApfProgramInNormalMode() {
        runApfTest(isSuspendMode = false)
    }

    @Test
    fun testApfProgramInSuspendMode() {
        runApfTest(isSuspendMode = true)
    }

    private fun generateApfV4Program(isDeviceIdle: Boolean): ByteArray {
        val countAndPassLabel = "countAndPass"
        val countAndDropLabel = "countAndDrop"
        val endOfDhcpFilter = "endOfDhcpFilter"
        val endOfRsFilter = "endOfRsFiler"
        val endOfPingFilter = "endOfPingFilter"
        val gen = ApfV4Generator(APF_VERSION_4, ramSize, clampSize)

        maybeSetupCounter(gen, Counter.TOTAL_PACKETS)
        gen.addLoadData(R0, 0)
        gen.addAdd(1)
        gen.addStoreData(R0, 0)

        maybeSetupCounter(gen, Counter.FILTER_AGE_SECONDS)
        gen.addLoadFromMemory(R0, MemorySlot.FILTER_AGE_SECONDS)
        gen.addStoreData(R0, 0)

        maybeSetupCounter(gen, Counter.FILTER_AGE_16384THS)
        gen.addLoadFromMemory(R0, MemorySlot.FILTER_AGE_16384THS)
        gen.addStoreData(R0, 0)

        // ethtype filter
        gen.addLoad16(R0, ETHER_TYPE_OFFSET)
        maybeSetupCounter(gen, Counter.DROPPED_ETHERTYPE_DENYLISTED)
        for (p in etherTypeDenyList) {
            gen.addJumpIfR0Equals(p.toLong(), countAndDropLabel)
        }

        // dhcp request filters

        // Check IPv4
        gen.addLoad16(R0, ETHER_TYPE_OFFSET)
        gen.addJumpIfR0NotEquals(ETH_P_IP.toLong(), endOfDhcpFilter)

        // Pass DHCP addressed to us.
        // Check src is IP is 0.0.0.0
        gen.addLoad32(R0, IPV4_SRC_ADDR_OFFSET)
        gen.addJumpIfR0NotEquals(0, endOfDhcpFilter)
        // Check dst ip is 255.255.255.255
        gen.addLoad32(R0, IPV4_DEST_ADDR_OFFSET)
        gen.addJumpIfR0NotEquals(IPV4_BROADCAST_ADDRESS.toLong(), endOfDhcpFilter)
        // Check it's UDP.
        gen.addLoad8(R0, IPV4_PROTOCOL_OFFSET)
        gen.addJumpIfR0NotEquals(OsConstants.IPPROTO_UDP.toLong(), endOfDhcpFilter)
        // Check it's addressed to DHCP client port.
        gen.addLoadFromMemory(R1, MemorySlot.IPV4_HEADER_SIZE)
        gen.addLoad16Indexed(R0, TCP_UDP_DESTINATION_PORT_OFFSET)
        gen.addJumpIfR0NotEquals(DHCP_SERVER_PORT.toLong(), endOfDhcpFilter)
        // drop dhcp the discovery and request
        maybeSetupCounter(gen, Counter.DROPPED_DHCP_REQUEST_DISCOVERY)
        gen.addJump(countAndDropLabel)

        gen.defineLabel(endOfDhcpFilter)

        // rs filters

        // check IPv6
        gen.addLoad16(R0, ETHER_TYPE_OFFSET)
        gen.addJumpIfR0NotEquals(OsConstants.ETH_P_IPV6.toLong(), endOfRsFilter)
        // check ICMP6 packet
        gen.addLoad8(R0, IPV6_NEXT_HEADER_OFFSET)
        gen.addJumpIfR0NotEquals(IPPROTO_ICMPV6.toLong(), endOfRsFilter)
        // check type it is RS
        gen.addLoad8(R0, ICMP6_TYPE_OFFSET)
        gen.addJumpIfR0NotEquals(ICMPV6_ROUTER_SOLICITATION.toLong(), endOfRsFilter)
        // drop rs packet
        maybeSetupCounter(gen, Counter.DROPPED_RS)
        gen.addJump(countAndDropLabel)

        gen.defineLabel(endOfRsFilter)

        if (isDeviceIdle) {
            // ping filter

            // Check IPv4
            gen.addLoad16(R0, ETHER_TYPE_OFFSET)
            gen.addJumpIfR0NotEquals(ETH_P_IP.toLong(), endOfPingFilter)
            // Check it's ICMP.
            gen.addLoad8(R0, IPV4_PROTOCOL_OFFSET)
            gen.addJumpIfR0NotEquals(OsConstants.IPPROTO_ICMP.toLong(), endOfPingFilter)
            // Check if it is echo request
            gen.addLoadFromMemory(R1, MemorySlot.IPV4_HEADER_SIZE)
            gen.addLoad8Indexed(R0, ETH_HEADER_LEN)
            gen.addJumpIfR0NotEquals(8, endOfPingFilter)
            // drop ping request
            maybeSetupCounter(gen, Counter.DROPPED_ICMP4_ECHO_REQUEST)
            gen.addJump(countAndDropLabel)

            gen.defineLabel(endOfPingFilter)
        }

        // end of filters.
        maybeSetupCounter(gen, Counter.PASSED_PACKET)

        gen.defineLabel(countAndPassLabel)
        gen.addLoadData(BaseApfGenerator.Register.R0, 0) // R0 = *(R1 + 0)
        gen.addAdd(1) // R0++
        gen.addStoreData(BaseApfGenerator.Register.R0, 0) // *(R1 + 0) = R0
        gen.addJump(BaseApfGenerator.PASS_LABEL)

        gen.defineLabel(countAndDropLabel)
        gen.addLoadData(BaseApfGenerator.Register.R0, 0) // R0 = *(R1 + 0)
        gen.addAdd(1) // R0++
        gen.addStoreData(BaseApfGenerator.Register.R0, 0) // *(R1 + 0) = R0
        gen.addJump(BaseApfGenerator.DROP_LABEL)

        return gen.generate()
    }

    enum class Counter {
        RESERVED,
        ENDIANNESS,
        FILTER_AGE_SECONDS,
        FILTER_AGE_16384THS,
        TOTAL_PACKETS,
        DROPPED_ETHERTYPE_DENYLISTED,
        DROPPED_DHCP_REQUEST_DISCOVERY,
        DROPPED_ICMP4_ECHO_REQUEST,
        DROPPED_RS,
        PASSED_PACKET;

        fun offset(): Int {
            return -4 * this.ordinal
        }

        companion object {
            fun totalSize(): Int {
                return (Counter::class.java.enumConstants.size - 1) * 4
            }
        }
    }

    private fun maybeSetupCounter(gen: ApfV4Generator, c: Counter) {
        gen.addLoadImmediate(R1, c.offset())
    }

    private fun decodeCountersIntoMap(counterBytes: ByteArray): Map<Counter, Long> {
        val counters = Counter::class.java.enumConstants
        val ret = HashMap<Counter, Long>()
        // starting from index 2 to skip the endianness mark
        for (c in listOf(*counters).subList(2, counters.size)) {
            val value = getCounterValue(counterBytes, c)
            if (value != 0L) {
                ret[c] = value
            }
        }
        return ret
    }

    private fun getCounterValue(data: ByteArray, counter: Counter): Long {
        var offset = data.size + Counter.ENDIANNESS.offset()
        var endianness = 0
        for (i in 0..3) {
            endianness = endianness shl 8 or (data[offset + i].toInt() and 0xff)
        }
        // Follow the same wrap-around addressing scheme of the interpreter.
        offset = data.size + counter.offset()
        var isBe = true
        when (endianness) {
            0, 0x12345678 -> isBe = true
            0x78563412 -> isBe = false
        }

        var value: Long = 0
        for (i in 0..3) {
            value = value shl 8 or
                    (data[offset + (if (isBe) i else 3 - i)].toInt() and 0xff).toLong()
        }
        return value
    }

    companion object {
        const val TAG = "ApfStandaloneTest"
    }
}
