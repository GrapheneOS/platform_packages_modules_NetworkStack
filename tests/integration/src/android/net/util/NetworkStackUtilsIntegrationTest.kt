/*
 * Copyright (C) 2020 The Android Open Source Project
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

package android.net.util

import android.Manifest.permission.MANAGE_TEST_NETWORKS
import android.content.Context
import android.net.InetAddresses.parseNumericAddress
import android.net.MacAddress
import android.net.TestNetworkInterface
import android.net.TestNetworkManager
import android.net.dhcp.DhcpPacket
import android.os.HandlerThread
import android.system.Os
import android.system.OsConstants.AF_INET
import android.system.OsConstants.IPPROTO_UDP
import android.system.OsConstants.SOCK_DGRAM
import android.system.OsConstants.SOCK_NONBLOCK
import androidx.test.platform.app.InstrumentationRegistry
import com.android.net.module.util.NetworkStackConstants.ETHER_ADDR_LEN
import com.android.net.module.util.NetworkStackConstants.IPV4_ADDR_ANY
import com.android.testutils.ArpRequestFilter
import com.android.testutils.ETHER_HEADER_LENGTH
import com.android.testutils.IPV4_HEADER_LENGTH
import com.android.testutils.IPv4UdpFilter
import com.android.testutils.TapPacketReader
import com.android.testutils.UDP_HEADER_LENGTH
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Before
import org.junit.Test
import java.net.Inet4Address
import kotlin.reflect.KClass
import kotlin.test.assertEquals
import kotlin.test.fail

class NetworkStackUtilsIntegrationTest {
    private val inst by lazy { InstrumentationRegistry.getInstrumentation() }
    private val context by lazy { inst.context }

    private val TEST_TIMEOUT_MS = 10_000L
    private val TEST_TARGET_IPV4_ADDR = parseNumericAddress("192.0.2.42") as Inet4Address
    private val TEST_TARGET_MAC = MacAddress.fromString("01:23:45:67:89:0A")

    private val readerHandler = HandlerThread(
            NetworkStackUtilsIntegrationTest::class.java.simpleName)
    private lateinit var iface: TestNetworkInterface
    private lateinit var reader: TapPacketReader

    @Before
    fun setUp() {
        inst.uiAutomation.adoptShellPermissionIdentity(MANAGE_TEST_NETWORKS)
        try {
            val tnm = context.assertHasService(TestNetworkManager::class)
            iface = tnm.createTapInterface()
        } finally {
            inst.uiAutomation.dropShellPermissionIdentity()
        }
        readerHandler.start()
        reader = TapPacketReader(readerHandler.threadHandler, iface.fileDescriptor.fileDescriptor,
                1500 /* maxPacketSize */)
        readerHandler.threadHandler.post { reader.start() }
    }

    @After
    fun tearDown() {
        readerHandler.quitSafely()
        if (this::iface.isInitialized) iface.fileDescriptor.close()
    }

    @Test
    fun testAddArpEntry() {
        val socket = Os.socket(AF_INET, SOCK_DGRAM or SOCK_NONBLOCK, IPPROTO_UDP)
        SocketUtils.bindSocketToInterface(socket, iface.interfaceName)

        NetworkStackUtils.addArpEntry(TEST_TARGET_IPV4_ADDR, TEST_TARGET_MAC, iface.interfaceName,
                socket)

        // Fake DHCP packet: would not be usable as a DHCP offer (most IPv4 addresses are all-zero,
        // no gateway or DNS servers, etc).
        // Using a DHCP packet to replicate actual usage of the API: it is used in DhcpServer to
        // send packets to clients before their IP address has been assigned.
        val buffer = DhcpPacket.buildOfferPacket(DhcpPacket.ENCAP_BOOTP, 123 /* transactionId */,
                false /* broadcast */, IPV4_ADDR_ANY /* serverIpAddr */,
                IPV4_ADDR_ANY /* relayIp */, IPV4_ADDR_ANY /* yourIp */,
                TEST_TARGET_MAC.toByteArray(), 3600 /* timeout */, IPV4_ADDR_ANY /* netMask */,
                IPV4_ADDR_ANY /* bcAddr */, emptyList<Inet4Address>() /* gateways */,
                emptyList<Inet4Address>() /* dnsServers */,
                IPV4_ADDR_ANY /* dhcpServerIdentifier */, null /* domainName */,
                null /* hostname */, false /* metered */, 1500 /* mtu */,
                null /* captivePortalUrl */)
        // Not using .array as per errorprone "ByteBufferBackingArray" recommendation
        val originalPacket = ByteArray(buffer.limit())
        buffer.get(originalPacket)

        Os.sendto(socket, originalPacket, 0 /* bytesOffset */, originalPacket.size /* bytesCount */,
                0 /* flags */, TEST_TARGET_IPV4_ADDR, DhcpPacket.DHCP_CLIENT.toInt() /* port */)

        // Verify the packet was sent to the mac address specified in the ARP entry
        // Also accept ARP requests, but expect that none is sent before the UDP packet
        // IPv6 NS may be sent on the interface but will be filtered out
        val sentPacket = reader.popPacket(TEST_TIMEOUT_MS, IPv4UdpFilter().or(ArpRequestFilter()))
                ?: fail("Packet was not sent on the interface")

        val sentTargetAddr = MacAddress.fromBytes(sentPacket.copyOfRange(0, ETHER_ADDR_LEN))
        assertEquals(TEST_TARGET_MAC, sentTargetAddr, "Destination ethernet address does not match")

        val sentDhcpPacket = sentPacket.copyOfRange(
                ETHER_HEADER_LENGTH + IPV4_HEADER_LENGTH + UDP_HEADER_LENGTH, sentPacket.size)

        assertArrayEquals("Sent packet != original packet", originalPacket, sentDhcpPacket)
    }
}

private fun <T : Any> Context.assertHasService(manager: KClass<T>) = getSystemService(manager.java)
        ?: fail("Could not find service $manager")