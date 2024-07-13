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

import android.content.Context
import android.net.LinkAddress
import android.net.LinkProperties
import android.net.MacAddress
import android.net.apf.ApfCounterTracker.Counter.DROPPED_ARP_REQUEST_REPLIED
import android.net.apf.ApfCounterTracker.Counter.DROPPED_ETHERTYPE_NOT_ALLOWED
import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_NON_DHCP4
import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_NS_INVALID
import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_NS_OTHER_HOST
import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_NS_REPLIED_NON_DAD
import android.net.apf.ApfCounterTracker.Counter.PASSED_ARP_REQUEST
import android.net.apf.ApfCounterTracker.Counter.PASSED_IPV4
import android.net.apf.ApfCounterTracker.Counter.PASSED_IPV4_FROM_DHCPV4_SERVER
import android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_ICMP
import android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_NS_DAD
import android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_NS_NO_ADDRESS
import android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_NS_NO_SLLA_OPTION
import android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_NS_TENTATIVE
import android.net.apf.ApfFilter.Dependencies
import android.net.apf.ApfTestHelpers.Companion.verifyProgramRun
import android.net.apf.BaseApfGenerator.APF_VERSION_3
import android.net.apf.BaseApfGenerator.APF_VERSION_6
import android.net.ip.IpClient.IpClientCallbacksWrapper
import android.os.Build
import android.system.OsConstants.IFA_F_TENTATIVE
import androidx.test.filters.SmallTest
import com.android.internal.annotations.GuardedBy
import com.android.net.module.util.HexDump
import com.android.net.module.util.InterfaceParams
import com.android.net.module.util.NetworkStackConstants.ARP_ETHER_IPV4_LEN
import com.android.net.module.util.NetworkStackConstants.ARP_REPLY
import com.android.net.module.util.NetworkStackConstants.ARP_REQUEST
import com.android.net.module.util.NetworkStackConstants.ETHER_HEADER_LEN
import com.android.net.module.util.NetworkStackConstants.ICMPV6_NA_HEADER_LEN
import com.android.net.module.util.NetworkStackConstants.ICMPV6_NS_HEADER_LEN
import com.android.net.module.util.NetworkStackConstants.IPV6_HEADER_LEN
import com.android.net.module.util.arp.ArpPacket
import com.android.networkstack.metrics.NetworkQuirkMetrics
import com.android.networkstack.packets.NeighborAdvertisement
import com.android.networkstack.packets.NeighborSolicitation
import com.android.networkstack.util.NetworkStackUtils
import com.android.testutils.DevSdkIgnoreRule
import com.android.testutils.DevSdkIgnoreRule.IgnoreUpTo
import com.android.testutils.DevSdkIgnoreRunner
import com.android.testutils.quitResources
import java.net.Inet6Address
import java.net.InetAddress
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import org.junit.After
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.ArgumentCaptor
import org.mockito.ArgumentMatchers.any
import org.mockito.Mock
import org.mockito.Mockito
import org.mockito.Mockito.doAnswer
import org.mockito.Mockito.times
import org.mockito.Mockito.verify
import org.mockito.Mockito.`when`
import org.mockito.MockitoAnnotations
import org.mockito.invocation.InvocationOnMock

/**
 * Test for APF filter.
 */
@DevSdkIgnoreRunner.MonitorThreadLeak
@RunWith(DevSdkIgnoreRunner::class)
@SmallTest
class ApfFilterTest {
    companion object {
        private const val THREAD_QUIT_MAX_RETRY_COUNT = 3
    }

    @get:Rule
    val ignoreRule = DevSdkIgnoreRule()

    @Mock
    private lateinit var context: Context

    @Mock private lateinit var metrics: NetworkQuirkMetrics

    @Mock private lateinit var dependencies: Dependencies

    @Mock private lateinit var ipClientCallback: IpClientCallbacksWrapper

    @GuardedBy("mApfFilterCreated")
    private val mApfFilterCreated = ArrayList<AndroidPacketFilter>()
    private val loInterfaceParams = InterfaceParams.getByName("lo")
    private val ifParams =
        InterfaceParams(
            "lo",
            loInterfaceParams.index,
            MacAddress.fromBytes(byteArrayOf(2, 3, 4, 5, 6, 7)),
            loInterfaceParams.defaultMtu
        )
    private val hostIpv4Address = byteArrayOf(10, 0, 0, 1)
    private val senderIpv4Address = byteArrayOf(10, 0, 0, 2)
    private val arpBroadcastMacAddress = intArrayOf(0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
        .map { it.toByte() }.toByteArray()
    private val senderMacAddress = intArrayOf(0x02, 0x22, 0x33, 0x44, 0x55, 0x66)
        .map { it.toByte() }.toByteArray()
    private val senderIpv6Address =
        // 2001::200:1a:1122:3344
        intArrayOf(0x20, 0x01, 0, 0, 0, 0, 0, 0, 0x02, 0, 0, 0x1a, 0x11, 0x22, 0x33, 0x44)
            .map{ it.toByte() }.toByteArray()
    private val hostIpv6Addresses = listOf(
        // 2001::200:1a:3344:1122
        intArrayOf(0x20, 0x01, 0, 0, 0, 0, 0, 0, 0x02, 0, 0, 0x1a, 0x33, 0x44, 0x11, 0x22)
            .map{ it.toByte() }.toByteArray(),
        // 2001::100:1b:4455:6677
        intArrayOf(0x20, 0x01, 0, 0, 0, 0, 0, 0, 0x01, 0, 0, 0x1b, 0x44, 0x55, 0x66, 0x77)
            .map{ it.toByte() }.toByteArray()
    )
    private val hostIpv6TentativeAddresses = listOf(
        // 2001::200:1a:1234:5678
        intArrayOf(0x20, 0x01, 0, 0, 0, 0, 0, 0, 0x02, 0, 0, 0x1a, 0x12, 0x34, 0x56, 0x78)
            .map{ it.toByte() }.toByteArray(),
        // 2001::100:1b:1234:5678
        intArrayOf(0x20, 0x01, 0, 0, 0, 0, 0, 0, 0x01, 0, 0, 0x1b, 0x12, 0x34, 0x56, 0x78)
            .map{ it.toByte() }.toByteArray()
    )
    private val hostAnycast6Addresses = listOf(
        // 2001::100:1b:aabb:ccdd
        intArrayOf(0x20, 0x01, 0, 0, 0, 0, 0, 0, 0x01, 0, 0, 0x1b, 0xaa, 0xbb, 0xcc, 0xdd)
            .map{ it.toByte() }.toByteArray()
    )
    private val hostMulticastMacAddresses = listOf(
        // 33:33:00:00:00:01
        intArrayOf(0x33, 0x33, 0, 0, 0, 1).map { it.toByte() }.toByteArray(),
        // 33:33:ff:44:11:22
        intArrayOf(0x33, 0x33, 0xff, 0x44, 0x11, 0x22).map { it.toByte() }.toByteArray(),
        // 33:33:ff:55:66:77
        intArrayOf(0x33, 0x33, 0xff, 0x55, 0x66, 0x77).map { it.toByte() }.toByteArray(),
        // 33:33:ff:bb:cc:dd
        intArrayOf(0x33, 0x33, 0xff, 0xbb, 0xcc, 0xdd).map { it.toByte() }.toByteArray(),
    )

    @Before
    fun setUp() {
        MockitoAnnotations.initMocks(this)
        // mock anycast6 address from /proc/net/anycast6
        `when`(dependencies.getAnycast6Addresses(any())).thenReturn(hostAnycast6Addresses)

        // mock ether multicast mac address from /proc/net/dev_mcast
        `when`(dependencies.getEtherMulticastAddresses(any())).thenReturn(hostMulticastMacAddresses)

        // mock nd traffic class from /proc/sys/net/ipv6/conf/{ifname}/ndisc_tclass
        `when`(dependencies.getNdTrafficClass(any())).thenReturn(0)
        doAnswer { invocation: InvocationOnMock ->
            synchronized(mApfFilterCreated) {
                mApfFilterCreated.add(invocation.getArgument(0))
            }
        }.`when`(dependencies).onApfFilterCreated(any())
    }

    private fun shutdownApfFilters() {
        quitResources(THREAD_QUIT_MAX_RETRY_COUNT, {
            synchronized(mApfFilterCreated) {
                val ret = ArrayList(mApfFilterCreated)
                mApfFilterCreated.clear()
                return@quitResources ret
            }
        }, { apf: AndroidPacketFilter ->
            apf.shutdown()
        })

        synchronized(mApfFilterCreated) {
            assertEquals(
                0,
                mApfFilterCreated.size.toLong(),
                "ApfFilters did not fully shutdown."
            )
        }
    }

    @After
    fun tearDown() {
        shutdownApfFilters()
        Mockito.framework().clearInlineMocks()
        ApfJniUtils.resetTransmittedPacketMemory()
    }

    private fun getDefaultConfig(apfVersion: Int = APF_VERSION_6): ApfFilter.ApfConfiguration {
        val config = ApfFilter.ApfConfiguration()
        config.apfVersionSupported = apfVersion
        // 4K is the highly recommended value in APFv6 for vendor
        config.apfRamSize = 4096
        config.multicastFilter = false
        config.ieee802_3Filter = false
        config.ethTypeBlackList = IntArray(0)
        config.shouldHandleArpOffload = true
        config.shouldHandleNdOffload = true
        return config
    }

    private fun getApfFilter(
        apfCfg: ApfFilter.ApfConfiguration = getDefaultConfig(APF_VERSION_6)
    ): ApfFilter {
        return ApfFilter(
            context,
            apfCfg,
            ifParams,
            ipClientCallback,
            metrics,
            dependencies
        )
    }

    private fun doTestEtherTypeAllowListFilter(apfFilter: ApfFilter) {
        val programCaptor = ArgumentCaptor.forClass(ByteArray::class.java)
        verify(ipClientCallback, times(2)).installPacketFilter(programCaptor.capture())
        val program = programCaptor.allValues.last()

        // Using scapy to generate IPv4 mDNS packet:
        //   eth = Ether(src="E8:9F:80:66:60:BB", dst="01:00:5E:00:00:FB")
        //   ip = IP(src="192.168.1.1")
        //   udp = UDP(sport=5353, dport=5353)
        //   dns = DNS(qd=DNSQR(qtype="PTR", qname="a.local"))
        //   p = eth/ip/udp/dns
        val mdnsPkt = "01005e0000fbe89f806660bb080045000035000100004011d812c0a80101e00000f" +
                "b14e914e900214d970000010000010000000000000161056c6f63616c00000c0001"
        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(mdnsPkt),
            PASSED_IPV4
        )

        // Using scapy to generate RA packet:
        //  eth = Ether(src="E8:9F:80:66:60:BB", dst="33:33:00:00:00:01")
        //  ip6 = IPv6(src="fe80::1", dst="ff02::1")
        //  icmp6 = ICMPv6ND_RA(routerlifetime=3600, retranstimer=3600)
        //  p = eth/ip6/icmp6
        val raPkt = "333300000001e89f806660bb86dd6000000000103afffe800000000000000000000000" +
                "000001ff0200000000000000000000000000018600600700080e100000000000000e10"
        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(raPkt),
            PASSED_IPV6_ICMP
        )

        // Using scapy to generate ethernet packet with type 0x88A2:
        //  p = Ether(type=0x88A2)/Raw(load="01")
        val ethPkt = "ffffffffffff047bcb463fb588a23031"
        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(ethPkt),
            DROPPED_ETHERTYPE_NOT_ALLOWED
        )
    }

    private fun generateNsPacket(
        srcMac: ByteArray,
        dstMac: ByteArray,
        srcIp: ByteArray,
        dstIp: ByteArray,
        target: ByteArray,
    ): ByteArray {
        val nsPacketBuf = NeighborSolicitation.build(
            MacAddress.fromBytes(srcMac),
            MacAddress.fromBytes(dstMac),
            InetAddress.getByAddress(srcIp) as Inet6Address,
            InetAddress.getByAddress(dstIp) as Inet6Address,
            InetAddress.getByAddress(target) as Inet6Address
        )

        val nsPacket = ByteArray(
            ETHER_HEADER_LEN + IPV6_HEADER_LEN + ICMPV6_NS_HEADER_LEN + 8 // option length
        )
        nsPacketBuf.get(nsPacket)
        return nsPacket
    }

    private fun generateNaPacket(
        srcMac: ByteArray,
        dstMac: ByteArray,
        srcIp: ByteArray,
        dstIp: ByteArray,
        flags: Int,
        target: ByteArray,
    ): ByteArray {
        val naPacketBuf = NeighborAdvertisement.build(
            MacAddress.fromBytes(srcMac),
            MacAddress.fromBytes(dstMac),
            InetAddress.getByAddress(srcIp) as Inet6Address,
            InetAddress.getByAddress(dstIp) as Inet6Address,
            flags,
            InetAddress.getByAddress(target) as Inet6Address
        )
        val naPacket = ByteArray(
            ETHER_HEADER_LEN + IPV6_HEADER_LEN + ICMPV6_NA_HEADER_LEN + 8 // lla option length
        )

        naPacketBuf.get(naPacket)
        return naPacket
    }

    @Test
    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    fun testV4EtherTypeAllowListFilter() {
        val apfFilter = getApfFilter(getDefaultConfig(APF_VERSION_3))
        doTestEtherTypeAllowListFilter(apfFilter)
    }

    @Test
    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    fun testV6EtherTypeAllowListFilter() {
        val apfFilter = getApfFilter(getDefaultConfig(APF_VERSION_6))
        doTestEtherTypeAllowListFilter(apfFilter)
    }

    @Test
    fun testIPv4PacketFilterOnV6OnlyNetwork() {
        val apfFilter = getApfFilter()
        apfFilter.updateClatInterfaceState(true)
        val programCaptor = ArgumentCaptor.forClass(ByteArray::class.java)
        verify(ipClientCallback, times(3)).installPacketFilter(programCaptor.capture())
        val program = programCaptor.allValues.last()

        // Using scapy to generate IPv4 mDNS packet:
        //   eth = Ether(src="E8:9F:80:66:60:BB", dst="01:00:5E:00:00:FB")
        //   ip = IP(src="192.168.1.1")
        //   udp = UDP(sport=5353, dport=5353)
        //   dns = DNS(qd=DNSQR(qtype="PTR", qname="a.local"))
        //   p = eth/ip/udp/dns
        val mdnsPkt = "01005e0000fbe89f806660bb080045000035000100004011d812c0a80101e00000f" +
                "b14e914e900214d970000010000010000000000000161056c6f63616c00000c0001"
        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(mdnsPkt),
            DROPPED_IPV4_NON_DHCP4
        )

        // Using scapy to generate DHCP4 offer packet:
        //   ether = Ether(src='00:11:22:33:44:55', dst='ff:ff:ff:ff:ff:ff')
        //   ip = IP(src='192.168.1.1', dst='255.255.255.255')
        //   udp = UDP(sport=67, dport=68)
        //   bootp = BOOTP(op=2,
        //                 yiaddr='192.168.1.100',
        //                 siaddr='192.168.1.1',
        //                 chaddr=b'\x00\x11\x22\x33\x44\x55')
        //   dhcp_options = [('message-type', 'offer'),
        //                   ('server_id', '192.168.1.1'),
        //                   ('subnet_mask', '255.255.255.0'),
        //                   ('router', '192.168.1.1'),
        //                   ('lease_time', 86400),
        //                   ('name_server', '8.8.8.8'),
        //                   'end']
        //   dhcp = DHCP(options=dhcp_options)
        //   dhcp_offer_packet = ether/ip/udp/bootp/dhcp
        val dhcp4Pkt =
            "ffffffffffff00112233445508004500012e000100004011b815c0a80101ffffffff0043" +
                    "0044011a5ffc02010600000000000000000000000000c0a80164c0a80101000000000011" +
                    "223344550000000000000000000000000000000000000000000000000000000000000000" +
                    "000000000000000000000000000000000000000000000000000000000000000000000000" +
                    "000000000000000000000000000000000000000000000000000000000000000000000000" +
                    "000000000000000000000000000000000000000000000000000000000000000000000000" +
                    "000000000000000000000000000000000000000000000000000000000000000000000000" +
                    "0000000000000000000000000000000000000000000000000000638253633501023604c0" +
                    "a801010104ffffff000304c0a80101330400015180060408080808ff"
        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(dhcp4Pkt),
            PASSED_IPV4_FROM_DHCPV4_SERVER
        )

        // Using scapy to generate DHCP4 offer packet:
        //   eth = Ether(src="E8:9F:80:66:60:BB", dst="01:00:5E:00:00:FB")
        //   ip = IP(src="192.168.1.10", dst="192.168.1.20")  # IPv4
        //   udp = UDP(sport=12345, dport=53)
        //   dns = DNS(qd=DNSQR(qtype="PTR", qname="a.local"))
        //   pkt = eth / ip / udp / dns
        //   fragments = fragment(pkt, fragsize=30)
        //   fragments[1]
        val fragmentedUdpPkt =
            "01005e0000fbe89f806660bb08004500001d000100034011f75dc0a8010ac0a8" +
                    "01146f63616c00000c0001"
        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(fragmentedUdpPkt),
            DROPPED_IPV4_NON_DHCP4
        )
    }

    // The APFv6 code path is only turned on in V+
    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    @Test
    fun testArpTransmit() {
        val apfFilter = getApfFilter()
        verify(ipClientCallback, times(2)).installPacketFilter(any())
        val linkAddress = LinkAddress(InetAddress.getByAddress(hostIpv4Address), 24)
        val lp = LinkProperties()
        lp.addLinkAddress(linkAddress)
        apfFilter.setLinkProperties(lp)
        val programCaptor = ArgumentCaptor.forClass(ByteArray::class.java)
        verify(ipClientCallback, times(3)).installPacketFilter(programCaptor.capture())
        val program = programCaptor.value
        val receivedArpPacketBuf = ArpPacket.buildArpPacket(
            arpBroadcastMacAddress,
            senderMacAddress,
            hostIpv4Address,
            HexDump.hexStringToByteArray("000000000000"),
            senderIpv4Address,
            ARP_REQUEST.toShort()
        )
        val receivedArpPacket = ByteArray(ARP_ETHER_IPV4_LEN)
        receivedArpPacketBuf.get(receivedArpPacket)
        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            receivedArpPacket,
            DROPPED_ARP_REQUEST_REPLIED
        )

        val transmittedPacket = ApfJniUtils.getTransmittedPacket()
        val expectedArpReplyBuf = ArpPacket.buildArpPacket(
            senderMacAddress,
            apfFilter.mHardwareAddress,
            senderIpv4Address,
            senderMacAddress,
            hostIpv4Address,
            ARP_REPLY.toShort()
        )
        val expectedArpReplyPacket = ByteArray(ARP_ETHER_IPV4_LEN)
        expectedArpReplyBuf.get(expectedArpReplyPacket)
        assertContentEquals(
            expectedArpReplyPacket + ByteArray(18) { 0 },
            transmittedPacket
        )
    }

    @Test
    fun testArpOffloadDisabled() {
        val apfConfig = getDefaultConfig()
        apfConfig.shouldHandleArpOffload = false
        val apfFilter = getApfFilter(apfConfig)
        verify(ipClientCallback, times(2)).installPacketFilter(any())
        val linkAddress = LinkAddress(InetAddress.getByAddress(hostIpv4Address), 24)
        val lp = LinkProperties()
        lp.addLinkAddress(linkAddress)
        apfFilter.setLinkProperties(lp)
        val programCaptor = ArgumentCaptor.forClass(ByteArray::class.java)
        verify(ipClientCallback, times(3)).installPacketFilter(programCaptor.capture())
        val program = programCaptor.value
        val receivedArpPacketBuf = ArpPacket.buildArpPacket(
            arpBroadcastMacAddress,
            senderMacAddress,
            hostIpv4Address,
            HexDump.hexStringToByteArray("000000000000"),
            senderIpv4Address,
            ARP_REQUEST.toShort()
        )
        val receivedArpPacket = ByteArray(ARP_ETHER_IPV4_LEN)
        receivedArpPacketBuf.get(receivedArpPacket)
        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            receivedArpPacket,
            PASSED_ARP_REQUEST
        )
    }

    @Test
    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    fun testNsFilterNoIPv6() {
        `when`(dependencies.getAnycast6Addresses(any())).thenReturn(listOf())
        val apfFilter = getApfFilter()
        // validate NS packet check when there is no IPv6 address
        val programCaptor = ArgumentCaptor.forClass(ByteArray::class.java)
        verify(ipClientCallback, times(2)).installPacketFilter(programCaptor.capture())
        val program = programCaptor.allValues.last()
        // Using scapy to generate IPv6 NS packet:
        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=255)
        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
        // pkt = eth/ip6/icmp6
        val nsPkt = "01020304050600010203040586DD6000000000183AFF200100000000000" +
                "00200001A1122334420010000000000000200001A334411228700452900" +
                "00000020010000000000000200001A33441122"
        // when there is no IPv6 addresses -> pass NS packet
        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(nsPkt),
            PASSED_IPV6_NS_NO_ADDRESS
        )
    }

    @Test
    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    fun testNsFilter() {
        val apfFilter = getApfFilter()
        verify(ipClientCallback, times(2)).installPacketFilter(any())

        val lp = LinkProperties()
        for (addr in hostIpv6Addresses) {
            lp.addLinkAddress(LinkAddress(InetAddress.getByAddress(addr), 64))
        }

        for (addr in hostIpv6TentativeAddresses) {
            lp.addLinkAddress(
                LinkAddress(
                    InetAddress.getByAddress(addr),
                    64,
                    IFA_F_TENTATIVE,
                    0
                )
            )
        }

        apfFilter.setLinkProperties(lp)
        verify(ipClientCallback, times(3)).installPacketFilter(any())
        apfFilter.updateClatInterfaceState(true)
        val programCaptor = ArgumentCaptor.forClass(ByteArray::class.java)
        verify(ipClientCallback, times(4)).installPacketFilter(programCaptor.capture())
        val program = programCaptor.value

        // validate Ethernet dst address check
        // Using scapy to generate IPv6 NS packet:
        // eth = Ether(src="00:01:02:03:04:05", dst="00:05:04:03:02:01")
        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=255)
        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
        // icmp6_opt = ICMPv6NDOptDstLLAddr(lladdr="00:01:02:03:04:05")
        // pkt = eth/ip6/icmp6/icmp6_opt
        val nonHostDstMacNsPkt =
            "00050403020100010203040586DD6000000000203AFF2001000000000000" +
                    "0200001A1122334420010000000000000200001A3344112287003D170000" +
                    "000020010000000000000200001A334411220201000102030405"
        // invalid unicast ether dst -> pass
        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(nonHostDstMacNsPkt),
            DROPPED_IPV6_NS_OTHER_HOST
        )

        // Using scapy to generate IPv6 NS packet:
        // eth = Ether(src="00:01:02:03:04:05", dst="33:33:ff:03:02:01")
        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=255)
        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
        // icmp6_opt = ICMPv6NDOptDstLLAddr(lladdr="00:01:02:03:04:05")
        // pkt = eth/ip6/icmp6/icmp6_opt
        val nonMcastDstMacNsPkt = "3333FF03020100010203040586DD6000000000203AFF20010000000000" +
                "000200001A1122334420010000000000000200001A3344112287003D17" +
                "0000000020010000000000000200001A334411220201000102030405"
        // mcast dst mac is not one of solicited mcast mac derived from one of device's ip -> pass
        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(nonMcastDstMacNsPkt),
            DROPPED_IPV6_NS_OTHER_HOST
        )

        // Using scapy to generate IPv6 NS packet:
        // eth = Ether(src="00:01:02:03:04:05", dst="33:33:ff:44:11:22")
        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=255)
        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
        // icmp6_opt = ICMPv6NDOptSrcLLAddr(lladdr="00:01:02:03:04:05")
        // pkt = eth/ip6/icmp6/icmp6_opt
        val hostMcastDstMacNsPkt =
            "3333FF44112200010203040586DD6000000000203AFF20010000000000" +
                    "000200001A1122334420010000000000000200001A3344112287003E17" +
                    "0000000020010000000000000200001A334411220101000102030405"
        // mcast dst mac is one of solicited mcast mac derived from one of device's ip
        // -> drop and replied
        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(hostMcastDstMacNsPkt),
            DROPPED_IPV6_NS_REPLIED_NON_DAD
        )

        // Using scapy to generate IPv6 NS packet:
        // eth = Ether(src="00:01:02:03:04:05", dst="FF:FF:FF:FF:FF:FF")
        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=255)
        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
        // icmp6_opt = ICMPv6NDOptSrcLLAddr(lladdr="00:01:02:03:04:05")
        // pkt = eth/ip6/icmp6/icmp6_opt
        val broadcastNsPkt =
            "FFFFFFFFFFFF00010203040586DD6000000000203AFF200100000000000002000" +
                    "01A1122334420010000000000000200001A3344112287003E1700000000200100" +
                    "00000000000200001A334411220101000102030405"
        // mcast dst mac is broadcast address -> drop and replied
        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(broadcastNsPkt),
            DROPPED_IPV6_NS_REPLIED_NON_DAD
        )

        // validate IPv6 dst address check

        // Using scapy to generate IPv6 NS packet:
        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=255)
        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
        // icmp6_opt = ICMPv6NDOptSrcLLAddr(lladdr="00:01:02:03:04:05")
        // pkt = eth/ip6/icmp6/icmp6_opt
        val validHostDstIpNsPkt =
            "02030405060700010203040586DD6000000000203AFF200100000000000" +
                    "00200001A1122334420010000000000000200001A3344112287003E1700" +
                    "00000020010000000000000200001A334411220101000102030405"
        // dst ip is one of device's ip -> drop and replied
        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(validHostDstIpNsPkt),
            DROPPED_IPV6_NS_REPLIED_NON_DAD
        )

        // Using scapy to generate IPv6 NS packet:
        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::100:1b:aabb:ccdd", hlim=255)
        // icmp6 = ICMPv6ND_NS(tgt="2001::100:1b:aabb:ccdd")
        // icmp6_opt = ICMPv6NDOptSrcLLAddr(lladdr="00:01:02:03:04:05")
        // pkt = eth/ip6/icmp6/icmp6_opt
        val validHostAnycastDstIpNsPkt =
            "02030405060700010203040586DD6000000000203AFF20010000" +
                    "000000000200001A1122334420010000000000000100001BAABB" +
                    "CCDD8700D9AE0000000020010000000000000100001BAABBCCDD" +
                    "0101000102030405"
        // dst ip is device's anycast address -> drop and replied
        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(validHostAnycastDstIpNsPkt),
            DROPPED_IPV6_NS_REPLIED_NON_DAD
        )

        // Using scapy to generate IPv6 NS packet:
        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:4444:5555", hlim=255)
        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
        // icmp6_opt = ICMPv6NDOptSrcLLAddr(lladdr="00:01:02:03:04:05")
        // pkt = eth/ip6/icmp6/icmp6_opt
        val nonHostUcastDstIpNsPkt =
            "02030405060700010203040586DD6000000000203AFF2001000000000" +
                    "0000200001A1122334420010000000000000200001A444455558700E8" +
                    "E30000000020010000000000000200001A334411220101000102030405"
        // unicast dst ip is not one of device's ip -> pass
        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(nonHostUcastDstIpNsPkt),
            DROPPED_IPV6_NS_OTHER_HOST
        )

        // Using scapy to generate IPv6 NS packet:
        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="ff02::1:ff44:1133", hlim=255)
        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
        // icmp6_opt = ICMPv6NDOptSrcLLAddr(lladdr="00:01:02:03:04:05")
        // pkt = eth/ip6/icmp6/icmp6_opt
        val nonHostMcastDstIpNsPkt =
            "02030405060700010203040586DD6000000000203AFF2001000000000" +
                    "0000200001A11223344FF0200000000000000000001FF441133870095" +
                    "1C0000000020010000000000000200001A334411220101000102030405"
        // mcast dst ip is not one of solicited mcast ip derived from one of device's ip -> pass
        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(nonHostMcastDstIpNsPkt),
            DROPPED_IPV6_NS_OTHER_HOST
        )

        // Using scapy to generate IPv6 NS packet:
        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="ff02::1:ff44:1122", hlim=255)
        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
        // icmp6_opt = ICMPv6NDOptSrcLLAddr(lladdr="00:01:02:03:04:05")
        // pkt = eth/ip6/icmp6/icmp6_opt
        val hostMcastDstIpNsPkt =
            "02030405060700010203040586DD6000000000203AFF2001000000000000" +
                    "0200001A11223344FF0200000000000000000001FF4411228700952D0000" +
                    "000020010000000000000200001A334411220101000102030405"
        // mcast dst ip is one of solicited mcast ip derived from one of device's ip
        //   -> drop and replied
        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(hostMcastDstIpNsPkt),
            DROPPED_IPV6_NS_REPLIED_NON_DAD
        )

        // validate IPv6 NS payload check

        // Using scapy to generate IPv6 NS packet:
        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=255, plen=20)
        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
        // icmp6_opt = ICMPv6NDOptSrcLLAddr(lladdr="01:02:03:04:05:06")
        // pkt = eth/ip6/icmp6/icmp6_opt
        val shortNsPkt =
            "02030405060700010203040586DD6000000000143AFF20010000000000000200001A1" +
                    "122334420010000000000000200001A3344112287003B140000000020010000000000" +
                    "000200001A334411220101010203040506"
        // payload len < 24 -> drop
        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(shortNsPkt),
            DROPPED_IPV6_NS_INVALID
        )

        // Using scapy to generate IPv6 NS packet:
        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=255)
        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:4444:5555")
        // icmp6_opt = ICMPv6NDOptSrcLLAddr(lladdr="01:02:03:04:05:06")
        // pkt = eth/ip6/icmp6/icmp6_opt
        val otherHostNsPkt =
            "02030405060700010203040586DD6000000000203AFF200100000000000002000" +
                    "01A1122334420010000000000000200001A334411228700E5E000000000200100" +
                    "00000000000200001A444455550101010203040506"
        // target ip is not one of device's ip -> drop
        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(otherHostNsPkt),
            DROPPED_IPV6_NS_OTHER_HOST
        )

        // Using scapy to generate IPv6 NS packet:
        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=20)
        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
        // icmp6_opt = ICMPv6NDOptSrcLLAddr(lladdr="01:02:03:04:05:06")
        // pkt = eth/ip6/icmp6/icmp6_opt
        val invalidHoplimitNsPkt =
            "02030405060700010203040586DD6000000000203A14200100000000000" +
                    "00200001A1122334420010000000000000200001A3344112287003B1400" +
                    "00000020010000000000000200001A334411220101010203040506"
        // hoplimit is not 255 -> drop
        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(invalidHoplimitNsPkt),
            DROPPED_IPV6_NS_INVALID
        )

        // Using scapy to generate IPv6 NS packet:
        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=255)
        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122", code=5)
        // icmp6_opt = ICMPv6NDOptSrcLLAddr(lladdr="01:02:03:04:05:06")
        // pkt = eth/ip6/icmp6/icmp6_opt
        val invalidIcmpCodeNsPkt =
            "02030405060700010203040586DD6000000000203AFF200100000000000" +
                    "00200001A1122334420010000000000000200001A3344112287053B0F00" +
                    "00000020010000000000000200001A334411220101010203040506"
        // icmp6 code is not 0 -> drop
        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(invalidIcmpCodeNsPkt),
            DROPPED_IPV6_NS_INVALID
        )

        // Using scapy to generate IPv6 NS packet:
        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=255)
        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:1234:5678")
        // icmp6_opt = ICMPv6NDOptSrcLLAddr(lladdr="01:02:03:04:05:06")
        // pkt = eth/ip6/icmp6/icmp6_opt
        val tentativeTargetIpNsPkt =
            "02030405060700010203040586DD6000000000203AFF200100000000" +
                    "00000200001A1122334420010000000000000200001A334411228700" +
                    "16CE0000000020010000000000000200001A123456780101010203040506"
        // target ip is one of tentative address -> pass
        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(tentativeTargetIpNsPkt),
            PASSED_IPV6_NS_TENTATIVE
        )

        // Using scapy to generate IPv6 NS packet:
        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=255)
        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1c:2255:6666")
        // icmp6_opt = ICMPv6NDOptSrcLLAddr(lladdr="01:02:03:04:05:06")
        // pkt = eth/ip6/icmp6/icmp6_opt
        val invalidTargetIpNsPkt =
            "02030405060700010203040586DD6000000000203AFF200100000000000" +
                    "00200001A1122334420010000000000000200001A334411228700F6BC00" +
                    "00000020010000000000000200001C225566660101010203040506"
        // target ip is none of {non-tentative, anycast} -> drop
        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(invalidTargetIpNsPkt),
            DROPPED_IPV6_NS_OTHER_HOST
        )

        // Using scapy to generate IPv6 NS packet:
        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
        // ip6 = IPv6(src="::", dst="ff02::1:ff44:1122", hlim=255)
        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
        // icmp6_opt = ICMPv6NDOptDstLLAddr(lladdr="02:03:04:05:06:07")
        // pkt = eth/ip6/icmp6/icmp6_opt
        val dadNsPkt =
            "02030405060700010203040586DD6000000000203AFF000000000000000000000000000" +
                    "00000FF0200000000000000000001FF4411228700F4A800000000200100000000000002" +
                    "00001A334411220201020304050607"
        // DAD NS request -> pass
        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(dadNsPkt),
            PASSED_IPV6_NS_DAD
        )

        // Using scapy to generate IPv6 NS packet:
        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=255)
        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
        // pkt = eth/ip6/icmp6
        val noOptionNsPkt =
            "02030405060700010203040586DD6000000000183AFF2001000000000000020000" +
                    "1A1122334420010000000000000200001A33441122870045290000000020010000" +
                    "000000000200001A33441122"
        // payload len < 32 -> pass
        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(noOptionNsPkt),
            PASSED_IPV6_NS_NO_SLLA_OPTION
        )

        // Using scapy to generate IPv6 NS packet:
        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
        // ip6 = IPv6(src="ff01::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=255)
        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
        // icmp6_opt = ICMPv6NDOptSrcLLAddr(lladdr="01:02:03:04:05:06")
        // pkt = eth/ip6/icmp6/icmp6_opt
        val nonDadMcastSrcIpPkt =
            "02030405060700010203040586DD6000000000203AFFFF01000000000000" +
                    "0200001A1122334420010000000000000200001A3344112287005C130000" +
                    "000020010000000000000200001A334411220101010203040506"
        // non-DAD src IPv6 is FF::/8 -> drop
        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(nonDadMcastSrcIpPkt),
            DROPPED_IPV6_NS_INVALID
        )

        // Using scapy to generate IPv6 NS packet:
        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
        // ip6 = IPv6(src="0001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=255)
        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
        // icmp6_opt = ICMPv6NDOptSrcLLAddr(lladdr="01:02:03:04:05:06")
        // pkt = eth/ip6/icmp6/icmp6_opt
        val nonDadLoopbackSrcIpPkt =
            "02030405060700010203040586DD6000000000203AFF0001000000000" +
                    "0000200001A1122334420010000000000000200001A3344112287005B" +
                    "140000000020010000000000000200001A334411220101010203040506"
        // non-DAD src IPv6 is 00::/8 -> drop
        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(nonDadLoopbackSrcIpPkt),
            DROPPED_IPV6_NS_INVALID
        )

        // Using scapy to generate IPv6 NS packet:
        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=255)
        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
        // icmp6_opt1 = ICMPv6NDOptDstLLAddr(lladdr="01:02:03:04:05:06")
        // icmp6_opt2 = ICMPv6NDOptSrcLLAddr(lladdr="01:02:03:04:05:06")
        // pkt = eth/ip6/icmp6/icmp6_opt1/icmp6_opt2
        val sllaNotFirstOptionNsPkt =
            "02030405060700010203040586DD6000000000283AFF200100000000" +
                    "00000200001A1122334420010000000000000200001A334411228700" +
                    "2FFF0000000020010000000000000200001A33441122020101020304" +
                    "05060101010203040506"
        // non-DAD with multiple options, SLLA in 2nd option -> pass
        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(sllaNotFirstOptionNsPkt),
            PASSED_IPV6_NS_NO_SLLA_OPTION
        )

        // Using scapy to generate IPv6 NS packet:
        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=255)
        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
        // icmp6_opt = ICMPv6NDOptDstLLAddr(lladdr="01:02:03:04:05:06")
        // pkt = eth/ip6/icmp6/icmp6_opt
        val noSllaOptionNsPkt =
            "02030405060700010203040586DD6000000000203AFF200100000000000002" +
                    "00001A1122334420010000000000000200001A3344112287003A1400000000" +
                    "20010000000000000200001A334411220201010203040506"
        // non-DAD with one option but not SLLA -> pass
        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(noSllaOptionNsPkt),
            PASSED_IPV6_NS_NO_SLLA_OPTION
        )

        // Using scapy to generate IPv6 NS packet:
        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=255)
        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
        // icmp6_opt = ICMPv6NDOptSrcLLAddr(lladdr="01:02:03:04:05:06")
        // pkt = eth/ip6/icmp6/icmp6_opt
        val mcastMacSllaOptionNsPkt =
            "02030405060700010203040586DD6000000000203AFF200100000000" +
                    "00000200001A1122334420010000000000000200001A334411228700" +
                    "3B140000000020010000000000000200001A33441122010101020304" +
                    "0506"
        // non-DAD, SLLA is multicast MAC -> drop
        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(mcastMacSllaOptionNsPkt),
            DROPPED_IPV6_NS_INVALID
        )
    }

    // The APFv6 code path is only turned on in V+
    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    @Test
    fun testNaTransmit() {
        val apfFilter = getApfFilter()
        val lp = LinkProperties()
        for (addr in hostIpv6Addresses) {
            lp.addLinkAddress(LinkAddress(InetAddress.getByAddress(addr), 64))
        }

        apfFilter.setLinkProperties(lp)
        val programCaptor = ArgumentCaptor.forClass(ByteArray::class.java)
        verify(ipClientCallback, times(3)).installPacketFilter(programCaptor.capture())
        val program = programCaptor.allValues.last()
        val validIpv6Addresses = hostIpv6Addresses + hostAnycast6Addresses
        for (addr in validIpv6Addresses) {
            // unicast solicited NS request
            val receivedUcastNsPacket = generateNsPacket(
                senderMacAddress,
                apfFilter.mHardwareAddress,
                senderIpv6Address,
                addr,
                addr
            )

            verifyProgramRun(
                apfFilter.mApfVersionSupported,
                program,
                receivedUcastNsPacket,
                DROPPED_IPV6_NS_REPLIED_NON_DAD
            )

            val transmittedUcastPacket = ApfJniUtils.getTransmittedPacket()
            val expectedUcastNaPacket = generateNaPacket(
                apfFilter.mHardwareAddress,
                senderMacAddress,
                addr,
                senderIpv6Address,
                0xe0000000.toInt(), //  R=1, S=1, O=1
                addr
            )

            assertContentEquals(
                expectedUcastNaPacket,
                transmittedUcastPacket
            )

            val solicitedMcastAddr = NetworkStackUtils.ipv6AddressToSolicitedNodeMulticast(
                InetAddress.getByAddress(addr) as Inet6Address
            )!!
            val mcastDa = NetworkStackUtils.ipv6MulticastToEthernetMulticast(solicitedMcastAddr)
                .toByteArray()

            // multicast solicited NS request
            var receivedMcastNsPacket = generateNsPacket(
                senderMacAddress,
                mcastDa,
                senderIpv6Address,
                solicitedMcastAddr.address,
                addr
            )

            verifyProgramRun(
                apfFilter.mApfVersionSupported,
                program,
                receivedMcastNsPacket,
                DROPPED_IPV6_NS_REPLIED_NON_DAD
            )

            val transmittedMcastPacket = ApfJniUtils.getTransmittedPacket()
            val expectedMcastNaPacket = generateNaPacket(
                apfFilter.mHardwareAddress,
                senderMacAddress,
                addr,
                senderIpv6Address,
                0xe0000000.toInt(), // R=1, S=1, O=1
                addr
            )

            assertContentEquals(
                expectedMcastNaPacket,
                transmittedMcastPacket
            )
        }
    }

    // The APFv6 code path is only turned on in V+
    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    @Test
    fun testNaTransmitWithTclass() {
        // mock nd traffic class from /proc/sys/net/ipv6/conf/{ifname}/ndisc_tclass to 20
        `when`(dependencies.getNdTrafficClass(any())).thenReturn(20)
        val apfFilter = getApfFilter()
        val lp = LinkProperties()
        for (addr in hostIpv6Addresses) {
            lp.addLinkAddress(LinkAddress(InetAddress.getByAddress(addr), 64))
        }
        apfFilter.setLinkProperties(lp)
        val programCaptor = ArgumentCaptor.forClass(ByteArray::class.java)
        verify(ipClientCallback, times(3)).installPacketFilter(programCaptor.capture())
        val program = programCaptor.allValues.last()
        // Using scapy to generate IPv6 NS packet:
        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="ff02::1:ff44:1122", hlim=255, tc=20)
        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
        // icmp6_opt = ICMPv6NDOptSrcLLAddr(lladdr="00:01:02:03:04:05")
        // pkt = eth/ip6/icmp6/icmp6_opt
        val hostMcastDstIpNsPkt =
            "02030405060700010203040586DD6140000000203AFF2001000000000000" +
                    "0200001A11223344FF0200000000000000000001FF4411228700952D0000" +
                    "000020010000000000000200001A334411220101000102030405"
        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(hostMcastDstIpNsPkt),
            DROPPED_IPV6_NS_REPLIED_NON_DAD
        )

        val transmitPkt = ApfJniUtils.getTransmittedPacket()
        // Using scapy to generate IPv6 NA packet:
        // eth = Ether(src="02:03:04:05:06:07", dst="00:01:02:03:04:05")
        // ip6 = IPv6(src="2001::200:1a:3344:1122", dst="2001::200:1a:1122:3344", hlim=255, tc=20)
        // icmp6 = ICMPv6ND_NA(tgt="2001::200:1a:3344:1122", R=1, S=1, O=1)
        // icmp6_opt = ICMPv6NDOptDstLLAddr(lladdr="02:03:04:05:06:07")
        // pkt = eth/ip6/icmp6/icmp6_opt
        val expectedNaPacket =
            "00010203040502030405060786DD6140000000203AFF2001000000000000020" +
                    "0001A3344112220010000000000000200001A1122334488005610E000000020" +
                    "010000000000000200001A334411220201020304050607"
        assertContentEquals(
            HexDump.hexStringToByteArray(expectedNaPacket),
            transmitPkt
        )
    }

    @Test
    fun testNdOffloadDisabled() {
        val apfConfig = getDefaultConfig()
        apfConfig.shouldHandleNdOffload = false
        val apfFilter = getApfFilter(apfConfig)
        val lp = LinkProperties()
        for (addr in hostIpv6Addresses) {
            lp.addLinkAddress(LinkAddress(InetAddress.getByAddress(addr), 64))
        }

        apfFilter.setLinkProperties(lp)
        val programCaptor = ArgumentCaptor.forClass(ByteArray::class.java)
        verify(ipClientCallback, times(3)).installPacketFilter(programCaptor.capture())
        val program = programCaptor.allValues.last()
        val validIpv6Addresses = hostIpv6Addresses + hostAnycast6Addresses
        for (addr in validIpv6Addresses) {
            // unicast solicited NS request
            val receivedUcastNsPacket = generateNsPacket(
                senderMacAddress,
                apfFilter.mHardwareAddress,
                senderIpv6Address,
                addr,
                addr
            )

            verifyProgramRun(
                apfFilter.mApfVersionSupported,
                program,
                receivedUcastNsPacket,
                PASSED_IPV6_ICMP
            )

            val solicitedMcastAddr = NetworkStackUtils.ipv6AddressToSolicitedNodeMulticast(
                InetAddress.getByAddress(addr) as Inet6Address
            )!!
            val mcastDa = NetworkStackUtils.ipv6MulticastToEthernetMulticast(solicitedMcastAddr)
                .toByteArray()

            // multicast solicited NS request
            var receivedMcastNsPacket = generateNsPacket(
                senderMacAddress,
                mcastDa,
                senderIpv6Address,
                solicitedMcastAddr.address,
                addr
            )

            verifyProgramRun(
                apfFilter.mApfVersionSupported,
                program,
                receivedMcastNsPacket,
                PASSED_IPV6_ICMP
            )
        }
    }

    @Test
    fun testApfProgramUpdate() {
        val apfFilter = getApfFilter()
        verify(ipClientCallback, times(2)).installPacketFilter(any())
        // add IPv4 address, expect to have apf program update
        val lp = LinkProperties()
        val linkAddress = LinkAddress(InetAddress.getByAddress(hostIpv4Address), 24)
        lp.addLinkAddress(linkAddress)
        apfFilter.setLinkProperties(lp)
        verify(ipClientCallback, times(3)).installPacketFilter(any())

        // add the same IPv4 address, expect to have no apf program update
        apfFilter.setLinkProperties(lp)
        verify(ipClientCallback, times(3)).installPacketFilter(any())

        // add IPv6 addresses, expect to have apf program update
        for (addr in hostIpv6Addresses) {
            lp.addLinkAddress(LinkAddress(InetAddress.getByAddress(addr), 64))
        }

        apfFilter.setLinkProperties(lp)
        verify(ipClientCallback, times(4)).installPacketFilter(any())

        // add the same IPv6 addresses, expect to have no apf program update
        apfFilter.setLinkProperties(lp)
        verify(ipClientCallback, times(4)).installPacketFilter(any())

        // add more tentative IPv6 addresses, expect to have apf program update
        for (addr in hostIpv6TentativeAddresses) {
            lp.addLinkAddress(
                LinkAddress(
                    InetAddress.getByAddress(addr),
                    64,
                    IFA_F_TENTATIVE,
                    0
                )
            )
        }

        apfFilter.setLinkProperties(lp)
        verify(ipClientCallback, times(5)).installPacketFilter(any())

        // add the same IPv6 addresses, expect to have no apf program update
        apfFilter.setLinkProperties(lp)
        verify(ipClientCallback, times(5)).installPacketFilter(any())
    }

    @Test
    fun testApfFilterInitializationCleanUpTheApfMemoryRegion() {
        val apfFilter = getApfFilter()
        val programCaptor = ArgumentCaptor.forClass(ByteArray::class.java)
        verify(ipClientCallback, times(2)).installPacketFilter(programCaptor.capture())
        val program = programCaptor.allValues.first()
        assertContentEquals(ByteArray(4096) { 0 }, program)
    }
}
