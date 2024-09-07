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
import android.net.NattKeepalivePacketDataParcelable
import android.net.TcpKeepalivePacketDataParcelable
import android.net.apf.ApfCounterTracker.Counter.DROPPED_ARP_NON_IPV4
import android.net.apf.ApfCounterTracker.Counter.DROPPED_ARP_OTHER_HOST
import android.net.apf.ApfCounterTracker.Counter.DROPPED_ARP_REPLY_SPA_NO_HOST
import android.net.apf.ApfCounterTracker.Counter.DROPPED_ARP_REQUEST_REPLIED
import android.net.apf.ApfCounterTracker.Counter.DROPPED_ARP_UNKNOWN
import android.net.apf.ApfCounterTracker.Counter.DROPPED_ARP_V6_ONLY
import android.net.apf.ApfCounterTracker.Counter.DROPPED_ETHERTYPE_NOT_ALLOWED
import android.net.apf.ApfCounterTracker.Counter.DROPPED_GARP_REPLY
import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_BROADCAST_ADDR
import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_BROADCAST_NET
import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_KEEPALIVE_ACK
import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_L2_BROADCAST
import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_MULTICAST
import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_NATT_KEEPALIVE
import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_NON_DHCP4
import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_TCP_PORT7_UNICAST
import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_MULTICAST_NA
import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_NON_ICMP_MULTICAST
import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_NS_INVALID
import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_NS_OTHER_HOST
import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_NS_REPLIED_NON_DAD
import android.net.apf.ApfCounterTracker.Counter.PASSED_ETHER_OUR_SRC_MAC
import android.net.apf.ApfCounterTracker.Counter.PASSED_ARP_BROADCAST_REPLY
import android.net.apf.ApfCounterTracker.Counter.PASSED_ARP_REQUEST
import android.net.apf.ApfCounterTracker.Counter.PASSED_ARP_UNICAST_REPLY
import android.net.apf.ApfCounterTracker.Counter.PASSED_DHCP
import android.net.apf.ApfCounterTracker.Counter.PASSED_IPV4
import android.net.apf.ApfCounterTracker.Counter.PASSED_IPV4_FROM_DHCPV4_SERVER
import android.net.apf.ApfCounterTracker.Counter.PASSED_IPV4_UNICAST
import android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_ICMP
import android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_NON_ICMP
import android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_NS_DAD
import android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_NS_NO_ADDRESS
import android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_NS_NO_SLLA_OPTION
import android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_NS_TENTATIVE
import android.net.apf.ApfCounterTracker.Counter.PASSED_MLD
import android.net.apf.ApfFilter.Dependencies
import android.net.apf.ApfTestHelpers.Companion.TIMEOUT_MS
import android.net.apf.ApfTestHelpers.Companion.consumeInstalledProgram
import android.net.apf.ApfTestHelpers.Companion.verifyProgramRun
import android.net.apf.BaseApfGenerator.APF_VERSION_3
import android.net.apf.BaseApfGenerator.APF_VERSION_6
import android.net.ip.IpClient.IpClientCallbacksWrapper
import android.net.nsd.NsdManager
import android.net.nsd.OffloadEngine
import android.net.nsd.OffloadServiceInfo
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.SystemClock
import android.system.Os
import android.system.OsConstants.AF_UNIX
import android.system.OsConstants.IFA_F_TENTATIVE
import android.system.OsConstants.SOCK_STREAM
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
import com.android.testutils.waitForIdle
import java.io.FileDescriptor
import java.net.Inet6Address
import java.net.InetAddress
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import libcore.io.IoUtils
import org.junit.After
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.ArgumentCaptor
import org.mockito.ArgumentMatchers.any
import org.mockito.ArgumentMatchers.anyInt
import org.mockito.ArgumentMatchers.anyLong
import org.mockito.ArgumentMatchers.eq
import org.mockito.Mock
import org.mockito.Mockito
import org.mockito.Mockito.doAnswer
import org.mockito.Mockito.doReturn
import org.mockito.Mockito.never
import org.mockito.Mockito.times
import org.mockito.Mockito.verify
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
        private const val TAG = "ApfFilterTest"
    }

    @get:Rule
    val ignoreRule = DevSdkIgnoreRule()

    @Mock
    private lateinit var context: Context

    @Mock private lateinit var metrics: NetworkQuirkMetrics

    @Mock private lateinit var dependencies: Dependencies

    @Mock private lateinit var ipClientCallback: IpClientCallbacksWrapper
    @Mock private lateinit var nsdManager: NsdManager

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

    private val handlerThread by lazy {
        HandlerThread("$TAG handler thread").apply { start() }
    }
    private val handler by lazy { Handler(handlerThread.looper) }
    private var writerSocket = FileDescriptor()

    @Before
    fun setUp() {
        MockitoAnnotations.initMocks(this)
        // mock anycast6 address from /proc/net/anycast6
        doReturn(hostAnycast6Addresses).`when`(dependencies).getAnycast6Addresses(any())

        // mock ether multicast mac address from /proc/net/dev_mcast
        doReturn(hostMulticastMacAddresses).`when`(dependencies).getEtherMulticastAddresses(any())

        // mock nd traffic class from /proc/sys/net/ipv6/conf/{ifname}/ndisc_tclass
        doReturn(0).`when`(dependencies).getNdTrafficClass(any())
        doAnswer { invocation: InvocationOnMock ->
            synchronized(mApfFilterCreated) {
                mApfFilterCreated.add(invocation.getArgument(0))
            }
        }.`when`(dependencies).onApfFilterCreated(any())
        doReturn(SystemClock.elapsedRealtime()).`when`(dependencies).elapsedRealtime()
        val readSocket = FileDescriptor()
        Os.socketpair(AF_UNIX, SOCK_STREAM, 0, writerSocket, readSocket)
        doReturn(readSocket).`when`(dependencies).createPacketReaderSocket(anyInt())
        doReturn(nsdManager).`when`(context).getSystemService(NsdManager::class.java)
    }

    private fun shutdownApfFilters() {
        quitResources(THREAD_QUIT_MAX_RETRY_COUNT, {
            synchronized(mApfFilterCreated) {
                val ret = ArrayList(mApfFilterCreated)
                mApfFilterCreated.clear()
                return@quitResources ret
            }
        }, { apf: AndroidPacketFilter ->
            handler.post { apf.shutdown() }
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
        IoUtils.closeQuietly(writerSocket)
        shutdownApfFilters()
        handler.waitForIdle(TIMEOUT_MS)
        Mockito.framework().clearInlineMocks()
        ApfJniUtils.resetTransmittedPacketMemory()
        handlerThread.quitSafely()
        handlerThread.join()
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
        lateinit var apfFilter: ApfFilter
        handler.post {
            apfFilter = ApfFilter(
                    handler,
                    context,
                    apfCfg,
                    ifParams,
                    ipClientCallback,
                    metrics,
                    dependencies
            )
        }
        handlerThread.waitForIdle(TIMEOUT_MS)
        return apfFilter
    }

    private fun doTestEtherTypeAllowListFilter(apfFilter: ApfFilter) {
        val program = consumeInstalledProgram(ipClientCallback, installCnt = 2)

        // Using scapy to generate IPv4 mDNS packet:
        //   eth = Ether(src="E8:9F:80:66:60:BB", dst="01:00:5E:00:00:FB")
        //   ip = IP(src="192.168.1.1")
        //   udp = UDP(sport=5353, dport=5353)
        //   dns = DNS(qd=DNSQR(qtype="PTR", qname="a.local"))
        //   p = eth/ip/udp/dns
        val mdnsPkt = """
            01005e0000fbe89f806660bb080045000035000100004011d812c0a80101e00000f
            b14e914e900214d970000010000010000000000000161056c6f63616c00000c0001
        """.replace("\\s+".toRegex(), "").trim()
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
        val raPkt = """
            333300000001e89f806660bb86dd6000000000103afffe800000000000000000000000
            000001ff0200000000000000000000000000018600600700080e100000000000000e10
        """.replace("\\s+".toRegex(), "").trim()
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
        val program = consumeInstalledProgram(ipClientCallback, installCnt = 3)

        // Using scapy to generate IPv4 mDNS packet:
        //   eth = Ether(src="E8:9F:80:66:60:BB", dst="01:00:5E:00:00:FB")
        //   ip = IP(src="192.168.1.1")
        //   udp = UDP(sport=5353, dport=5353)
        //   dns = DNS(qd=DNSQR(qtype="PTR", qname="a.local"))
        //   p = eth/ip/udp/dns
        val mdnsPkt = """
            01005e0000fbe89f806660bb080045000035000100004011d812c0a80101e00000f
            b14e914e900214d970000010000010000000000000161056c6f63616c00000c0001
        """.replace("\\s+".toRegex(), "").trim()
        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(mdnsPkt),
            DROPPED_IPV4_NON_DHCP4
        )

        // Using scapy to generate non UDP protocol packet:
        //   ether = Ether(src='00:11:22:33:44:55', dst='ff:ff:ff:ff:ff:ff')
        //   ip = IP(src='192.168.1.1', dst='255.255.255.255', proto=12)
        //   pkt = ether/ip
        val nonUdpPkt = """
            ffffffffffff00112233445508004500001400010000400cb934c0a80101ffffffff
        """.replace("\\s+".toRegex(), "").trim()
        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(nonUdpPkt),
            DROPPED_IPV4_NON_DHCP4
        )

        // Using scapy to generate fragmented UDP protocol packet:
        //   ether = Ether(src='00:11:22:33:44:55', dst='ff:ff:ff:ff:ff:ff')
        //   ip = IP(src='192.168.1.1', dst='255.255.255.255', flags=1, frag=10, proto=17)
        //   pkt = ether/ip
        val fragmentUdpPkt = """
            ffffffffffff0011223344550800450000140001200a40119925c0a80101ffffffff
        """.replace("\\s+".toRegex(), "").trim()
        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(fragmentUdpPkt),
            DROPPED_IPV4_NON_DHCP4
        )

        // Using scapy to generate destination port is not DHCP client port packet:
        //   ether = Ether(src='00:11:22:33:44:55', dst='ff:ff:ff:ff:ff:ff')
        //   ip = IP(src='192.168.1.1', dst='255.255.255.255')
        //   udp = UDP(dport=70)
        //   pkt = ether/ip/udp
        val nonDhcpServerPkt = """
            ffffffffffff00112233445508004500001c000100004011b927c0a80101ffffffff0035004600083dba
        """.replace("\\s+".toRegex(), "").trim()
        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(nonDhcpServerPkt),
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
        val dhcp4Pkt = """
            ffffffffffff00112233445508004500012e000100004011b815c0a80101ffffffff0043
            0044011a5ffc02010600000000000000000000000000c0a80164c0a80101000000000011
            223344550000000000000000000000000000000000000000000000000000000000000000
            000000000000000000000000000000000000000000000000000000000000000000000000
            000000000000000000000000000000000000000000000000000000000000000000000000
            000000000000000000000000000000000000000000000000000000000000000000000000
            000000000000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000638253633501023604c0
            a801010104ffffff000304c0a80101330400015180060408080808ff
        """.replace("\\s+".toRegex(), "").trim()
        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(dhcp4Pkt),
            PASSED_IPV4_FROM_DHCPV4_SERVER
        )

        // Duplicate of dhcp4Pkt with DF flag set.
        val dhcp4PktDf = """
            ffffffffffff00112233445508004500012e000140004011b815c0a80101ffffffff0043
            0044011a5ffc02010600000000000000000000000000c0a80164c0a80101000000000011
            223344550000000000000000000000000000000000000000000000000000000000000000
            000000000000000000000000000000000000000000000000000000000000000000000000
            000000000000000000000000000000000000000000000000000000000000000000000000
            000000000000000000000000000000000000000000000000000000000000000000000000
            000000000000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000638253633501023604c0
            a801010104ffffff000304c0a80101330400015180060408080808ff
        """.replace("\\s+".toRegex(), "").trim()
        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(dhcp4PktDf),
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
        val fragmentedUdpPkt = """
            01005e0000fbe89f806660bb08004500001d000100034011f75dc0a8010ac0a8
            01146f63616c00000c0001
        """.replace("\\s+".toRegex(), "").trim()
        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(fragmentedUdpPkt),
            DROPPED_IPV4_NON_DHCP4
        )
    }

    @Test
    fun testLoopbackFilter() {
        val apfConfig = getDefaultConfig()
        val apfFilter = getApfFilter(apfConfig)
        val program = consumeInstalledProgram(ipClientCallback, installCnt = 2)
        // Using scapy to generate echo-ed broadcast packet:
        //   ether = Ether(src=${ifParams.macAddr}, dst='ff:ff:ff:ff:ff:ff')
        //   ip = IP(src='192.168.1.1', dst='255.255.255.255', proto=21)
        //   pkt = ether/ip
        val nonDhcpBcastPkt = """
            ffffffffffff020304050607080045000014000100004015b92bc0a80101ffffffff
        """.replace("\\s+".toRegex(), "").trim()
        verifyProgramRun(
                apfFilter.mApfVersionSupported,
                program,
                HexDump.hexStringToByteArray(nonDhcpBcastPkt),
                PASSED_ETHER_OUR_SRC_MAC
        )
    }

    @Test
    fun testIPv4MulticastPacketFilter() {
        val apfConfig = getDefaultConfig()
        apfConfig.multicastFilter = true
        val apfFilter = getApfFilter(apfConfig)
        consumeInstalledProgram(ipClientCallback, installCnt = 2)
        val linkAddress = LinkAddress(InetAddress.getByAddress(hostIpv4Address), 24)
        val lp = LinkProperties()
        lp.addLinkAddress(linkAddress)
        apfFilter.setLinkProperties(lp)
        val program = consumeInstalledProgram(ipClientCallback, installCnt = 1)

        // Using scapy to generate DHCP4 offer packet:
        //   ether = Ether(src='00:11:22:33:44:55', dst='ff:ff:ff:ff:ff:ff')
        //   ip = IP(src='192.168.1.1', dst='255.255.255.255')
        //   udp = UDP(sport=67, dport=68)
        //   bootp = BOOTP(op=2,
        //                 yiaddr='192.168.1.100',
        //                 siaddr='192.168.1.1',
        //                 chaddr=b'\x02\x03\x04\x05\x06\x07')
        //   dhcp_options = [('message-type', 'offer'),
        //                   ('server_id', '192.168.1.1'),
        //                   ('subnet_mask', '255.255.255.0'),
        //                   ('router', '192.168.1.1'),
        //                   ('lease_time', 86400),
        //                   ('name_server', '8.8.8.8'),
        //                   'end']
        //   dhcp = DHCP(options=dhcp_options)
        //   dhcp_offer_packet = ether/ip/udp/bootp/dhcp
        val dhcp4Pkt = """
            ffffffffffff00112233445508004500012e000100004011b815c0a80101ffffffff0043
            0044011a5ffc02010600000000000000000000000000c0a80164c0a80101000000000203
            040506070000000000000000000000000000000000000000000000000000000000000000
            000000000000000000000000000000000000000000000000000000000000000000000000
            000000000000000000000000000000000000000000000000000000000000000000000000
            000000000000000000000000000000000000000000000000000000000000000000000000
            000000000000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000638253633501023604c0
            a801010104ffffff000304c0a80101330400015180060408080808ff
        """.replace("\\s+".toRegex(), "").trim()
        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(dhcp4Pkt),
            PASSED_DHCP
        )

        // Using scapy to generate non DHCP multicast packet:
        //   ether = Ether(src='00:11:22:33:44:55', dst='ff:ff:ff:ff:ff:ff')
        //   ip = IP(src='192.168.1.1', dst='224.0.0.1', proto=21)
        //   pkt = ether/ip
        val nonDhcpMcastPkt = """
            ffffffffffff001122334455080045000014000100004015d929c0a80101e0000001
        """.replace("\\s+".toRegex(), "").trim()
        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(nonDhcpMcastPkt),
            DROPPED_IPV4_MULTICAST
        )

        // Using scapy to generate non DHCP broadcast packet:
        //   ether = Ether(src='00:11:22:33:44:55', dst='ff:ff:ff:ff:ff:ff')
        //   ip = IP(src='192.168.1.1', dst='255.255.255.255', proto=21)
        //   pkt = ether/ip
        val nonDhcpBcastPkt = """
            ffffffffffff001122334455080045000014000100004015b92bc0a80101ffffffff
        """.replace("\\s+".toRegex(), "").trim()
        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(nonDhcpBcastPkt),
            DROPPED_IPV4_BROADCAST_ADDR
        )

        // Using scapy to generate non DHCP subnet broadcast packet:
        //   ether = Ether(src='00:11:22:33:44:55', dst='ff:ff:ff:ff:ff:ff')
        //   ip = IP(src='192.168.1.1', dst='10.0.0.255', proto=21)
        //   pkt = ether/ip
        val nonDhcpNetBcastPkt = """
            ffffffffffff001122334455080045000014000100004015ae2cc0a801010a0000ff
        """.replace("\\s+".toRegex(), "").trim()
        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(nonDhcpNetBcastPkt),
            DROPPED_IPV4_BROADCAST_NET
        )

        // Using scapy to generate non DHCP unicast packet:
        //   ether = Ether(src='00:11:22:33:44:55', dst='02:03:04:05:06:07')
        //   ip = IP(src='192.168.1.1', dst='192.168.1.2', proto=21)
        //   pkt = ether/ip
        val nonDhcpUcastPkt = """
            020304050607001122334455080045000014000100004015f780c0a80101c0a80102
        """.replace("\\s+".toRegex(), "").trim()
        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(nonDhcpUcastPkt),
            PASSED_IPV4_UNICAST
        )

        // Using scapy to generate non DHCP unicast packet with broadcast ether destination:
        //   ether = Ether(src='00:11:22:33:44:55', dst='ff:ff:ff:ff:ff:ff')
        //   ip = IP(src='192.168.1.1', dst='192.168.1.2', proto=21)
        //   pkt = ether/ip
        val nonDhcpUcastL2BcastPkt = """
            ffffffffffff001122334455080045000014000100004015f780c0a80101c0a80102
        """.replace("\\s+".toRegex(), "").trim()
        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(nonDhcpUcastL2BcastPkt),
            DROPPED_IPV4_L2_BROADCAST
        )
    }

    @Test
    fun testArpFilterDropPktsOnV6OnlyNetwork() {
        val apfFilter = getApfFilter()
        consumeInstalledProgram(ipClientCallback, installCnt = 2)
        apfFilter.updateClatInterfaceState(true)
        val program = consumeInstalledProgram(ipClientCallback, installCnt = 1)

        // Drop ARP request packet when clat is enabled
        // Using scapy to generate ARP request packet:
        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
        // arp = ARP()
        // pkt = eth/arp
        val arpPkt = """
            010203040506000102030405080600010800060400015c857e3c74e1c0a8012200000000000000000000
        """.replace("\\s+".toRegex(), "").trim()
        verifyProgramRun(
            APF_VERSION_6,
            program,
            HexDump.hexStringToByteArray(arpPkt),
            DROPPED_ARP_V6_ONLY
        )
    }

    @Test
    fun testIPv4TcpKeepaliveFilter() {
        val srcAddr = byteArrayOf(10, 0, 0, 5)
        val dstAddr = byteArrayOf(10, 0, 0, 6)
        val srcPort = 12345
        val dstPort = 54321
        val seqNum = 2123456789
        val ackNum = 1234567890

        // src: 10.0.0.5:12345
        // dst: 10.0.0.6:54321
        val parcel = TcpKeepalivePacketDataParcelable()
        parcel.srcAddress = InetAddress.getByAddress(srcAddr).address
        parcel.srcPort = srcPort
        parcel.dstAddress = InetAddress.getByAddress(dstAddr).address
        parcel.dstPort = dstPort
        parcel.seq = seqNum
        parcel.ack = ackNum

        val apfConfig = getDefaultConfig()
        apfConfig.multicastFilter = true
        apfConfig.ieee802_3Filter = true
        val apfFilter = getApfFilter(apfConfig)
        consumeInstalledProgram(ipClientCallback, installCnt = 2)
        apfFilter.addTcpKeepalivePacketFilter(1, parcel)
        var program = consumeInstalledProgram(ipClientCallback, installCnt = 1)

        // Drop IPv4 keepalive ack
        // Using scapy to generate IPv4 TCP keepalive ack packet with seq + 1:
        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
        // ip = IP(src='10.0.0.6', dst='10.0.0.5')
        // tcp = TCP(sport=54321, dport=12345, flags="A", seq=1234567890, ack=2123456790)
        // pkt = eth/ip/tcp
        val keepaliveAckPkt = """
            01020304050600010203040508004500002800010000400666c50a0000060a000005d4313039499602d2
            7e916116501020004b4f0000
        """.replace("\\s+".toRegex(), "").trim()
        verifyProgramRun(
            APF_VERSION_6,
            program,
            HexDump.hexStringToByteArray(keepaliveAckPkt),
            DROPPED_IPV4_KEEPALIVE_ACK
        )

        // Pass IPv4 non-keepalive ack from the same source address
        // Using scapy to generate IPv4 TCP non-keepalive ack from the same source address:
        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
        // ip = IP(src='10.0.0.6', dst='10.0.0.5')
        // tcp = TCP(sport=54321, dport=12345, flags="A", seq=1234567990, ack=2123456789)
        // pkt = eth/ip/tcp
        val nonKeepaliveAckPkt1 = """
            01020304050600010203040508004500002800010000400666c50a0000060a000005d431303949960336
            7e916115501020004aec0000
        """.replace("\\s+".toRegex(), "").trim()
        verifyProgramRun(
            APF_VERSION_6,
            program,
            HexDump.hexStringToByteArray(nonKeepaliveAckPkt1),
            PASSED_IPV4_UNICAST
        )

        // Pass IPv4 non-keepalive ack from the same source address
        // Using scapy to generate IPv4 TCP non-keepalive ack from the same source address:
        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
        // ip = IP(src='10.0.0.6', dst='10.0.0.5')
        // tcp = TCP(sport=54321, dport=12345, flags="A", seq=1234567890, ack=2123456790)
        // payload = Raw(b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09')
        // pkt = eth/ip/tcp/payload
        val nonKeepaliveAckPkt2 = """
            01020304050600010203040508004500003200010000400666bb0a0000060a000005d4313039499602d27
            e91611650102000372c000000010203040506070809
        """.replace("\\s+".toRegex(), "").trim()
        verifyProgramRun(
            APF_VERSION_6,
            program,
            HexDump.hexStringToByteArray(nonKeepaliveAckPkt2),
            PASSED_IPV4_UNICAST
        )

        // Pass IPv4 keepalive ack from another address
        // Using scapy to generate IPv4 TCP keepalive ack from another address:
        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
        // ip = IP(src='10.0.0.7', dst='10.0.0.5')
        // tcp = TCP(sport=23456, dport=65432, flags="A", seq=2123456780, ack=1123456789)
        // pkt = eth/ip/tcp
        val otherSrcKeepaliveAck = """
            01020304050600010203040508004500002800010000400666c40a0000070a0000055ba0ff987e91610c4
            2f697155010200066e60000
        """.replace("\\s+".toRegex(), "").trim()
        verifyProgramRun(
            APF_VERSION_6,
            program,
            HexDump.hexStringToByteArray(otherSrcKeepaliveAck),
            PASSED_IPV4_UNICAST
        )

        // test IPv4 packets when TCP keepalive filter is removed
        apfFilter.removeKeepalivePacketFilter(1)
        program = consumeInstalledProgram(ipClientCallback, installCnt = 1)
        verifyProgramRun(
            APF_VERSION_6,
            program,
            HexDump.hexStringToByteArray(keepaliveAckPkt),
            PASSED_IPV4_UNICAST
        )

        verifyProgramRun(
            APF_VERSION_6,
            program,
            HexDump.hexStringToByteArray(otherSrcKeepaliveAck),
            PASSED_IPV4_UNICAST
        )
    }

    @Test
    fun testIPv4NattKeepaliveFilter() {
        val srcAddr = byteArrayOf(10, 0, 0, 5)
        val dstAddr = byteArrayOf(10, 0, 0, 6)
        val srcPort = 1024
        val dstPort = 4500

        // src: 10.0.0.5:1024
        // dst: 10.0.0.6:4500
        val parcel = NattKeepalivePacketDataParcelable()
        parcel.srcAddress = InetAddress.getByAddress(srcAddr).address
        parcel.srcPort = srcPort
        parcel.dstAddress = InetAddress.getByAddress(dstAddr).address
        parcel.dstPort = dstPort

        val apfConfig = getDefaultConfig()
        apfConfig.multicastFilter = true
        apfConfig.ieee802_3Filter = true
        val apfFilter = getApfFilter(apfConfig)
        consumeInstalledProgram(ipClientCallback, installCnt = 2)
        apfFilter.addNattKeepalivePacketFilter(1, parcel)
        val program = consumeInstalledProgram(ipClientCallback, installCnt = 1)

        // Drop IPv4 keepalive response packet
        // Using scapy to generate IPv4 NAT-T keepalive ack packet with payload 0xff:
        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
        // ip = IP(src='10.0.0.6', dst='10.0.0.5')
        // udp = UDP(sport=4500, dport=1024)
        // payload = NAT_KEEPALIVE(nat_keepalive=0xff)
        // pkt = eth/ip/udp/payload
        val validNattPkt = """
            01020304050600010203040508004500001d00010000401166c50a0000060a000005119404000009d73cff
        """.replace("\\s+".toRegex(), "").trim()
        verifyProgramRun(
            APF_VERSION_6,
            program,
            HexDump.hexStringToByteArray(validNattPkt),
            DROPPED_IPV4_NATT_KEEPALIVE
        )

        // Pass IPv4 keepalive response packet with 0xfe payload
        // Using scapy to generate IPv4 NAT-T keepalive ack packet with payload 0xfe:
        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
        // ip = IP(src='10.0.0.6', dst='10.0.0.5')
        // udp = UDP(sport=4500, dport=1024)
        // payload = NAT_KEEPALIVE(nat_keepalive=0xfe)
        // pkt = eth/ip/udp/payload
        val invalidNattPkt = """
            01020304050600010203040508004500001d00010000401166c50a0000060a000005119404000009d83cfe
        """.replace("\\s+".toRegex(), "").trim()
        verifyProgramRun(
            APF_VERSION_6,
            program,
            HexDump.hexStringToByteArray(invalidNattPkt),
            PASSED_IPV4_UNICAST
        )

        // Pass IPv4 non-keepalive response packet from the same source address
        // Using scapy to generate IPv4 NAT-T keepalive ack packet with payload 0xfe:
        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
        // ip = IP(src='10.0.0.6', dst='10.0.0.5')
        // udp = UDP(sport=4500, dport=1024)
        // payload = Raw(b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09')
        // pkt = eth/ip/udp/payload
        val nonNattPkt = """
            01020304050600010203040508004500002600010000401166bc0a0000060a000005119404000012c2120
            0010203040506070809
        """.replace("\\s+".toRegex(), "").trim()
        verifyProgramRun(
            APF_VERSION_6,
            program,
            HexDump.hexStringToByteArray(nonNattPkt),
            PASSED_IPV4_UNICAST
        )

        // Pass IPv4 non-keepalive response packet from other source address
        // Using scapy to generate IPv4 NAT-T keepalive ack packet with payload 0xfe:
        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
        // ip = IP(src='10.0.0.7', dst='10.0.0.5')
        // udp = UDP(sport=4500, dport=1024)
        // payload = Raw(b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09')
        // pkt = eth/ip/udp/payload
        val otherSrcNonNattPkt = """
            01020304050600010203040508004500002600010000401166bb0a0000070a000005119404000012c2110
            0010203040506070809
        """.replace("\\s+".toRegex(), "").trim()
        verifyProgramRun(
            APF_VERSION_6,
            program,
            HexDump.hexStringToByteArray(otherSrcNonNattPkt),
            PASSED_IPV4_UNICAST
        )
    }

    @Test
    fun testIPv4TcpPort7Filter() {
        val apfFilter = getApfFilter()
        val program = consumeInstalledProgram(ipClientCallback, installCnt = 2)

        // Drop IPv4 TCP port 7 packet
        // Using scapy to generate IPv4 TCP port 7 packet:
        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
        // ip = IP(src='10.0.0.6', dst='10.0.0.5')
        // tcp = TCP(dport=7)
        // pkt = eth/ip/tcp
        val tcpPort7Pkt = """
            01020304050600010203040508004500002800010000400666c50a0000060a00000500140007000000000
            0000000500220007bbd0000
        """.replace("\\s+".toRegex(), "").trim()
        verifyProgramRun(
            APF_VERSION_6,
            program,
            HexDump.hexStringToByteArray(tcpPort7Pkt),
            DROPPED_IPV4_TCP_PORT7_UNICAST
        )

        // Pass IPv4 TCP initial fragment packet
        // Using scapy to generate IPv4 TCP initial fragment packet:
        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
        // ip = IP(src='10.0.0.6', dst='10.0.0.5', flags=1, frag=0)
        // tcp = TCP()
        // pkt = eth/ip/tcp
        val initialFragmentTcpPkt = """
            01020304050600010203040508004500002800012000400646c50a0000060a00000500140050000000000
            0000000500220007b740000
        """.replace("\\s+".toRegex(), "").trim()
        verifyProgramRun(
            APF_VERSION_6,
            program,
            HexDump.hexStringToByteArray(initialFragmentTcpPkt),
            PASSED_IPV4
        )

        // Pass IPv4 TCP fragment packet
        // Using scapy to generate IPv4 TCP fragment packet:
        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
        // ip = IP(src='10.0.0.6', dst='10.0.0.5', flags=1, frag=100)
        // tcp = TCP()
        // pkt = eth/ip/tcp
        val fragmentTcpPkt = """
            01020304050600010203040508004500002800012064400646610a0000060a00000500140050000000000
            0000000500220007b740000
        """.replace("\\s+".toRegex(), "").trim()
        verifyProgramRun(
            APF_VERSION_6,
            program,
            HexDump.hexStringToByteArray(fragmentTcpPkt),
            PASSED_IPV4
        )
    }

    @Test
    fun testIPv6MulticastPacketFilterInDozeMode() {
        val apfConfig = getDefaultConfig()
        apfConfig.multicastFilter = true
        val apfFilter = getApfFilter(apfConfig)
        consumeInstalledProgram(ipClientCallback, installCnt = 2)
        val lp = LinkProperties()
        for (addr in hostIpv6Addresses) {
            lp.addLinkAddress(LinkAddress(InetAddress.getByAddress(addr), 64))
        }
        apfFilter.setLinkProperties(lp)
        apfFilter.setDozeMode(true)
        val program = consumeInstalledProgram(ipClientCallback, installCnt = 2)
        // Using scapy to generate non ICMPv6 sent to ff00::/8 (multicast prefix) packet:
        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="ff00::1", nh=59)
        // pkt = eth/ip6
        val nonIcmpv6McastPkt = """
            ffffffffffff00112233445586dd6000000000003b4020010000000000000200001a11223344ff00000
            0000000000000000000000000
        """.replace("\\s+".toRegex(), "").trim()
        verifyProgramRun(
            APF_VERSION_6,
            program,
            HexDump.hexStringToByteArray(nonIcmpv6McastPkt),
            DROPPED_IPV6_NON_ICMP_MULTICAST
        )

        // Using scapy to generate ICMPv6 echo sent to ff00::/8 (multicast prefix) packet:
        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="ff00::1", hlim=255)
        // icmp6 = ICMPv6EchoRequest()
        // pkt = eth/ip6/icmp6
        val icmpv6EchoPkt = """
            02030405060700010203040586dd6000000000083aff20010000000000000200001a11223344ff00000
            000000000000000000000000180001a3a00000000
        """.replace("\\s+".toRegex(), "").trim()
        verifyProgramRun(
            APF_VERSION_6,
            program,
            HexDump.hexStringToByteArray(icmpv6EchoPkt),
            DROPPED_IPV6_NON_ICMP_MULTICAST
        )
    }

    @Test
    fun testIPv6PacketFilter() {
        val apfFilter = getApfFilter()
        consumeInstalledProgram(ipClientCallback, installCnt = 2)
        val lp = LinkProperties()
        for (addr in hostIpv6Addresses) {
            lp.addLinkAddress(LinkAddress(InetAddress.getByAddress(addr), 64))
        }
        apfFilter.setLinkProperties(lp)
        val program = consumeInstalledProgram(ipClientCallback, installCnt = 1)
        // Using scapy to generate non ICMPv6 packet:
        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", nh=59)
        // pkt = eth/ip6
        val nonIcmpv6Pkt = """
            ffffffffffff00112233445586dd6000000000003b4020010000000000000200001a112233442001000
            0000000000200001a33441122
        """.replace("\\s+".toRegex(), "").trim()
        verifyProgramRun(
            APF_VERSION_6,
            program,
            HexDump.hexStringToByteArray(nonIcmpv6Pkt),
            PASSED_IPV6_NON_ICMP
        )

        // Using scapy to generate ICMPv6 NA sent to ff02::/120 packet:
        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="ff02::1")
        // icmp6 = ICMPv6ND_NA()
        // pkt = eth/ip6/icmp6
        val icmpv6McastNaPkt = """
            01020304050600010203040586dd6000000000183aff20010000000000000200001a11223344ff02000
            000000000000000000000000188007227a000000000000000000000000000000000000000
        """.replace("\\s+".toRegex(), "").trim()
        verifyProgramRun(
            APF_VERSION_6,
            program,
            HexDump.hexStringToByteArray(icmpv6McastNaPkt),
            DROPPED_IPV6_MULTICAST_NA
        )

        // Using scapy to generate IPv6 packet with hop-by-hop option:
        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", nh=0)
        // pkt = eth/ip6
        val ipv6WithHopByHopOptionPkt = """
            01020304050600010203040586dd600000000000004020010000000000000200001a112233442001000
            0000000000200001a33441122
        """.replace("\\s+".toRegex(), "").trim()
        verifyProgramRun(
            APF_VERSION_6,
            program,
            HexDump.hexStringToByteArray(ipv6WithHopByHopOptionPkt),
            PASSED_MLD
        )
    }

    @Test
    fun testArpFilterDropPktsNoIPv4() {
        val apfFilter = getApfFilter()
        val program = consumeInstalledProgram(ipClientCallback, installCnt = 2)

        // Drop ARP request packet with invalid hw type
        // Using scapy to generate ARP request packet with invalid hw type :
        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
        // arp = ARP(hwtype=3)
        // pkt = eth/arp
        val invalidHwTypePkt = """
            01020304050600010203040508060003080000040001c0a8012200000000
        """.replace("\\s+".toRegex(), "").trim()
        verifyProgramRun(
            APF_VERSION_6,
            program,
            HexDump.hexStringToByteArray(invalidHwTypePkt),
            DROPPED_ARP_NON_IPV4
        )

        // Drop ARP request packet with invalid proto type
        // Using scapy to generate ARP request packet with invalid proto type:
        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
        // arp = ARP(ptype=20)
        // pkt = eth/arp
        val invalidProtoTypePkt = """
            010203040506000102030405080600010014060000015c857e3c74e1000000000000
        """.replace("\\s+".toRegex(), "").trim()
        verifyProgramRun(
            APF_VERSION_6,
            program,
            HexDump.hexStringToByteArray(invalidProtoTypePkt),
            DROPPED_ARP_NON_IPV4
        )

        // Drop ARP request packet with invalid hw len
        // Using scapy to generate ARP request packet with invalid hw len:
        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
        // arp = ARP(hwlen=20)
        // pkt = eth/arp
        val invalidHwLenPkt = """
            01020304050600010203040508060001080014040001000000000000000000000000
            0000000000000000c0a8012200000000000000000000000000000000000000000000
            0000
        """.replace("\\s+".toRegex(), "").trim()
        verifyProgramRun(
            APF_VERSION_6,
            program,
            HexDump.hexStringToByteArray(invalidHwLenPkt),
            DROPPED_ARP_NON_IPV4
        )

        // Drop ARP request packet with invalid proto len
        // Using scapy to generate ARP request packet with invalid proto len:
        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
        // arp = ARP(plen=20)
        // pkt = eth/arp
        val invalidProtoLenPkt = """
            010203040506000102030405080600010800061400015c857e3c74e1000000000000
            00000000000000000000000000000000000000000000000000000000000000000000
            000000000000
        """.replace("\\s+".toRegex(), "").trim()
        verifyProgramRun(
            APF_VERSION_6,
            program,
            HexDump.hexStringToByteArray(invalidProtoLenPkt),
            DROPPED_ARP_NON_IPV4
        )

        // Drop ARP request packet with invalid opcode
        // Using scapy to generate ARP request packet with invalid opcode:
        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
        // arp = ARP(op=5)
        // pkt = eth/arp
        val invalidOpPkt = """
            010203040506000102030405080600010800060400055c857e3c74e1c0a8012200000000000000000000
        """.replace("\\s+".toRegex(), "").trim()
        verifyProgramRun(
            APF_VERSION_6,
            program,
            HexDump.hexStringToByteArray(invalidOpPkt),
            DROPPED_ARP_UNKNOWN
        )

        // Drop ARP reply packet with zero source protocol address
        // Using scapy to generate ARP request packet with zero source protocol address:
        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
        // arp = ARP(op=2, psrc="0.0.0.0)
        // pkt = eth/arp
        val noHostArpReplyPkt = """
            010203040506000102030405080600010800060400025c857e3c74e10000000000000000000000000000
        """.replace("\\s+".toRegex(), "").trim()
        verifyProgramRun(
            APF_VERSION_6,
            program,
            HexDump.hexStringToByteArray(noHostArpReplyPkt),
            DROPPED_ARP_REPLY_SPA_NO_HOST
        )

        // Drop ARP reply packet with ethernet broadcast destination
        // Using scapy to generate ARP reply packet with ethernet broadcast destination:
        // eth = Ether(src="00:01:02:03:04:05", dst="FF:FF:FF:FF:FF:FF")
        // arp = ARP(op=2, pdst="0.0.0.0")
        // pkt = eth/arp
        val garpReplyPkt = """
            ffffffffffff000102030405080600010800060400025c857e3c74e1c0a8012200000000000000000000
        """.replace("\\s+".toRegex(), "").trim()
        verifyProgramRun(
            APF_VERSION_6,
            program,
            HexDump.hexStringToByteArray(garpReplyPkt),
            DROPPED_GARP_REPLY
        )
    }

    @Test
    fun testArpFilterPassPktsNoIPv4() {
        val apfFilter = getApfFilter()
        val program = consumeInstalledProgram(ipClientCallback, installCnt = 2)
        // Pass non-broadcast ARP reply packet
        // Using scapy to generate unicast ARP reply packet:
        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
        // arp = ARP(op=2, psrc="1.2.3.4")
        // pkt = eth/arp
        val nonBcastArpReplyPkt = """
            010203040506000102030405080600010800060400025c857e3c74e10102030400000000000000000000
        """.replace("\\s+".toRegex(), "").trim()
        verifyProgramRun(
            APF_VERSION_6,
            program,
            HexDump.hexStringToByteArray(nonBcastArpReplyPkt),
            PASSED_ARP_UNICAST_REPLY
        )

        // Pass ARP request packet if device doesn't have any IPv4 address
        // Using scapy to generate ARP request packet:
        // eth = Ether(src="00:01:02:03:04:05", dst="FF:FF:FF:FF:FF:FF")
        // arp = ARP(op=1, pdst="1.2.3.4")
        // pkt = eth/arp
        val arpRequestPkt = """
            ffffffffffff000102030405080600010800060400015c857e3c74e1c0a8012200000000000001020304
        """.replace("\\s+".toRegex(), "").trim()
        verifyProgramRun(
            APF_VERSION_6,
            program,
            HexDump.hexStringToByteArray(arpRequestPkt),
            PASSED_ARP_REQUEST
        )
    }

    @Test
    fun testArpFilterDropPktsWithIPv4() {
        val apfFilter = getApfFilter()
        consumeInstalledProgram(ipClientCallback, installCnt = 2)
        val linkAddress = LinkAddress(InetAddress.getByAddress(hostIpv4Address), 24)
        val lp = LinkProperties()
        lp.addLinkAddress(linkAddress)
        apfFilter.setLinkProperties(lp)
        val program = consumeInstalledProgram(ipClientCallback, installCnt = 1)
        // Drop ARP reply packet is not for the device
        // Using scapy to generate ARP reply packet not for the device:
        // eth = Ether(src="00:01:02:03:04:05", dst="FF:FF:FF:FF:FF:FF")
        // arp = ARP(op=2, pdst="1.2.3.4")
        // pkt = eth/arp
        val otherHostArpReplyPkt = """
            ffffffffffff000102030405080600010800060400025c857e3c74e1c0a8012200000000000001020304
        """.replace("\\s+".toRegex(), "").trim()
        verifyProgramRun(
            APF_VERSION_6,
            program,
            HexDump.hexStringToByteArray(otherHostArpReplyPkt),
            DROPPED_ARP_OTHER_HOST
        )

        // Drop broadcast ARP request packet not for the device
        // Using scapy to generate ARP broadcast request packet not for the device:
        // eth = Ether(src="00:01:02:03:04:05", dst="FF:FF:FF:FF:FF:FF")
        // arp = ARP(op=1, pdst="1.2.3.4")
        // pkt = eth/arp
        val otherHostArpRequestPkt = """
            ffffffffffff000102030405080600010800060400015c857e3c74e1c0a8012200000000000001020304
        """.replace("\\s+".toRegex(), "").trim()
        verifyProgramRun(
            APF_VERSION_6,
            program,
            HexDump.hexStringToByteArray(otherHostArpRequestPkt),
            DROPPED_ARP_OTHER_HOST
        )
    }

    @Test
    fun testArpFilterPassPktsWithIPv4() {
        val apfFilter = getApfFilter()
        consumeInstalledProgram(ipClientCallback, installCnt = 2)
        val linkAddress = LinkAddress(InetAddress.getByAddress(hostIpv4Address), 24)
        val lp = LinkProperties()
        lp.addLinkAddress(linkAddress)
        apfFilter.setLinkProperties(lp)
        val program = consumeInstalledProgram(ipClientCallback, installCnt = 1)

        // Using scapy to generate ARP broadcast reply packet:
        // eth = Ether(src="00:01:02:03:04:05", dst="FF:FF:FF:FF:FF:FF")
        // arp = ARP(op=2, pdst="10.0.0.1")
        // pkt = eth/arp
        val bcastArpReplyPkt = """
            ffffffffffff000102030405080600010800060400025c857e3c74e1c0a801220000000000000a000001
        """.replace("\\s+".toRegex(), "").trim()
        verifyProgramRun(
            APF_VERSION_6,
            program,
            HexDump.hexStringToByteArray(bcastArpReplyPkt),
            PASSED_ARP_BROADCAST_REPLY
        )
    }

    // The APFv6 code path is only turned on in V+
    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    @Test
    fun testArpTransmit() {
        val apfFilter = getApfFilter()
        consumeInstalledProgram(ipClientCallback, installCnt = 2)
        val linkAddress = LinkAddress(InetAddress.getByAddress(hostIpv4Address), 24)
        val lp = LinkProperties()
        lp.addLinkAddress(linkAddress)
        apfFilter.setLinkProperties(lp)
        val program = consumeInstalledProgram(ipClientCallback, installCnt = 1)
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
        consumeInstalledProgram(ipClientCallback, installCnt = 2)
        val linkAddress = LinkAddress(InetAddress.getByAddress(hostIpv4Address), 24)
        val lp = LinkProperties()
        lp.addLinkAddress(linkAddress)
        apfFilter.setLinkProperties(lp)
        val program = consumeInstalledProgram(ipClientCallback, installCnt = 1)
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
        doReturn(listOf<ByteArray>()).`when`(dependencies).getAnycast6Addresses(any())
        val apfFilter = getApfFilter()
        // validate NS packet check when there is no IPv6 address
        val program = consumeInstalledProgram(ipClientCallback, installCnt = 2)
        // Using scapy to generate IPv6 NS packet:
        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=255)
        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
        // pkt = eth/ip6/icmp6
        val nsPkt = """
            01020304050600010203040586DD6000000000183AFF200100000000000
            00200001A1122334420010000000000000200001A334411228700452900
            00000020010000000000000200001A33441122
        """.replace("\\s+".toRegex(), "").trim()
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
        consumeInstalledProgram(ipClientCallback, installCnt = 2)
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
        consumeInstalledProgram(ipClientCallback, installCnt = 1)
        apfFilter.updateClatInterfaceState(true)
        val program = consumeInstalledProgram(ipClientCallback, installCnt = 1)

        // validate Ethernet dst address check
        // Using scapy to generate IPv6 NS packet:
        // eth = Ether(src="00:01:02:03:04:05", dst="00:05:04:03:02:01")
        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="2001::200:1a:3344:1122", hlim=255)
        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
        // icmp6_opt = ICMPv6NDOptDstLLAddr(lladdr="00:01:02:03:04:05")
        // pkt = eth/ip6/icmp6/icmp6_opt
        val nonHostDstMacNsPkt = """
            00050403020100010203040586DD6000000000203AFF2001000000000000
            0200001A1122334420010000000000000200001A3344112287003D170000
            000020010000000000000200001A334411220201000102030405
        """.replace("\\s+".toRegex(), "").trim()
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
        val nonMcastDstMacNsPkt = """
            3333FF03020100010203040586DD6000000000203AFF20010000000000
            000200001A1122334420010000000000000200001A3344112287003D17
            0000000020010000000000000200001A334411220201000102030405
        """.replace("\\s+".toRegex(), "").trim()
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
        val hostMcastDstMacNsPkt = """
            3333FF44112200010203040586DD6000000000203AFF20010000000000
            000200001A1122334420010000000000000200001A3344112287003E17
            0000000020010000000000000200001A334411220101000102030405
        """.replace("\\s+".toRegex(), "").trim()
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
        val broadcastNsPkt = """
            FFFFFFFFFFFF00010203040586DD6000000000203AFF200100000000000002000
            01A1122334420010000000000000200001A3344112287003E1700000000200100
            00000000000200001A334411220101000102030405
        """.replace("\\s+".toRegex(), "").trim()
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
        val validHostDstIpNsPkt = """
            02030405060700010203040586DD6000000000203AFF200100000000000
            00200001A1122334420010000000000000200001A3344112287003E1700
            00000020010000000000000200001A334411220101000102030405
        """.replace("\\s+".toRegex(), "").trim()
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
        val validHostAnycastDstIpNsPkt = """
            02030405060700010203040586DD6000000000203AFF20010000
            000000000200001A1122334420010000000000000100001BAABB
            CCDD8700D9AE0000000020010000000000000100001BAABBCCDD
            0101000102030405
        """.replace("\\s+".toRegex(), "").trim()
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
        val nonHostUcastDstIpNsPkt = """
            02030405060700010203040586DD6000000000203AFF2001000000000
            0000200001A1122334420010000000000000200001A444455558700E8
            E30000000020010000000000000200001A334411220101000102030405
        """.replace("\\s+".toRegex(), "").trim()
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
        val nonHostMcastDstIpNsPkt = """
            02030405060700010203040586DD6000000000203AFF2001000000000
            0000200001A11223344FF0200000000000000000001FF441133870095
            1C0000000020010000000000000200001A334411220101000102030405
        """.replace("\\s+".toRegex(), "").trim()
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
        val shortNsPkt = """
            02030405060700010203040586DD6000000000143AFF20010000000000000200001A1
            122334420010000000000000200001A3344112287003B140000000020010000000000
            000200001A334411220101010203040506
        """.replace("\\s+".toRegex(), "").trim()
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
        val otherHostNsPkt = """
            02030405060700010203040586DD6000000000203AFF200100000000000002000
            01A1122334420010000000000000200001A334411228700E5E000000000200100
            00000000000200001A444455550101010203040506
        """.replace("\\s+".toRegex(), "").trim()
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
        val invalidHoplimitNsPkt = """
            02030405060700010203040586DD6000000000203A14200100000000000
            00200001A1122334420010000000000000200001A3344112287003B1400
            00000020010000000000000200001A334411220101010203040506
        """.replace("\\s+".toRegex(), "").trim()
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
        val invalidIcmpCodeNsPkt = """
            02030405060700010203040586DD6000000000203AFF200100000000000
            00200001A1122334420010000000000000200001A3344112287053B0F00
            00000020010000000000000200001A334411220101010203040506
        """.replace("\\s+".toRegex(), "").trim()
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
        val tentativeTargetIpNsPkt = """
            02030405060700010203040586DD6000000000203AFF200100000000
            00000200001A1122334420010000000000000200001A334411228700
            16CE0000000020010000000000000200001A123456780101010203040506
        """.replace("\\s+".toRegex(), "").trim()
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
        val invalidTargetIpNsPkt = """
            02030405060700010203040586DD6000000000203AFF200100000000000
            00200001A1122334420010000000000000200001A334411228700F6BC00
            00000020010000000000000200001C225566660101010203040506
        """.replace("\\s+".toRegex(), "").trim()
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
        val dadNsPkt = """
            02030405060700010203040586DD6000000000203AFF000000000000000000000000000
            00000FF0200000000000000000001FF4411228700F4A800000000200100000000000002
            00001A334411220201020304050607
        """.replace("\\s+".toRegex(), "").trim()
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
        val noOptionNsPkt = """
            02030405060700010203040586DD6000000000183AFF2001000000000000020000
            1A1122334420010000000000000200001A33441122870045290000000020010000
            000000000200001A33441122
        """.replace("\\s+".toRegex(), "").trim()
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
        val nonDadMcastSrcIpPkt = """
            02030405060700010203040586DD6000000000203AFFFF01000000000000
            0200001A1122334420010000000000000200001A3344112287005C130000
            000020010000000000000200001A334411220101010203040506
        """.replace("\\s+".toRegex(), "").trim()
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
        val nonDadLoopbackSrcIpPkt = """
            02030405060700010203040586DD6000000000203AFF0001000000000
            0000200001A1122334420010000000000000200001A3344112287005B
            140000000020010000000000000200001A334411220101010203040506
        """.replace("\\s+".toRegex(), "").trim()
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
        val sllaNotFirstOptionNsPkt = """
            02030405060700010203040586DD6000000000283AFF200100000000
            00000200001A1122334420010000000000000200001A334411228700
            2FFF0000000020010000000000000200001A33441122020101020304
            05060101010203040506
        """.replace("\\s+".toRegex(), "").trim()
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
        val noSllaOptionNsPkt = """
            02030405060700010203040586DD6000000000203AFF200100000000000002
            00001A1122334420010000000000000200001A3344112287003A1400000000
            20010000000000000200001A334411220201010203040506
        """.replace("\\s+".toRegex(), "").trim()
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
        val mcastMacSllaOptionNsPkt = """
            02030405060700010203040586DD6000000000203AFF200100000000
            00000200001A1122334420010000000000000200001A334411228700
            3B140000000020010000000000000200001A33441122010101020304
            0506
        """.replace("\\s+".toRegex(), "").trim()
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
        val program = consumeInstalledProgram(ipClientCallback, installCnt = 3)
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
        doReturn(20).`when`(dependencies).getNdTrafficClass(any())
        val apfFilter = getApfFilter()
        val lp = LinkProperties()
        for (addr in hostIpv6Addresses) {
            lp.addLinkAddress(LinkAddress(InetAddress.getByAddress(addr), 64))
        }
        apfFilter.setLinkProperties(lp)
        val program = consumeInstalledProgram(ipClientCallback, installCnt = 3)
        // Using scapy to generate IPv6 NS packet:
        // eth = Ether(src="00:01:02:03:04:05", dst="02:03:04:05:06:07")
        // ip6 = IPv6(src="2001::200:1a:1122:3344", dst="ff02::1:ff44:1122", hlim=255, tc=20)
        // icmp6 = ICMPv6ND_NS(tgt="2001::200:1a:3344:1122")
        // icmp6_opt = ICMPv6NDOptSrcLLAddr(lladdr="00:01:02:03:04:05")
        // pkt = eth/ip6/icmp6/icmp6_opt
        val hostMcastDstIpNsPkt = """
            02030405060700010203040586DD6140000000203AFF2001000000000000
            0200001A11223344FF0200000000000000000001FF4411228700952D0000
            000020010000000000000200001A334411220101000102030405
        """.replace("\\s+".toRegex(), "").trim()
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
        val expectedNaPacket = """
            00010203040502030405060786DD6140000000203AFF2001000000000000020
            0001A3344112220010000000000000200001A1122334488005610E000000020
            010000000000000200001A334411220201020304050607
        """.replace("\\s+".toRegex(), "").trim()
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
        val program = consumeInstalledProgram(ipClientCallback, installCnt = 3)
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

    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    @Test
    fun testRegisterOffloadEngine() {
        val apfConfig = getDefaultConfig()
        apfConfig.shouldHandleMdnsOffload = true
        val apfFilter = getApfFilter(apfConfig)
        val captor = ArgumentCaptor.forClass(OffloadEngine::class.java)
        verify(nsdManager).registerOffloadEngine(
                eq(ifParams.name),
                anyLong(),
                anyLong(),
                any(),
                captor.capture()
        )
        val offloadEngine = captor.value
        val info1 = OffloadServiceInfo(
                OffloadServiceInfo.Key("TestServiceName", "_advertisertest._tcp"),
                listOf(),
                "Android_test.local",
                byteArrayOf(0x01, 0x02, 0x03, 0x04),
                0,
                OffloadEngine.OFFLOAD_TYPE_REPLY.toLong()
        )
        val info2 = OffloadServiceInfo(
                OffloadServiceInfo.Key("TestServiceName2", "_advertisertest._tcp"),
                listOf(),
                "Android_test.local",
                byteArrayOf(0x01, 0x02, 0x03, 0x04),
                0,
                OffloadEngine.OFFLOAD_TYPE_REPLY.toLong()
        )
        val updatedInfo1 = OffloadServiceInfo(
                OffloadServiceInfo.Key("TestServiceName", "_advertisertest._tcp"),
                listOf(),
                "Android_test.local",
                byteArrayOf(),
                0,
                OffloadEngine.OFFLOAD_TYPE_REPLY.toLong()
        )
        handler.post { offloadEngine.onOffloadServiceUpdated(info1) }
        handlerThread.waitForIdle(TIMEOUT_MS)
        assertContentEquals(listOf(info1), apfFilter.mOffloadServiceInfos)
        handler.post { offloadEngine.onOffloadServiceUpdated(info2) }
        handlerThread.waitForIdle(TIMEOUT_MS)
        assertContentEquals(listOf(info1, info2), apfFilter.mOffloadServiceInfos)
        handler.post { offloadEngine.onOffloadServiceUpdated(updatedInfo1) }
        handlerThread.waitForIdle(TIMEOUT_MS)
        assertContentEquals(listOf(info2, updatedInfo1), apfFilter.mOffloadServiceInfos)
        handler.post { offloadEngine.onOffloadServiceRemoved(updatedInfo1) }
        handlerThread.waitForIdle(TIMEOUT_MS)
        assertContentEquals(listOf(info2), apfFilter.mOffloadServiceInfos)

        handler.post { apfFilter.shutdown() }
        handlerThread.waitForIdle(TIMEOUT_MS)
        verify(nsdManager).unregisterOffloadEngine(any())
    }

    @Test
    fun testApfProgramUpdate() {
        val apfFilter = getApfFilter()
        consumeInstalledProgram(ipClientCallback, installCnt = 2)
        // add IPv4 address, expect to have apf program update
        val lp = LinkProperties()
        val linkAddress = LinkAddress(InetAddress.getByAddress(hostIpv4Address), 24)
        lp.addLinkAddress(linkAddress)
        apfFilter.setLinkProperties(lp)
        consumeInstalledProgram(ipClientCallback, installCnt = 1)

        // add the same IPv4 address, expect to have no apf program update
        apfFilter.setLinkProperties(lp)
        verify(ipClientCallback, never()).installPacketFilter(any())

        // add IPv6 addresses, expect to have apf program update
        for (addr in hostIpv6Addresses) {
            lp.addLinkAddress(LinkAddress(InetAddress.getByAddress(addr), 64))
        }

        apfFilter.setLinkProperties(lp)
        consumeInstalledProgram(ipClientCallback, installCnt = 1)

        // add the same IPv6 addresses, expect to have no apf program update
        apfFilter.setLinkProperties(lp)
        verify(ipClientCallback, never()).installPacketFilter(any())

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
        consumeInstalledProgram(ipClientCallback, installCnt = 1)

        // add the same IPv6 addresses, expect to have no apf program update
        apfFilter.setLinkProperties(lp)
        verify(ipClientCallback, never()).installPacketFilter(any())
    }

    @Test
    fun testApfFilterInitializationCleanUpTheApfMemoryRegion() {
        val apfFilter = getApfFilter()
        val programCaptor = ArgumentCaptor.forClass(ByteArray::class.java)
        verify(ipClientCallback, times(2)).installPacketFilter(programCaptor.capture())
        val program = programCaptor.allValues.first()
        assertContentEquals(ByteArray(4096) { 0 }, program)
    }

    @Test
    fun testApfFilterResumeWillCleanUpTheApfMemoryRegion() {
        val apfFilter = getApfFilter()
        consumeInstalledProgram(ipClientCallback, installCnt = 2)
        apfFilter.resume()
        val program = consumeInstalledProgram(ipClientCallback, installCnt = 1)
        assertContentEquals(ByteArray(4096) { 0 }, program)
    }
}
