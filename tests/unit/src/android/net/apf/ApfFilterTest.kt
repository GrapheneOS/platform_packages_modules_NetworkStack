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
import android.net.InetAddresses
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
import android.net.apf.ApfCounterTracker.Counter.DROPPED_IGMP_INVALID
import android.net.apf.ApfCounterTracker.Counter.DROPPED_IGMP_REPORT
import android.net.apf.ApfCounterTracker.Counter.DROPPED_IGMP_V2_GENERAL_QUERY_REPLIED
import android.net.apf.ApfCounterTracker.Counter.DROPPED_IGMP_V3_GENERAL_QUERY_REPLIED
import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_BROADCAST_ADDR
import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_BROADCAST_NET
import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_ICMP_INVALID
import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_KEEPALIVE_ACK
import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_L2_BROADCAST
import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_MULTICAST
import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_NATT_KEEPALIVE
import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_NON_DHCP4
import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_PING_REQUEST_REPLIED
import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_TCP_PORT7_UNICAST
import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_MULTICAST_NA
import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_NON_ICMP_MULTICAST
import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_NS_INVALID
import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_NS_OTHER_HOST
import android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_NS_REPLIED_NON_DAD
import android.net.apf.ApfCounterTracker.Counter.DROPPED_MDNS
import android.net.apf.ApfCounterTracker.Counter.DROPPED_MDNS_INVALID
import android.net.apf.ApfCounterTracker.Counter.DROPPED_MDNS_REPLIED
import android.net.apf.ApfCounterTracker.Counter.PASSED_ARP_BROADCAST_REPLY
import android.net.apf.ApfCounterTracker.Counter.PASSED_ARP_REQUEST
import android.net.apf.ApfCounterTracker.Counter.PASSED_ARP_UNICAST_REPLY
import android.net.apf.ApfCounterTracker.Counter.PASSED_DHCP
import android.net.apf.ApfCounterTracker.Counter.PASSED_ETHER_OUR_SRC_MAC
import android.net.apf.ApfCounterTracker.Counter.PASSED_IPV4
import android.net.apf.ApfCounterTracker.Counter.PASSED_IPV4_FROM_DHCPV4_SERVER
import android.net.apf.ApfCounterTracker.Counter.PASSED_IPV4_UNICAST
import android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_ICMP
import android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_NON_ICMP
import android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_NS_DAD
import android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_NS_NO_ADDRESS
import android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_NS_NO_SLLA_OPTION
import android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_NS_TENTATIVE
import android.net.apf.ApfCounterTracker.Counter.PASSED_MDNS
import android.net.apf.ApfCounterTracker.Counter.PASSED_MLD
import android.net.apf.ApfFilter.Dependencies
import android.net.apf.ApfTestHelpers.Companion.TIMEOUT_MS
import android.net.apf.ApfTestHelpers.Companion.consumeInstalledProgram
import android.net.apf.ApfTestHelpers.Companion.consumeTransmittedPackets
import android.net.apf.ApfTestHelpers.Companion.verifyProgramRun
import android.net.apf.BaseApfGenerator.APF_VERSION_3
import android.net.apf.BaseApfGenerator.APF_VERSION_6
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
import com.android.testutils.visibleOnHandlerThread
import com.android.testutils.waitForIdle
import java.io.FileDescriptor
import java.net.Inet4Address
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
        private const val NO_CALLBACK_TIMEOUT_MS: Long = 500
        private const val TAG = "ApfFilterTest"
    }

    @get:Rule
    val ignoreRule = DevSdkIgnoreRule()

    @Mock
    private lateinit var context: Context

    @Mock private lateinit var metrics: NetworkQuirkMetrics

    @Mock private lateinit var dependencies: Dependencies

    @Mock private lateinit var apfController: ApfFilter.IApfController
    @Mock private lateinit var nsdManager: NsdManager

    @GuardedBy("mApfFilterCreated")
    private val mApfFilterCreated = ArrayList<ApfFilter>()
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
    private val hostLinkLocalIpv6Address = InetAddresses.parseNumericAddress("fe80::3")
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

    // Using scapy to generate payload:
    // answers = [
    //    DNSRR(rrname="_googlecast._tcp.local", type="PTR", ttl=120, rdata="gambit-3cb56c6253638b3641e3d289013cc0ae._googlecast._tcp.local."),
    //    DNSRR(rrname="gambit-3cb56c6253638b3641e3d289013cc0ae._googlecast._tcp.local", type="SRV", ttl=120, rdata="0 0 8009 3cb56c62-5363-8b36-41e3-d289013cc0ae.local."),
    //    DNSRR(rrname="gambit-3cb56c6253638b3641e3d289013cc0ae._googlecast._tcp.local", type="TXT", ttl=120, rdata=' "id=3cb56c6253638b3641e3d289013cc0ae cd=8ECC37F6755390D005DFC02F8EC0D4FA rm=4ABD579644ACFCCF ve=05 md=gambit ic=/setup/icon.png fn=gambit a=264709 st=0 bs=FA8FFD2242A7 nf=1 rs= ',),
    //    DNSRR(rrname="Android_f47ac10b58cc4b88bc3f5e7a81e59872.local", type="A", ttl=120, rdata="100.89.85.228"),
    //    DNSRR(rrname="Android_f47ac10b58cc4b88bc3f5e7a81e59872.local", type="AAAA", ttl=120, rdata="fe80:0000:0000:0000:0000:0000:0000:0003"),
    //    DNSRR(rrname="Android_f47ac10b58cc4b88bc3f5e7a81e59872.local", type="AAAA", ttl=120, rdata="200a:0000:0000:0000:0000:0000:0000:0003"),
    //    DNSRR(rrname="Android_f47ac10b58cc4b88bc3f5e7a81e59872.local", type="AAAA", ttl=120, rdata="200b:0000:0000:0000:0000:0000:0000:0003"),
    // ]
    // dns = dns_compress(DNS(qr=1, aa=1, rd=0, qd=None, an=answers))
    private val castOffloadPayload = """
            0000840000000007000000000b5f676f6f676c6563617374045f746370056c6
            f63616c00000c000100000078002a2767616d6269742d336362353663363235
            3336333862333634316533643238393031336363306165c00c01c0000021000
            100000078003430203020383030392033636235366336322d353336332d3862
            33362d343165332d6432383930313363633061652e6c6f63616c2e01c000001
            000010000007800b3b2202269643d3363623536633632353336333862333634
            3165336432383930313363633061652063643d3845434333374636373535333
            93044303035444643303246384543304434464120726d3d3441424435373936
            34344143464343462076653d3035206d643d67616d6269742069633d2f73657
            475702f69636f6e2e706e6720666e3d67616d62697420613d32363437303920
            73743d302062733d464138464644323234324137206e663d312072733d20284
            16e64726f69645f663437616331306235386363346238386263336635653761
            3831653539383732c01d00010001000000780004645955e4c157001c0001000
            000780010fe800000000000000000000000000003c157001c00010000007800
            10200a0000000000000000000000000003c157001c0001000000780010200b0
            000000000000000000000000003
        """.replace("\\s+".toRegex(), "").trim()

    // Using scapy to generate payload:
    // answers = [
    //    DNSRR(rrname="_androidtvremote2._tcp.local", type="PTR", rdata="gambit._androidtvremote2._tcp.local", ttl=120),
    //    DNSRR(rrname="gambit._androidtvremote2._tcp.local", type="SRV", rdata="0 0 6466 Android_2570595cc11d4af4a4b7146b946eeb9e.local", ttl=120),
    //    DNSRR(rrname="gambit._androidtvremote2._tcp.local", type="TXT", rdata='''"bt=3C:4E:56:76:1E:E9"''', ttl=120),
    //    DNSRR(rrname="Android_f47ac10b58cc4b88bc3f5e7a81e59872.local", type="A", ttl=120, rdata="100.89.85.228"),
    //    DNSRR(rrname="Android_f47ac10b58cc4b88bc3f5e7a81e59872.local", type="AAAA", ttl=120, rdata="fe80:0000:0000:0000:0000:0000:0000:0003"),
    //    DNSRR(rrname="Android_f47ac10b58cc4b88bc3f5e7a81e59872.local", type="AAAA", ttl=120, rdata="200a:0000:0000:0000:0000:0000:0000:0003"),
    //    DNSRR(rrname="Android_f47ac10b58cc4b88bc3f5e7a81e59872.local", type="AAAA", ttl=120, rdata="200b:0000:0000:0000:0000:0000:0000:0003"),
    // ]
    // dns = dns_compress(DNS(qr=1, aa=1, rd=0, qd=None, an=answers))
    val tvRemoteOffloadPayload = """
            000084000000000700000000115f616e64726f6964747672656d6f746532045
            f746370056c6f63616c00000c00010000007800090667616d626974c00cc034
            00210001000000780037302030203634363620416e64726f69645f323537303
            53935636331316434616634613462373134366239343665656239652e6c6f63
            616cc03400100001000000780017162262743d33433a34453a35363a37363a3
            1453a45392228416e64726f69645f6634376163313062353863633462383862
            633366356537613831653539383732c02300010001000000780004645955e4c
            0a3001c0001000000780010fe800000000000000000000000000003c0a3001c
            0001000000780010200a0000000000000000000000000003c0a3001c0001000
            000780010200b0000000000000000000000000003
        """.replace("\\s+".toRegex(), "").trim()

    private val handlerThread by lazy {
        HandlerThread("$TAG handler thread").apply { start() }
    }
    private val handler by lazy { Handler(handlerThread.looper) }
    private var writerSocket = FileDescriptor()
    private var igmpWriteSocket = FileDescriptor()

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
        val igmpReadSocket = FileDescriptor()
        Os.socketpair(AF_UNIX, SOCK_STREAM, 0, igmpWriteSocket, igmpReadSocket)
        doReturn(igmpReadSocket).`when`(dependencies).createEgressIgmpReportsReaderSocket(anyInt())
        doReturn(nsdManager).`when`(context).getSystemService(NsdManager::class.java)
    }

    private fun shutdownApfFilters() {
        quitResources(THREAD_QUIT_MAX_RETRY_COUNT, {
            synchronized(mApfFilterCreated) {
                val ret = ArrayList(mApfFilterCreated)
                mApfFilterCreated.clear()
                return@quitResources ret
            }
        }, { apf: ApfFilter ->
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
        IoUtils.closeQuietly(igmpWriteSocket)
        shutdownApfFilters()
        handler.waitForIdle(TIMEOUT_MS)
        Mockito.framework().clearInlineMocks()
        ApfTestHelpers.resetTransmittedPacketMemory()
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
        config.handleArpOffload = true
        config.handleNdOffload = true
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
                    apfController,
                    metrics,
                    dependencies
            )
        }
        handlerThread.waitForIdle(TIMEOUT_MS)
        return apfFilter
    }

    private fun getIgmpApfFilter(): ApfFilter {
        val mcastAddrs = listOf(
            InetAddress.getByName("224.0.0.1") as Inet4Address,
            InetAddress.getByName("239.0.0.1") as Inet4Address,
            InetAddress.getByName("239.0.0.2") as Inet4Address,
            InetAddress.getByName("239.0.0.3") as Inet4Address
        )
        val apfConfig = getDefaultConfig()
        apfConfig.handleIgmpOffload = true

        // mock IPv4 multicast address from /proc/net/igmp
        doReturn(mcastAddrs).`when`(dependencies).getIPv4MulticastAddresses(any())
        val apfFilter = getApfFilter(apfConfig)
        val linkAddress = LinkAddress(InetAddress.getByAddress(hostIpv4Address), 24)
        val lp = LinkProperties()
        lp.addLinkAddress(linkAddress)
        apfFilter.setLinkProperties(lp)
        return apfFilter
    }

    private fun doTestEtherTypeAllowListFilter(apfFilter: ApfFilter) {
        val program = consumeInstalledProgram(apfController, installCnt = 2)

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
        val program = consumeInstalledProgram(apfController, installCnt = 3)

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
        val program = consumeInstalledProgram(apfController, installCnt = 2)
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

    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    @Test
    fun testInvalidIgmpPacketDropped() {
        val apfFilter = getIgmpApfFilter()
        val program = consumeInstalledProgram(apfController, installCnt = 3)
        // Using scapy to generate invalid length IGMPv1 general query packet:
        //   ether = Ether(src='00:11:22:33:44:55', dst='01:00:5e:00:00:01')
        //   ip = IP(src='10.0.0.2', dst='224.0.0.1', len=24, proto=2)
        //   payload = Raw(b'\x11\x00\xee\xff\x01\x02\x03\x04\x05\x06')
        //   pkt = ether/ip/payload
        val payloadLen10Pkt = """
            01005e00000100112233445508004500001800010000400290e00a000002e00000011100eeff010203040506
        """.replace("\\s+".toRegex(), "").trim()

        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(payloadLen10Pkt),
            DROPPED_IGMP_INVALID
        )

        // Using scapy to generate invalid length IGMPv1 general query packet:
        //   ether = Ether(src='00:11:22:33:44:55', dst='01:00:5e:00:00:01')
        //   ip = IP(src='10.0.0.2', dst='224.0.0.1', len=20, proto=2)
        //   payload = Raw(b'\x11\x00\xee\xff\x01\x02')
        //   pkt = ether/ip/payload
        val payloadLen7Pkt = """
            01005e00000100112233445508004500001400010000400290e40a000002e00000011100eeff010203
        """.replace("\\s+".toRegex(), "").trim()

        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(payloadLen7Pkt),
            DROPPED_IGMP_INVALID
        )

        // Using scapy to generate invalid length IGMP general query which the destination IP is
        // not 224.0.0.1:
        //   ether = Ether(src='00:11:22:33:44:55', dst='01:00:5e:00:00:05')
        //   ip = IP(src='10.0.0.2', dst='224.0.0.5')
        //   igmp = IGMP(type=0x11, mrcode=0)
        //   pkt = ether/ip/igmp
        val pktWithWrongDst = """
            01005e00000300112233445508004500001c000100000102cfda0a000002e00000031100eeff00000000
        """.replace("\\s+".toRegex(), "").trim()

        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(pktWithWrongDst),
            DROPPED_IGMP_INVALID
        )

        // Using scapy to generate invalid IGMP general query with wrong type:
        //   ether = Ether(src='00:11:22:33:44:55', dst='01:00:5e:00:00:01')
        //   ip = IP(src='10.0.0.2', dst='224.0.0.1')
        //   igmp = IGMP(type=0x51, mrcode=0)
        //   pkt = ether/ip/igmp
        val pktWithWrongType = """
            01005e00000100112233445508004500001c000100000102cfdc0a000002e00000015100aeff00000000
        """.replace("\\s+".toRegex(), "").trim()

        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(pktWithWrongType),
            DROPPED_IGMP_INVALID
        )
    }

    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    @Test
    fun testIgmpV1ReportDropped() {
        val apfFilter = getIgmpApfFilter()
        val program = consumeInstalledProgram(apfController, installCnt = 3)
        // Using scapy to generate IGMPv1 report packet:
        //   ether = Ether(src='00:11:22:33:44:55', dst='01:00:5e:7f:00:01')
        //   ip = IP(src='10.0.0.2', dst='239.0.0.1')
        //   igmp = IGMP(type=0x12, mrcode=0, gaddr='239.0.0.1')
        //   pkt = ether/ip/igmp
        val pkt = """
            01005e7f000100112233445508004500001c000100000102c0dc0a000002ef0000011200fefdef000001
        """.replace("\\s+".toRegex(), "").trim()

        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(pkt),
            DROPPED_IGMP_REPORT
        )
    }

    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    @Test
    fun testIgmpV1GeneralQueryPassed() {
        val apfFilter = getIgmpApfFilter()
        val program = consumeInstalledProgram(apfController, installCnt = 3)
        // Using scapy to generate IGMPv1 general query packet:
        //   ether = Ether(src='00:11:22:33:44:55', dst='01:00:5e:00:00:01')
        //   ip = IP(src='10.0.0.2', dst='224.0.0.1')
        //   igmp = IGMP(type=0x11, mrcode=0)
        //   pkt = ether/ip/igmp
        val pkt = """
            01005e00000100112233445508004500001c000100000102cfdc0a000002e00000011100eeff00000000
        """.replace("\\s+".toRegex(), "").trim()

        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(pkt),
            PASSED_IPV4
        )
    }

    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    @Test
    fun testIgmpV2ReportDropped() {
        val apfFilter = getIgmpApfFilter()
        val program = consumeInstalledProgram(apfController, installCnt = 3)
        // Using scapy to generate IGMPv2 report packet:
        //   ether = Ether(src='00:11:22:33:44:55', dst='01:00:5e:7f:00:01')
        //   ip = IP(src='10.0.0.2', dst='239.0.0.1')
        //   igmp = IGMP(type=0x16, gaddr='239.0.0.1')
        //   pkt = ether/ip/igmp
        val v2ReportPkt = """
            01005e7f000100112233445508004500001c000100000102c0dc0a000002ef0000011614fae9ef000001
        """.replace("\\s+".toRegex(), "").trim()

        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(v2ReportPkt),
            DROPPED_IGMP_REPORT
        )

        // Using scapy to generate IGMPv2 leave packet:
        //   ether = Ether(src='00:11:22:33:44:55', dst='01:00:5e:7f:00:01')
        //   ip = IP(src='10.0.0.2', dst='239.0.0.1')
        //   igmp = IGMP(type=0x17, gaddr='239.0.0.1')
        //   pkt = ether/ip/igmp
        val v2LeaveReportPkt = """
            01005e7f000100112233445508004500001c000100000102c0dc0a000002ef0000011714f9e9ef000001
        """.replace("\\s+".toRegex(), "").trim()

        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(v2LeaveReportPkt),
            DROPPED_IGMP_REPORT
        )
    }

    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    @Test
    fun testIgmpV2GeneralQueryReplied() {
        val apfFilter = getIgmpApfFilter()
        val program = consumeInstalledProgram(apfController, installCnt = 3)
        // Using scapy to generate IGMPv2 general query packet without router alert option:
        //   ether = Ether(src='00:11:22:33:44:55', dst='01:00:5e:00:00:01')
        //   ip = IP(src='10.0.0.2', dst='224.0.0.1')
        //   igmp = IGMP(type=0x11)
        //   pkt = ether/ip/igmp
        val pkt = """
            01005e00000100112233445508004500001c000100000102cfdc0a000002e00000011114eeeb00000000
        """.replace("\\s+".toRegex(), "").trim()

        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(pkt),
            DROPPED_IGMP_V2_GENERAL_QUERY_REPLIED
        )

        val igmpv2ReportPkts = setOf(
            // ###[ Ethernet ]###
            //   dst       = 01:00:5e:00:00:01
            //   src       = 02:03:04:05:06:07
            //   type      = IPv4
            // ###[ IP ]###
            //      version   = 4
            //      ihl       = 6
            //      tos       = 0xc0
            //      len       = 32
            //      id        = 0
            //      flags     = DF
            //      frag      = 0
            //      ttl       = 1
            //      proto     = igmp
            //      chksum    = 0xeb15
            //      src       = 10.0.0.1
            //      dst       = 239.0.0.1
            //      \options   \
            //       |###[ IP Option Router Alert ]###
            //       |  copy_flag = 1
            //       |  optclass  = control
            //       |  option    = router_alert
            //       |  length    = 4
            //       |  alert     = router_shall_examine_packet
            // ###[ IGMP ]###
            //         type      = Version 2 - Membership Report
            //         mrcode    = 0
            //         chksum    = 0xfafd
            //         gaddr     = 239.0.0.1
            """
            01005e000001020304050607080046c00020000040000102eb150a000001ef000001940400001600fafd
            ef000001
            """.replace("\\s+".toRegex(), "").trim().uppercase(),

            // ###[ Ethernet ]###
            //   dst       = 01:00:5e:00:00:02
            //   src       = 02:03:04:05:06:07
            //   type      = IPv4
            // ###[ IP ]###
            //      version   = 4
            //      ihl       = 6
            //      tos       = 0xc0
            //      len       = 32
            //      id        = 0
            //      flags     = DF
            //      frag      = 0
            //      ttl       = 1
            //      proto     = igmp
            //      chksum    = 0xeb14
            //      src       = 10.0.0.1
            //      dst       = 239.0.0.2
            //      \options   \
            //       |###[ IP Option Router Alert ]###
            //       |  copy_flag = 1
            //       |  optclass  = control
            //       |  option    = router_alert
            //       |  length    = 4
            //       |  alert     = router_shall_examine_packet
            // ###[ IGMP ]###
            //         type      = Version 2 - Membership Report
            //         mrcode    = 0
            //         chksum    = 0xfafc
            //         gaddr     = 239.0.0.2
            """
            01005e000002020304050607080046c00020000040000102eb140a000001ef000002940400001600fafc
            ef000002
            """.replace("\\s+".toRegex(), "").trim().uppercase(),
            // ###[ Ethernet ]###
            //   dst       = 01:00:5e:00:00:03
            //   src       = 02:03:04:05:06:07
            //   type      = IPv4
            // ###[ IP ]###
            //      version   = 4
            //      ihl       = 6
            //      tos       = 0xc0
            //      len       = 32
            //      id        = 0
            //      flags     = DF
            //      frag      = 0
            //      ttl       = 1
            //      proto     = igmp
            //      chksum    = 0xeb13
            //      src       = 10.0.0.1
            //      dst       = 239.0.0.3
            //      \options   \
            //       |###[ IP Option Router Alert ]###
            //       |  copy_flag = 1
            //       |  optclass  = control
            //       |  option    = router_alert
            //       |  length    = 4
            //       |  alert     = router_shall_examine_packet
            // ###[ IGMP ]###
            //         type      = Version 2 - Membership Report
            //         mrcode    = 0
            //         chksum    = 0xfafb
            //         gaddr     = 239.0.0.3
            """
            01005e000003020304050607080046c00020000040000102eb130a000001ef000003940400001600fafb
            ef000003
            """.replace("\\s+".toRegex(), "").trim().uppercase()
        )

        val transmitPackets = ApfTestHelpers.getAllTransmittedPackets()
            .map { HexDump.toHexString(it).uppercase() }.toSet()
        assertEquals(igmpv2ReportPkts, transmitPackets)
    }

    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    @Test
    fun testIgmpV2GeneralQueryWithRouterAlertOptionReplied() {
        val apfFilter = getIgmpApfFilter()
        val program = consumeInstalledProgram(apfController, installCnt = 3)
        // Using scapy to generate IGMPv2 general query packet with router alert option:
        //   ether = Ether(src='00:11:22:33:44:55', dst='01:00:5e:00:00:01')
        //   ip = IP(src='10.0.0.2', dst='224.0.0.1', options=[IPOption_Router_Alert()])
        //   igmp = IGMP(type=0x11)
        //   pkt = ether/ip/igmp
        val pkt = """
            01005e0000010011223344550800460000200001000001023ad40a000002e0000001940400001114eeeb
            00000000
        """.replace("\\s+".toRegex(), "").trim()

        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(pkt),
            DROPPED_IGMP_V2_GENERAL_QUERY_REPLIED
        )

        val igmpv2ReportPkts = setOf(
            // ###[ Ethernet ]###
            //   dst       = 01:00:5e:00:00:01
            //   src       = 02:03:04:05:06:07
            //   type      = IPv4
            // ###[ IP ]###
            //      version   = 4
            //      ihl       = 6
            //      tos       = 0xc0
            //      len       = 32
            //      id        = 0
            //      flags     = DF
            //      frag      = 0
            //      ttl       = 1
            //      proto     = igmp
            //      chksum    = 0xeb15
            //      src       = 10.0.0.1
            //      dst       = 239.0.0.1
            //      \options   \
            //       |###[ IP Option Router Alert ]###
            //       |  copy_flag = 1
            //       |  optclass  = control
            //       |  option    = router_alert
            //       |  length    = 4
            //       |  alert     = router_shall_examine_packet
            // ###[ IGMP ]###
            //         type      = Version 2 - Membership Report
            //         mrcode    = 0
            //         chksum    = 0xfafd
            //         gaddr     = 239.0.0.1
            """
            01005e000001020304050607080046c00020000040000102eb150a000001ef000001940400001600fafd
            ef000001
            """.replace("\\s+".toRegex(), "").trim().uppercase(),

            // ###[ Ethernet ]###
            //   dst       = 01:00:5e:00:00:02
            //   src       = 02:03:04:05:06:07
            //   type      = IPv4
            // ###[ IP ]###
            //      version   = 4
            //      ihl       = 6
            //      tos       = 0xc0
            //      len       = 32
            //      id        = 0
            //      flags     = DF
            //      frag      = 0
            //      ttl       = 1
            //      proto     = igmp
            //      chksum    = 0xeb14
            //      src       = 10.0.0.1
            //      dst       = 239.0.0.2
            //      \options   \
            //       |###[ IP Option Router Alert ]###
            //       |  copy_flag = 1
            //       |  optclass  = control
            //       |  option    = router_alert
            //       |  length    = 4
            //       |  alert     = router_shall_examine_packet
            // ###[ IGMP ]###
            //         type      = Version 2 - Membership Report
            //         mrcode    = 0
            //         chksum    = 0xfafc
            //         gaddr     = 239.0.0.2
            """
            01005e000002020304050607080046c00020000040000102eb140a000001ef000002940400001600fafc
            ef000002
            """.replace("\\s+".toRegex(), "").trim().uppercase(),

            // ###[ Ethernet ]###
            //   dst       = 01:00:5e:00:00:03
            //   src       = 02:03:04:05:06:07
            //   type      = IPv4
            // ###[ IP ]###
            //      version   = 4
            //      ihl       = 6
            //      tos       = 0xc0
            //      len       = 32
            //      id        = 0
            //      flags     = DF
            //      frag      = 0
            //      ttl       = 1
            //      proto     = igmp
            //      chksum    = 0xeb13
            //      src       = 10.0.0.1
            //      dst       = 239.0.0.3
            //      \options   \
            //       |###[ IP Option Router Alert ]###
            //       |  copy_flag = 1
            //       |  optclass  = control
            //       |  option    = router_alert
            //       |  length    = 4
            //       |  alert     = router_shall_examine_packet
            // ###[ IGMP ]###
            //         type      = Version 2 - Membership Report
            //         mrcode    = 0
            //         chksum    = 0xfafb
            //         gaddr     = 239.0.0.3
            """
            01005e000003020304050607080046c00020000040000102eb130a000001ef000003940400001600fafb
            ef000003
            """.replace("\\s+".toRegex(), "").trim().uppercase()
        )

        val transmitPackets = ApfTestHelpers.getAllTransmittedPackets()
            .map { HexDump.toHexString(it).uppercase() }.toSet()
        assertEquals(igmpv2ReportPkts, transmitPackets)
    }

    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    @Test
    fun testIgmpV2GroupSpecificQueryPassed() {
        val apfFilter = getIgmpApfFilter()
        val program = consumeInstalledProgram(apfController, installCnt = 3)
        // Using scapy to generate IGMPv2 group specific query packet without router alert option:
        //   ether = Ether(src='00:11:22:33:44:55', dst='01:00:5e:7f:00:01')
        //   ip = IP(src='10.0.0.2', dst='239.0.0.1')
        //   igmp = IGMP(type=0x11, gaddr='239.0.0.1')
        //   pkt = ether/ip/igmp
        val pkt = """
            01005e7f000100112233445508004500001c000100000102c0dc0a000002ef0000011114ffe9ef000001
        """.replace("\\s+".toRegex(), "").trim()

        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(pkt),
            PASSED_IPV4
        )
    }

    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    @Test
    fun testIgmpV3ReportDropped() {
        val apfFilter = getIgmpApfFilter()
        val program = consumeInstalledProgram(apfController, installCnt = 3)
        // Using scapy to generate IGMPv3 report packet without router alert option:
        //   ether = Ether(src='00:11:22:33:44:55', dst='01:00:5e:00:00:16')
        //   ip = IP(src='10.0.0.2', dst='224.0.0.22')
        //   igmp = IGMPv3(type=0x22)/IGMPv3mr(records=[IGMPv3gr(rtype=2, maddr='239.0.0.1')])
        //   pkt = ether/ip/igmp
        val pkt = """
            01005e000001001122334455080045c00024000100000102cf140a000002e00000012200ecfc000000
            0102000000ef000001
        """.replace("\\s+".toRegex(), "").trim()

        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(pkt),
            DROPPED_IGMP_REPORT
        )
    }

    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    @Test
    fun testIgmpV3GeneralQueryReplied() {
        val apfFilter = getIgmpApfFilter()
        val program = consumeInstalledProgram(apfController, installCnt = 3)
        // Using scapy to generate IGMPv3 general query packet without router alert option:
        //   ether = Ether(src='00:11:22:33:44:55', dst='01:00:5e:00:00:01')
        //   ip = IP(src='10.0.0.2', dst='224.0.0.1')
        //   igmp = IGMPv3(type=0x11)/IGMPv3mq()
        //   pkt = ether/ip/igmp
        val pkt = """
            01005e000001001122334455080045c00020000100000102cf180a000002e00000011114eeeb00000000
            00000000
        """.replace("\\s+".toRegex(), "").trim()

        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(pkt),
            DROPPED_IGMP_V3_GENERAL_QUERY_REPLIED
        )

        val transmittedIgmpv3Reports = consumeTransmittedPackets(1)

        // ###[ Ethernet ]###
        //   dst       = 01:00:5e:00:00:16
        //   src       = 02:03:04:05:06:07
        //   type      = IPv4
        // ###[ IP ]###
        //      version   = 4
        //      ihl       = 6
        //      tos       = 0xc0
        //      len       = 56
        //      id        = 0
        //      flags     = DF
        //      frag      = 0
        //      ttl       = 1
        //      proto     = igmp
        //      chksum    = 0xf9e8
        //      src       = 10.0.0.1
        //      dst       = 224.0.0.22
        //      \options   \
        //       |###[ IP Option Router Alert ]###
        //       |  copy_flag = 1
        //       |  optclass  = control
        //       |  option    = router_alert
        //       |  length    = 4
        //       |  alert     = router_shall_examine_packet
        // ###[ IGMPv3 ]###
        //         type      = Version 3 Membership Report
        //         mrcode    = 0
        //         chksum    = 0xaf4
        // ###[ IGMPv3mr ]###
        //            res2      = 0x0
        //            numgrp    = 3
        //            \records   \
        //             |###[ IGMPv3gr ]###
        //             |  rtype     = Mode Is Exclude
        //             |  auxdlen   = 0
        //             |  numsrc    = 0
        //             |  maddr     = 239.0.0.1
        //             |  srcaddrs  = []
        //             |###[ IGMPv3gr ]###
        //             |  rtype     = Mode Is Exclude
        //             |  auxdlen   = 0
        //             |  numsrc    = 0
        //             |  maddr     = 239.0.0.2
        //             |  srcaddrs  = []
        //             |###[ IGMPv3gr ]###
        //             |  rtype     = Mode Is Exclude
        //             |  auxdlen   = 0
        //             |  numsrc    = 0
        //             |  maddr     = 239.0.0.3
        //             |  srcaddrs  = []
        val igmpv3ReportPkt = """
            01005e000016020304050607080046c00038000040000102f9e80a000001e00000169404000022000af40
            000000302000000ef00000102000000ef00000202000000ef000003
        """.replace("\\s+".toRegex(), "").trim()

        assertContentEquals(
            HexDump.hexStringToByteArray(igmpv3ReportPkt),
            transmittedIgmpv3Reports[0]
        )
    }

    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    @Test
    fun testIgmpV3GeneralQueryWithRouterAlertOptionReplied() {
        val apfFilter = getIgmpApfFilter()
        val program = consumeInstalledProgram(apfController, installCnt = 3)
        // Using scapy to generate IGMPv3 general query packet with router alert option:
        //   ether = Ether(src='00:11:22:33:44:55', dst='01:00:5e:00:00:01')
        //   ip = IP(src='10.0.0.2', dst='224.0.0.1', options=[IPOption_Router_Alert()])
        //   igmp = IGMPv3(type=0x11)/IGMPv3mq()
        //   pkt = ether/ip/igmp
        val pkt = """
            01005e000001001122334455080046c000240001000001023a100a000002e0000001940400001114eeeb0
            000000000000000
        """.replace("\\s+".toRegex(), "").trim()

        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(pkt),
            DROPPED_IGMP_V3_GENERAL_QUERY_REPLIED
        )

        val transmittedIgmpv3Reports = consumeTransmittedPackets(1)

        // ###[ Ethernet ]###
        //   dst       = 01:00:5e:00:00:16
        //   src       = 02:03:04:05:06:07
        //   type      = IPv4
        // ###[ IP ]###
        //      version   = 4
        //      ihl       = 6
        //      tos       = 0xc0
        //      len       = 56
        //      id        = 0
        //      flags     = DF
        //      frag      = 0
        //      ttl       = 1
        //      proto     = igmp
        //      chksum    = 0xf9e8
        //      src       = 10.0.0.1
        //      dst       = 224.0.0.22
        //      \options   \
        //       |###[ IP Option Router Alert ]###
        //       |  copy_flag = 1
        //       |  optclass  = control
        //       |  option    = router_alert
        //       |  length    = 4
        //       |  alert     = router_shall_examine_packet
        // ###[ IGMPv3 ]###
        //         type      = Version 3 Membership Report
        //         mrcode    = 0
        //         chksum    = 0xaf4
        // ###[ IGMPv3mr ]###
        //            res2      = 0x0
        //            numgrp    = 3
        //            \records   \
        //             |###[ IGMPv3gr ]###
        //             |  rtype     = Mode Is Exclude
        //             |  auxdlen   = 0
        //             |  numsrc    = 0
        //             |  maddr     = 239.0.0.1
        //             |  srcaddrs  = []
        //             |###[ IGMPv3gr ]###
        //             |  rtype     = Mode Is Exclude
        //             |  auxdlen   = 0
        //             |  numsrc    = 0
        //             |  maddr     = 239.0.0.2
        //             |  srcaddrs  = []
        //             |###[ IGMPv3gr ]###
        //             |  rtype     = Mode Is Exclude
        //             |  auxdlen   = 0
        //             |  numsrc    = 0
        //             |  maddr     = 239.0.0.3
        //             |  srcaddrs  = []
        val igmpv3ReportPkt = """
            01005e000016020304050607080046c00038000040000102f9e80a000001e00000169404000022000af40
            000000302000000ef00000102000000ef00000202000000ef000003
        """.replace("\\s+".toRegex(), "").trim()

        assertContentEquals(
            HexDump.hexStringToByteArray(igmpv3ReportPkt),
            transmittedIgmpv3Reports[0]
        )
    }

    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    @Test
    fun testIgmpV3GroupSpecificQueryPassed() {
        val apfFilter = getIgmpApfFilter()
        val program = consumeInstalledProgram(apfController, installCnt = 3)
        // Using scapy to generate IGMPv3 group specific query packet
        //   ether = Ether(src='00:11:22:33:44:55', dst='01:00:5e:7f:00:01')
        //   ip = IP(src='10.0.0.2', dst='239.0.0.1')
        //   igmp = IGMPv3(type=0x11)/IGMPv3mq(gaddr='239.0.0.1')
        //   pkt = ether/ip/igmp
        val pkt = """
            01005e7f0001001122334455080045c00020000100000102c0180a000002ef0000011114ffe9ef000001
            00000000
        """.replace("\\s+".toRegex(), "").trim()

        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(pkt),
            PASSED_IPV4
        )
    }

    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    @Test
    fun testIgmpV3GroupAndSourceSpecificQueryPassed() {
        val apfFilter = getIgmpApfFilter()
        val program = consumeInstalledProgram(apfController, installCnt = 3)
        // Using scapy to generate IGMPv3 group and source specific query packet
        //   ether = Ether(src='00:11:22:33:44:55', dst='01:00:5e:7f:00:01')
        //   ip = IP(src='10.0.0.2', dst='239.0.0.1')
        //   igmp = IGMPv3(type=0x11)/IGMPv3mq(gaddr='239.0.0.1', numsrc=1, srcaddrs=['10.0.0.1'])
        //   pkt = ether/ip/igmp
        val pkt = """
            01005e7f0001001122334455080045c00024000100000102c0140a000002ef0000011114f5e7ef0000010
            00000010a000001
        """.replace("\\s+".toRegex(), "").trim()

        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(pkt),
            PASSED_IPV4
        )
    }

    @Test
    fun testIPv4MulticastPacketFilter() {
        val apfConfig = getDefaultConfig()
        apfConfig.multicastFilter = true
        val apfFilter = getApfFilter(apfConfig)
        consumeInstalledProgram(apfController, installCnt = 2)
        val linkAddress = LinkAddress(InetAddress.getByAddress(hostIpv4Address), 24)
        val lp = LinkProperties()
        lp.addLinkAddress(linkAddress)
        apfFilter.setLinkProperties(lp)
        val program = consumeInstalledProgram(apfController, installCnt = 1)

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
        consumeInstalledProgram(apfController, installCnt = 2)
        apfFilter.updateClatInterfaceState(true)
        val program = consumeInstalledProgram(apfController, installCnt = 1)

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
        consumeInstalledProgram(apfController, installCnt = 2)
        apfFilter.addTcpKeepalivePacketFilter(1, parcel)
        var program = consumeInstalledProgram(apfController, installCnt = 1)

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
        program = consumeInstalledProgram(apfController, installCnt = 1)
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
        consumeInstalledProgram(apfController, installCnt = 2)
        apfFilter.addNattKeepalivePacketFilter(1, parcel)
        val program = consumeInstalledProgram(apfController, installCnt = 1)

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
        val program = consumeInstalledProgram(apfController, installCnt = 2)

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
        consumeInstalledProgram(apfController, installCnt = 2)
        val lp = LinkProperties()
        for (addr in hostIpv6Addresses) {
            lp.addLinkAddress(LinkAddress(InetAddress.getByAddress(addr), 64))
        }
        apfFilter.setLinkProperties(lp)
        apfFilter.setDozeMode(true)
        val program = consumeInstalledProgram(apfController, installCnt = 2)
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
        consumeInstalledProgram(apfController, installCnt = 2)
        val lp = LinkProperties()
        for (addr in hostIpv6Addresses) {
            lp.addLinkAddress(LinkAddress(InetAddress.getByAddress(addr), 64))
        }
        apfFilter.setLinkProperties(lp)
        val program = consumeInstalledProgram(apfController, installCnt = 1)
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
        val program = consumeInstalledProgram(apfController, installCnt = 2)

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
        val program = consumeInstalledProgram(apfController, installCnt = 2)
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
        consumeInstalledProgram(apfController, installCnt = 2)
        val linkAddress = LinkAddress(InetAddress.getByAddress(hostIpv4Address), 24)
        val lp = LinkProperties()
        lp.addLinkAddress(linkAddress)
        apfFilter.setLinkProperties(lp)
        val program = consumeInstalledProgram(apfController, installCnt = 1)
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
        consumeInstalledProgram(apfController, installCnt = 2)
        val linkAddress = LinkAddress(InetAddress.getByAddress(hostIpv4Address), 24)
        val lp = LinkProperties()
        lp.addLinkAddress(linkAddress)
        apfFilter.setLinkProperties(lp)
        val program = consumeInstalledProgram(apfController, installCnt = 1)

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
        consumeInstalledProgram(apfController, installCnt = 2)
        val linkAddress = LinkAddress(InetAddress.getByAddress(hostIpv4Address), 24)
        val lp = LinkProperties()
        lp.addLinkAddress(linkAddress)
        apfFilter.setLinkProperties(lp)
        val program = consumeInstalledProgram(apfController, installCnt = 1)
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

        val transmittedPackets = consumeTransmittedPackets(1)
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
            transmittedPackets[0]
        )
    }

    @Test
    fun testArpOffloadDisabled() {
        val apfConfig = getDefaultConfig()
        apfConfig.handleArpOffload = false
        val apfFilter = getApfFilter(apfConfig)
        consumeInstalledProgram(apfController, installCnt = 2)
        val linkAddress = LinkAddress(InetAddress.getByAddress(hostIpv4Address), 24)
        val lp = LinkProperties()
        lp.addLinkAddress(linkAddress)
        apfFilter.setLinkProperties(lp)
        val program = consumeInstalledProgram(apfController, installCnt = 1)
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
        val program = consumeInstalledProgram(apfController, installCnt = 2)
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
        consumeInstalledProgram(apfController, installCnt = 2)
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
        consumeInstalledProgram(apfController, installCnt = 1)
        apfFilter.updateClatInterfaceState(true)
        val program = consumeInstalledProgram(apfController, installCnt = 1)

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
        val program = consumeInstalledProgram(apfController, installCnt = 3)
        val validIpv6Addresses = hostIpv6Addresses + hostAnycast6Addresses
        val expectPackets = mutableListOf<ByteArray>()
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

            val expectedUcastNaPacket = generateNaPacket(
                apfFilter.mHardwareAddress,
                senderMacAddress,
                addr,
                senderIpv6Address,
                0xe0000000.toInt(), //  R=1, S=1, O=1
                addr
            )
            expectPackets.add(expectedUcastNaPacket)

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

            val expectedMcastNaPacket = generateNaPacket(
                apfFilter.mHardwareAddress,
                senderMacAddress,
                addr,
                senderIpv6Address,
                0xe0000000.toInt(), // R=1, S=1, O=1
                addr
            )
            expectPackets.add(expectedMcastNaPacket)
        }

        val transmitPackets = consumeTransmittedPackets(expectPackets.size)
        for (i in transmitPackets.indices) {
            assertContentEquals(expectPackets[i], transmitPackets[i])
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
        val program = consumeInstalledProgram(apfController, installCnt = 3)
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

        val transmitPkts = consumeTransmittedPackets(1)
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
            transmitPkts[0]
        )
    }

    @Test
    fun testNdOffloadDisabled() {
        val apfConfig = getDefaultConfig()
        apfConfig.handleNdOffload = false
        val apfFilter = getApfFilter(apfConfig)
        val lp = LinkProperties()
        for (addr in hostIpv6Addresses) {
            lp.addLinkAddress(LinkAddress(InetAddress.getByAddress(addr), 64))
        }

        apfFilter.setLinkProperties(lp)
        val program = consumeInstalledProgram(apfController, installCnt = 3)
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

    private fun getApfWithIpv4PingOffloadEnabled(
        enableMultiCastFilter: Boolean = true
    ): Pair<ApfFilter, ByteArray> {
        val apfConfig = getDefaultConfig()
        apfConfig.multicastFilter = enableMultiCastFilter
        apfConfig.handleIpv4PingOffload = true
        val apfFilter = getApfFilter(apfConfig)
        consumeInstalledProgram(apfController, installCnt = 2)
        val linkAddress = LinkAddress(InetAddress.getByAddress(hostIpv4Address), 24)
        val lp = LinkProperties()
        lp.addLinkAddress(linkAddress)
        apfFilter.setLinkProperties(lp)
        val program = consumeInstalledProgram(apfController, installCnt = 1)
        return Pair(apfFilter, program)
    }

    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    @Test
    fun testIpv4EchoRequestReplied() {
        doReturn(64).`when`(dependencies).ipv4DefaultTtl
        val (apfFilter, program) = getApfWithIpv4PingOffloadEnabled()
        // Using scapy to generate IPv4 echo request packet:
        // eth = Ether(src="01:02:03:04:05:06", dst="02:03:04:05:06:07")
        // ip = IP(src="10.0.0.2", dst="10.0.0.1")
        // icmp = ICMP(id=1, seq=123)
        // pkt = eth/ip/icmp/b"hello"
        val ipv4EchoRequestPkt = """
            02030405060701020304050608004500002100010000400166d90a0000020a0
            000010800b3b10001007b68656c6c6f
        """.replace("\\s+".toRegex(), "").trim()

        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(ipv4EchoRequestPkt),
            DROPPED_IPV4_PING_REQUEST_REPLIED
        )

        val transmitPkt = consumeTransmittedPackets(1)[0]

        // ###[ Ethernet ]###
        //   dst       = 01:02:03:04:05:06
        //   src       = 02:03:04:05:06:07
        //   type      = IPv4
        // ###[ IP ]###
        //      version   = 4
        //      ihl       = 5
        //      tos       = 0x0
        //      len       = 33
        //      id        = 1
        //      flags     =
        //      frag      = 0
        //      ttl       = 64
        //      proto     = icmp
        //      chksum    = 0x66d9
        //      src       = 10.0.0.1
        //      dst       = 10.0.0.2
        //      \options   \
        // ###[ ICMP ]###
        //         type      = echo-reply
        //         code      = 0
        //         chksum    = 0xbbb1
        //         id        = 0x1
        //         seq       = 0x7b
        //         unused    = b''
        // ###[ Raw ]###
        //            load      = b'hello'
        val expectedReply = """
            01020304050602030405060708004500002100010000400166D90A0000010A0
            000020000BBB10001007B68656C6C6F
        """.replace("\\s+".toRegex(), "").trim()
        assertContentEquals(
            HexDump.hexStringToByteArray(expectedReply),
            transmitPkt
        )
    }

    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    @Test
    fun testCorruptedIpv4IcmpPacketDropped() {
        val (apfFilter, program) = getApfWithIpv4PingOffloadEnabled()
        // Using scapy to generate corrupted icmp packet
        // eth = Ether(src="01:02:03:04:05:06", dst="02:03:04:05:06:07")
        // ip = IP(proto=1, src="10.0.0.2", dst="10.0.0.1")
        // pkt = eth/ip/b"hello"
        val ipv4EchoRequestPkt = """
            02030405060701020304050608004500001900010000400166e10a0000020a0
            0000168656c6c6f
        """.replace("\\s+".toRegex(), "").trim()

        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(ipv4EchoRequestPkt),
            DROPPED_IPV4_ICMP_INVALID
        )
    }

    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    @Test
    fun testIpv4EchoRequestWithOptionPassed() {
        val (apfFilter, program) = getApfWithIpv4PingOffloadEnabled()
        // Using scapy to generate IPv4 echo request packet with option:
        // eth = Ether(src="01:02:03:04:05:06", dst="02:03:04:05:06:07")
        // ip = IP(src="10.0.0.2", dst="10.0.0.1", options=IPOption(b'\x94\x04\x00\x00'))
        // icmp = ICMP(id=1, seq=123)
        // pkt = eth/ip/icmp/b"hello"
        val ipv4EchoRequestPkt = """
            020304050607010203040506080046000025000100004001d1d00a0000020a0
            00001940400000800b3b10001007b68656c6c6f
        """.replace("\\s+".toRegex(), "").trim()

        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(ipv4EchoRequestPkt),
            PASSED_IPV4_UNICAST
        )
    }

    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    @Test
    fun testIpv4EchoRequestToOtherHostPassed() {
        val (apfFilter, program) = getApfWithIpv4PingOffloadEnabled()
        // Using scapy to generate IPv4 echo request packet to other host:
        // eth = Ether(src="01:02:03:04:05:06", dst="02:03:04:05:06:07")
        // ip = IP(src="10.0.0.2", dst="10.0.0.111")
        // icmp = ICMP(id=1, seq=123)
        // pkt = eth/ip/icmp/b"hello"
        val ipv4EchoRequestPkt = """
            020304050607010203040506080045000021000100004001666b0a0000020a0
            0006f0800b3b10001007b68656c6c6f
        """.replace("\\s+".toRegex(), "").trim()

        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(ipv4EchoRequestPkt),
            PASSED_IPV4_UNICAST
        )
    }

    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    @Test
    fun testBroadcastIpv4EchoRequestPassed() {
        val (apfFilter, program) = getApfWithIpv4PingOffloadEnabled(enableMultiCastFilter = false)
        // Using scapy to generate broadcast IPv4 echo request packet:
        // eth = Ether(src="01:02:03:04:05:06", dst="ff:ff:ff:ff:ff:ff")
        // ip = IP(src="10.0.0.2", dst="10.0.0.255")
        // icmp = ICMP(id=1, seq=123)
        // pkt = eth/ip/icmp/b"hello"
        val ipv4EchoRequestPkt = """
            ffffffffffff01020304050608004500002100010000400165db0a0000020a0
            000ff0800b3b10001007b68656c6c6f
        """.replace("\\s+".toRegex(), "").trim()

        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(ipv4EchoRequestPkt),
            PASSED_IPV4
        )
    }

    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    @Test
    fun testIpv4EchoReplyPassed() {
        val (apfFilter, program) = getApfWithIpv4PingOffloadEnabled()
        // Using scapy to generate IPv4 echo reply packet:
        // eth = Ether(src="01:02:03:04:05:06", dst="02:03:04:05:06:07")
        // ip = IP(src="10.0.0.2", dst="10.0.0.1")
        // icmp = ICMP(type=0, id=1, seq=123)
        // pkt = eth/ip/icmp/b"hello"
        val ipv4EchoReplyPkt = """
            02030405060701020304050608004500002100010000400166d90a0000020a0
            000010000bbb10001007b68656c6c6f
        """.replace("\\s+".toRegex(), "").trim()

        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(ipv4EchoReplyPkt),
            PASSED_IPV4_UNICAST
        )
    }

    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    @Test
    fun testOffloadServiceInfoUpdateTriggersProgramInstall() {
        val apfConfig = getDefaultConfig()
        apfConfig.handleMdnsOffload = true
        val apfFilter = getApfFilter(apfConfig)
        consumeInstalledProgram(apfController, installCnt = 2)
        val captor = ArgumentCaptor.forClass(OffloadEngine::class.java)
        verify(nsdManager).registerOffloadEngine(
            eq(ifParams.name),
            anyLong(),
            anyLong(),
            any(),
            captor.capture()
        )
        val offloadEngine = captor.value
        val info = OffloadServiceInfo(
            OffloadServiceInfo.Key("gambit", "_googlecast._tcp"),
            listOf(),
            "Android_f47ac10b58cc4b88bc3f5e7a81e59872.local",
            ByteArray(5) { 0x01 },
            0,
            OffloadEngine.OFFLOAD_TYPE_REPLY.toLong()
        )
        visibleOnHandlerThread(handler) { offloadEngine.onOffloadServiceUpdated(info) }

        verify(apfController).installPacketFilter(any())

        visibleOnHandlerThread(handler) { apfFilter.shutdown() }
        verify(nsdManager).unregisterOffloadEngine(eq(offloadEngine))
    }

    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    @Test
    fun testCorruptedOffloadServiceInfoUpdateNotTriggerNewProgramInstall() {
        val apfConfig = getDefaultConfig()
        apfConfig.handleMdnsOffload = true
        val apfFilter = getApfFilter(apfConfig)
        consumeInstalledProgram(apfController, installCnt = 2)
        val captor = ArgumentCaptor.forClass(OffloadEngine::class.java)
        verify(nsdManager).registerOffloadEngine(
            eq(ifParams.name),
            anyLong(),
            anyLong(),
            any(),
            captor.capture()
        )
        val offloadEngine = captor.value
        val castOffloadInfo = OffloadServiceInfo(
            OffloadServiceInfo.Key("gambit", "_googlecast._tcp"),
            listOf(),
            "Android_f47ac10b58cc4b88bc3f5e7a81e59872.local",
            HexDump.hexStringToByteArray(castOffloadPayload),
            0,
            OffloadEngine.OFFLOAD_TYPE_REPLY.toLong()
        )
        visibleOnHandlerThread(handler) {
            offloadEngine.onOffloadServiceUpdated(castOffloadInfo)
        }
        consumeInstalledProgram(apfController, installCnt = 1)
        val corruptedOffloadInfo = OffloadServiceInfo(
            OffloadServiceInfo.Key("gambit", "_${"a".repeat(63)}._tcp"),
            listOf(),
            "Android_f47ac10b58cc4b88bc3f5e7a81e59872.local",
            byteArrayOf(0x01, 0x02, 0x03, 0x04),
            0,
            OffloadEngine.OFFLOAD_TYPE_REPLY.toLong()
        )
        visibleOnHandlerThread(handler) {
            offloadEngine.onOffloadServiceUpdated(corruptedOffloadInfo)
        }
        verify(apfController, never()).installPacketFilter(any())
    }

    private fun getApfWithMdnsOffloadEnabled(
        mcFilter: Boolean = true,
        v6Only: Boolean = false,
        removeTvRemoteRecord: Boolean = false
    ): Pair<ApfFilter, ByteArray> {
        val apfConfig = getDefaultConfig()
        apfConfig.handleMdnsOffload = true
        if (mcFilter) {
            apfConfig.multicastFilter = true
        }
        val apfFilter = getApfFilter(apfConfig)
        consumeInstalledProgram(apfController, installCnt = 2)
        val captor = ArgumentCaptor.forClass(OffloadEngine::class.java)
        verify(nsdManager).registerOffloadEngine(
            eq(ifParams.name),
            anyLong(),
            anyLong(),
            any(),
            captor.capture()
        )
        val offloadEngine = captor.value
        val lp = LinkProperties()
        if (v6Only) {
            apfFilter.updateClatInterfaceState(true)
            consumeInstalledProgram(apfController, installCnt = 1)
        } else {
            val ipv4LinkAddress = LinkAddress(InetAddress.getByAddress(hostIpv4Address), 24)
            lp.addLinkAddress(ipv4LinkAddress)
        }
        val ipv6LinkAddress = LinkAddress(hostLinkLocalIpv6Address, 64)
        lp.addLinkAddress(ipv6LinkAddress)
        apfFilter.setLinkProperties(lp)
        consumeInstalledProgram(apfController, installCnt = 1)
        val castOffloadInfo = OffloadServiceInfo(
            OffloadServiceInfo.Key("gambit-3cb56c6253638b3641e3d289013cc0ae", "_googlecast._tcp"),
            listOf(),
            "Android_f47ac10b58cc4b88bc3f5e7a81e59872.local",
            HexDump.hexStringToByteArray(castOffloadPayload),
            0,
            OffloadEngine.OFFLOAD_TYPE_REPLY.toLong()
        )
        val tvRemoteOffloadInfo = OffloadServiceInfo(
            OffloadServiceInfo.Key("gambit", "_androidtvremote2._tcp"),
            listOf(),
            "Android_f47ac10b58cc4b88bc3f5e7a81e59872.local",
            HexDump.hexStringToByteArray(tvRemoteOffloadPayload),
            0,
            OffloadEngine.OFFLOAD_TYPE_REPLY.toLong()
        )

        visibleOnHandlerThread(handler) {
            offloadEngine.onOffloadServiceUpdated(castOffloadInfo)
            offloadEngine.onOffloadServiceUpdated(tvRemoteOffloadInfo)
            if (removeTvRemoteRecord) {
                offloadEngine.onOffloadServiceRemoved(tvRemoteOffloadInfo)
            }
        }
        val program = consumeInstalledProgram(
            apfController,
            installCnt = if (removeTvRemoteRecord) 3 else 2
        )
        return Pair(apfFilter, program)
    }

    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    @Test
    fun testIPv4MdnsQueryReplied() {
        val (apfFilter, program) = getApfWithMdnsOffloadEnabled(mcFilter = false)
        // Using scapy to generate packet:
        // eth = Ether(src="01:02:03:04:05:06", dst="01:00:5e:00:00:fb")
        // ip = IP(src="10.0.0.3", dst="224.0.0.251")
        // udp = UDP(dport=5353, sport=5353)
        // dns = DNS(qd=DNSQR(qname="_googlecast._tcp.local", qtype="PTR"))
        // pkt = eth/ip/udp/dns
        val castIPv4MdnsPtrQuery = """
            01005e0000fb0102030405060800450000440001000040118faa0a000003e00
            000fb14e914e900309fa50000010000010000000000000b5f676f6f676c6563
            617374045f746370056c6f63616c00000c0001
        """.replace("\\s+".toRegex(), "").trim()

        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(castIPv4MdnsPtrQuery),
            DROPPED_MDNS_REPLIED
        )

        var transmitPkt = consumeTransmittedPackets(1)[0]

        // ###[ Ethernet ]###
        //   dst       = 01:00:5e:00:00:fb
        //   src       = 02:03:04:05:06:07
        //   type      = IPv4
        // ###[ IP ]###
        //      version   = 4
        //      ihl       = 5
        //      tos       = 0x0
        //      len       = 514
        //      id        = 0
        //      flags     = DF
        //      frag      = 0
        //      ttl       = 255
        //      proto     = udp
        //      chksum    = 0x8eee
        //      src       = 10.0.0.1
        //      dst       = 224.0.0.251
        //      \options   \
        // ###[ UDP ]###
        //         sport     = mdns
        //         dport     = mdns
        //         len       = 494
        //         chksum    = 0x2f0d
        // ###[ DNS ]###
        //           id        = 0
        //           qr        = 1
        //           opcode    = QUERY
        //           aa        = 1
        //           tc        = 0
        //           rd        = 0
        //           ra        = 0
        //           z         = 0
        //           ad        = 0
        //           cd        = 0
        //           rcode     = ok
        //           qdcount   = 0
        //           ancount   = 7
        //           nscount   = 0
        //           arcount   = 0
        //           \qd        \
        //           \an        \
        //            |###[ DNS Resource Record ]###
        //            |  rrname    = b'_googlecast._tcp.local.'
        //            |  type      = PTR
        //            |  cacheflush= 0
        //            |  rclass    = IN
        //            |  ttl       = 120
        //            |  rdlen     = None
        //            |  rdata     = b'gambit-3cb56c6253638b3641e3d289013cc0ae._googlecast._tcp.local.'
        //            |###[ DNS SRV Resource Record ]###
        //            |  rrname    = b'\xc0.'
        //            |  type      = SRV
        //            |  cacheflush= 0
        //            |  rclass    = IN
        //            |  ttl       = 120
        //            |  rdlen     = None
        //            |  priority  = 12320
        //            |  weight    = 12320
        //            |  port      = 14384
        //            |  target    = b'9 3cb56c62-5363-8b36-41e3-d289013cc0ae.local..'
        //            |###[ DNS Resource Record ]###
        //            |  rrname    = b'\xc0.'
        //            |  type      = TXT
        //            |  cacheflush= 0
        //            |  rclass    = IN
        //            |  ttl       = 120
        //            |  rdlen     = None
        //            |  rdata     = [b' "id=3cb56c6253638b3641e3d289013cc0ae cd=8ECC37F6755390D005DFC02F8EC0D4FA rm=4ABD579644ACFCCF ve=05 md=gambit ic=/setup/icon.png fn=gambit a=264709 st=0 bs=FA8FFD2242A7 nf=1 rs= ']
        //            |###[ DNS Resource Record ]###
        //            |  rrname    = b'Android_f47ac10b58cc4b88bc3f5e7a81e59872.local.'
        //            |  type      = A
        //            |  cacheflush= 0
        //            |  rclass    = IN
        //            |  ttl       = 120
        //            |  rdlen     = None
        //            |  rdata     = 100.89.85.228
        //            |###[ DNS Resource Record ]###
        //            |  rrname    = b' (Android_f47ac10b58cc4b88bc3f5e7a81e59872\xc0\x1d\x00\x01\x00\x01\x00\x00\x00x\x00\x04dYU\xe4\xc1W\x00.\x00\x01\x00\x00\x00x\x00\x10\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\xc1W\x00\x1c.'
        //            |  type      = AAAA
        //            |  cacheflush= 0
        //            |  rclass    = IN
        //            |  ttl       = 120
        //            |  rdlen     = None
        //            |  rdata     = fe80::3
        //            |###[ DNS Resource Record ]###
        //            |  rrname    = b' (Android_f47ac10b58cc4b88bc3f5e7a81e59872\xc0\x1d\x00\x01\x00\x01\x00\x00\x00x\x00\x04dYU\xe4\xc1W\x00.\x00\x01\x00\x00\x00x\x00\x10\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\xc1W\x00\x1c.'
        //            |  type      = AAAA
        //            |  cacheflush= 0
        //            |  rclass    = IN
        //            |  ttl       = 120
        //            |  rdlen     = None
        //            |  rdata     = 200a::3
        //            |###[ DNS Resource Record ]###
        //            |  rrname    = b' (Android_f47ac10b58cc4b88bc3f5e7a81e59872\xc0\x1d\x00\x01\x00\x01\x00\x00\x00x\x00\x04dYU\xe4\xc1W\x00.\x00\x01\x00\x00\x00x\x00\x10\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\xc1W\x00\x1c.'
        //            |  type      = AAAA
        //            |  cacheflush= 0
        //            |  rclass    = IN
        //            |  ttl       = 120
        //            |  rdlen     = None
        //            |  rdata     = 200b::3
        //           \ns        \
        //           \ar        \
        val expectedIPv4CastMdnsReply = """
            01005E0000FB02030405060708004500020200004000FF118EEE0A000001E00
            000FB14E914E901EE2F0D0000840000000007000000000B5F676F6F676C6563
            617374045F746370056C6F63616C00000C000100000078002A2767616D62697
            42D336362353663363235333633386233363431653364323839303133636330
            6165C00C01C0000021000100000078003430203020383030392033636235366
            336322D353336332D386233362D343165332D6432383930313363633061652E
            6C6F63616C2E01C000001000010000007800B3B2202269643D3363623536633
            6323533363338623336343165336432383930313363633061652063643D3845
            434333374636373535333930443030354446433032463845433044344641207
            26D3D344142443537393634344143464343462076653D3035206D643D67616D
            6269742069633D2F73657475702F69636F6E2E706E6720666E3D67616D62697
            420613D3236343730392073743D302062733D46413846464432323432413720
            6E663D312072733D2028416E64726F69645F663437616331306235386363346
            2383862633366356537613831653539383732C01D0001000100000078000464
            5955E4C157001C0001000000780010FE800000000000000000000000000003C
            157001C0001000000780010200A0000000000000000000000000003C157001C
            0001000000780010200B0000000000000000000000000003
        """.replace("\\s+".toRegex(), "").trim()

        assertContentEquals(
            HexDump.hexStringToByteArray(expectedIPv4CastMdnsReply),
            transmitPkt
        )

        // Using scapy to generate packet:
        // eth = Ether(src="01:02:03:04:05:06", dst="01:00:5e:00:00:fb")
        // ip = IP(src="10.0.0.3", dst="224.0.0.251")
        // udp = UDP(dport=5353, sport=5353)
        // questions = [
        //   DNSQR(qname="_airplay._tcp.local", qtype="PTR"),
        //   DNSQR(qname="gambit-3cb56c6253638b3641e3d289013cc0ae._googlecast._tcp.local", qtype="TXT")
        // ]
        // dns = dns_compress(DNS(qd=questions))
        // pkt = eth/ip/udp/dns
        val castIPv4MdnsTxtQuery = """
            01005e0000fb0102030405060800450000440001000040118faa0a000003e00
            000fb14e914e900309fa50000010000010000000000000b5f676f6f676c6563
            617374045f746370056c6f63616c00000c0001
        """.replace("\\s+".toRegex(), "").trim()

        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(castIPv4MdnsTxtQuery),
            DROPPED_MDNS_REPLIED
        )

        transmitPkt = consumeTransmittedPackets(1)[0]

        assertContentEquals(
            HexDump.hexStringToByteArray(expectedIPv4CastMdnsReply),
            transmitPkt
        )

        // Using scapy to generate packet:
        // eth = Ether(src="01:02:03:04:05:06", dst="01:00:5e:00:00:fb")
        // ip = IP(src="10.0.0.3", dst="224.0.0.251")
        // udp = UDP(dport=5353, sport=5353)
        // dns = DNS(qd=DNSQR(qname="_androidtvremote2._tcp.local", qtype="PTR"))
        // pkt = eth/ip/udp/dns
        val tvRemoteIPv4MdnsPtrQuery = """
            01005e0000fb01020304050608004500004a0001000040118fa40a000003e00
            000fb14e914e900366966000001000001000000000000115f616e64726f6964
            747672656d6f746532045f746370056c6f63616c00000c0001
        """.replace("\\s+".toRegex(), "").trim()

        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(tvRemoteIPv4MdnsPtrQuery),
            DROPPED_MDNS_REPLIED
        )

        transmitPkt = consumeTransmittedPackets(1)[0]

        // ###[ Ethernet ]###
        //  dst       = 01:00:5e:00:00:fb
        //  src       = 02:03:04:05:06:07
        //  type      = IPv4
        // ###[ IP ]###
        //      version   = 4
        //      ihl       = 5
        //      tos       = 0x0
        //      len       = 332
        //      id        = 0
        //      flags     = DF
        //      frag      = 0
        //      ttl       = 255
        //      proto     = udp
        //      chksum    = 0x8fa4
        //      src       = 10.0.0.1
        //      dst       = 224.0.0.251
        //      \options   \
        // ###[ UDP ]###
        //         sport     = mdns
        //         dport     = mdns
        //         len       = 312
        //         chksum    = 0xf867
        // ###[ DNS ]###
        //            id        = 0
        //           qr        = 1
        //           opcode    = QUERY
        //           aa        = 1
        //           tc        = 0
        //           rd        = 0
        //           ra        = 0
        //           z         = 0
        //           ad        = 0
        //           cd        = 0
        //           rcode     = ok
        //           qdcount   = 0
        //           ancount   = 7
        //           nscount   = 0
        //           arcount   = 0
        //           \qd        \
        //           \an        \
        //            |###[ DNS Resource Record ]###
        //            |  rrname    = b'_androidtvremote2._tcp.local.'
        //            |  type      = PTR
        //            |  cacheflush= 0
        //            |  rclass    = IN
        //            |  ttl       = 120
        //            |  rdlen     = None
        //            |  rdata     = b'gambit._androidtvremote2._tcp.local.'
        //            |###[ DNS SRV Resource Record ]###
        //            |  rrname    = b'gambit._androidtvremote2._tcp.local.'
        //            |  type      = SRV
        //            |  cacheflush= 0
        //            |  rclass    = IN
        //            |  ttl       = 120
        //            |  rdlen     = None
        //            |  priority  = 12320
        //            |  weight    = 12320
        //            |  port      = 13876
        //            |  target    = b'6 Android_2570595cc11d4af4a4b7146b946eeb9e.local.'
        //            |###[ DNS Resource Record ]###
        //            |  rrname    = b'gambit._androidtvremote2._tcp.local.'
        //            |  type      = TXT
        //            |  cacheflush= 0
        //            |  rclass    = IN
        //            |  ttl       = 120
        //            |  rdlen     = None
        //            |  rdata     = [b'"bt=3C:4E:56:76:1E:E9"']
        //            |###[ DNS Resource Record ]###
        //            |  rrname    = b'Android_f47ac10b58cc4b88bc3f5e7a81e59872.local.'
        //            |  type      = A
        //            |  cacheflush= 0
        //            |  rclass    = IN
        //            |  ttl       = 120
        //            |  rdlen     = None
        //            |  rdata     = 100.89.85.228
        //            |###[ DNS Resource Record ]###
        //            |  rrname    = b'Android_f47ac10b58cc4b88bc3f5e7a81e59872.local.'
        //            |  type      = AAAA
        //            |  cacheflush= 0
        //            |  rclass    = IN
        //            |  ttl       = 120
        //            |  rdlen     = None
        //            |  rdata     = fe80::3
        //            |###[ DNS Resource Record ]###
        //            |  rrname    = b'Android_f47ac10b58cc4b88bc3f5e7a81e59872.local.'
        //            |  type      = AAAA
        //            |  cacheflush= 0
        //            |  rclass    = IN
        //            |  ttl       = 120
        //            |  rdlen     = None
        //            |  rdata     = 200a::3
        //            |###[ DNS Resource Record ]###
        //            |  rrname    = b'Android_f47ac10b58cc4b88bc3f5e7a81e59872.local.'
        //            |  type      = AAAA
        //            |  cacheflush= 0
        //            |  rclass    = IN
        //            |  ttl       = 120
        //            |  rdlen     = None
        //            |  rdata     = 200b::3
        //           \ns        \
        //           \ar        \
        val expectedIPv4tvRemoteMdnsReply = """
            01005E0000FB02030405060708004500014C00004000FF118FA40A000001E00
            000FB14E914E90138F867000084000000000700000000115F616E64726F6964
            747672656D6F746532045F746370056C6F63616C00000C00010000007800090
            667616D626974C00CC03400210001000000780037302030203634363620416E
            64726F69645F323537303539356363313164346166346134623731343662393
            43665656239652E6C6F63616CC03400100001000000780017162262743D3343
            3A34453A35363A37363A31453A45392228416E64726F69645F6634376163313
            062353863633462383862633366356537613831653539383732C02300010001
            000000780004645955E4C0A3001C0001000000780010FE80000000000000000
            0000000000003C0A3001C0001000000780010200A0000000000000000000000
            000003C0A3001C0001000000780010200B0000000000000000000000000003
        """.replace("\\s+".toRegex(), "").trim()

        assertContentEquals(
            HexDump.hexStringToByteArray(expectedIPv4tvRemoteMdnsReply),
            transmitPkt
        )
    }

    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    @Test
    fun testIPv4MdnsQueryDropped() {
        val (apfFilter, program) = getApfWithMdnsOffloadEnabled(removeTvRemoteRecord = true)
        // Using scapy to generate packet:
        // eth = Ether(src="01:02:03:04:05:06", dst="01:00:5e:00:00:fb")
        // ip = IP(src="10.0.0.3", dst="224.0.0.251")
        // udp = UDP(dport=5353, sport=5353)
        // dns = DNS(qd=DNSQR(qname="_airplay._tcp.local", qtype="PTR"))
        // pkt = eth/ip/udp/dns
        val airplayIPv4MdnsPtrQuery = """
            01005e0000fb0102030405060800450000410001000040118fad0a000003e00
            000fb14e914e9002d8203000001000001000000000000085f616972706c6179
            045f746370056c6f63616c00000c0001
        """.replace("\\s+".toRegex(), "").trim()

        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(airplayIPv4MdnsPtrQuery),
            DROPPED_MDNS
        )

        // Using scapy to generate packet:
        // eth = Ether(src="01:02:03:04:05:06", dst="01:00:5e:00:00:fb")
        // ip = IP(src="10.0.0.3", dst="224.0.0.251")
        // udp = UDP(dport=5353, sport=5353)
        // dns = DNS(qd=DNSQR(qname="_androidtvremote2._tcp.local", qtype="PTR"))
        // pkt = eth/ip/udp/dns
        val tvRemoteIPv4MdnsPtrQuery = """
            01005e0000fb01020304050608004500004a0001000040118fa40a000003e00
            000fb14e914e900366966000001000001000000000000115f616e64726f6964
            747672656d6f746532045f746370056c6f63616c00000c0001
        """.replace("\\s+".toRegex(), "").trim()

        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(tvRemoteIPv4MdnsPtrQuery),
            DROPPED_MDNS
        )
    }

    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    @Test
    fun testIPv4MdnsQueryWithOptionPassed() {
        val (apfFilter, program) = getApfWithMdnsOffloadEnabled(mcFilter = false)
        // Using scapy to generate packet:
        // eth = Ether(src="01:02:03:04:05:06", dst="01:00:5e:00:00:fb")
        // ip = IP(src="10.0.0.3", dst="224.0.0.251", options=IPOption(b'\x94\x04\x00\x00'))
        // udp = UDP(dport=5353, sport=5353)
        // dns = DNS(qd=DNSQR(qname="_googlecast._tcp.local", qtype="PTR"))
        // pkt = eth/ip/udp/dns
        val castIPv4MdnsPtrQueryWithOption = """
            01005e0000fb010203040506080046000048000100004011faa10a000003e00
            000fb9404000014e914e900309fa50000010000010000000000000b5f676f6f
            676c6563617374045f746370056c6f63616c00000c0001
        """.replace("\\s+".toRegex(), "").trim()

        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(castIPv4MdnsPtrQueryWithOption),
            PASSED_IPV4
        )
    }

    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    @Test
    fun testIPv4MdnsQueryDroppedOnV6OnlyNetwork() {
        val (apfFilter, program) = getApfWithMdnsOffloadEnabled(mcFilter = false, v6Only = true)
        // Using scapy to generate packet:
        // eth = Ether(src="01:02:03:04:05:06", dst="01:00:5e:00:00:fb")
        // ip = IP(src="10.0.0.3", dst="224.0.0.251")
        // udp = UDP(dport=5353, sport=5353)
        // dns = DNS(qd=DNSQR(qname="_googlecast._tcp.local", qtype="PTR"))
        // pkt = eth/ip/udp/dns
        val castIPv4MdnsPtrQuery = """
            01005e0000fb0102030405060800450000440001000040118faa0a000003e00
            000fb14e914e900309fa50000010000010000000000000b5f676f6f676c6563
            617374045f746370056c6f63616c00000c0001
        """.replace("\\s+".toRegex(), "").trim()

        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(castIPv4MdnsPtrQuery),
            DROPPED_IPV4_NON_DHCP4
        )
    }

    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    @Test
    fun testIPv4MdnsReplyPassed() {
        val (apfFilter, program) = getApfWithMdnsOffloadEnabled(mcFilter = false)
        // Using scapy to generate packet:
        // eth = Ether(src="01:02:03:04:05:06", dst="01:00:5e:00:00:fb")
        // ip = IP(src="10.0.0.3", dst="224.0.0.251")
        // udp = UDP(dport=5353, sport=5353)
        // dns = DNS(qr=1, aa=1, rd=0, qd=None, an=DNSRR(rrname="_androidtvremote2._tcp.local", type="PTR", rdata="gambit._androidtvremote2._tcp.local", ttl=120))
        // pkt = eth/ip/udp/dns
        val tvRemoteIPv4MdnsPtrAnswer = """
            01005e0000fb0102030405060800450000750001000040118f790a000003e00
            000fb14e914e9006169b4000084000000000100000000115f616e64726f6964
            747672656d6f746532045f746370056c6f63616c00000c00010000007800250
            667616d626974115f616e64726f6964747672656d6f746532045f746370056c
            6f63616c00
        """.replace("\\s+".toRegex(), "").trim()

        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(tvRemoteIPv4MdnsPtrAnswer),
            PASSED_MDNS
        )
    }

    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    @Test
    fun testCorruptedIPv4MdnsPacketDropped() {
        val (apfFilter, program) = getApfWithMdnsOffloadEnabled(mcFilter = false)
        // Using scapy to generate packet:
        // eth = Ether(src="01:02:03:04:05:06", dst="01:00:5e:00:00:fb")
        // ip = IP(proto=17, src="10.0.0.3", dst="224.0.0.251")
        // udp = UDP(dport=5353, sport=5353)
        // pkt = eth/ip/udp/b"hello"
        val corruptedIPv4MdnsPkt = """
            01005e0000fb0102030405060800450000210001000040118fcd0a000003e00
            000fb14e914e9000da73168656c6c6f
        """.replace("\\s+".toRegex(), "").trim()

        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(corruptedIPv4MdnsPkt),
            DROPPED_MDNS_INVALID
        )
    }

    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    @Test
    fun testIPv6MdnsQueryReplied() {
        val (apfFilter, program) = getApfWithMdnsOffloadEnabled(mcFilter = false)
        // Using scapy to generate packet:
        // eth = Ether(src="01:02:03:04:05:06", dst="33:33:00:00:00:FB")
        // ip = IPv6(src="fe80::1", dst="ff02::fb")
        // udp = UDP(dport=5353, sport=5353)
        // dns = DNS(qd=DNSQR(qname="_googlecast._tcp.local", qtype="PTR"))
        // pkt = eth/ip/udp/dns
        val castIPv6MdnsPtrQuery = """
            3333000000fb01020304050686dd6000000000301140fe80000000000000000
            0000000000001ff0200000000000000000000000000fb14e914e900308c2400
            00010000010000000000000b5f676f6f676c6563617374045f746370056c6f6
            3616c00000c0001
        """.replace("\\s+".toRegex(), "").trim()

        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(castIPv6MdnsPtrQuery),
            DROPPED_MDNS_REPLIED
        )

        var transmitPkt = consumeTransmittedPackets(1)[0]

        // ###[ Ethernet ]###
        //  dst       = 33:33:00:00:00:fb
        //  src       = 02:03:04:05:06:07
        //  type      = IPv6
        // ###[ IPv6 ]###
        //      version   = 6
        //      tc        = 0
        //      fl        = 0
        //      plen      = 494
        //      nh        = UDP
        //      hlim      = 255
        //      src       = fe80::3
        //      dst       = ff02::fb
        // ###[ UDP ]###
        //         sport     = mdns
        //         dport     = mdns
        //         len       = 494
        //         chksum    = 0x1b88
        // ###[ DNS ]###
        //           id        = 0
        //           qr        = 1
        //           opcode    = QUERY
        //           aa        = 1
        //           tc        = 0
        //           rd        = 0
        //           ra        = 0
        //           z         = 0
        //           ad        = 0
        //           cd        = 0
        //           rcode     = ok
        //           qdcount   = 0
        //           ancount   = 7
        //           nscount   = 0
        //           arcount   = 0
        //           \qd        \
        //           \an        \
        //            |###[ DNS Resource Record ]###
        //            |  rrname    = b'_googlecast._tcp.local.'
        //            |  type      = PTR
        //            |  cacheflush= 0
        //            |  rclass    = IN
        //            |  ttl       = 120
        //            |  rdlen     = None
        //            |  rdata     = b'gambit-3cb56c6253638b3641e3d289013cc0ae._googlecast._tcp.local.'
        //            |###[ DNS SRV Resource Record ]###
        //            |  rrname    = b'\xc0.'
        //            |  type      = SRV
        //            |  cacheflush= 0
        //            |  rclass    = IN
        //            |  ttl       = 120
        //            |  rdlen     = None
        //            |  priority  = 12320
        //            |  weight    = 12320
        //            |  port      = 14384
        //            |  target    = b'9 3cb56c62-5363-8b36-41e3-d289013cc0ae.local..'
        //            |###[ DNS Resource Record ]###
        //            |  rrname    = b'\xc0.'
        //            |  type      = TXT
        //            |  cacheflush= 0
        //            |  rclass    = IN
        //            |  ttl       = 120
        //            |  rdlen     = None
        //            |  rdata     = [b' "id=3cb56c6253638b3641e3d289013cc0ae cd=8ECC37F6755390D005DFC02F8EC0D4FA rm=4ABD579644ACFCCF ve=05 md=gambit ic=/setup/icon.png fn=gambit a=264709 st=0 bs=FA8FFD2242A7 nf=1 rs= ']
        //            |###[ DNS Resource Record ]###
        //            |  rrname    = b'Android_f47ac10b58cc4b88bc3f5e7a81e59872.local.'
        //            |  type      = A
        //            |  cacheflush= 0
        //            |  rclass    = IN
        //            |  ttl       = 120
        //            |  rdlen     = None
        //            |  rdata     = 100.89.85.228
        //            |###[ DNS Resource Record ]###
        //            |  rrname    = b' (Android_f47ac10b58cc4b88bc3f5e7a81e59872\xc0\x1d\x00\x01\x00\x01\x00\x00\x00x\x00\x04dYU\xe4\xc1W\x00.\x00\x01\x00\x00\x00x\x00\x10\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\xc1W\x00\x1c.'
        //            |  type      = AAAA
        //            |  cacheflush= 0
        //            |  rclass    = IN
        //            |  ttl       = 120
        //            |  rdlen     = None
        //            |  rdata     = fe80::3
        //            |###[ DNS Resource Record ]###
        //            |  rrname    = b' (Android_f47ac10b58cc4b88bc3f5e7a81e59872\xc0\x1d\x00\x01\x00\x01\x00\x00\x00x\x00\x04dYU\xe4\xc1W\x00.\x00\x01\x00\x00\x00x\x00\x10\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\xc1W\x00\x1c.'
        //            |  type      = AAAA
        //            |  cacheflush= 0
        //            |  rclass    = IN
        //            |  ttl       = 120
        //            |  rdlen     = None
        //            |  rdata     = 200a::3
        //            |###[ DNS Resource Record ]###
        //            |  rrname    = b' (Android_f47ac10b58cc4b88bc3f5e7a81e59872\xc0\x1d\x00\x01\x00\x01\x00\x00\x00x\x00\x04dYU\xe4\xc1W\x00.\x00\x01\x00\x00\x00x\x00\x10\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\xc1W\x00\x1c.'
        //            |  type      = AAAA
        //            |  cacheflush= 0
        //            |  rclass    = IN
        //            |  ttl       = 120
        //            |  rdlen     = None
        //            |  rdata     = 200b::3
        //           \ns        \
        //           \ar        \
        val expectedIPv6CastMdnsReply = """
            3333000000FB02030405060786DD6000000001EE11FFFE80000000000000000
            0000000000003FF0200000000000000000000000000FB14E914E901EE1B8800
            00840000000007000000000B5F676F6F676C6563617374045F746370056C6F6
            3616C00000C000100000078002A2767616D6269742D33636235366336323533
            36333862333634316533643238393031336363306165C00C01C000002100010
            0000078003430203020383030392033636235366336322D353336332D386233
            362D343165332D6432383930313363633061652E6C6F63616C2E01C00000100
            0010000007800B3B2202269643D336362353663363235333633386233363431
            65336432383930313363633061652063643D384543433337463637353533393
            044303035444643303246384543304434464120726D3D344142443537393634
            344143464343462076653D3035206D643D67616D6269742069633D2F7365747
            5702F69636F6E2E706E6720666E3D67616D62697420613D3236343730392073
            743D302062733D464138464644323234324137206E663D312072733D2028416
            E64726F69645F66343761633130623538636334623838626333663565376138
            31653539383732C01D00010001000000780004645955E4C157001C000100000
            0780010FE800000000000000000000000000003C157001C0001000000780010
            200A0000000000000000000000000003C157001C0001000000780010200B000
            0000000000000000000000003
        """.replace("\\s+".toRegex(), "").trim()

        assertContentEquals(
            HexDump.hexStringToByteArray(expectedIPv6CastMdnsReply),
            transmitPkt
        )

        // Using scapy to generate packet:
        // eth = Ether(src="01:02:03:04:05:06", dst="33:33:00:00:00:FB")
        // ip = IPv6(src="fe80::1", dst="ff02::fb")
        // udp = UDP(dport=5353, sport=5353)
        // questions = [
        //   DNSQR(qname="_airplay._tcp.local", qtype="PTR"),
        //   DNSQR(qname="gambit-3cb56c6253638b3641e3d289013cc0ae._googlecast._tcp.local", qtype="TXT")
        // ]
        // dns = dns_compress(DNS(qd=questions))
        // pkt = eth/ip/udp/dns
        val castIPv6MdnsTxtQuery = """
            3333000000fb01020304050686dd6000000000671140fe80000000000000000
            0000000000001ff0200000000000000000000000000fb14e914e90067439100
            0001000002000000000000085f616972706c6179045f746370056c6f63616c0
            0000c00012767616d6269742d33636235366336323533363338623336343165
            336432383930313363633061650b5f676f6f676c6563617374c01500100001
        """.replace("\\s+".toRegex(), "").trim()

        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(castIPv6MdnsTxtQuery),
            DROPPED_MDNS_REPLIED
        )

        transmitPkt = consumeTransmittedPackets(1)[0]

        assertContentEquals(
            HexDump.hexStringToByteArray(expectedIPv6CastMdnsReply),
            transmitPkt
        )

        // Using scapy to generate packet:
        // eth = Ether(src="01:02:03:04:05:06", dst="33:33:00:00:00:FB")
        // ip = IPv6(src="fe80::1", dst="ff02::fb")
        // udp = UDP(dport=5353, sport=5353)
        // dns = DNS(qd=DNSQR(qname="_androidtvremote2._tcp.local", qtype="PTR"))
        // pkt = eth/ip/udp/dns
        val tvRemoteIPv6MdnsPtrQuery = """
            3333000000fb01020304050686dd6000000000361140fe80000000000000000
            0000000000001ff0200000000000000000000000000fb14e914e9003655e500
            0001000001000000000000115f616e64726f6964747672656d6f746532045f7
            46370056c6f63616c00000c0001
        """.replace("\\s+".toRegex(), "").trim()

        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(tvRemoteIPv6MdnsPtrQuery),
            DROPPED_MDNS_REPLIED
        )

        transmitPkt = consumeTransmittedPackets(1)[0]

        // ###[ Ethernet ]###
        // dst       = 33:33:00:00:00:fb
        // src       = 02:03:04:05:06:07
        // type      = IPv6
        // ###[ IPv6 ]###
        // version   = 6
        // tc        = 0
        // fl        = 0
        // plen      = 312
        // nh        = UDP
        // hlim      = 255
        // src       = fe80::3
        // dst       = ff02::fb
        // ###[ UDP ]###
        //         sport     = mdns
        //         dport     = mdns
        //         len       = 312
        //         chksum    = 0xf867
        // ###[ DNS ]###
        //            id        = 0
        //           qr        = 1
        //           opcode    = QUERY
        //           aa        = 1
        //           tc        = 0
        //           rd        = 0
        //           ra        = 0
        //           z         = 0
        //           ad        = 0
        //           cd        = 0
        //           rcode     = ok
        //           qdcount   = 0
        //           ancount   = 7
        //           nscount   = 0
        //           arcount   = 0
        //           \qd        \
        //           \an        \
        //            |###[ DNS Resource Record ]###
        //            |  rrname    = b'_androidtvremote2._tcp.local.'
        //            |  type      = PTR
        //            |  cacheflush= 0
        //            |  rclass    = IN
        //            |  ttl       = 120
        //            |  rdlen     = None
        //            |  rdata     = b'gambit._androidtvremote2._tcp.local.'
        //            |###[ DNS SRV Resource Record ]###
        //            |  rrname    = b'gambit._androidtvremote2._tcp.local.'
        //            |  type      = SRV
        //            |  cacheflush= 0
        //            |  rclass    = IN
        //            |  ttl       = 120
        //            |  rdlen     = None
        //            |  priority  = 12320
        //            |  weight    = 12320
        //            |  port      = 13876
        //            |  target    = b'6 Android_2570595cc11d4af4a4b7146b946eeb9e.local.'
        //            |###[ DNS Resource Record ]###
        //            |  rrname    = b'gambit._androidtvremote2._tcp.local.'
        //            |  type      = TXT
        //            |  cacheflush= 0
        //            |  rclass    = IN
        //            |  ttl       = 120
        //            |  rdlen     = None
        //            |  rdata     = [b'"bt=3C:4E:56:76:1E:E9"']
        //            |###[ DNS Resource Record ]###
        //            |  rrname    = b'Android_f47ac10b58cc4b88bc3f5e7a81e59872.local.'
        //            |  type      = A
        //            |  cacheflush= 0
        //            |  rclass    = IN
        //            |  ttl       = 120
        //            |  rdlen     = None
        //            |  rdata     = 100.89.85.228
        //            |###[ DNS Resource Record ]###
        //            |  rrname    = b'Android_f47ac10b58cc4b88bc3f5e7a81e59872.local.'
        //            |  type      = AAAA
        //            |  cacheflush= 0
        //            |  rclass    = IN
        //            |  ttl       = 120
        //            |  rdlen     = None
        //            |  rdata     = fe80::3
        //            |###[ DNS Resource Record ]###
        //            |  rrname    = b'Android_f47ac10b58cc4b88bc3f5e7a81e59872.local.'
        //            |  type      = AAAA
        //            |  cacheflush= 0
        //            |  rclass    = IN
        //            |  ttl       = 120
        //            |  rdlen     = None
        //            |  rdata     = 200a::3
        //            |###[ DNS Resource Record ]###
        //            |  rrname    = b'Android_f47ac10b58cc4b88bc3f5e7a81e59872.local.'
        //            |  type      = AAAA
        //            |  cacheflush= 0
        //            |  rclass    = IN
        //            |  ttl       = 120
        //            |  rdlen     = None
        //            |  rdata     = 200b::3
        //           \ns        \
        //           \ar        \
        val expectedIPv6tvRemoteMdnsReply = """
            3333000000FB02030405060786DD60000000013811FFFE80000000000000000
            0000000000003FF0200000000000000000000000000FB14E914E90138E4E200
            0084000000000700000000115F616E64726F6964747672656D6F746532045F7
            46370056C6F63616C00000C00010000007800090667616D626974C00CC03400
            210001000000780037302030203634363620416E64726F69645F32353730353
            935636331316434616634613462373134366239343665656239652E6C6F6361
            6CC03400100001000000780017162262743D33433A34453A35363A37363A314
            53A45392228416E64726F69645F663437616331306235386363346238386263
            3366356537613831653539383732C02300010001000000780004645955E4C0A
            3001C0001000000780010FE800000000000000000000000000003C0A3001C00
            01000000780010200A0000000000000000000000000003C0A3001C000100000
            0780010200B0000000000000000000000000003
        """.replace("\\s+".toRegex(), "").trim()

        assertContentEquals(
            HexDump.hexStringToByteArray(expectedIPv6tvRemoteMdnsReply),
            transmitPkt
        )
    }

    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    @Test
    fun testIPv6MdnsQueryDropped() {
        val (apfFilter, program) = getApfWithMdnsOffloadEnabled(removeTvRemoteRecord = true)
        // Using scapy to generate packet:
        // eth = Ether(src="01:02:03:04:05:06", dst="33:33:00:00:00:FB")
        // ip = IPv6(src="fe80::1", dst="ff02::fb")
        // udp = UDP(dport=5353, sport=5353)
        // dns = DNS(qd=DNSQR(qname="_airplay._tcp.local", qtype="PTR"))
        // pkt = eth/ip/udp/dns
        val airplayIPv6MdnsPtrQuery = """
            3333000000fb01020304050686dd60000000002d1140fe80000000000000000
            0000000000001ff0200000000000000000000000000fb14e914e9002d6e8200
            0001000001000000000000085f616972706c6179045f746370056c6f63616c0
            0000c0001
        """.replace("\\s+".toRegex(), "").trim()

        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(airplayIPv6MdnsPtrQuery),
            DROPPED_MDNS
        )

        // Using scapy to generate packet:
        // eth = Ether(src="01:02:03:04:05:06", dst="33:33:00:00:00:FB")
        // ip = IPv6(src="fe80::1", dst="ff02::fb")
        // udp = UDP(dport=5353, sport=5353)
        // dns = DNS(qd=DNSQR(qname="_androidtvremote2._tcp.local", qtype="PTR"))
        // pkt = eth/ip/udp/dns
        val tvRemoteIPv6MdnsPtrQuery = """
            3333000000fb01020304050686dd6000000000361140fe80000000000000000
            0000000000001ff0200000000000000000000000000fb14e914e9003655e500
            0001000001000000000000115f616e64726f6964747672656d6f746532045f7
            46370056c6f63616c00000c0001
        """.replace("\\s+".toRegex(), "").trim()

        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(tvRemoteIPv6MdnsPtrQuery),
            DROPPED_MDNS
        )
    }

    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    @Test
    fun testIPv6MdnsReplyPassed() {
        val (apfFilter, program) = getApfWithMdnsOffloadEnabled(mcFilter = false)
        // Using scapy to generate packet:
        // eth = Ether(src="01:02:03:04:05:06", dst="33:33:00:00:00:FB")
        // ip = IPv6(src="fe80::1", dst="ff02::fb")
        // udp = UDP(dport=5353, sport=5353)
        // dns = DNS(qr=1, aa=1, rd=0, qd=None, an=DNSRR(rrname="_androidtvremote2._tcp.local", type="PTR", rdata="gambit._androidtvremote2._tcp.local", ttl=120))
        // pkt = eth/ip/udp/dns
        val tvRemoteIPv6MdnsPtrAnswer = """
            3333000000fb01020304050686dd6000000000611140fe80000000000000000
            0000000000001ff0200000000000000000000000000fb14e914e90061563300
            0084000000000100000000115f616e64726f6964747672656d6f746532045f7
            46370056c6f63616c00000c00010000007800250667616d626974115f616e64
            726f6964747672656d6f746532045f746370056c6f63616c00
        """.replace("\\s+".toRegex(), "").trim()

        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(tvRemoteIPv6MdnsPtrAnswer),
            PASSED_MDNS
        )
    }

    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    @Test
    fun testCorruptedIPv6MdnsPacketDropped() {
        val (apfFilter, program) = getApfWithMdnsOffloadEnabled(mcFilter = false)
        // Using scapy to generate packet:
        // eth = Ether(src="01:02:03:04:05:06", dst="33:33:00:00:00:FB")
        // ip = IPv6(src="fe80::1", dst="ff02::fb")
        // udp = UDP(dport=5353, sport=5353)
        // pkt = eth/ip/udp/b"hello"
        val corruptedIPv6MdnsPkt = """
            3333000000fb01020304050686dd60000000000d1140fe80000000000000000
            0000000000001ff0200000000000000000000000000fb14e914e9000d93b068
            656c6c6f
        """.replace("\\s+".toRegex(), "").trim()

        verifyProgramRun(
            apfFilter.mApfVersionSupported,
            program,
            HexDump.hexStringToByteArray(corruptedIPv6MdnsPkt),
            DROPPED_MDNS_INVALID
        )
    }

    @Test
    fun testApfProgramUpdate() {
        val apfFilter = getApfFilter()
        consumeInstalledProgram(apfController, installCnt = 2)
        // add IPv4 address, expect to have apf program update
        val lp = LinkProperties()
        val linkAddress = LinkAddress(InetAddress.getByAddress(hostIpv4Address), 24)
        lp.addLinkAddress(linkAddress)
        apfFilter.setLinkProperties(lp)
        consumeInstalledProgram(apfController, installCnt = 1)

        // add the same IPv4 address, expect to have no apf program update
        apfFilter.setLinkProperties(lp)
        verify(apfController, never()).installPacketFilter(any())

        // add IPv6 addresses, expect to have apf program update
        for (addr in hostIpv6Addresses) {
            lp.addLinkAddress(LinkAddress(InetAddress.getByAddress(addr), 64))
        }

        apfFilter.setLinkProperties(lp)
        consumeInstalledProgram(apfController, installCnt = 1)

        // add the same IPv6 addresses, expect to have no apf program update
        apfFilter.setLinkProperties(lp)
        verify(apfController, never()).installPacketFilter(any())

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
        consumeInstalledProgram(apfController, installCnt = 1)

        // add the same IPv6 addresses, expect to have no apf program update
        apfFilter.setLinkProperties(lp)
        verify(apfController, never()).installPacketFilter(any())
    }

    // The APFv6 code path is only turned on in V+
    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    @Test
    fun testApfProgramUpdateWithMulticastAddressChange() {
        val mcastAddrs = mutableListOf(
            InetAddress.getByName("224.0.0.1") as Inet4Address
        )
        doReturn(mcastAddrs).`when`(dependencies).getIPv4MulticastAddresses(any())
        val apfConfig = getDefaultConfig()
        apfConfig.handleIgmpOffload = true
        val apfFilter = getApfFilter(apfConfig)
        consumeInstalledProgram(apfController, installCnt = 2)
        val addr = InetAddress.getByName("239.0.0.1") as Inet4Address
        mcastAddrs.add(addr)
        doReturn(mcastAddrs).`when`(dependencies).getIPv4MulticastAddresses(any())
        val testPacket = HexDump.hexStringToByteArray("000000")
        Os.write(igmpWriteSocket, testPacket, 0, testPacket.size)
        consumeInstalledProgram(apfController, installCnt = 1)

        Os.write(igmpWriteSocket, testPacket, 0, testPacket.size)
        Thread.sleep(NO_CALLBACK_TIMEOUT_MS)
        verify(apfController, never()).installPacketFilter(any())

        mcastAddrs.remove(addr)
        doReturn(mcastAddrs).`when`(dependencies).getIPv4MulticastAddresses(any())
        Os.write(igmpWriteSocket, testPacket, 0, testPacket.size)
        consumeInstalledProgram(apfController, installCnt = 1)
    }

    @Test
    fun testApfFilterInitializationCleanUpTheApfMemoryRegion() {
        val apfFilter = getApfFilter()
        val programCaptor = ArgumentCaptor.forClass(ByteArray::class.java)
        verify(apfController, times(2)).installPacketFilter(programCaptor.capture())
        val program = programCaptor.allValues.first()
        assertContentEquals(ByteArray(4096) { 0 }, program)
    }

    @Test
    fun testApfFilterResumeWillCleanUpTheApfMemoryRegion() {
        val apfFilter = getApfFilter()
        consumeInstalledProgram(apfController, installCnt = 2)
        apfFilter.resume()
        val program = consumeInstalledProgram(apfController, installCnt = 1)
        assertContentEquals(ByteArray(4096) { 0 }, program)
    }

    @Test
    fun testApfIPv4MulticastAddrsUpdate() {
        // mock IPv4 multicast address from /proc/net/igmp
        val mcastAddrs = mutableListOf(
            InetAddress.getByName("224.0.0.1") as Inet4Address,
            InetAddress.getByName("239.0.0.1") as Inet4Address
        )
        val mcastAddrsExcludeAllHost = mutableListOf(
            InetAddress.getByName("239.0.0.1") as Inet4Address
        )
        doReturn(mcastAddrs).`when`(dependencies).getIPv4MulticastAddresses(any())
        val apfFilter = getApfFilter()
        consumeInstalledProgram(apfController, installCnt = 2)
        assertEquals(mcastAddrs.toSet(), apfFilter.mIPv4MulticastAddresses)
        assertEquals(mcastAddrsExcludeAllHost.toSet(), apfFilter.mIPv4McastAddrsExcludeAllHost)

        val addr = InetAddress.getByName("239.0.0.2") as Inet4Address
        mcastAddrs.add(addr)
        mcastAddrsExcludeAllHost.add(addr)
        doReturn(mcastAddrs).`when`(dependencies).getIPv4MulticastAddresses(any())
        apfFilter.updateIPv4MulticastAddrs()
        consumeInstalledProgram(apfController, installCnt = 1)
        assertEquals(mcastAddrs.toSet(), apfFilter.mIPv4MulticastAddresses)
        assertEquals(mcastAddrsExcludeAllHost.toSet(), apfFilter.mIPv4McastAddrsExcludeAllHost)

        apfFilter.updateIPv4MulticastAddrs()
        verify(apfController, never()).installPacketFilter(any())
    }

    @Test
    fun testApfFailOpenOnLimitedRAM() {
        val apfConfig = getDefaultConfig()
        apfConfig.apfRamSize = 256
        val apfFilter = getApfFilter(apfConfig)
        val program = consumeInstalledProgram(apfController, installCnt = 2)
        assertContentEquals(
            ByteArray(apfConfig.apfRamSize - ApfCounterTracker.Counter.totalSize()) { 0 },
            program
        )
    }
}
