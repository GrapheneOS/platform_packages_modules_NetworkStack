/*
 * Copyright (C) 2012 The Android Open Source Project
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

import static android.net.apf.ApfJniUtils.dropsAllPackets;
import static android.net.apf.ApfTestHelpers.TIMEOUT_MS;
import static android.system.OsConstants.AF_UNIX;
import static android.net.apf.ApfTestHelpers.DROP;
import static android.net.apf.ApfTestHelpers.PASS;
import static android.system.OsConstants.ETH_P_ARP;
import static android.system.OsConstants.ETH_P_IP;
import static android.system.OsConstants.ETH_P_IPV6;
import static android.system.OsConstants.IPPROTO_ICMPV6;
import static android.system.OsConstants.IPPROTO_TCP;
import static android.system.OsConstants.IPPROTO_UDP;
import static android.system.OsConstants.SOCK_STREAM;

import static com.android.net.module.util.HexDump.hexStringToByteArray;
import static com.android.net.module.util.NetworkStackConstants.ICMPV6_ECHO_REQUEST_TYPE;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import android.content.Context;
import android.net.IpPrefix;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.NattKeepalivePacketDataParcelable;
import android.net.TcpKeepalivePacketDataParcelable;
import android.net.apf.ApfCounterTracker.Counter;
import android.net.apf.ApfFilter.ApfConfiguration;
import android.net.ip.IIpClientCallbacks;
import android.net.ip.IpClient;
import android.net.metrics.IpConnectivityLog;
import android.os.Build;
import android.os.ConditionVariable;
import android.os.PowerManager;
import android.stats.connectivity.NetworkQuirkEvent;
import android.system.ErrnoException;
import android.system.Os;
import android.text.format.DateUtils;
import android.util.ArrayMap;
import android.util.Log;

import androidx.test.InstrumentationRegistry;
import androidx.test.filters.SmallTest;

import com.android.internal.annotations.GuardedBy;
import com.android.internal.util.HexDump;
import com.android.net.module.util.InterfaceParams;
import com.android.net.module.util.NetworkStackConstants;
import com.android.net.module.util.SharedLog;
import com.android.networkstack.apishim.NetworkInformationShimImpl;
import com.android.networkstack.metrics.ApfSessionInfoMetrics;
import com.android.networkstack.metrics.IpClientRaInfoMetrics;
import com.android.networkstack.metrics.NetworkQuirkMetrics;
import com.android.server.networkstack.tests.R;
import com.android.testutils.ConcurrentUtils;
import com.android.testutils.DevSdkIgnoreRule;
import com.android.testutils.DevSdkIgnoreRunner;

import libcore.io.IoUtils;
import libcore.io.Streams;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * Tests for APF program generator and interpreter.
 *
 * The test cases will be executed by both APFv4 and APFv6 interpreter.
 */
@DevSdkIgnoreRunner.MonitorThreadLeak
@RunWith(DevSdkIgnoreRunner.class)
@SmallTest
public class LegacyApfTest {
    private static final int APF_VERSION_2 = 2;

    @Rule
    public DevSdkIgnoreRule mDevSdkIgnoreRule = new DevSdkIgnoreRule();
    // Indicates which apf interpreter to run.
    @Parameterized.Parameter()
    public int mApfVersion;

    @Parameterized.Parameters
    public static Iterable<? extends Object> data() {
        return Arrays.asList(4, 6);
    }

    @Mock private Context mContext;
    @Mock
    private ApfFilter.Dependencies mDependencies;
    @Mock private PowerManager mPowerManager;
    @Mock private IpConnectivityLog mIpConnectivityLog;
    @Mock private NetworkQuirkMetrics mNetworkQuirkMetrics;
    @Mock private ApfSessionInfoMetrics mApfSessionInfoMetrics;
    @Mock private IpClientRaInfoMetrics mIpClientRaInfoMetrics;
    @Mock private LegacyApfFilter.Clock mClock;
    @GuardedBy("mApfFilterCreated")
    private final ArrayList<AndroidPacketFilter> mApfFilterCreated = new ArrayList<>();
    @GuardedBy("mThreadsToBeCleared")
    private final ArrayList<Thread> mThreadsToBeCleared = new ArrayList<>();

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        doReturn(mPowerManager).when(mContext).getSystemService(PowerManager.class);
        doReturn(mApfSessionInfoMetrics).when(mDependencies).getApfSessionInfoMetrics();
        doReturn(mIpClientRaInfoMetrics).when(mDependencies).getIpClientRaInfoMetrics();
        doAnswer((invocation) -> {
            synchronized (mApfFilterCreated) {
                mApfFilterCreated.add(invocation.getArgument(0));
            }
            return null;
        }).when(mDependencies).onApfFilterCreated(any());
        doAnswer((invocation) -> {
            synchronized (mThreadsToBeCleared) {
                mThreadsToBeCleared.add(invocation.getArgument(0));
            }
            return null;
        }).when(mDependencies).onThreadCreated(any());
    }

    private void quitThreads() throws Exception {
        ConcurrentUtils.quitThreads(
                THREAD_QUIT_MAX_RETRY_COUNT,
                false /* interrupt */,
                HANDLER_TIMEOUT_MS,
                () -> {
                    synchronized (mThreadsToBeCleared) {
                        final ArrayList<Thread> ret = new ArrayList<>(mThreadsToBeCleared);
                        mThreadsToBeCleared.clear();
                        return ret;
                    }
                });
    }

    private void shutdownApfFilters() throws Exception {
        ConcurrentUtils.quitResources(THREAD_QUIT_MAX_RETRY_COUNT, () -> {
            synchronized (mApfFilterCreated) {
                final ArrayList<AndroidPacketFilter> ret =
                        new ArrayList<>(mApfFilterCreated);
                mApfFilterCreated.clear();
                return ret;
            }
        }, (apf) -> {
            apf.shutdown();
        });
        synchronized (mApfFilterCreated) {
            assertEquals("ApfFilters did not fully shutdown.",
                    0, mApfFilterCreated.size());
        }
        // It's necessary to wait until all ReceiveThreads have finished running because
        // clearInlineMocks clears all Mock objects, including some privilege frameworks
        // required by logStats, at the end of ReceiveThread#run.
        quitThreads();
    }

    @After
    public void tearDown() throws Exception {
        shutdownApfFilters();
        // Clear mocks to prevent from stubs holding instances and cause memory leaks.
        Mockito.framework().clearInlineMocks();
    }

    private static final String TAG = "ApfTest";

    private static final boolean DROP_MULTICAST = true;
    private static final boolean ALLOW_MULTICAST = false;

    private static final boolean DROP_802_3_FRAMES = true;
    private static final boolean ALLOW_802_3_FRAMES = false;

    private static final int MIN_RDNSS_LIFETIME_SEC = 0;
    private static final int MIN_METRICS_SESSION_DURATIONS_MS = 300_000;

    private static final int HANDLER_TIMEOUT_MS = 1000;
    private static final int THREAD_QUIT_MAX_RETRY_COUNT = 3;

    // Constants for opcode encoding
    private static final byte LI_OP   = (byte)(13 << 3);
    private static final byte LDDW_OP = (byte)(22 << 3);
    private static final byte STDW_OP = (byte)(23 << 3);
    private static final byte SIZE0   = (byte)(0 << 1);
    private static final byte SIZE8   = (byte)(1 << 1);
    private static final byte SIZE16  = (byte)(2 << 1);
    private static final byte SIZE32  = (byte)(3 << 1);
    private static final byte R1_REG = 1;

    private static ApfConfiguration getDefaultConfig() {
        ApfFilter.ApfConfiguration config = new ApfConfiguration();
        config.apfVersionSupported = 2;
        config.apfRamSize = 4096;
        config.multicastFilter = ALLOW_MULTICAST;
        config.ieee802_3Filter = ALLOW_802_3_FRAMES;
        config.ethTypeBlackList = new int[0];
        config.minRdnssLifetimeSec = MIN_RDNSS_LIFETIME_SEC;
        config.minRdnssLifetimeSec = 67;
        config.minMetricsSessionDurationMs = MIN_METRICS_SESSION_DURATIONS_MS;
        return config;
    }

    private void assertPass(ApfV4Generator gen) throws ApfV4Generator.IllegalInstructionException {
        ApfTestHelpers.assertPass(mApfVersion, gen);
    }

    private void assertDrop(ApfV4Generator gen) throws ApfV4Generator.IllegalInstructionException {
        ApfTestHelpers.assertDrop(mApfVersion, gen);
    }

    private void assertPass(byte[] program, byte[] packet) {
        ApfTestHelpers.assertPass(mApfVersion, program, packet);
    }

    private void assertDrop(byte[] program, byte[] packet) {
        ApfTestHelpers.assertDrop(mApfVersion, program, packet);
    }

    private void assertPass(byte[] program, byte[] packet, int filterAge) {
        ApfTestHelpers.assertPass(mApfVersion, program, packet, filterAge);
    }

    private void assertDrop(byte[] program, byte[] packet, int filterAge) {
        ApfTestHelpers.assertDrop(mApfVersion, program, packet, filterAge);
    }

    private void assertPass(ApfV4Generator gen, byte[] packet, int filterAge)
            throws ApfV4Generator.IllegalInstructionException {
        ApfTestHelpers.assertPass(mApfVersion, gen, packet, filterAge);
    }

    private void assertDrop(ApfV4Generator gen, byte[] packet, int filterAge)
            throws ApfV4Generator.IllegalInstructionException {
        ApfTestHelpers.assertDrop(mApfVersion, gen, packet, filterAge);
    }

    private void assertDataMemoryContents(int expected, byte[] program, byte[] packet,
            byte[] data, byte[] expectedData) throws Exception {
        ApfTestHelpers.assertDataMemoryContents(mApfVersion, expected, program, packet, data,
                expectedData, false /* ignoreInterpreterVersion */);
    }

    private void assertDataMemoryContentsIgnoreVersion(int expected, byte[] program,
            byte[] packet, byte[] data, byte[] expectedData) throws Exception {
        ApfTestHelpers.assertDataMemoryContents(mApfVersion, expected, program, packet, data,
                expectedData, true /* ignoreInterpreterVersion */);
    }

    private void assertVerdict(String msg, int expected, byte[] program,
            byte[] packet, int filterAge) {
        ApfTestHelpers.assertVerdict(mApfVersion, msg, expected, program, packet, filterAge);
    }

    private void assertVerdict(int expected, byte[] program, byte[] packet) {
        ApfTestHelpers.assertVerdict(mApfVersion, expected, program, packet);
    }

    /**
     * Generate APF program, run pcap file though APF filter, then check all the packets in the file
     * should be dropped.
     */
    @Test
    public void testApfFilterPcapFile() throws Exception {
        final byte[] MOCK_PCAP_IPV4_ADDR = {(byte) 172, 16, 7, (byte) 151};
        String pcapFilename = stageFile(R.raw.apfPcap);
        MockIpClientCallback ipClientCallback = new MockIpClientCallback();
        LinkAddress link = new LinkAddress(InetAddress.getByAddress(MOCK_PCAP_IPV4_ADDR), 16);
        LinkProperties lp = new LinkProperties();
        lp.addLinkAddress(link);

        ApfConfiguration config = getDefaultConfig();
        config.apfVersionSupported = 4;
        config.apfRamSize = 1700;
        config.multicastFilter = DROP_MULTICAST;
        config.ieee802_3Filter = DROP_802_3_FRAMES;
        TestLegacyApfFilter apfFilter = new TestLegacyApfFilter(mContext, config, ipClientCallback,
                mIpConnectivityLog, mNetworkQuirkMetrics, mDependencies, mClock);
        apfFilter.setLinkProperties(lp);
        byte[] program = ipClientCallback.assertProgramUpdateAndGet();
        byte[] data = new byte[Counter.totalSize()];
        final boolean result;

        result = dropsAllPackets(mApfVersion, program, data, pcapFilename);
        Log.i(TAG, "testApfFilterPcapFile(): Data counters: " + HexDump.toHexString(data, false));

        assertTrue("Failed to drop all packets by filter. \nAPF counters:" +
            HexDump.toHexString(data, false), result);
    }

    private static final int ETH_HEADER_LEN               = 14;
    private static final int ETH_DEST_ADDR_OFFSET         = 0;
    private static final int ETH_ETHERTYPE_OFFSET         = 12;
    private static final byte[] ETH_BROADCAST_MAC_ADDRESS =
            {(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff };
    private static final byte[] ETH_MULTICAST_MDNS_v4_MAC_ADDRESS =
            {(byte) 0x01, (byte) 0x00, (byte) 0x5e, (byte) 0x00, (byte) 0x00, (byte) 0xfb};
    private static final byte[] ETH_MULTICAST_MDNS_V6_MAC_ADDRESS =
            {(byte) 0x33, (byte) 0x33, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xfb};

    private static final int IP_HEADER_OFFSET = ETH_HEADER_LEN;

    private static final int IPV4_HEADER_LEN          = 20;
    private static final int IPV4_TOTAL_LENGTH_OFFSET = IP_HEADER_OFFSET + 2;
    private static final int IPV4_PROTOCOL_OFFSET     = IP_HEADER_OFFSET + 9;
    private static final int IPV4_SRC_ADDR_OFFSET     = IP_HEADER_OFFSET + 12;
    private static final int IPV4_DEST_ADDR_OFFSET    = IP_HEADER_OFFSET + 16;

    private static final int IPV4_TCP_HEADER_LEN           = 20;
    private static final int IPV4_TCP_HEADER_OFFSET        = IP_HEADER_OFFSET + IPV4_HEADER_LEN;
    private static final int IPV4_TCP_SRC_PORT_OFFSET      = IPV4_TCP_HEADER_OFFSET + 0;
    private static final int IPV4_TCP_DEST_PORT_OFFSET     = IPV4_TCP_HEADER_OFFSET + 2;
    private static final int IPV4_TCP_SEQ_NUM_OFFSET       = IPV4_TCP_HEADER_OFFSET + 4;
    private static final int IPV4_TCP_ACK_NUM_OFFSET       = IPV4_TCP_HEADER_OFFSET + 8;
    private static final int IPV4_TCP_HEADER_LENGTH_OFFSET = IPV4_TCP_HEADER_OFFSET + 12;
    private static final int IPV4_TCP_HEADER_FLAG_OFFSET   = IPV4_TCP_HEADER_OFFSET + 13;

    private static final int IPV4_UDP_HEADER_OFFSET    = IP_HEADER_OFFSET + IPV4_HEADER_LEN;
    private static final int IPV4_UDP_SRC_PORT_OFFSET  = IPV4_UDP_HEADER_OFFSET + 0;
    private static final int IPV4_UDP_DEST_PORT_OFFSET = IPV4_UDP_HEADER_OFFSET + 2;
    private static final int IPV4_UDP_LENGTH_OFFSET    = IPV4_UDP_HEADER_OFFSET + 4;
    private static final int IPV4_UDP_PAYLOAD_OFFSET   = IPV4_UDP_HEADER_OFFSET + 8;
    private static final byte[] IPV4_BROADCAST_ADDRESS =
            {(byte) 255, (byte) 255, (byte) 255, (byte) 255};

    private static final int IPV6_HEADER_LEN             = 40;
    private static final int IPV6_PAYLOAD_LENGTH_OFFSET  = IP_HEADER_OFFSET + 4;
    private static final int IPV6_NEXT_HEADER_OFFSET     = IP_HEADER_OFFSET + 6;
    private static final int IPV6_SRC_ADDR_OFFSET        = IP_HEADER_OFFSET + 8;
    private static final int IPV6_DEST_ADDR_OFFSET       = IP_HEADER_OFFSET + 24;
    private static final int IPV6_PAYLOAD_OFFSET = IP_HEADER_OFFSET + IPV6_HEADER_LEN;
    private static final int IPV6_TCP_SRC_PORT_OFFSET    = IPV6_PAYLOAD_OFFSET + 0;
    private static final int IPV6_TCP_DEST_PORT_OFFSET   = IPV6_PAYLOAD_OFFSET + 2;
    private static final int IPV6_TCP_SEQ_NUM_OFFSET     = IPV6_PAYLOAD_OFFSET + 4;
    private static final int IPV6_TCP_ACK_NUM_OFFSET     = IPV6_PAYLOAD_OFFSET + 8;
    // The IPv6 all nodes address ff02::1
    private static final byte[] IPV6_ALL_NODES_ADDRESS   =
            { (byte) 0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    private static final byte[] IPV6_ALL_ROUTERS_ADDRESS =
            { (byte) 0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };
    private static final byte[] IPV6_SOLICITED_NODE_MULTICAST_ADDRESS = {
            (byte) 0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            (byte) 0xff, (byte) 0xab, (byte) 0xcd, (byte) 0xef,
    };

    private static final int ICMP6_TYPE_OFFSET           = IP_HEADER_OFFSET + IPV6_HEADER_LEN;
    private static final int ICMP6_ROUTER_SOLICITATION   = 133;
    private static final int ICMP6_ROUTER_ADVERTISEMENT  = 134;
    private static final int ICMP6_NEIGHBOR_SOLICITATION = 135;
    private static final int ICMP6_NEIGHBOR_ANNOUNCEMENT = 136;

    private static final int ICMP6_RA_HEADER_LEN = 16;
    private static final int ICMP6_RA_CHECKSUM_OFFSET =
            IP_HEADER_OFFSET + IPV6_HEADER_LEN + 2;
    private static final int ICMP6_RA_ROUTER_LIFETIME_OFFSET =
            IP_HEADER_OFFSET + IPV6_HEADER_LEN + 6;
    private static final int ICMP6_RA_REACHABLE_TIME_OFFSET =
            IP_HEADER_OFFSET + IPV6_HEADER_LEN + 8;
    private static final int ICMP6_RA_RETRANSMISSION_TIMER_OFFSET =
            IP_HEADER_OFFSET + IPV6_HEADER_LEN + 12;
    private static final int ICMP6_RA_OPTION_OFFSET =
            IP_HEADER_OFFSET + IPV6_HEADER_LEN + ICMP6_RA_HEADER_LEN;

    private static final int ICMP6_PREFIX_OPTION_TYPE                      = 3;
    private static final int ICMP6_PREFIX_OPTION_LEN                       = 32;
    private static final int ICMP6_PREFIX_OPTION_VALID_LIFETIME_OFFSET     = 4;
    private static final int ICMP6_PREFIX_OPTION_PREFERRED_LIFETIME_OFFSET = 8;

    // From RFC6106: Recursive DNS Server option
    private static final int ICMP6_RDNSS_OPTION_TYPE = 25;
    // From RFC6106: DNS Search List option
    private static final int ICMP6_DNSSL_OPTION_TYPE = 31;

    // From RFC4191: Route Information option
    private static final int ICMP6_ROUTE_INFO_OPTION_TYPE = 24;
    // Above three options all have the same format:
    private static final int ICMP6_4_BYTE_OPTION_LEN      = 8;
    private static final int ICMP6_4_BYTE_LIFETIME_OFFSET = 4;
    private static final int ICMP6_4_BYTE_LIFETIME_LEN    = 4;

    private static final int UDP_HEADER_LEN              = 8;
    private static final int UDP_DESTINATION_PORT_OFFSET = ETH_HEADER_LEN + 22;

    private static final int DHCP_CLIENT_PORT       = 68;
    private static final int DHCP_CLIENT_MAC_OFFSET = ETH_HEADER_LEN + UDP_HEADER_LEN + 48;

    private static final int ARP_HEADER_OFFSET          = ETH_HEADER_LEN;
    private static final byte[] ARP_IPV4_REQUEST_HEADER = {
            0, 1, // Hardware type: Ethernet (1)
            8, 0, // Protocol type: IP (0x0800)
            6,    // Hardware size: 6
            4,    // Protocol size: 4
            0, 1  // Opcode: request (1)
    };
    private static final byte[] ARP_IPV4_REPLY_HEADER = {
            0, 1, // Hardware type: Ethernet (1)
            8, 0, // Protocol type: IP (0x0800)
            6,    // Hardware size: 6
            4,    // Protocol size: 4
            0, 2  // Opcode: reply (2)
    };
    private static final int ARP_SOURCE_IP_ADDRESS_OFFSET = ARP_HEADER_OFFSET + 14;
    private static final int ARP_TARGET_IP_ADDRESS_OFFSET = ARP_HEADER_OFFSET + 24;

    private static final byte[] MOCK_IPV4_ADDR           = {10, 0, 0, 1};
    private static final byte[] MOCK_BROADCAST_IPV4_ADDR = {10, 0, 31, (byte) 255}; // prefix = 19
    private static final byte[] MOCK_MULTICAST_IPV4_ADDR = {(byte) 224, 0, 0, 1};
    private static final byte[] ANOTHER_IPV4_ADDR        = {10, 0, 0, 2};
    private static final byte[] IPV4_SOURCE_ADDR         = {10, 0, 0, 3};
    private static final byte[] ANOTHER_IPV4_SOURCE_ADDR = {(byte) 192, 0, 2, 1};
    private static final byte[] BUG_PROBE_SOURCE_ADDR1   = {0, 0, 1, 2};
    private static final byte[] BUG_PROBE_SOURCE_ADDR2   = {3, 4, 0, 0};
    private static final byte[] IPV4_ANY_HOST_ADDR       = {0, 0, 0, 0};
    private static final byte[] IPV4_MDNS_MULTICAST_ADDR = {(byte) 224, 0, 0, (byte) 251};
    private static final byte[] IPV6_MDNS_MULTICAST_ADDR =
            {(byte) 0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 0xfb};
    private static final int IPV6_UDP_DEST_PORT_OFFSET = IPV6_PAYLOAD_OFFSET + 2;
    private static final int MDNS_UDP_PORT = 5353;

    private static void setIpv4VersionFields(ByteBuffer packet) {
        packet.putShort(ETH_ETHERTYPE_OFFSET, (short) ETH_P_IP);
        packet.put(IP_HEADER_OFFSET, (byte) 0x45);
    }

    private static void setIpv6VersionFields(ByteBuffer packet) {
        packet.putShort(ETH_ETHERTYPE_OFFSET, (short) ETH_P_IPV6);
        packet.put(IP_HEADER_OFFSET, (byte) 0x60);
    }

    private static ByteBuffer makeIpv4Packet(int proto) {
        ByteBuffer packet = ByteBuffer.wrap(new byte[100]);
        setIpv4VersionFields(packet);
        packet.put(IPV4_PROTOCOL_OFFSET, (byte) proto);
        return packet;
    }

    private static ByteBuffer makeIpv6Packet(int nextHeader) {
        ByteBuffer packet = ByteBuffer.wrap(new byte[100]);
        setIpv6VersionFields(packet);
        packet.put(IPV6_NEXT_HEADER_OFFSET, (byte) nextHeader);
        return packet;
    }

    @Test
    public void testApfFilterIPv4() throws Exception {
        MockIpClientCallback ipClientCallback = new MockIpClientCallback();
        LinkAddress link = new LinkAddress(InetAddress.getByAddress(MOCK_IPV4_ADDR), 19);
        LinkProperties lp = new LinkProperties();
        lp.addLinkAddress(link);

        ApfConfiguration config = getDefaultConfig();
        config.multicastFilter = DROP_MULTICAST;
        TestLegacyApfFilter apfFilter = new TestLegacyApfFilter(mContext, config, ipClientCallback,
                mIpConnectivityLog, mNetworkQuirkMetrics, mDependencies, mClock);
        apfFilter.setLinkProperties(lp);

        byte[] program = ipClientCallback.assertProgramUpdateAndGet();

        ByteBuffer packet = ByteBuffer.wrap(new byte[100]);
        // Verify empty packet of 100 zero bytes is passed
        assertPass(program, packet.array());

        // Verify unicast IPv4 packet is passed
        put(packet, ETH_DEST_ADDR_OFFSET, TestLegacyApfFilter.MOCK_MAC_ADDR);
        packet.putShort(ETH_ETHERTYPE_OFFSET, (short)ETH_P_IP);
        put(packet, IPV4_DEST_ADDR_OFFSET, MOCK_IPV4_ADDR);
        assertPass(program, packet.array());

        // Verify L2 unicast to IPv4 broadcast addresses is dropped (b/30231088)
        put(packet, IPV4_DEST_ADDR_OFFSET, IPV4_BROADCAST_ADDRESS);
        assertDrop(program, packet.array());
        put(packet, IPV4_DEST_ADDR_OFFSET, MOCK_BROADCAST_IPV4_ADDR);
        assertDrop(program, packet.array());

        // Verify multicast/broadcast IPv4, not DHCP to us, is dropped
        put(packet, ETH_DEST_ADDR_OFFSET, ETH_BROADCAST_MAC_ADDRESS);
        assertDrop(program, packet.array());
        packet.put(IP_HEADER_OFFSET, (byte) 0x45);
        assertDrop(program, packet.array());
        packet.put(IPV4_PROTOCOL_OFFSET, (byte)IPPROTO_UDP);
        assertDrop(program, packet.array());
        packet.putShort(UDP_DESTINATION_PORT_OFFSET, (short)DHCP_CLIENT_PORT);
        assertDrop(program, packet.array());
        put(packet, IPV4_DEST_ADDR_OFFSET, MOCK_MULTICAST_IPV4_ADDR);
        assertDrop(program, packet.array());
        put(packet, IPV4_DEST_ADDR_OFFSET, MOCK_BROADCAST_IPV4_ADDR);
        assertDrop(program, packet.array());
        put(packet, IPV4_DEST_ADDR_OFFSET, IPV4_BROADCAST_ADDRESS);
        assertDrop(program, packet.array());

        // Verify broadcast IPv4 DHCP to us is passed
        put(packet, DHCP_CLIENT_MAC_OFFSET, TestLegacyApfFilter.MOCK_MAC_ADDR);
        assertPass(program, packet.array());

        // Verify unicast IPv4 DHCP to us is passed
        put(packet, ETH_DEST_ADDR_OFFSET, TestLegacyApfFilter.MOCK_MAC_ADDR);
        assertPass(program, packet.array());
    }

    @Test
    public void testApfFilterIPv6() throws Exception {
        MockIpClientCallback ipClientCallback = new MockIpClientCallback();
        ApfConfiguration config = getDefaultConfig();
        TestLegacyApfFilter apfFilter = new TestLegacyApfFilter(mContext, config, ipClientCallback,
                mIpConnectivityLog, mNetworkQuirkMetrics, mDependencies, mClock);
        byte[] program = ipClientCallback.assertProgramUpdateAndGet();

        // Verify empty IPv6 packet is passed
        ByteBuffer packet = makeIpv6Packet(IPPROTO_UDP);
        assertPass(program, packet.array());

        // Verify empty ICMPv6 packet is passed
        packet.put(IPV6_NEXT_HEADER_OFFSET, (byte)IPPROTO_ICMPV6);
        assertPass(program, packet.array());

        // Verify empty ICMPv6 NA packet is passed
        packet.put(ICMP6_TYPE_OFFSET, (byte)ICMP6_NEIGHBOR_ANNOUNCEMENT);
        assertPass(program, packet.array());

        // Verify ICMPv6 NA to ff02::1 is dropped
        put(packet, IPV6_DEST_ADDR_OFFSET, IPV6_ALL_NODES_ADDRESS);
        assertDrop(program, packet.array());

        // Verify ICMPv6 NA to ff02::2 is dropped
        put(packet, IPV6_DEST_ADDR_OFFSET, IPV6_ALL_ROUTERS_ADDRESS);
        assertDrop(program, packet.array());

        // Verify ICMPv6 NA to Solicited-Node Multicast is passed
        put(packet, IPV6_DEST_ADDR_OFFSET, IPV6_SOLICITED_NODE_MULTICAST_ADDRESS);
        assertPass(program, packet.array());

        // Verify ICMPv6 RS to any is dropped
        packet.put(ICMP6_TYPE_OFFSET, (byte)ICMP6_ROUTER_SOLICITATION);
        assertDrop(program, packet.array());
        put(packet, IPV6_DEST_ADDR_OFFSET, IPV6_ALL_ROUTERS_ADDRESS);
        assertDrop(program, packet.array());
    }

    @Test
    public void testApfFilterMulticast() throws Exception {
        final byte[] unicastIpv4Addr   = {(byte)192,0,2,63};
        final byte[] broadcastIpv4Addr = {(byte)192,0,2,(byte)255};
        final byte[] multicastIpv4Addr = {(byte)224,0,0,1};
        final byte[] multicastIpv6Addr = {(byte)0xff,2,0,0,0,0,0,0,0,0,0,0,0,0,0,(byte)0xfb};

        MockIpClientCallback ipClientCallback = new MockIpClientCallback();
        LinkAddress link = new LinkAddress(InetAddress.getByAddress(unicastIpv4Addr), 24);
        LinkProperties lp = new LinkProperties();
        lp.addLinkAddress(link);

        ApfConfiguration config = getDefaultConfig();
        config.ieee802_3Filter = DROP_802_3_FRAMES;
        TestLegacyApfFilter apfFilter = new TestLegacyApfFilter(mContext, config, ipClientCallback,
                mIpConnectivityLog, mNetworkQuirkMetrics, mDependencies, mClock);
        apfFilter.setLinkProperties(lp);

        byte[] program = ipClientCallback.assertProgramUpdateAndGet();

        // Construct IPv4 and IPv6 multicast packets.
        ByteBuffer mcastv4packet = makeIpv4Packet(IPPROTO_UDP);
        put(mcastv4packet, IPV4_DEST_ADDR_OFFSET, multicastIpv4Addr);

        ByteBuffer mcastv6packet = makeIpv6Packet(IPPROTO_UDP);
        put(mcastv6packet, IPV6_DEST_ADDR_OFFSET, multicastIpv6Addr);

        // Construct IPv4 broadcast packet.
        ByteBuffer bcastv4packet1 = makeIpv4Packet(IPPROTO_UDP);
        bcastv4packet1.put(ETH_BROADCAST_MAC_ADDRESS);
        bcastv4packet1.putShort(ETH_ETHERTYPE_OFFSET, (short)ETH_P_IP);
        put(bcastv4packet1, IPV4_DEST_ADDR_OFFSET, multicastIpv4Addr);

        ByteBuffer bcastv4packet2 = makeIpv4Packet(IPPROTO_UDP);
        bcastv4packet2.put(ETH_BROADCAST_MAC_ADDRESS);
        bcastv4packet2.putShort(ETH_ETHERTYPE_OFFSET, (short)ETH_P_IP);
        put(bcastv4packet2, IPV4_DEST_ADDR_OFFSET, IPV4_BROADCAST_ADDRESS);

        // Construct IPv4 broadcast with L2 unicast address packet (b/30231088).
        ByteBuffer bcastv4unicastl2packet = makeIpv4Packet(IPPROTO_UDP);
        bcastv4unicastl2packet.put(TestLegacyApfFilter.MOCK_MAC_ADDR);
        bcastv4unicastl2packet.putShort(ETH_ETHERTYPE_OFFSET, (short)ETH_P_IP);
        put(bcastv4unicastl2packet, IPV4_DEST_ADDR_OFFSET, broadcastIpv4Addr);

        // Verify initially disabled multicast filter is off
        assertPass(program, mcastv4packet.array());
        assertPass(program, mcastv6packet.array());
        assertPass(program, bcastv4packet1.array());
        assertPass(program, bcastv4packet2.array());
        assertPass(program, bcastv4unicastl2packet.array());

        // Turn on multicast filter and verify it works
        ipClientCallback.resetApfProgramWait();
        apfFilter.setMulticastFilter(true);
        program = ipClientCallback.assertProgramUpdateAndGet();
        assertDrop(program, mcastv4packet.array());
        assertDrop(program, mcastv6packet.array());
        assertDrop(program, bcastv4packet1.array());
        assertDrop(program, bcastv4packet2.array());
        assertDrop(program, bcastv4unicastl2packet.array());

        // Turn off multicast filter and verify it's off
        ipClientCallback.resetApfProgramWait();
        apfFilter.setMulticastFilter(false);
        program = ipClientCallback.assertProgramUpdateAndGet();
        assertPass(program, mcastv4packet.array());
        assertPass(program, mcastv6packet.array());
        assertPass(program, bcastv4packet1.array());
        assertPass(program, bcastv4packet2.array());
        assertPass(program, bcastv4unicastl2packet.array());

        // Verify it can be initialized to on
        ipClientCallback.resetApfProgramWait();
        config.multicastFilter = DROP_MULTICAST;
        config.ieee802_3Filter = DROP_802_3_FRAMES;
        apfFilter =  new TestLegacyApfFilter(mContext, config, ipClientCallback,
                mIpConnectivityLog, mNetworkQuirkMetrics, mDependencies, mClock);
        apfFilter.setLinkProperties(lp);
        program = ipClientCallback.assertProgramUpdateAndGet();
        assertDrop(program, mcastv4packet.array());
        assertDrop(program, mcastv6packet.array());
        assertDrop(program, bcastv4packet1.array());
        assertDrop(program, bcastv4unicastl2packet.array());

        // Verify that ICMPv6 multicast is not dropped.
        mcastv6packet.put(IPV6_NEXT_HEADER_OFFSET, (byte)IPPROTO_ICMPV6);
        assertPass(program, mcastv6packet.array());
    }

    @Test
    public void testApfFilterMulticastPingWhileDozing() throws Exception {
        MockIpClientCallback ipClientCallback = new MockIpClientCallback();
        final ApfConfiguration configuration = getDefaultConfig();
        final LegacyApfFilter apfFilter = new TestLegacyApfFilter(mContext, configuration,
                ipClientCallback, mIpConnectivityLog, mNetworkQuirkMetrics, mDependencies, mClock);

        // Construct a multicast ICMPv6 ECHO request.
        final byte[] multicastIpv6Addr = {(byte)0xff,2,0,0,0,0,0,0,0,0,0,0,0,0,0,(byte)0xfb};
        ByteBuffer packet = makeIpv6Packet(IPPROTO_ICMPV6);
        packet.put(ICMP6_TYPE_OFFSET, (byte)ICMPV6_ECHO_REQUEST_TYPE);
        put(packet, IPV6_DEST_ADDR_OFFSET, multicastIpv6Addr);

        // Normally, we let multicast pings alone...
        assertPass(ipClientCallback.assertProgramUpdateAndGet(), packet.array());

        // ...and even while dozing...
        apfFilter.setDozeMode(true);
        assertPass(ipClientCallback.assertProgramUpdateAndGet(), packet.array());

        // ...but when the multicast filter is also enabled, drop the multicast pings to save power.
        apfFilter.setMulticastFilter(true);
        assertDrop(ipClientCallback.assertProgramUpdateAndGet(), packet.array());

        // However, we should still let through all other ICMPv6 types.
        ByteBuffer raPacket = ByteBuffer.wrap(packet.array().clone());
        setIpv6VersionFields(packet);
        packet.put(IPV6_NEXT_HEADER_OFFSET, (byte) IPPROTO_ICMPV6);
        raPacket.put(ICMP6_TYPE_OFFSET, (byte) NetworkStackConstants.ICMPV6_ROUTER_ADVERTISEMENT);
        assertPass(ipClientCallback.assertProgramUpdateAndGet(), raPacket.array());

        // Now wake up from doze mode to ensure that we no longer drop the packets.
        // (The multicast filter is still enabled at this point).
        apfFilter.setDozeMode(false);
        assertPass(ipClientCallback.assertProgramUpdateAndGet(), packet.array());

        apfFilter.shutdown();
    }

    @Test
    @DevSdkIgnoreRule.IgnoreAfter(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    public void testApfFilter802_3() throws Exception {
        MockIpClientCallback ipClientCallback = new MockIpClientCallback();
        ApfConfiguration config = getDefaultConfig();
        TestLegacyApfFilter apfFilter =  new TestLegacyApfFilter(mContext, config, ipClientCallback,
                mIpConnectivityLog, mNetworkQuirkMetrics, mDependencies, mClock);
        byte[] program = ipClientCallback.assertProgramUpdateAndGet();

        // Verify empty packet of 100 zero bytes is passed
        // Note that eth-type = 0 makes it an IEEE802.3 frame
        ByteBuffer packet = ByteBuffer.wrap(new byte[100]);
        assertPass(program, packet.array());

        // Verify empty packet with IPv4 is passed
        setIpv4VersionFields(packet);
        assertPass(program, packet.array());

        // Verify empty IPv6 packet is passed
        setIpv6VersionFields(packet);
        assertPass(program, packet.array());

        // Now turn on the filter
        ipClientCallback.resetApfProgramWait();
        config.ieee802_3Filter = DROP_802_3_FRAMES;
        apfFilter =  new TestLegacyApfFilter(mContext, config, ipClientCallback,
                mIpConnectivityLog, mNetworkQuirkMetrics, mDependencies, mClock);
        program = ipClientCallback.assertProgramUpdateAndGet();

        // Verify that IEEE802.3 frame is dropped
        // In this case ethtype is used for payload length
        packet.putShort(ETH_ETHERTYPE_OFFSET, (short)(100 - 14));
        assertDrop(program, packet.array());

        // Verify that IPv4 (as example of Ethernet II) frame will pass
        setIpv4VersionFields(packet);
        assertPass(program, packet.array());

        // Verify that IPv6 (as example of Ethernet II) frame will pass
        setIpv6VersionFields(packet);
        assertPass(program, packet.array());
    }

    @Test
    @DevSdkIgnoreRule.IgnoreAfter(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    public void testApfFilterEthTypeBL() throws Exception {
        final int[] emptyBlackList = {};
        final int[] ipv4BlackList = {ETH_P_IP};
        final int[] ipv4Ipv6BlackList = {ETH_P_IP, ETH_P_IPV6};

        MockIpClientCallback ipClientCallback = new MockIpClientCallback();
        ApfConfiguration config = getDefaultConfig();
        TestLegacyApfFilter apfFilter =  new TestLegacyApfFilter(mContext, config, ipClientCallback,
                mIpConnectivityLog, mNetworkQuirkMetrics, mDependencies, mClock);
        byte[] program = ipClientCallback.assertProgramUpdateAndGet();

        // Verify empty packet of 100 zero bytes is passed
        // Note that eth-type = 0 makes it an IEEE802.3 frame
        ByteBuffer packet = ByteBuffer.wrap(new byte[100]);
        assertPass(program, packet.array());

        // Verify empty packet with IPv4 is passed
        setIpv4VersionFields(packet);
        assertPass(program, packet.array());

        // Verify empty IPv6 packet is passed
        setIpv6VersionFields(packet);
        assertPass(program, packet.array());

        // Now add IPv4 to the black list
        ipClientCallback.resetApfProgramWait();
        config.ethTypeBlackList = ipv4BlackList;
        apfFilter =  new TestLegacyApfFilter(mContext, config, ipClientCallback,
                mIpConnectivityLog, mNetworkQuirkMetrics, mDependencies, mClock);
        program = ipClientCallback.assertProgramUpdateAndGet();

        // Verify that IPv4 frame will be dropped
        setIpv4VersionFields(packet);
        assertDrop(program, packet.array());

        // Verify that IPv6 frame will pass
        setIpv6VersionFields(packet);
        assertPass(program, packet.array());

        // Now let us have both IPv4 and IPv6 in the black list
        ipClientCallback.resetApfProgramWait();
        config.ethTypeBlackList = ipv4Ipv6BlackList;
        apfFilter =  new TestLegacyApfFilter(mContext, config, ipClientCallback,
                mIpConnectivityLog, mNetworkQuirkMetrics, mDependencies, mClock);
        program = ipClientCallback.assertProgramUpdateAndGet();

        // Verify that IPv4 frame will be dropped
        setIpv4VersionFields(packet);
        assertDrop(program, packet.array());

        // Verify that IPv6 frame will be dropped
        setIpv6VersionFields(packet);
        assertDrop(program, packet.array());
    }

    private byte[] getProgram(MockIpClientCallback cb, TestLegacyApfFilter filter,
            LinkProperties lp) {
        cb.resetApfProgramWait();
        filter.setLinkProperties(lp);
        return cb.assertProgramUpdateAndGet();
    }

    private void verifyArpFilter(byte[] program, int filterResult) {
        // Verify ARP request packet
        assertPass(program, arpRequestBroadcast(MOCK_IPV4_ADDR));
        assertVerdict(filterResult, program, arpRequestBroadcast(ANOTHER_IPV4_ADDR));
        assertVerdict(DROP, program, arpRequestBroadcast(IPV4_ANY_HOST_ADDR));

        // Verify ARP reply packets from different source ip
        assertDrop(program, arpReply(IPV4_ANY_HOST_ADDR, IPV4_ANY_HOST_ADDR));
        assertPass(program, arpReply(ANOTHER_IPV4_SOURCE_ADDR, IPV4_ANY_HOST_ADDR));
        assertPass(program, arpReply(BUG_PROBE_SOURCE_ADDR1, IPV4_ANY_HOST_ADDR));
        assertPass(program, arpReply(BUG_PROBE_SOURCE_ADDR2, IPV4_ANY_HOST_ADDR));

        // Verify unicast ARP reply packet is always accepted.
        assertPass(program, arpReply(IPV4_SOURCE_ADDR, MOCK_IPV4_ADDR));
        assertPass(program, arpReply(IPV4_SOURCE_ADDR, ANOTHER_IPV4_ADDR));
        assertPass(program, arpReply(IPV4_SOURCE_ADDR, IPV4_ANY_HOST_ADDR));

        // Verify GARP reply packets are always filtered
        assertDrop(program, garpReply());
    }

    @Test
    public void testApfFilterArp() throws Exception {
        MockIpClientCallback ipClientCallback = new MockIpClientCallback();
        ApfConfiguration config = getDefaultConfig();
        config.multicastFilter = DROP_MULTICAST;
        config.ieee802_3Filter = DROP_802_3_FRAMES;
        TestLegacyApfFilter apfFilter =  new TestLegacyApfFilter(mContext, config, ipClientCallback,
                mIpConnectivityLog, mNetworkQuirkMetrics, mDependencies, mClock);

        // Verify initially ARP request filter is off, and GARP filter is on.
        verifyArpFilter(ipClientCallback.assertProgramUpdateAndGet(), PASS);

        // Inform ApfFilter of our address and verify ARP filtering is on
        LinkAddress linkAddress = new LinkAddress(InetAddress.getByAddress(MOCK_IPV4_ADDR), 24);
        LinkProperties lp = new LinkProperties();
        assertTrue(lp.addLinkAddress(linkAddress));
        verifyArpFilter(getProgram(ipClientCallback, apfFilter, lp), DROP);

        // Inform ApfFilter of loss of IP and verify ARP filtering is off
        verifyArpFilter(getProgram(ipClientCallback, apfFilter, new LinkProperties()), PASS);
    }

    private static byte[] arpReply(byte[] sip, byte[] tip) {
        ByteBuffer packet = ByteBuffer.wrap(new byte[100]);
        packet.putShort(ETH_ETHERTYPE_OFFSET, (short)ETH_P_ARP);
        put(packet, ARP_HEADER_OFFSET, ARP_IPV4_REPLY_HEADER);
        put(packet, ARP_SOURCE_IP_ADDRESS_OFFSET, sip);
        put(packet, ARP_TARGET_IP_ADDRESS_OFFSET, tip);
        return packet.array();
    }

    private static byte[] arpRequestBroadcast(byte[] tip) {
        ByteBuffer packet = ByteBuffer.wrap(new byte[100]);
        packet.putShort(ETH_ETHERTYPE_OFFSET, (short)ETH_P_ARP);
        put(packet, ETH_DEST_ADDR_OFFSET, ETH_BROADCAST_MAC_ADDRESS);
        put(packet, ARP_HEADER_OFFSET, ARP_IPV4_REQUEST_HEADER);
        put(packet, ARP_TARGET_IP_ADDRESS_OFFSET, tip);
        return packet.array();
    }

    private static byte[] garpReply() {
        ByteBuffer packet = ByteBuffer.wrap(new byte[100]);
        packet.putShort(ETH_ETHERTYPE_OFFSET, (short)ETH_P_ARP);
        put(packet, ETH_DEST_ADDR_OFFSET, ETH_BROADCAST_MAC_ADDRESS);
        put(packet, ARP_HEADER_OFFSET, ARP_IPV4_REPLY_HEADER);
        put(packet, ARP_TARGET_IP_ADDRESS_OFFSET, IPV4_ANY_HOST_ADDR);
        return packet.array();
    }

    private static final byte[] IPV4_KEEPALIVE_SRC_ADDR = {10, 0, 0, 5};
    private static final byte[] IPV4_KEEPALIVE_DST_ADDR = {10, 0, 0, 6};
    private static final byte[] IPV4_ANOTHER_ADDR = {10, 0 , 0, 7};
    private static final byte[] IPV6_KEEPALIVE_SRC_ADDR =
            {(byte) 0x24, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 0xfa, (byte) 0xf1};
    private static final byte[] IPV6_KEEPALIVE_DST_ADDR =
            {(byte) 0x24, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 0xfa, (byte) 0xf2};
    private static final byte[] IPV6_ANOTHER_ADDR =
            {(byte) 0x24, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 0xfa, (byte) 0xf5};

    @Test
    public void testApfFilterKeepaliveAck() throws Exception {
        final MockIpClientCallback cb = new MockIpClientCallback();
        final ApfConfiguration config = getDefaultConfig();
        config.multicastFilter = DROP_MULTICAST;
        config.ieee802_3Filter = DROP_802_3_FRAMES;
        TestLegacyApfFilter apfFilter =  new TestLegacyApfFilter(mContext, config, cb,
                mIpConnectivityLog, mNetworkQuirkMetrics, mDependencies, mClock);
        byte[] program;
        final int srcPort = 12345;
        final int dstPort = 54321;
        final int seqNum = 2123456789;
        final int ackNum = 1234567890;
        final int anotherSrcPort = 23456;
        final int anotherDstPort = 65432;
        final int anotherSeqNum = 2123456780;
        final int anotherAckNum = 1123456789;
        final int slot1 = 1;
        final int slot2 = 2;
        final int window = 14480;
        final int windowScale = 4;

        // src: 10.0.0.5, port: 12345
        // dst: 10.0.0.6, port: 54321
        InetAddress srcAddr = InetAddress.getByAddress(IPV4_KEEPALIVE_SRC_ADDR);
        InetAddress dstAddr = InetAddress.getByAddress(IPV4_KEEPALIVE_DST_ADDR);

        final TcpKeepalivePacketDataParcelable parcel = new TcpKeepalivePacketDataParcelable();
        parcel.srcAddress = srcAddr.getAddress();
        parcel.srcPort = srcPort;
        parcel.dstAddress = dstAddr.getAddress();
        parcel.dstPort = dstPort;
        parcel.seq = seqNum;
        parcel.ack = ackNum;

        apfFilter.addTcpKeepalivePacketFilter(slot1, parcel);
        program = cb.assertProgramUpdateAndGet();

        // Verify IPv4 keepalive ack packet is dropped
        // src: 10.0.0.6, port: 54321
        // dst: 10.0.0.5, port: 12345
        assertDrop(program,
                ipv4TcpPacket(IPV4_KEEPALIVE_DST_ADDR, IPV4_KEEPALIVE_SRC_ADDR,
                        dstPort, srcPort, ackNum, seqNum + 1, 0 /* dataLength */));
        // Verify IPv4 non-keepalive ack packet from the same source address is passed
        assertPass(program,
                ipv4TcpPacket(IPV4_KEEPALIVE_DST_ADDR, IPV4_KEEPALIVE_SRC_ADDR,
                        dstPort, srcPort, ackNum + 100, seqNum, 0 /* dataLength */));
        assertPass(program,
                ipv4TcpPacket(IPV4_KEEPALIVE_DST_ADDR, IPV4_KEEPALIVE_SRC_ADDR,
                        dstPort, srcPort, ackNum, seqNum + 1, 10 /* dataLength */));
        // Verify IPv4 packet from another address is passed
        assertPass(program,
                ipv4TcpPacket(IPV4_ANOTHER_ADDR, IPV4_KEEPALIVE_SRC_ADDR, anotherSrcPort,
                        anotherDstPort, anotherSeqNum, anotherAckNum, 0 /* dataLength */));

        // Remove IPv4 keepalive filter
        apfFilter.removeKeepalivePacketFilter(slot1);

        try {
            // src: 2404:0:0:0:0:0:faf1, port: 12345
            // dst: 2404:0:0:0:0:0:faf2, port: 54321
            srcAddr = InetAddress.getByAddress(IPV6_KEEPALIVE_SRC_ADDR);
            dstAddr = InetAddress.getByAddress(IPV6_KEEPALIVE_DST_ADDR);

            final TcpKeepalivePacketDataParcelable ipv6Parcel =
                    new TcpKeepalivePacketDataParcelable();
            ipv6Parcel.srcAddress = srcAddr.getAddress();
            ipv6Parcel.srcPort = srcPort;
            ipv6Parcel.dstAddress = dstAddr.getAddress();
            ipv6Parcel.dstPort = dstPort;
            ipv6Parcel.seq = seqNum;
            ipv6Parcel.ack = ackNum;

            apfFilter.addTcpKeepalivePacketFilter(slot1, ipv6Parcel);
            program = cb.assertProgramUpdateAndGet();

            // Verify IPv6 keepalive ack packet is dropped
            // src: 2404:0:0:0:0:0:faf2, port: 54321
            // dst: 2404:0:0:0:0:0:faf1, port: 12345
            assertDrop(program,
                    ipv6TcpPacket(IPV6_KEEPALIVE_DST_ADDR, IPV6_KEEPALIVE_SRC_ADDR,
                            dstPort, srcPort, ackNum, seqNum + 1));
            // Verify IPv6 non-keepalive ack packet from the same source address is passed
            assertPass(program,
                    ipv6TcpPacket(IPV6_KEEPALIVE_DST_ADDR, IPV6_KEEPALIVE_SRC_ADDR,
                            dstPort, srcPort, ackNum + 100, seqNum));
            // Verify IPv6 packet from another address is passed
            assertPass(program,
                    ipv6TcpPacket(IPV6_ANOTHER_ADDR, IPV6_KEEPALIVE_SRC_ADDR, anotherSrcPort,
                            anotherDstPort, anotherSeqNum, anotherAckNum));

            // Remove IPv6 keepalive filter
            apfFilter.removeKeepalivePacketFilter(slot1);

            // Verify multiple filters
            apfFilter.addTcpKeepalivePacketFilter(slot1, parcel);
            apfFilter.addTcpKeepalivePacketFilter(slot2, ipv6Parcel);
            program = cb.assertProgramUpdateAndGet();

            // Verify IPv4 keepalive ack packet is dropped
            // src: 10.0.0.6, port: 54321
            // dst: 10.0.0.5, port: 12345
            assertDrop(program,
                    ipv4TcpPacket(IPV4_KEEPALIVE_DST_ADDR, IPV4_KEEPALIVE_SRC_ADDR,
                            dstPort, srcPort, ackNum, seqNum + 1, 0 /* dataLength */));
            // Verify IPv4 non-keepalive ack packet from the same source address is passed
            assertPass(program,
                    ipv4TcpPacket(IPV4_KEEPALIVE_DST_ADDR, IPV4_KEEPALIVE_SRC_ADDR,
                            dstPort, srcPort, ackNum + 100, seqNum, 0 /* dataLength */));
            // Verify IPv4 packet from another address is passed
            assertPass(program,
                    ipv4TcpPacket(IPV4_ANOTHER_ADDR, IPV4_KEEPALIVE_SRC_ADDR, anotherSrcPort,
                            anotherDstPort, anotherSeqNum, anotherAckNum, 0 /* dataLength */));

            // Verify IPv6 keepalive ack packet is dropped
            // src: 2404:0:0:0:0:0:faf2, port: 54321
            // dst: 2404:0:0:0:0:0:faf1, port: 12345
            assertDrop(program,
                    ipv6TcpPacket(IPV6_KEEPALIVE_DST_ADDR, IPV6_KEEPALIVE_SRC_ADDR,
                            dstPort, srcPort, ackNum, seqNum + 1));
            // Verify IPv6 non-keepalive ack packet from the same source address is passed
            assertPass(program,
                    ipv6TcpPacket(IPV6_KEEPALIVE_DST_ADDR, IPV6_KEEPALIVE_SRC_ADDR,
                            dstPort, srcPort, ackNum + 100, seqNum));
            // Verify IPv6 packet from another address is passed
            assertPass(program,
                    ipv6TcpPacket(IPV6_ANOTHER_ADDR, IPV6_KEEPALIVE_SRC_ADDR, anotherSrcPort,
                            anotherDstPort, anotherSeqNum, anotherAckNum));

            // Remove keepalive filters
            apfFilter.removeKeepalivePacketFilter(slot1);
            apfFilter.removeKeepalivePacketFilter(slot2);
        } catch (UnsupportedOperationException e) {
            // TODO: support V6 packets
        }

        program = cb.assertProgramUpdateAndGet();

        // Verify IPv4, IPv6 packets are passed
        assertPass(program,
                ipv4TcpPacket(IPV4_KEEPALIVE_DST_ADDR, IPV4_KEEPALIVE_SRC_ADDR,
                        dstPort, srcPort, ackNum, seqNum + 1, 0 /* dataLength */));
        assertPass(program,
                ipv6TcpPacket(IPV6_KEEPALIVE_DST_ADDR, IPV6_KEEPALIVE_SRC_ADDR,
                        dstPort, srcPort, ackNum, seqNum + 1));
        assertPass(program,
                ipv4TcpPacket(IPV4_ANOTHER_ADDR, IPV4_KEEPALIVE_SRC_ADDR, srcPort,
                        dstPort, anotherSeqNum, anotherAckNum, 0 /* dataLength */));
        assertPass(program,
                ipv6TcpPacket(IPV6_ANOTHER_ADDR, IPV6_KEEPALIVE_SRC_ADDR, srcPort,
                        dstPort, anotherSeqNum, anotherAckNum));
    }

    private static byte[] ipv4TcpPacket(byte[] sip, byte[] dip, int sport,
            int dport, int seq, int ack, int dataLength) {
        final int totalLength = dataLength + IPV4_HEADER_LEN + IPV4_TCP_HEADER_LEN;

        ByteBuffer packet = ByteBuffer.wrap(new byte[totalLength + ETH_HEADER_LEN]);

        // Ethertype and IPv4 header
        setIpv4VersionFields(packet);
        packet.putShort(IPV4_TOTAL_LENGTH_OFFSET, (short) totalLength);
        packet.put(IPV4_PROTOCOL_OFFSET, (byte) IPPROTO_TCP);
        put(packet, IPV4_SRC_ADDR_OFFSET, sip);
        put(packet, IPV4_DEST_ADDR_OFFSET, dip);
        packet.putShort(IPV4_TCP_SRC_PORT_OFFSET, (short) sport);
        packet.putShort(IPV4_TCP_DEST_PORT_OFFSET, (short) dport);
        packet.putInt(IPV4_TCP_SEQ_NUM_OFFSET, seq);
        packet.putInt(IPV4_TCP_ACK_NUM_OFFSET, ack);

        // TCP header length 5(20 bytes), reserved 3 bits, NS=0
        packet.put(IPV4_TCP_HEADER_LENGTH_OFFSET, (byte) 0x50);
        // TCP flags: ACK set
        packet.put(IPV4_TCP_HEADER_FLAG_OFFSET, (byte) 0x10);
        return packet.array();
    }

    private static byte[] ipv6TcpPacket(byte[] sip, byte[] tip, int sport,
            int dport, int seq, int ack) {
        ByteBuffer packet = ByteBuffer.wrap(new byte[100]);
        setIpv6VersionFields(packet);
        packet.put(IPV6_NEXT_HEADER_OFFSET, (byte) IPPROTO_TCP);
        put(packet, IPV6_SRC_ADDR_OFFSET, sip);
        put(packet, IPV6_DEST_ADDR_OFFSET, tip);
        packet.putShort(IPV6_TCP_SRC_PORT_OFFSET, (short) sport);
        packet.putShort(IPV6_TCP_DEST_PORT_OFFSET, (short) dport);
        packet.putInt(IPV6_TCP_SEQ_NUM_OFFSET, seq);
        packet.putInt(IPV6_TCP_ACK_NUM_OFFSET, ack);
        return packet.array();
    }

    @Test
    public void testApfFilterNattKeepalivePacket() throws Exception {
        final MockIpClientCallback cb = new MockIpClientCallback();
        final ApfConfiguration config = getDefaultConfig();
        config.multicastFilter = DROP_MULTICAST;
        config.ieee802_3Filter = DROP_802_3_FRAMES;
        TestLegacyApfFilter apfFilter =  new TestLegacyApfFilter(mContext, config, cb,
                mIpConnectivityLog, mNetworkQuirkMetrics, mDependencies, mClock);
        byte[] program;
        final int srcPort = 1024;
        final int dstPort = 4500;
        final int slot1 = 1;
        // NAT-T keepalive
        final byte[] kaPayload = {(byte) 0xff};
        final byte[] nonKaPayload = {(byte) 0xfe};

        // src: 10.0.0.5, port: 1024
        // dst: 10.0.0.6, port: 4500
        InetAddress srcAddr = InetAddress.getByAddress(IPV4_KEEPALIVE_SRC_ADDR);
        InetAddress dstAddr = InetAddress.getByAddress(IPV4_KEEPALIVE_DST_ADDR);

        final NattKeepalivePacketDataParcelable parcel = new NattKeepalivePacketDataParcelable();
        parcel.srcAddress = srcAddr.getAddress();
        parcel.srcPort = srcPort;
        parcel.dstAddress = dstAddr.getAddress();
        parcel.dstPort = dstPort;

        apfFilter.addNattKeepalivePacketFilter(slot1, parcel);
        program = cb.assertProgramUpdateAndGet();

        // Verify IPv4 keepalive packet is dropped
        // src: 10.0.0.6, port: 4500
        // dst: 10.0.0.5, port: 1024
        byte[] pkt = ipv4UdpPacket(IPV4_KEEPALIVE_DST_ADDR,
                    IPV4_KEEPALIVE_SRC_ADDR, dstPort, srcPort, 1 /* dataLength */);
        System.arraycopy(kaPayload, 0, pkt, IPV4_UDP_PAYLOAD_OFFSET, kaPayload.length);
        assertDrop(program, pkt);

        // Verify a packet with payload length 1 byte but it is not 0xff will pass the filter.
        System.arraycopy(nonKaPayload, 0, pkt, IPV4_UDP_PAYLOAD_OFFSET, nonKaPayload.length);
        assertPass(program, pkt);

        // Verify IPv4 non-keepalive response packet from the same source address is passed
        assertPass(program,
                ipv4UdpPacket(IPV4_KEEPALIVE_DST_ADDR, IPV4_KEEPALIVE_SRC_ADDR,
                        dstPort, srcPort, 10 /* dataLength */));

        // Verify IPv4 non-keepalive response packet from other source address is passed
        assertPass(program,
                ipv4UdpPacket(IPV4_ANOTHER_ADDR, IPV4_KEEPALIVE_SRC_ADDR,
                        dstPort, srcPort, 10 /* dataLength */));

        apfFilter.removeKeepalivePacketFilter(slot1);
    }

    private static byte[] ipv4UdpPacket(byte[] sip, byte[] dip, int sport,
            int dport, int dataLength) {
        final int totalLength = dataLength + IPV4_HEADER_LEN + UDP_HEADER_LEN;
        final int udpLength = UDP_HEADER_LEN + dataLength;
        ByteBuffer packet = ByteBuffer.wrap(new byte[totalLength + ETH_HEADER_LEN]);

        // Ethertype and IPv4 header
        setIpv4VersionFields(packet);
        packet.putShort(IPV4_TOTAL_LENGTH_OFFSET, (short) totalLength);
        packet.put(IPV4_PROTOCOL_OFFSET, (byte) IPPROTO_UDP);
        put(packet, IPV4_SRC_ADDR_OFFSET, sip);
        put(packet, IPV4_DEST_ADDR_OFFSET, dip);
        packet.putShort(IPV4_UDP_SRC_PORT_OFFSET, (short) sport);
        packet.putShort(IPV4_UDP_DEST_PORT_OFFSET, (short) dport);
        packet.putShort(IPV4_UDP_LENGTH_OFFSET, (short) udpLength);

        return packet.array();
    }

    private static class RaPacketBuilder {
        final ByteArrayOutputStream mPacket = new ByteArrayOutputStream();
        int mFlowLabel = 0x12345;
        int mReachableTime = 30_000;
        int mRetransmissionTimer = 1000;

        public RaPacketBuilder(int routerLft) throws Exception {
            InetAddress src = InetAddress.getByName("fe80::1234:abcd");
            ByteBuffer buffer = ByteBuffer.allocate(ICMP6_RA_OPTION_OFFSET);

            buffer.putShort(ETH_ETHERTYPE_OFFSET, (short) ETH_P_IPV6);
            buffer.position(ETH_HEADER_LEN);

            // skip version, tclass, flowlabel; set in build()
            buffer.position(buffer.position() + 4);

            buffer.putShort((short) 0);                     // Payload length; updated later
            buffer.put((byte) IPPROTO_ICMPV6);              // Next header
            buffer.put((byte) 0xff);                        // Hop limit
            buffer.put(src.getAddress());                   // Source address
            buffer.put(IPV6_ALL_NODES_ADDRESS);             // Destination address

            buffer.put((byte) ICMP6_ROUTER_ADVERTISEMENT);  // Type
            buffer.put((byte) 0);                           // Code (0)
            buffer.putShort((short) 0);                     // Checksum (ignored)
            buffer.put((byte) 64);                          // Hop limit
            buffer.put((byte) 0);                           // M/O, reserved
            buffer.putShort((short) routerLft);             // Router lifetime
            // skip reachable time; set in build()
            // skip retransmission timer; set in build();

            mPacket.write(buffer.array(), 0, buffer.capacity());
        }

        public RaPacketBuilder setFlowLabel(int flowLabel) {
            mFlowLabel = flowLabel;
            return this;
        }

        public RaPacketBuilder setReachableTime(int reachable) {
            mReachableTime = reachable;
            return this;
        }

        public RaPacketBuilder setRetransmissionTimer(int retrans) {
            mRetransmissionTimer = retrans;
            return this;
        }

        public RaPacketBuilder addPioOption(int valid, int preferred, String prefixString)
                throws Exception {
            ByteBuffer buffer = ByteBuffer.allocate(ICMP6_PREFIX_OPTION_LEN);

            IpPrefix prefix = new IpPrefix(prefixString);
            buffer.put((byte) ICMP6_PREFIX_OPTION_TYPE);  // Type
            buffer.put((byte) 4);                         // Length in 8-byte units
            buffer.put((byte) prefix.getPrefixLength());  // Prefix length
            buffer.put((byte) 0b11000000);                // L = 1, A = 1
            buffer.putInt(valid);
            buffer.putInt(preferred);
            buffer.putInt(0);                             // Reserved
            buffer.put(prefix.getRawAddress());

            mPacket.write(buffer.array(), 0, buffer.capacity());
            return this;
        }

        public RaPacketBuilder addRioOption(int lifetime, String prefixString) throws Exception {
            IpPrefix prefix = new IpPrefix(prefixString);

            int optionLength;
            if (prefix.getPrefixLength() == 0) {
                optionLength = 1;
            } else if (prefix.getPrefixLength() <= 64) {
                optionLength = 2;
            } else {
                optionLength = 3;
            }

            ByteBuffer buffer = ByteBuffer.allocate(optionLength * 8);

            buffer.put((byte) ICMP6_ROUTE_INFO_OPTION_TYPE);  // Type
            buffer.put((byte) optionLength);                  // Length in 8-byte units
            buffer.put((byte) prefix.getPrefixLength());      // Prefix length
            buffer.put((byte) 0b00011000);                    // Pref = high
            buffer.putInt(lifetime);                          // Lifetime

            byte[] prefixBytes = prefix.getRawAddress();
            buffer.put(prefixBytes, 0, (optionLength - 1) * 8);

            mPacket.write(buffer.array(), 0, buffer.capacity());
            return this;
        }

        public RaPacketBuilder addDnsslOption(int lifetime, String... domains) {
            ByteArrayOutputStream dnssl = new ByteArrayOutputStream();
            for (String domain : domains) {
                for (String label : domain.split("\\.")) {
                    final byte[] bytes = label.getBytes(StandardCharsets.UTF_8);
                    dnssl.write((byte) bytes.length);
                    dnssl.write(bytes, 0, bytes.length);
                }
                dnssl.write((byte) 0);
            }

            // Extend with 0s to make it 8-byte aligned.
            while (dnssl.size() % 8 != 0) {
                dnssl.write((byte) 0);
            }

            final int length = ICMP6_4_BYTE_OPTION_LEN + dnssl.size();
            ByteBuffer buffer = ByteBuffer.allocate(length);

            buffer.put((byte) ICMP6_DNSSL_OPTION_TYPE);  // Type
            buffer.put((byte) (length / 8));             // Length
            // skip past reserved bytes
            buffer.position(buffer.position() + 2);
            buffer.putInt(lifetime);                     // Lifetime
            buffer.put(dnssl.toByteArray());             // Domain names

            mPacket.write(buffer.array(), 0, buffer.capacity());
            return this;
        }

        public RaPacketBuilder addRdnssOption(int lifetime, String... servers) throws Exception {
            int optionLength = 1 + 2 * servers.length;   // In 8-byte units
            ByteBuffer buffer = ByteBuffer.allocate(optionLength * 8);

            buffer.put((byte) ICMP6_RDNSS_OPTION_TYPE);  // Type
            buffer.put((byte) optionLength);             // Length
            buffer.putShort((short) 0);                  // Reserved
            buffer.putInt(lifetime);                     // Lifetime
            for (String server : servers) {
                buffer.put(InetAddress.getByName(server).getAddress());
            }

            mPacket.write(buffer.array(), 0, buffer.capacity());
            return this;
        }

        public RaPacketBuilder addZeroLengthOption() throws Exception {
            ByteBuffer buffer = ByteBuffer.allocate(ICMP6_4_BYTE_OPTION_LEN);
            buffer.put((byte) ICMP6_PREFIX_OPTION_TYPE);
            buffer.put((byte) 0);

            mPacket.write(buffer.array(), 0, buffer.capacity());
            return this;
        }

        public byte[] build() {
            ByteBuffer buffer = ByteBuffer.wrap(mPacket.toByteArray());
            // IPv6, traffic class = 0, flow label = mFlowLabel
            buffer.putInt(IP_HEADER_OFFSET, 0x60000000 | (0xFFFFF & mFlowLabel));
            buffer.putShort(IPV6_PAYLOAD_LENGTH_OFFSET, (short) buffer.capacity());

            buffer.position(ICMP6_RA_REACHABLE_TIME_OFFSET);
            buffer.putInt(mReachableTime);
            buffer.putInt(mRetransmissionTimer);

            return buffer.array();
        }
    }

    private byte[] buildLargeRa() throws Exception {
        RaPacketBuilder builder = new RaPacketBuilder(1800 /* router lft */);

        builder.addRioOption(1200, "64:ff9b::/96");
        builder.addRdnssOption(7200, "2001:db8:1::1", "2001:db8:1::2");
        builder.addRioOption(2100, "2000::/3");
        builder.addRioOption(2400, "::/0");
        builder.addPioOption(600, 300, "2001:db8:a::/64");
        builder.addRioOption(1500, "2001:db8:c:d::/64");
        builder.addPioOption(86400, 43200, "fd95:d1e:12::/64");

        return builder.build();
    }

    // Verify that the last program pushed to the IpClient.Callback properly filters the
    // given packet for the given lifetime.
    private void verifyRaLifetime(byte[] program, ByteBuffer packet, int lifetime) {
        verifyRaLifetime(program, packet, lifetime, 0);
    }

    // Verify that the last program pushed to the IpClient.Callback properly filters the
    // given packet for the given lifetime and programInstallTime. programInstallTime is
    // the time difference between when RA is last seen and the program is installed.
    private void verifyRaLifetime(byte[] program, ByteBuffer packet, int lifetime,
            int programInstallTime) {
        final int FRACTION_OF_LIFETIME = 6;
        final int ageLimit = lifetime / FRACTION_OF_LIFETIME - programInstallTime;

        // Verify new program should drop RA for 1/6th its lifetime and pass afterwards.
        assertDrop(program, packet.array());
        assertDrop(program, packet.array(), ageLimit);
        assertPass(program, packet.array(), ageLimit + 1);
        assertPass(program, packet.array(), lifetime);
        // Verify RA checksum is ignored
        final short originalChecksum = packet.getShort(ICMP6_RA_CHECKSUM_OFFSET);
        packet.putShort(ICMP6_RA_CHECKSUM_OFFSET, (short)12345);
        assertDrop(program, packet.array());
        packet.putShort(ICMP6_RA_CHECKSUM_OFFSET, (short)-12345);
        assertDrop(program, packet.array());
        packet.putShort(ICMP6_RA_CHECKSUM_OFFSET, originalChecksum);

        // Verify other changes to RA (e.g., a change in the source address) make it not match.
        final int offset = IPV6_SRC_ADDR_OFFSET + 5;
        final byte originalByte = packet.get(offset);
        packet.put(offset, (byte) (~originalByte));
        assertPass(program, packet.array());
        packet.put(offset, originalByte);
        assertDrop(program, packet.array());
    }

    // Test that when ApfFilter is shown the given packet, it generates a program to filter it
    // for the given lifetime.
    private void verifyRaLifetime(TestLegacyApfFilter apfFilter,
            MockIpClientCallback ipClientCallback, ByteBuffer packet, int lifetime)
            throws IOException, ErrnoException {
        // Verify new program generated if ApfFilter witnesses RA
        apfFilter.pretendPacketReceived(packet.array());
        byte[] program = ipClientCallback.assertProgramUpdateAndGet();
        verifyRaLifetime(program, packet, lifetime);
    }

    private void assertInvalidRa(TestLegacyApfFilter apfFilter,
            MockIpClientCallback ipClientCallback, ByteBuffer packet)
            throws IOException, ErrnoException {
        apfFilter.pretendPacketReceived(packet.array());
        ipClientCallback.assertNoProgramUpdate();
    }

    @Test
    public void testApfFilterRa() throws Exception {
        MockIpClientCallback ipClientCallback = new MockIpClientCallback();
        ApfConfiguration config = getDefaultConfig();
        config.multicastFilter = DROP_MULTICAST;
        config.ieee802_3Filter = DROP_802_3_FRAMES;
        TestLegacyApfFilter apfFilter = new TestLegacyApfFilter(mContext, config, ipClientCallback,
                mIpConnectivityLog, mNetworkQuirkMetrics, mDependencies, mClock);
        byte[] program = ipClientCallback.assertProgramUpdateAndGet();

        final int ROUTER_LIFETIME = 1000;
        final int PREFIX_VALID_LIFETIME = 200;
        final int PREFIX_PREFERRED_LIFETIME = 100;
        final int RDNSS_LIFETIME  = 300;
        final int ROUTE_LIFETIME  = 400;
        // Note that lifetime of 2000 will be ignored in favor of shorter route lifetime of 1000.
        final int DNSSL_LIFETIME  = 2000;

        // Verify RA is passed the first time
        RaPacketBuilder ra = new RaPacketBuilder(ROUTER_LIFETIME);
        ByteBuffer basePacket = ByteBuffer.wrap(ra.build());
        assertPass(program, basePacket.array());

        verifyRaLifetime(apfFilter, ipClientCallback, basePacket, ROUTER_LIFETIME);

        ra = new RaPacketBuilder(ROUTER_LIFETIME);
        // Check that changes are ignored in every byte of the flow label.
        ra.setFlowLabel(0x56789);
        ByteBuffer newFlowLabelPacket = ByteBuffer.wrap(ra.build());

        // Ensure zero-length options cause the packet to be silently skipped.
        // Do this before we test other packets. http://b/29586253
        ra = new RaPacketBuilder(ROUTER_LIFETIME);
        ra.addZeroLengthOption();
        ByteBuffer zeroLengthOptionPacket = ByteBuffer.wrap(ra.build());
        assertInvalidRa(apfFilter, ipClientCallback, zeroLengthOptionPacket);

        // Generate several RAs with different options and lifetimes, and verify when
        // ApfFilter is shown these packets, it generates programs to filter them for the
        // appropriate lifetime.
        ra = new RaPacketBuilder(ROUTER_LIFETIME);
        ra.addPioOption(PREFIX_VALID_LIFETIME, PREFIX_PREFERRED_LIFETIME, "2001:db8::/64");
        ByteBuffer prefixOptionPacket = ByteBuffer.wrap(ra.build());
        verifyRaLifetime(
                apfFilter, ipClientCallback, prefixOptionPacket, PREFIX_PREFERRED_LIFETIME);

        ra = new RaPacketBuilder(ROUTER_LIFETIME);
        ra.addRdnssOption(RDNSS_LIFETIME, "2001:4860:4860::8888", "2001:4860:4860::8844");
        ByteBuffer rdnssOptionPacket = ByteBuffer.wrap(ra.build());
        verifyRaLifetime(apfFilter, ipClientCallback, rdnssOptionPacket, RDNSS_LIFETIME);

        final int lowLifetime = 60;
        ra = new RaPacketBuilder(ROUTER_LIFETIME);
        ra.addRdnssOption(lowLifetime, "2620:fe::9");
        ByteBuffer lowLifetimeRdnssOptionPacket = ByteBuffer.wrap(ra.build());
        verifyRaLifetime(apfFilter, ipClientCallback, lowLifetimeRdnssOptionPacket,
                ROUTER_LIFETIME);

        ra = new RaPacketBuilder(ROUTER_LIFETIME);
        ra.addRioOption(ROUTE_LIFETIME, "64:ff9b::/96");
        ByteBuffer routeInfoOptionPacket = ByteBuffer.wrap(ra.build());
        verifyRaLifetime(apfFilter, ipClientCallback, routeInfoOptionPacket, ROUTE_LIFETIME);

        // Check that RIOs differing only in the first 4 bytes are different.
        ra = new RaPacketBuilder(ROUTER_LIFETIME);
        ra.addRioOption(ROUTE_LIFETIME, "64:ff9b::/64");
        // Packet should be passed because it is different.
        program = ipClientCallback.assertProgramUpdateAndGet();
        assertPass(program, ra.build());

        ra = new RaPacketBuilder(ROUTER_LIFETIME);
        ra.addDnsslOption(DNSSL_LIFETIME, "test.example.com", "one.more.example.com");
        ByteBuffer dnsslOptionPacket = ByteBuffer.wrap(ra.build());
        verifyRaLifetime(apfFilter, ipClientCallback, dnsslOptionPacket, ROUTER_LIFETIME);

        ByteBuffer largeRaPacket = ByteBuffer.wrap(buildLargeRa());
        verifyRaLifetime(apfFilter, ipClientCallback, largeRaPacket, 300);

        // Verify that current program filters all the RAs (note: ApfFilter.MAX_RAS == 10).
        program = ipClientCallback.assertProgramUpdateAndGet();
        verifyRaLifetime(program, basePacket, ROUTER_LIFETIME);
        verifyRaLifetime(program, newFlowLabelPacket, ROUTER_LIFETIME);
        verifyRaLifetime(program, prefixOptionPacket, PREFIX_PREFERRED_LIFETIME);
        verifyRaLifetime(program, rdnssOptionPacket, RDNSS_LIFETIME);
        verifyRaLifetime(program, lowLifetimeRdnssOptionPacket, ROUTER_LIFETIME);
        verifyRaLifetime(program, routeInfoOptionPacket, ROUTE_LIFETIME);
        verifyRaLifetime(program, dnsslOptionPacket, ROUTER_LIFETIME);
        verifyRaLifetime(program, largeRaPacket, 300);
    }

    @Test
    public void testRaWithDifferentReachableTimeAndRetransTimer() throws Exception {
        final MockIpClientCallback ipClientCallback = new MockIpClientCallback();
        final ApfConfiguration config = getDefaultConfig();
        config.multicastFilter = DROP_MULTICAST;
        config.ieee802_3Filter = DROP_802_3_FRAMES;
        final TestLegacyApfFilter apfFilter = new TestLegacyApfFilter(mContext, config,
                ipClientCallback, mIpConnectivityLog, mNetworkQuirkMetrics, mDependencies, mClock);
        byte[] program = ipClientCallback.assertProgramUpdateAndGet();
        final int RA_REACHABLE_TIME = 1800;
        final int RA_RETRANSMISSION_TIMER = 1234;

        // Create an Ra packet without options
        // Reachable time = 1800, retransmission timer = 1234
        RaPacketBuilder ra = new RaPacketBuilder(1800 /* router lft */);
        ra.setReachableTime(RA_REACHABLE_TIME);
        ra.setRetransmissionTimer(RA_RETRANSMISSION_TIMER);
        byte[] raPacket = ra.build();
        // First RA passes filter
        assertPass(program, raPacket);

        // Assume apf is shown the given RA, it generates program to filter it.
        apfFilter.pretendPacketReceived(raPacket);
        program = ipClientCallback.assertProgramUpdateAndGet();
        assertDrop(program, raPacket);

        // A packet with different reachable time should be passed.
        // Reachable time = 2300, retransmission timer = 1234
        ra.setReachableTime(RA_REACHABLE_TIME + 500);
        raPacket = ra.build();
        assertPass(program, raPacket);

        // A packet with different retransmission timer should be passed.
        // Reachable time = 1800, retransmission timer = 2234
        ra.setReachableTime(RA_REACHABLE_TIME);
        ra.setRetransmissionTimer(RA_RETRANSMISSION_TIMER + 1000);
        raPacket = ra.build();
        assertPass(program, raPacket);
    }

    /**
     * Stage a file for testing, i.e. make it native accessible. Given a resource ID,
     * copy that resource into the app's data directory and return the path to it.
     */
    private String stageFile(int rawId) throws Exception {
        File file = new File(InstrumentationRegistry.getContext().getFilesDir(), "staged_file");
        new File(file.getParent()).mkdirs();
        InputStream in = null;
        OutputStream out = null;
        try {
            in = InstrumentationRegistry.getContext().getResources().openRawResource(rawId);
            out = new FileOutputStream(file);
            Streams.copy(in, out);
        } finally {
            if (in != null) in.close();
            if (out != null) out.close();
        }
        return file.getAbsolutePath();
    }

    private static void put(ByteBuffer buffer, int position, byte[] bytes) {
        final int original = buffer.position();
        buffer.position(position);
        buffer.put(bytes);
        buffer.position(original);
    }

    @Test
    public void testRaParsing() throws Exception {
        final int maxRandomPacketSize = 512;
        final Random r = new Random();
        MockIpClientCallback cb = new MockIpClientCallback();
        ApfConfiguration config = getDefaultConfig();
        config.multicastFilter = DROP_MULTICAST;
        config.ieee802_3Filter = DROP_802_3_FRAMES;
        final TestLegacyApfFilter apfFilter = new TestLegacyApfFilter(mContext, config,
                cb, mIpConnectivityLog, mNetworkQuirkMetrics, mDependencies, mClock);
        for (int i = 0; i < 1000; i++) {
            byte[] packet = new byte[r.nextInt(maxRandomPacketSize + 1)];
            r.nextBytes(packet);
            try {
                apfFilter.new Ra(packet, packet.length);
            } catch (LegacyApfFilter.InvalidRaException e) {
            } catch (Exception e) {
                throw new Exception("bad packet: " + HexDump.toHexString(packet), e);
            }
        }
    }

    @Test
    public void testRaProcessing() throws Exception {
        final int maxRandomPacketSize = 512;
        final Random r = new Random();
        MockIpClientCallback cb = new MockIpClientCallback();
        ApfConfiguration config = getDefaultConfig();
        config.multicastFilter = DROP_MULTICAST;
        config.ieee802_3Filter = DROP_802_3_FRAMES;
        final TestLegacyApfFilter apfFilter = new TestLegacyApfFilter(mContext, config,
                cb, mIpConnectivityLog, mNetworkQuirkMetrics, mDependencies, mClock);
        for (int i = 0; i < 1000; i++) {
            byte[] packet = new byte[r.nextInt(maxRandomPacketSize + 1)];
            r.nextBytes(packet);
            try {
                apfFilter.processRa(packet, packet.length);
            } catch (Exception e) {
                throw new Exception("bad packet: " + HexDump.toHexString(packet), e);
            }
        }
    }

    @Test
    public void testProcessRaWithInfiniteLifeTimeWithoutCrash() throws Exception {
        final MockIpClientCallback ipClientCallback = new MockIpClientCallback();
        // configure accept_ra_min_lft
        final ApfConfiguration config = getDefaultConfig();
        config.acceptRaMinLft = 180;
        TestLegacyApfFilter apfFilter;
        // Template packet:
        // Frame 1: 150 bytes on wire (1200 bits), 150 bytes captured (1200 bits)
        // Ethernet II, Src: Netgear_23:67:2c (28:c6:8e:23:67:2c), Dst: IPv6mcast_01 (33:33:00:00:00:01)
        // Internet Protocol Version 6, Src: fe80::2ac6:8eff:fe23:672c, Dst: ff02::1
        // Internet Control Message Protocol v6
        //   Type: Router Advertisement (134)
        //   Code: 0
        //   Checksum: 0x0acd [correct]
        //   Checksum Status: Good
        //   Cur hop limit: 64
        //   Flags: 0xc0, Managed address configuration, Other configuration, Prf (Default Router Preference): Medium
        //   Router lifetime (s): 7000
        //   Reachable time (ms): 0
        //   Retrans timer (ms): 0
        //   ICMPv6 Option (Source link-layer address : 28:c6:8e:23:67:2c)
        //     Type: Source link-layer address (1)
        //     Length: 1 (8 bytes)
        //     Link-layer address: Netgear_23:67:2c (28:c6:8e:23:67:2c)
        //     Source Link-layer address: Netgear_23:67:2c (28:c6:8e:23:67:2c)
        //   ICMPv6 Option (MTU : 1500)
        //     Type: MTU (5)
        //     Length: 1 (8 bytes)
        //     Reserved
        //     MTU: 1500
        //   ICMPv6 Option (Prefix information : 2401:fa00:480:f000::/64)
        //     Type: Prefix information (3)
        //     Length: 4 (32 bytes)
        //     Prefix Length: 64
        //     Flag: 0xc0, On-link flag(L), Autonomous address-configuration flag(A)
        //     Valid Lifetime: Infinity (4294967295)
        //     Preferred Lifetime: Infinity (4294967295)
        //     Reserved
        //     Prefix: 2401:fa00:480:f000::
        //   ICMPv6 Option (Recursive DNS Server 2401:fa00:480:f000::1)
        //     Type: Recursive DNS Server (25)
        //     Length: 3 (24 bytes)
        //     Reserved
        //     Lifetime: 7000
        //     Recursive DNS Servers: 2401:fa00:480:f000::1
        //   ICMPv6 Option (Advertisement Interval : 600000)
        //     Type: Advertisement Interval (7)
        //     Length: 1 (8 bytes)
        //     Reserved
        //     Advertisement Interval: 600000
        final String packetStringFmt = "33330000000128C68E23672C86DD60054C6B00603AFFFE800000000000002AC68EFFFE23672CFF02000000000000000000000000000186000ACD40C01B580000000000000000010128C68E23672C05010000000005DC030440C0%s000000002401FA000480F00000000000000000001903000000001B582401FA000480F000000000000000000107010000000927C0";
        final List<String> lifetimes = List.of("FFFFFFFF", "00000001", "00001B58");
        for (String lifetime : lifetimes) {
            apfFilter = new TestLegacyApfFilter(mContext, config, ipClientCallback,
                    mIpConnectivityLog, mNetworkQuirkMetrics, mDependencies, mClock);
            final byte[] ra = hexStringToByteArray(
                    String.format(packetStringFmt, lifetime + lifetime));
            // feed the RA into APF and generate the filter, the filter shouldn't crash.
            apfFilter.pretendPacketReceived(ra);
            ipClientCallback.assertProgramUpdateAndGet();
        }
    }

    private TestAndroidPacketFilter makeTestApfFilter(ApfConfiguration config,
            MockIpClientCallback ipClientCallback) throws Exception {
        return new TestLegacyApfFilter(mContext, config, ipClientCallback, mIpConnectivityLog,
                mNetworkQuirkMetrics, mDependencies, mClock);
    }


    @Test
    public void testInstallPacketFilterFailure_LegacyApfFilter() throws Exception {
        final MockIpClientCallback ipClientCallback = new MockIpClientCallback(false);
        final ApfConfiguration config = getDefaultConfig();
        final TestAndroidPacketFilter apfFilter = makeTestApfFilter(config, ipClientCallback);
        verify(mNetworkQuirkMetrics).setEvent(NetworkQuirkEvent.QE_APF_INSTALL_FAILURE);
        verify(mNetworkQuirkMetrics).statsWrite();
        reset(mNetworkQuirkMetrics);
        synchronized (apfFilter) {
            apfFilter.installNewProgramLocked();
        }
        verify(mNetworkQuirkMetrics).setEvent(NetworkQuirkEvent.QE_APF_INSTALL_FAILURE);
        verify(mNetworkQuirkMetrics).statsWrite();
    }

    @Test
    public void testApfProgramOverSize_LegacyApfFilter() throws Exception {
        final MockIpClientCallback ipClientCallback = new MockIpClientCallback();
        final ApfConfiguration config = getDefaultConfig();
        config.apfVersionSupported = 2;
        config.apfRamSize = 512;
        final TestAndroidPacketFilter apfFilter = makeTestApfFilter(config, ipClientCallback);
        byte[] program = ipClientCallback.assertProgramUpdateAndGet();
        final byte[] ra = buildLargeRa();
        apfFilter.pretendPacketReceived(ra);
        // The generated program size will be 529, which is larger than 512
        program = ipClientCallback.assertProgramUpdateAndGet();
        verify(mNetworkQuirkMetrics).setEvent(NetworkQuirkEvent.QE_APF_OVER_SIZE_FAILURE);
        verify(mNetworkQuirkMetrics).statsWrite();
    }

    @Test
    public void testGenerateApfProgramException_LegacyApfFilter() throws Exception {
        final MockIpClientCallback ipClientCallback = new MockIpClientCallback();
        final ApfConfiguration config = getDefaultConfig();
        final TestAndroidPacketFilter apfFilter;
        apfFilter = new TestLegacyApfFilter(mContext, config, ipClientCallback, mIpConnectivityLog,
                mNetworkQuirkMetrics, mDependencies,
                true /* throwsExceptionWhenGeneratesProgram */);
        synchronized (apfFilter) {
            apfFilter.installNewProgramLocked();
        }
        verify(mNetworkQuirkMetrics).setEvent(NetworkQuirkEvent.QE_APF_GENERATE_FILTER_EXCEPTION);
        verify(mNetworkQuirkMetrics).statsWrite();
    }

    @Test
    public void testApfSessionInfoMetrics_LegacyApfFilter() throws Exception {
        final MockIpClientCallback ipClientCallback = new MockIpClientCallback();
        final ApfConfiguration config = getDefaultConfig();
        config.apfVersionSupported = 4;
        config.apfRamSize = 4096;
        final long startTimeMs = 12345;
        final long durationTimeMs = config.minMetricsSessionDurationMs;
        doReturn(startTimeMs).when(mClock).elapsedRealtime();
        final TestAndroidPacketFilter apfFilter = makeTestApfFilter(config, ipClientCallback);
        int maxProgramSize = 0;
        int numProgramUpdated = 0;
        byte[] program = ipClientCallback.assertProgramUpdateAndGet();
        maxProgramSize = Math.max(maxProgramSize, program.length);
        numProgramUpdated++;

        final byte[] data = new byte[Counter.totalSize()];
        final byte[] expectedData = data.clone();
        final int totalPacketsCounterIdx = Counter.totalSize() + Counter.TOTAL_PACKETS.offset();
        final int passedIpv6IcmpCounterIdx =
                Counter.totalSize() + Counter.PASSED_IPV6_ICMP.offset();
        final int droppedIpv4MulticastIdx =
                Counter.totalSize() + Counter.DROPPED_IPV4_MULTICAST.offset();

        // Receive an RA packet (passed).
        final byte[] ra = buildLargeRa();
        expectedData[totalPacketsCounterIdx + 3] += 1;
        expectedData[passedIpv6IcmpCounterIdx + 3] += 1;
        assertDataMemoryContentsIgnoreVersion(PASS, program, ra, data, expectedData);
        apfFilter.pretendPacketReceived(ra);
        program = ipClientCallback.assertProgramUpdateAndGet();
        maxProgramSize = Math.max(maxProgramSize, program.length);
        numProgramUpdated++;

        apfFilter.setMulticastFilter(true);
        // setMulticastFilter will trigger program installation.
        program = ipClientCallback.assertProgramUpdateAndGet();
        maxProgramSize = Math.max(maxProgramSize, program.length);
        numProgramUpdated++;

        // Receive IPv4 multicast packet (dropped).
        final byte[] multicastIpv4Addr = {(byte) 224, 0, 0, 1};
        ByteBuffer mcastv4packet = makeIpv4Packet(IPPROTO_UDP);
        put(mcastv4packet, IPV4_DEST_ADDR_OFFSET, multicastIpv4Addr);
        expectedData[totalPacketsCounterIdx + 3] += 1;
        expectedData[droppedIpv4MulticastIdx + 3] += 1;
        assertDataMemoryContentsIgnoreVersion(DROP, program, mcastv4packet.array(), data,
                expectedData);

        // Set data snapshot and update counters.
        apfFilter.setDataSnapshot(data);

        // Write metrics data to statsd pipeline when shutdown.
        doReturn(startTimeMs + durationTimeMs).when(mClock).elapsedRealtime();
        apfFilter.shutdown();
        verify(mApfSessionInfoMetrics).setVersion(4);
        verify(mApfSessionInfoMetrics).setMemorySize(4096);

        // Verify Counters
        final Map<Counter, Long> expectedCounters = Map.of(Counter.TOTAL_PACKETS, 2L,
                Counter.PASSED_IPV6_ICMP, 1L, Counter.DROPPED_IPV4_MULTICAST, 1L);
        final ArgumentCaptor<Counter> counterCaptor = ArgumentCaptor.forClass(Counter.class);
        final ArgumentCaptor<Long> valueCaptor = ArgumentCaptor.forClass(Long.class);
        verify(mApfSessionInfoMetrics, times(expectedCounters.size())).addApfCounter(
                counterCaptor.capture(), valueCaptor.capture());
        final List<Counter> counters = counterCaptor.getAllValues();
        final List<Long> values = valueCaptor.getAllValues();
        final ArrayMap<Counter, Long> capturedCounters = new ArrayMap<>();
        for (int i = 0; i < counters.size(); i++) {
            capturedCounters.put(counters.get(i), values.get(i));
        }
        assertEquals(expectedCounters, capturedCounters);

        verify(mApfSessionInfoMetrics).setApfSessionDurationSeconds(
                (int) (durationTimeMs / DateUtils.SECOND_IN_MILLIS));
        verify(mApfSessionInfoMetrics).setNumOfTimesApfProgramUpdated(numProgramUpdated);
        verify(mApfSessionInfoMetrics).setMaxProgramSize(maxProgramSize);
        verify(mApfSessionInfoMetrics).statsWrite();
    }

    @Test
    public void testIpClientRaInfoMetrics_LegacyApfFilter() throws Exception {
        final MockIpClientCallback ipClientCallback = new MockIpClientCallback();
        final ApfConfiguration config = getDefaultConfig();
        final long startTimeMs = 12345;
        final long durationTimeMs = config.minMetricsSessionDurationMs;
        doReturn(startTimeMs).when(mClock).elapsedRealtime();
        final TestAndroidPacketFilter apfFilter = makeTestApfFilter(config, ipClientCallback);
        byte[] program = ipClientCallback.assertProgramUpdateAndGet();

        final int routerLifetime = 1000;
        final int prefixValidLifetime = 200;
        final int prefixPreferredLifetime = 100;
        final int rdnssLifetime  = 300;
        final int routeLifetime  = 400;

        // Construct 2 RAs with partial lifetimes larger than predefined constants
        final RaPacketBuilder ra1 = new RaPacketBuilder(routerLifetime);
        ra1.addPioOption(prefixValidLifetime + 123, prefixPreferredLifetime, "2001:db8::/64");
        ra1.addRdnssOption(rdnssLifetime, "2001:4860:4860::8888", "2001:4860:4860::8844");
        ra1.addRioOption(routeLifetime + 456, "64:ff9b::/96");
        final RaPacketBuilder ra2 = new RaPacketBuilder(routerLifetime + 123);
        ra2.addPioOption(prefixValidLifetime, prefixPreferredLifetime, "2001:db9::/64");
        ra2.addRdnssOption(rdnssLifetime + 456, "2001:4860:4860::8888", "2001:4860:4860::8844");
        ra2.addRioOption(routeLifetime, "64:ff9b::/96");

        // Construct an invalid RA packet
        final RaPacketBuilder raInvalid = new RaPacketBuilder(routerLifetime);
        raInvalid.addZeroLengthOption();

        // Construct 4 different kinds of zero lifetime RAs
        final RaPacketBuilder raZeroRouterLifetime = new RaPacketBuilder(0 /* routerLft */);
        final RaPacketBuilder raZeroPioValidLifetime = new RaPacketBuilder(routerLifetime);
        raZeroPioValidLifetime.addPioOption(0, prefixPreferredLifetime, "2001:db10::/64");
        final RaPacketBuilder raZeroRdnssLifetime = new RaPacketBuilder(routerLifetime);
        raZeroRdnssLifetime.addPioOption(
                prefixValidLifetime, prefixPreferredLifetime, "2001:db11::/64");
        raZeroRdnssLifetime.addRdnssOption(0, "2001:4860:4860::8888", "2001:4860:4860::8844");
        final RaPacketBuilder raZeroRioRouteLifetime = new RaPacketBuilder(routerLifetime);
        raZeroRioRouteLifetime.addPioOption(
                prefixValidLifetime, prefixPreferredLifetime, "2001:db12::/64");
        raZeroRioRouteLifetime.addRioOption(0, "64:ff9b::/96");

        // Inject RA packets. Calling assertProgramUpdateAndGet()/assertNoProgramUpdate() is to make
        // sure that the RA packet has been processed.
        apfFilter.pretendPacketReceived(ra1.build());
        program = ipClientCallback.assertProgramUpdateAndGet();
        apfFilter.pretendPacketReceived(ra2.build());
        program = ipClientCallback.assertProgramUpdateAndGet();
        apfFilter.pretendPacketReceived(raInvalid.build());
        ipClientCallback.assertNoProgramUpdate();
        apfFilter.pretendPacketReceived(raZeroRouterLifetime.build());
        ipClientCallback.assertNoProgramUpdate();
        apfFilter.pretendPacketReceived(raZeroPioValidLifetime.build());
        ipClientCallback.assertNoProgramUpdate();
        apfFilter.pretendPacketReceived(raZeroRdnssLifetime.build());
        ipClientCallback.assertNoProgramUpdate();
        apfFilter.pretendPacketReceived(raZeroRioRouteLifetime.build());
        ipClientCallback.assertNoProgramUpdate();

        // Write metrics data to statsd pipeline when shutdown.
        doReturn(startTimeMs + durationTimeMs).when(mClock).elapsedRealtime();
        apfFilter.shutdown();

        // Verify each metric fields in IpClientRaInfoMetrics.
        // LegacyApfFilter will purge expired RAs before adding new RA. Every time a new zero
        // lifetime RA is received, zero lifetime RAs except the newly added one will be
        // cleared, so the number of distinct RAs is 3 (ra1, ra2 and the newly added RA).
        verify(mIpClientRaInfoMetrics).setMaxNumberOfDistinctRas(3);
        verify(mIpClientRaInfoMetrics).setNumberOfZeroLifetimeRas(4);
        verify(mIpClientRaInfoMetrics).setNumberOfParsingErrorRas(1);
        verify(mIpClientRaInfoMetrics).setLowestRouterLifetimeSeconds(routerLifetime);
        verify(mIpClientRaInfoMetrics).setLowestPioValidLifetimeSeconds(prefixValidLifetime);
        verify(mIpClientRaInfoMetrics).setLowestRioRouteLifetimeSeconds(routeLifetime);
        verify(mIpClientRaInfoMetrics).setLowestRdnssLifetimeSeconds(rdnssLifetime);
        verify(mIpClientRaInfoMetrics).statsWrite();
    }

    @Test
    public void testNoMetricsWrittenForShortDuration_LegacyApfFilter() throws Exception {
        final MockIpClientCallback ipClientCallback = new MockIpClientCallback();
        final ApfConfiguration config = getDefaultConfig();
        final long startTimeMs = 12345;
        final long durationTimeMs = config.minMetricsSessionDurationMs;

        // Verify no metrics data written to statsd for duration less than durationTimeMs.
        doReturn(startTimeMs).when(mClock).elapsedRealtime();
        final TestAndroidPacketFilter apfFilter = makeTestApfFilter(config, ipClientCallback);
        doReturn(startTimeMs + durationTimeMs - 1).when(mClock).elapsedRealtime();
        apfFilter.shutdown();
        verify(mApfSessionInfoMetrics, never()).statsWrite();
        verify(mIpClientRaInfoMetrics, never()).statsWrite();

        // Verify metrics data written to statsd for duration greater than or equal to
        // durationTimeMs.
        LegacyApfFilter.Clock clock = mock(LegacyApfFilter.Clock.class);
        doReturn(startTimeMs).when(clock).elapsedRealtime();
        final TestAndroidPacketFilter apfFilter2 = new TestLegacyApfFilter(mContext, config,
                ipClientCallback, mIpConnectivityLog, mNetworkQuirkMetrics, mDependencies, clock);
        doReturn(startTimeMs + durationTimeMs).when(clock).elapsedRealtime();
        apfFilter2.shutdown();
        verify(mApfSessionInfoMetrics).statsWrite();
        verify(mIpClientRaInfoMetrics).statsWrite();
    }

    /**
     * The Mock ip client callback class.
     */
    private static class MockIpClientCallback extends IpClient.IpClientCallbacksWrapper {
        private final ConditionVariable mGotApfProgram = new ConditionVariable();
        private byte[] mLastApfProgram;
        private boolean mInstallPacketFilterReturn = true;

        MockIpClientCallback() {
            super(mock(IIpClientCallbacks.class), mock(SharedLog.class), mock(SharedLog.class),
                    NetworkInformationShimImpl.newInstance(), false);
        }

        MockIpClientCallback(boolean installPacketFilterReturn) {
            super(mock(IIpClientCallbacks.class), mock(SharedLog.class), mock(SharedLog.class),
                    NetworkInformationShimImpl.newInstance(), false);
            mInstallPacketFilterReturn = installPacketFilterReturn;
        }

        @Override
        public boolean installPacketFilter(byte[] filter) {
            mLastApfProgram = filter;
            mGotApfProgram.open();
            return mInstallPacketFilterReturn;
        }

        /**
         * Reset the apf program and wait for the next update.
         */
        public void resetApfProgramWait() {
            mGotApfProgram.close();
        }

        /**
         * Assert the program is update within TIMEOUT_MS and return the program.
         */
        public byte[] assertProgramUpdateAndGet() {
            assertTrue(mGotApfProgram.block(TIMEOUT_MS));
            return mLastApfProgram;
        }

        /**
         * Assert the program is not update within TIMEOUT_MS.
         */
        public void assertNoProgramUpdate() {
            assertFalse(mGotApfProgram.block(TIMEOUT_MS));
        }
    }

    /**
     * The test legacy apf filter class.
     */
    private static class TestLegacyApfFilter extends LegacyApfFilter
            implements TestAndroidPacketFilter {
        public static final byte[] MOCK_MAC_ADDR = {1, 2, 3, 4, 5, 6};
        private static final byte[] MOCK_IPV4_ADDR = {10, 0, 0, 1};

        private FileDescriptor mWriteSocket;
        private final MockIpClientCallback mMockIpClientCb;
        private final boolean mThrowsExceptionWhenGeneratesProgram;

        TestLegacyApfFilter(Context context, ApfFilter.ApfConfiguration config,
                MockIpClientCallback ipClientCallback, IpConnectivityLog ipConnectivityLog,
                NetworkQuirkMetrics networkQuirkMetrics) throws Exception {
            this(context, config, ipClientCallback, ipConnectivityLog, networkQuirkMetrics,
                    new ApfFilter.Dependencies(context),
                    false /* throwsExceptionWhenGeneratesProgram */, new Clock());
        }

        TestLegacyApfFilter(Context context, ApfFilter.ApfConfiguration config,
                MockIpClientCallback ipClientCallback, IpConnectivityLog ipConnectivityLog,
                NetworkQuirkMetrics networkQuirkMetrics, ApfFilter.Dependencies dependencies,
                boolean throwsExceptionWhenGeneratesProgram) throws Exception {
            this(context, config, ipClientCallback, ipConnectivityLog, networkQuirkMetrics,
                    dependencies, throwsExceptionWhenGeneratesProgram, new Clock());
        }

        TestLegacyApfFilter(Context context, ApfFilter.ApfConfiguration config,
                MockIpClientCallback ipClientCallback, IpConnectivityLog ipConnectivityLog,
                NetworkQuirkMetrics networkQuirkMetrics, ApfFilter.Dependencies dependencies,
                Clock clock) throws Exception {
            this(context, config, ipClientCallback, ipConnectivityLog, networkQuirkMetrics,
                    dependencies, false /* throwsExceptionWhenGeneratesProgram */, clock);
        }

        TestLegacyApfFilter(Context context, ApfFilter.ApfConfiguration config,
                MockIpClientCallback ipClientCallback, IpConnectivityLog ipConnectivityLog,
                NetworkQuirkMetrics networkQuirkMetrics, ApfFilter.Dependencies dependencies,
                boolean throwsExceptionWhenGeneratesProgram, Clock clock)
                throws Exception {
            super(context, config, InterfaceParams.getByName("lo"), ipClientCallback,
                    ipConnectivityLog, networkQuirkMetrics, dependencies, clock);
            mMockIpClientCb = ipClientCallback;
            mThrowsExceptionWhenGeneratesProgram = throwsExceptionWhenGeneratesProgram;
        }

        /**
         * Pretend an RA packet has been received and show it to LegacyApfFilter.
         */
        public void pretendPacketReceived(byte[] packet) throws IOException, ErrnoException {
            mMockIpClientCb.resetApfProgramWait();
            // ApfFilter's ReceiveThread will be waiting to read this.
            Os.write(mWriteSocket, packet, 0, packet.length);
        }

        @Override
        public synchronized void maybeStartFilter() {
            mHardwareAddress = MOCK_MAC_ADDR;
            installNewProgramLocked();

            // Create two sockets, "readSocket" and "mWriteSocket" and connect them together.
            FileDescriptor readSocket = new FileDescriptor();
            mWriteSocket = new FileDescriptor();
            try {
                Os.socketpair(AF_UNIX, SOCK_STREAM, 0, mWriteSocket, readSocket);
            } catch (ErrnoException e) {
                fail();
                return;
            }
            // Now pass readSocket to ReceiveThread as if it was setup to read raw RAs.
            // This allows us to pretend RA packets have been received via pretendPacketReceived().
            mReceiveThread = new ReceiveThread(readSocket);
            mReceiveThread.start();
        }

        @Override
        public synchronized void shutdown() {
            super.shutdown();
            if (mReceiveThread != null) {
                mReceiveThread.halt();
                mReceiveThread = null;
            }
            IoUtils.closeQuietly(mWriteSocket);
        }

        @Override
        @GuardedBy("this")
        protected ApfV4Generator emitPrologueLocked() throws
                BaseApfGenerator.IllegalInstructionException {
            if (mThrowsExceptionWhenGeneratesProgram) {
                throw new IllegalStateException();
            }
            return super.emitPrologueLocked();
        }
    }
}
