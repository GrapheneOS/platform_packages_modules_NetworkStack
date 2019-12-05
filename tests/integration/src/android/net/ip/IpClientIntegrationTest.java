/*
 * Copyright (C) 2019 The Android Open Source Project
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

package android.net.ip;

import static android.net.dhcp.DhcpClient.EXPIRED_LEASE;
import static android.net.dhcp.DhcpPacket.DHCP_BOOTREQUEST;
import static android.net.dhcp.DhcpPacket.DHCP_CLIENT;
import static android.net.dhcp.DhcpPacket.DHCP_MAGIC_COOKIE;
import static android.net.dhcp.DhcpPacket.DHCP_SERVER;
import static android.net.dhcp.DhcpPacket.ENCAP_L2;
import static android.net.dhcp.DhcpPacket.INFINITE_LEASE;
import static android.net.ipmemorystore.Status.SUCCESS;
import static android.net.networkstack.shared.Inet4AddressUtils.getBroadcastAddress;
import static android.net.networkstack.shared.Inet4AddressUtils.getPrefixMaskAsInet4Address;
import static android.system.OsConstants.ETH_P_IPV6;
import static android.system.OsConstants.IPPROTO_ICMPV6;
import static android.system.OsConstants.IPPROTO_TCP;

import static com.android.internal.util.BitUtils.uint16;
import static com.android.server.util.NetworkStackConstants.ETHER_HEADER_LEN;
import static com.android.server.util.NetworkStackConstants.ETHER_TYPE_IPV6;
import static com.android.server.util.NetworkStackConstants.ETHER_TYPE_OFFSET;
import static com.android.server.util.NetworkStackConstants.ICMPV6_CHECKSUM_OFFSET;
import static com.android.server.util.NetworkStackConstants.ICMPV6_ND_OPTION_LENGTH_SCALING_FACTOR;
import static com.android.server.util.NetworkStackConstants.ICMPV6_ND_OPTION_PIO;
import static com.android.server.util.NetworkStackConstants.ICMPV6_ND_OPTION_RDNSS;
import static com.android.server.util.NetworkStackConstants.ICMPV6_RA_HEADER_LEN;
import static com.android.server.util.NetworkStackConstants.ICMPV6_ROUTER_ADVERTISEMENT;
import static com.android.server.util.NetworkStackConstants.ICMPV6_ROUTER_SOLICITATION;
import static com.android.server.util.NetworkStackConstants.IPV6_HEADER_LEN;
import static com.android.server.util.NetworkStackConstants.IPV6_LEN_OFFSET;
import static com.android.server.util.NetworkStackConstants.IPV6_PROTOCOL_OFFSET;

import static junit.framework.Assert.fail;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.argThat;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import android.app.AlarmManager;
import android.app.Instrumentation;
import android.content.ContentResolver;
import android.content.Context;
import android.content.res.Resources;
import android.net.ConnectivityManager;
import android.net.INetd;
import android.net.InetAddresses;
import android.net.InterfaceConfigurationParcel;
import android.net.IpPrefix;
import android.net.Layer2PacketParcelable;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.MacAddress;
import android.net.NetworkStackIpMemoryStore;
import android.net.TestNetworkInterface;
import android.net.TestNetworkManager;
import android.net.dhcp.DhcpClient;
import android.net.dhcp.DhcpDiscoverPacket;
import android.net.dhcp.DhcpPacket;
import android.net.dhcp.DhcpPacket.ParseException;
import android.net.dhcp.DhcpRequestPacket;
import android.net.ipmemorystore.NetworkAttributes;
import android.net.ipmemorystore.OnNetworkAttributesRetrievedListener;
import android.net.ipmemorystore.Status;
import android.net.shared.ProvisioningConfiguration;
import android.net.util.IpUtils;
import android.net.util.NetworkStackUtils;
import android.net.util.PacketReader;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;
import android.os.RemoteException;
import android.system.ErrnoException;
import android.system.Os;

import androidx.annotation.Nullable;
import androidx.test.InstrumentationRegistry;
import androidx.test.filters.SmallTest;
import androidx.test.runner.AndroidJUnit4;

import com.android.server.NetworkObserverRegistry;
import com.android.server.NetworkStackService.NetworkStackServiceManager;
import com.android.server.connectivity.ipmemorystore.IpMemoryStoreService;

import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.Spy;

import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * Tests for IpClient.
 */
@RunWith(AndroidJUnit4.class)
@SmallTest
public class IpClientIntegrationTest {
    private static final int DATA_BUFFER_LEN = 4096;
    private static final int PACKET_TIMEOUT_MS = 5_000;
    private static final int TEST_TIMEOUT_MS = 400;
    private static final String TEST_L2KEY = "some l2key";
    private static final String TEST_GROUPHINT = "some grouphint";
    private static final int TEST_LEASE_DURATION_S = 3_600; // 1 hour

    @Mock private Context mContext;
    @Mock private ConnectivityManager mCm;
    @Mock private Resources mResources;
    @Mock private IIpClientCallbacks mCb;
    @Mock private AlarmManager mAlarm;
    @Mock private ContentResolver mContentResolver;
    @Mock private NetworkStackServiceManager mNetworkStackServiceManager;
    @Mock private NetworkStackIpMemoryStore mIpMemoryStore;
    @Mock private IpMemoryStoreService mIpMemoryStoreService;

    @Spy private INetd mNetd;

    private String mIfaceName;
    private HandlerThread mPacketReaderThread;
    private Handler mHandler;
    private TapPacketReader mPacketReader;
    private IpClient mIpc;
    private Dependencies mDependencies;

    // Ethernet header
    private static final int ETH_HEADER_LEN = 14;

    // IP header
    private static final int IPV4_HEADER_LEN = 20;
    private static final int IPV4_SRC_ADDR_OFFSET = ETH_HEADER_LEN + 12;

    // UDP header
    private static final int UDP_HEADER_LEN = 8;
    private static final int UDP_HEADER_OFFSET = ETH_HEADER_LEN + IPV4_HEADER_LEN;
    private static final int UDP_SRC_PORT_OFFSET = UDP_HEADER_OFFSET + 0;

    // DHCP header
    private static final int DHCP_HEADER_OFFSET = ETH_HEADER_LEN + IPV4_HEADER_LEN
            + UDP_HEADER_LEN;
    private static final int DHCP_MESSAGE_OP_CODE_OFFSET = DHCP_HEADER_OFFSET + 0;
    private static final int DHCP_TRANSACTION_ID_OFFSET = DHCP_HEADER_OFFSET + 4;
    private static final int DHCP_OPTION_MAGIC_COOKIE_OFFSET = DHCP_HEADER_OFFSET + 236;
    private static final int DHCP_OPTION_MESSAGE_TYPE_OFFSET = DHCP_OPTION_MAGIC_COOKIE_OFFSET + 4;

    private static final Inet4Address SERVER_ADDR =
            (Inet4Address) InetAddresses.parseNumericAddress("192.168.1.100");
    private static final Inet4Address CLIENT_ADDR =
            (Inet4Address) InetAddresses.parseNumericAddress("192.168.1.2");
    private static final Inet4Address INADDR_ANY =
            (Inet4Address) InetAddresses.parseNumericAddress("0.0.0.0");
    private static final int PREFIX_LENGTH = 24;
    private static final Inet4Address NETMASK = getPrefixMaskAsInet4Address(PREFIX_LENGTH);
    private static final Inet4Address BROADCAST_ADDR = getBroadcastAddress(
            SERVER_ADDR, PREFIX_LENGTH);
    private static final String HOSTNAME = "testhostname";
    private static final int TEST_DEFAULT_MTU = 1500;
    private static final int TEST_MIN_MTU = 1280;

    private static class TapPacketReader extends PacketReader {
        private final ParcelFileDescriptor mTapFd;
        private final LinkedBlockingQueue<byte[]> mReceivedPackets =
                new LinkedBlockingQueue<byte[]>();

        TapPacketReader(Handler h, ParcelFileDescriptor tapFd) {
            super(h, DATA_BUFFER_LEN);
            mTapFd = tapFd;
        }

        @Override
        protected FileDescriptor createFd() {
            return mTapFd.getFileDescriptor();
        }

        @Override
        protected void handlePacket(byte[] recvbuf, int length) {
            final byte[] newPacket = Arrays.copyOf(recvbuf, length);
            try {
                mReceivedPackets.put(newPacket);
            } catch (InterruptedException e) {
                fail("fail to put the new packet in the queue");
            }
        }

        /**
         * Get the next packet that was received on the interface.
         *
         */
        @Nullable
        public byte[] popPacket(long timeoutMs) {
            try {
                return mReceivedPackets.poll(timeoutMs, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                // Fall through
            }
            return null;
        }
    }

    private class Dependencies extends IpClient.Dependencies {
        private boolean mIsDhcpLeaseCacheEnabled;
        private boolean mIsDhcpRapidCommitEnabled;
        // Can't use SparseIntArray, it doesn't have an easy way to know if a key is not present.
        private HashMap<String, Integer> mIntConfigProperties = new HashMap<>();

        public void setDhcpLeaseCacheEnabled(final boolean enable) {
            mIsDhcpLeaseCacheEnabled = enable;
        }

        public void setDhcpRapidCommitEnabled(final boolean enable) {
            mIsDhcpRapidCommitEnabled = enable;
        }

        @Override
        public INetd getNetd(Context context) {
            return mNetd;
        }

        @Override
        public NetworkStackIpMemoryStore getIpMemoryStore(Context context,
                NetworkStackServiceManager nssManager) {
            return mIpMemoryStore;
        }

        @Override
        public DhcpClient.Dependencies getDhcpClientDependencies(
                NetworkStackIpMemoryStore ipMemoryStore) {
            return new DhcpClient.Dependencies(ipMemoryStore) {
                @Override
                public boolean getBooleanDeviceConfig(final String nameSpace,
                        final String flagName) {
                    switch (flagName) {
                        case NetworkStackUtils.DHCP_RAPID_COMMIT_ENABLED:
                            return mIsDhcpRapidCommitEnabled;
                        case NetworkStackUtils.DHCP_INIT_REBOOT_ENABLED:
                            return mIsDhcpLeaseCacheEnabled;
                        default:
                            fail("Invalid experiment flag: " + flagName);
                            return false;
                    }
                }
            };
        }

        @Override
        public int getDeviceConfigPropertyInt(String name, int defaultValue) {
            Integer value = mIntConfigProperties.get(name);
            if (value == null) {
                throw new IllegalStateException("Non-mocked device config property " + name);
            }
            return value;
        }

        public void setDeviceConfigProperty(String name, int value) {
            mIntConfigProperties.put(name, value);
        }
    }

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);

        mDependencies = new Dependencies();
        when(mContext.getSystemService(eq(Context.ALARM_SERVICE))).thenReturn(mAlarm);
        when(mContext.getSystemService(eq(ConnectivityManager.class))).thenReturn(mCm);
        when(mContext.getResources()).thenReturn(mResources);
        when(mContext.getContentResolver()).thenReturn(mContentResolver);
        when(mNetworkStackServiceManager.getIpMemoryStoreService())
                .thenReturn(mIpMemoryStoreService);

        mDependencies.setDeviceConfigProperty(IpClient.CONFIG_MIN_RDNSS_LIFETIME, 67);

        setUpTapInterface();
        setUpIpClient();
    }

    private void awaitIpClientShutdown() throws Exception {
        verify(mCb, timeout(TEST_TIMEOUT_MS)).onQuit();
    }

    @After
    public void tearDown() throws Exception {
        if (mPacketReader != null) {
            mHandler.post(() -> mPacketReader.stop()); // Also closes the socket
        }
        if (mPacketReaderThread != null) {
            mPacketReaderThread.quitSafely();
        }
        mIpc.shutdown();
        awaitIpClientShutdown();
    }

    private void setUpTapInterface() {
        final Instrumentation inst = InstrumentationRegistry.getInstrumentation();
        // Adopt the shell permission identity to create a test TAP interface.
        inst.getUiAutomation().adoptShellPermissionIdentity();

        final TestNetworkInterface iface;
        try {
            final TestNetworkManager tnm = (TestNetworkManager)
                    inst.getContext().getSystemService(Context.TEST_NETWORK_SERVICE);
            iface = tnm.createTapInterface();
        } finally {
            // Drop the identity in order to regain the network stack permissions, which the shell
            // does not have.
            inst.getUiAutomation().dropShellPermissionIdentity();
        }
        mIfaceName = iface.getInterfaceName();
        mPacketReaderThread = new HandlerThread(IpClientIntegrationTest.class.getSimpleName());
        mPacketReaderThread.start();
        mHandler = mPacketReaderThread.getThreadHandler();

        final ParcelFileDescriptor tapFd = iface.getFileDescriptor();
        mPacketReader = new TapPacketReader(mHandler, tapFd);
        mHandler.post(() -> mPacketReader.start());
    }

    private void setUpIpClient() throws Exception {
        final Instrumentation inst = InstrumentationRegistry.getInstrumentation();
        final IBinder netdIBinder =
                (IBinder) inst.getContext().getSystemService(Context.NETD_SERVICE);
        mNetd = spy(INetd.Stub.asInterface(netdIBinder));
        when(mContext.getSystemService(eq(Context.NETD_SERVICE))).thenReturn(netdIBinder);
        assertNotNull(mNetd);

        final NetworkObserverRegistry reg = new NetworkObserverRegistry();
        reg.register(mNetd);
        mIpc = new IpClient(mContext, mIfaceName, mCb, reg, mNetworkStackServiceManager,
                mDependencies);
    }

    private boolean packetContainsExpectedField(final byte[] packet, final int offset,
            final byte[] expected) {
        if (packet.length < offset + expected.length) return false;
        for (int i = 0; i < expected.length; ++i) {
            if (packet[offset + i] != expected[i]) return false;
        }
        return true;
    }

    private boolean isDhcpPacket(final byte[] packet) {
        final ByteBuffer buffer = ByteBuffer.wrap(packet);

        // check the packet length
        if (packet.length < DHCP_HEADER_OFFSET) return false;

        // check the source port and dest port in UDP header
        buffer.position(UDP_SRC_PORT_OFFSET);
        final short udpSrcPort = buffer.getShort();
        final short udpDstPort = buffer.getShort();
        if (udpSrcPort != DHCP_CLIENT || udpDstPort != DHCP_SERVER) return false;

        // check DHCP message type
        buffer.position(DHCP_MESSAGE_OP_CODE_OFFSET);
        final byte dhcpOpCode = buffer.get();
        if (dhcpOpCode != DHCP_BOOTREQUEST) return false;

        // check DHCP magic cookie
        buffer.position(DHCP_OPTION_MAGIC_COOKIE_OFFSET);
        final int dhcpMagicCookie = buffer.getInt();
        if (dhcpMagicCookie != DHCP_MAGIC_COOKIE) return false;

        return true;
    }

    private static ByteBuffer buildDhcpOfferPacket(final DhcpPacket packet,
            final Integer leaseTimeSec, final short mtu) {
        return DhcpPacket.buildOfferPacket(DhcpPacket.ENCAP_L2, packet.getTransactionId(),
                false /* broadcast */, SERVER_ADDR, INADDR_ANY /* relayIp */,
                CLIENT_ADDR /* yourIp */, packet.getClientMac(), leaseTimeSec,
                NETMASK /* netMask */, BROADCAST_ADDR /* bcAddr */,
                Collections.singletonList(SERVER_ADDR) /* gateways */,
                Collections.singletonList(SERVER_ADDR) /* dnsServers */,
                SERVER_ADDR /* dhcpServerIdentifier */, null /* domainName */, HOSTNAME,
                false /* metered */, mtu);
    }

    private static ByteBuffer buildDhcpAckPacket(final DhcpPacket packet,
            final Integer leaseTimeSec, final short mtu) {
        return DhcpPacket.buildAckPacket(DhcpPacket.ENCAP_L2, packet.getTransactionId(),
                false /* broadcast */, SERVER_ADDR, INADDR_ANY /* relayIp */,
                CLIENT_ADDR /* yourIp */, CLIENT_ADDR /* requestIp */, packet.getClientMac(),
                leaseTimeSec, NETMASK /* netMask */, BROADCAST_ADDR /* bcAddr */,
                Collections.singletonList(SERVER_ADDR) /* gateways */,
                Collections.singletonList(SERVER_ADDR) /* dnsServers */,
                SERVER_ADDR /* dhcpServerIdentifier */, null /* domainName */, HOSTNAME,
                false /* metered */, mtu);
    }

    private static ByteBuffer buildDhcpNakPacket(final DhcpPacket packet) {
        return DhcpPacket.buildNakPacket(DhcpPacket.ENCAP_L2, packet.getTransactionId(),
            SERVER_ADDR /* serverIp */, INADDR_ANY /* relayIp */, packet.getClientMac(),
            false /* broadcast */, "duplicated request IP address");
    }

    private void sendResponse(final ByteBuffer packet) throws IOException {
        try (FileOutputStream out = new FileOutputStream(mPacketReader.createFd())) {
            byte[] packetBytes = new byte[packet.limit()];
            packet.get(packetBytes);
            packet.flip();  // So we can reuse it in the future.
            out.write(packetBytes);
        }
    }

    private void startIpClientProvisioning(final boolean isDhcpLeaseCacheEnabled,
            final boolean isDhcpRapidCommitEnabled, final boolean isPreconnectionEnabled)
            throws RemoteException {
        ProvisioningConfiguration.Builder builder = new ProvisioningConfiguration.Builder()
                .withoutIpReachabilityMonitor()
                .withoutIPv6();
        if (isPreconnectionEnabled) builder.withPreconnection();

        mDependencies.setDhcpLeaseCacheEnabled(isDhcpLeaseCacheEnabled);
        mDependencies.setDhcpRapidCommitEnabled(isDhcpRapidCommitEnabled);
        mIpc.setL2KeyAndGroupHint(TEST_L2KEY, TEST_GROUPHINT);
        mIpc.startProvisioning(builder.build());
        verify(mCb).setNeighborDiscoveryOffload(true);
        if (!isPreconnectionEnabled) {
            verify(mCb, timeout(TEST_TIMEOUT_MS)).setFallbackMulticastFilter(false);
        }
        verify(mCb, never()).onProvisioningFailure(any());
    }

    private void assertIpMemoryStoreNetworkAttributes(final Integer leaseTimeSec,
            final long startTime, final int mtu) {
        final ArgumentCaptor<NetworkAttributes> networkAttributes =
                ArgumentCaptor.forClass(NetworkAttributes.class);

        verify(mIpMemoryStore, timeout(TEST_TIMEOUT_MS))
            .storeNetworkAttributes(eq(TEST_L2KEY), networkAttributes.capture(), any());
        final NetworkAttributes naValueCaptured = networkAttributes.getValue();
        assertEquals(CLIENT_ADDR, naValueCaptured.assignedV4Address);
        if (leaseTimeSec == null || leaseTimeSec.intValue() == DhcpPacket.INFINITE_LEASE) {
            assertEquals(Long.MAX_VALUE, naValueCaptured.assignedV4AddressExpiry.longValue());
        } else {
            // check the lease expiry's scope
            final long upperBound = startTime + 7_200_000; // start timestamp + 2h
            final long lowerBound = startTime + 3_600_000; // start timestamp + 1h
            final long expiry = naValueCaptured.assignedV4AddressExpiry;
            assertTrue(upperBound > expiry);
            assertTrue(lowerBound < expiry);
        }
        assertEquals(Collections.singletonList(SERVER_ADDR), naValueCaptured.dnsAddresses);
        assertEquals(new Integer(mtu), naValueCaptured.mtu);
    }

    private void assertIpMemoryNeverStoreNetworkAttributes() {
        verify(mIpMemoryStore, never()).storeNetworkAttributes(any(), any(), any());
    }

    // Helper method to complete DHCP 2-way or 4-way handshake
    private void performDhcpHandshake(final boolean isSuccessLease,
            final Integer leaseTimeSec, final boolean isDhcpLeaseCacheEnabled,
            final boolean isDhcpRapidCommitEnabled, final int mtu) throws Exception {
        startIpClientProvisioning(isDhcpLeaseCacheEnabled, isDhcpRapidCommitEnabled,
                false /* isPreconnectionEnabled */);

        DhcpPacket packet;
        while ((packet = getNextDhcpPacket()) != null) {
            if (packet instanceof DhcpDiscoverPacket) {
                if (isDhcpRapidCommitEnabled) {
                    sendResponse(buildDhcpAckPacket(packet, leaseTimeSec, (short) mtu));
                } else {
                    sendResponse(buildDhcpOfferPacket(packet, leaseTimeSec, (short) mtu));
                }
            } else if (packet instanceof DhcpRequestPacket) {
                final ByteBuffer byteBuffer = isSuccessLease
                        ? buildDhcpAckPacket(packet, leaseTimeSec, (short) mtu)
                        : buildDhcpNakPacket(packet);
                sendResponse(byteBuffer);
            } else {
                fail("invalid DHCP packet");
            }
            // wait for reply to DHCPOFFER packet if disabling rapid commit option
            if (isDhcpRapidCommitEnabled || !(packet instanceof DhcpDiscoverPacket)) return;
        }
        fail("No DHCPREQUEST received on interface");
    }

    private DhcpPacket getNextDhcpPacket() throws ParseException {
        byte[] packet;
        while ((packet = mPacketReader.popPacket(PACKET_TIMEOUT_MS)) != null) {
            if (!isDhcpPacket(packet)) continue;
            return DhcpPacket.decodeFullPacket(packet, packet.length, ENCAP_L2);
        }
        fail("No expected DHCP packet received on interface within timeout");
        return null;
    }

    private DhcpPacket getReplyFromDhcpLease(final NetworkAttributes na, boolean timeout)
            throws Exception {
        doAnswer(invocation -> {
            if (timeout) return null;
            ((OnNetworkAttributesRetrievedListener) invocation.getArgument(1))
                    .onNetworkAttributesRetrieved(new Status(SUCCESS), TEST_L2KEY, na);
            return null;
        }).when(mIpMemoryStore).retrieveNetworkAttributes(eq(TEST_L2KEY), any());
        startIpClientProvisioning(true /* isDhcpLeaseCacheEnabled */,
                false /* isDhcpRapidCommitEnabled */, false /* isPreconnectionEnabled */);
        return getNextDhcpPacket();
    }

    private void removeTapInterface(final FileDescriptor fd) {
        try {
            Os.close(fd);
        } catch (ErrnoException e) {
            fail("Fail to close file descriptor: " + e);
        }
    }

    private void verifyAfterIpClientShutdown() throws RemoteException {
        final LinkProperties emptyLp = new LinkProperties();
        emptyLp.setInterfaceName(mIfaceName);
        verify(mCb, timeout(TEST_TIMEOUT_MS)).onLinkPropertiesChange(emptyLp);
    }

    private void doRestoreInitialMtuTest(final boolean shouldChangeMtu,
            final boolean shouldRemoveTapInterface) throws Exception {
        final long currentTime = System.currentTimeMillis();
        int mtu = TEST_DEFAULT_MTU;

        if (shouldChangeMtu) mtu = TEST_MIN_MTU;
        performDhcpHandshake(true /* isSuccessLease */, TEST_LEASE_DURATION_S,
                true /* isDhcpLeaseCacheEnabled */, false /* isDhcpRapidCommitEnabled */, mtu);
        assertIpMemoryStoreNetworkAttributes(TEST_LEASE_DURATION_S, currentTime, mtu);

        if (shouldChangeMtu) {
            // Pretend that ConnectivityService set the MTU.
            mNetd.interfaceSetMtu(mIfaceName, mtu);
            assertEquals(NetworkInterface.getByName(mIfaceName).getMTU(), mtu);
        }

        if (shouldRemoveTapInterface) removeTapInterface(mPacketReader.createFd());
        try {
            mIpc.shutdown();
            awaitIpClientShutdown();
            if (shouldRemoveTapInterface) {
                verify(mNetd, never()).interfaceSetMtu(mIfaceName, TEST_DEFAULT_MTU);
            } else {
                // Verify that MTU indeed has been restored or not.
                verify(mNetd, times(shouldChangeMtu ? 1 : 0))
                        .interfaceSetMtu(mIfaceName, TEST_DEFAULT_MTU);
            }
            verifyAfterIpClientShutdown();
        } catch (Exception e) {
            fail("Exception should not have been thrown after shutdown: " + e);
        }
    }

    private void doIpClientProvisioningWithPreconnectionTest(final boolean isDhcpRapidCommitEnabled,
            final boolean shouldAbortPreconnection) throws Exception {
        final long currentTime = System.currentTimeMillis();
        final ArgumentCaptor<List<Layer2PacketParcelable>> l2PacketList =
                ArgumentCaptor.forClass(List.class);
        final ArgumentCaptor<InterfaceConfigurationParcel> ifConfig =
                ArgumentCaptor.forClass(InterfaceConfigurationParcel.class);

        startIpClientProvisioning(true /* isDhcpLeaseCacheEnabled */,
                isDhcpRapidCommitEnabled, true /* isDhcpPreConnectionEnabled */);
        verify(mCb, timeout(TEST_TIMEOUT_MS).times(1))
                .onPreconnectionStart(l2PacketList.capture());
        final byte[] payload = l2PacketList.getValue().get(0).payload;
        DhcpPacket packet = DhcpPacket.decodeFullPacket(payload, payload.length, ENCAP_L2);
        assertTrue(packet instanceof DhcpDiscoverPacket);

        if (shouldAbortPreconnection) {
            mIpc.sendMessage(IpClient.CMD_COMPLETE_PRECONNECTION, 0 /* abort */);
            packet = getNextDhcpPacket();
            assertTrue(packet instanceof DhcpDiscoverPacket);
        }

        final short mtu = (short) TEST_DEFAULT_MTU;
        if (!isDhcpRapidCommitEnabled) {
            sendResponse(buildDhcpOfferPacket(packet, TEST_LEASE_DURATION_S, mtu));
            packet = getNextDhcpPacket();
            assertTrue(packet instanceof DhcpRequestPacket);
        }
        // TODO: currently the DHCPACK packet doesn't include the Rapid Commit option.
        // This does not matter because the client will accept the ACK even if the Rapid Commit
        // option is not present. Fix the test code, and then change the client to ensure
        // it will only accept the ACK if the Rapid Commit option is present.
        sendResponse(buildDhcpAckPacket(packet, TEST_LEASE_DURATION_S, mtu));
        if (!shouldAbortPreconnection) {
            mIpc.sendMessage(IpClient.CMD_COMPLETE_PRECONNECTION, 1 /* success */);
        }
        verify(mCb, timeout(TEST_TIMEOUT_MS)).setFallbackMulticastFilter(false);

        final LinkAddress ipAddress = new LinkAddress(CLIENT_ADDR, PREFIX_LENGTH);
        verify(mNetd, timeout(TEST_TIMEOUT_MS).times(1)).interfaceSetCfg(ifConfig.capture());
        assertEquals(ifConfig.getValue().ifName, mIfaceName);
        assertEquals(ifConfig.getValue().ipv4Addr, ipAddress.getAddress().getHostAddress());
        assertEquals(ifConfig.getValue().prefixLength, PREFIX_LENGTH);
        assertIpMemoryStoreNetworkAttributes(TEST_LEASE_DURATION_S, currentTime, TEST_DEFAULT_MTU);
    }

    @Test
    public void testDhcpInit() throws Exception {
        startIpClientProvisioning(false /* isDhcpLeaseCacheEnabled */,
                false /* isDhcpRapidCommitEnabled */, false /* isPreconnectionEnabled */);
        final DhcpPacket packet = getNextDhcpPacket();
        assertTrue(packet instanceof DhcpDiscoverPacket);
    }

    @Test
    public void testHandleSuccessDhcpLease() throws Exception {
        final long currentTime = System.currentTimeMillis();
        performDhcpHandshake(true /* isSuccessLease */, TEST_LEASE_DURATION_S,
                true /* isDhcpLeaseCacheEnabled */, false /* isDhcpRapidCommitEnabled */,
                TEST_DEFAULT_MTU);
        assertIpMemoryStoreNetworkAttributes(TEST_LEASE_DURATION_S, currentTime, TEST_DEFAULT_MTU);
    }

    @Test
    public void testHandleFailureDhcpLease() throws Exception {
        performDhcpHandshake(false /* isSuccessLease */, TEST_LEASE_DURATION_S,
                true /* isDhcpLeaseCacheEnabled */, false /* isDhcpRapidCommitEnabled */,
                TEST_DEFAULT_MTU);
        assertIpMemoryNeverStoreNetworkAttributes();
    }

    @Test
    public void testHandleInfiniteLease() throws Exception {
        final long currentTime = System.currentTimeMillis();
        performDhcpHandshake(true /* isSuccessLease */, INFINITE_LEASE,
                true /* isDhcpLeaseCacheEnabled */, false /* isDhcpRapidCommitEnabled */,
                TEST_DEFAULT_MTU);
        assertIpMemoryStoreNetworkAttributes(INFINITE_LEASE, currentTime, TEST_DEFAULT_MTU);
    }

    @Test
    public void testHandleNoLease() throws Exception {
        final long currentTime = System.currentTimeMillis();
        performDhcpHandshake(true /* isSuccessLease */, null /* no lease time */,
                true /* isDhcpLeaseCacheEnabled */, false /* isDhcpRapidCommitEnabled */,
                TEST_DEFAULT_MTU);
        assertIpMemoryStoreNetworkAttributes(null, currentTime, TEST_DEFAULT_MTU);
    }

    @Test
    public void testHandleDisableInitRebootState() throws Exception {
        performDhcpHandshake(true /* isSuccessLease */, TEST_LEASE_DURATION_S,
                false /* isDhcpLeaseCacheEnabled */, false /* isDhcpRapidCommitEnabled */,
                TEST_DEFAULT_MTU);
        assertIpMemoryNeverStoreNetworkAttributes();
    }

    @Ignore
    @Test
    public void testHandleRapidCommitOption() throws Exception {
        // TODO: remove @Ignore after supporting rapid commit option in DHCP server
        final long currentTime = System.currentTimeMillis();
        performDhcpHandshake(true /* isSuccessLease */, TEST_LEASE_DURATION_S,
                true /* isDhcpLeaseCacheEnabled */, true /* isDhcpRapidCommitEnabled */,
                TEST_DEFAULT_MTU);
        assertIpMemoryStoreNetworkAttributes(TEST_LEASE_DURATION_S, currentTime, TEST_DEFAULT_MTU);
    }

    @Test
    public void testDhcpClientStartWithCachedInfiniteLease() throws Exception {
        final DhcpPacket packet = getReplyFromDhcpLease(
                new NetworkAttributes.Builder()
                    .setAssignedV4Address(CLIENT_ADDR)
                    .setAssignedV4AddressExpiry(Long.MAX_VALUE) // lease is always valid
                    .setMtu(new Integer(TEST_DEFAULT_MTU))
                    .setGroupHint(TEST_GROUPHINT)
                    .setDnsAddresses(Collections.singletonList(SERVER_ADDR))
                    .build(), false /* timeout */);
        assertTrue(packet instanceof DhcpRequestPacket);
    }

    @Test
    public void testDhcpClientStartWithCachedExpiredLease() throws Exception {
        final DhcpPacket packet = getReplyFromDhcpLease(
                 new NetworkAttributes.Builder()
                    .setAssignedV4Address(CLIENT_ADDR)
                    .setAssignedV4AddressExpiry(EXPIRED_LEASE)
                    .setMtu(new Integer(TEST_DEFAULT_MTU))
                    .setGroupHint(TEST_GROUPHINT)
                    .setDnsAddresses(Collections.singletonList(SERVER_ADDR))
                    .build(), false /* timeout */);
        assertTrue(packet instanceof DhcpDiscoverPacket);
    }

    @Test
    public void testDhcpClientStartWithNullRetrieveNetworkAttributes() throws Exception {
        final DhcpPacket packet = getReplyFromDhcpLease(null /* na */, false /* timeout */);
        assertTrue(packet instanceof DhcpDiscoverPacket);
    }

    @Test
    public void testDhcpClientStartWithTimeoutRetrieveNetworkAttributes() throws Exception {
        final DhcpPacket packet = getReplyFromDhcpLease(
                new NetworkAttributes.Builder()
                    .setAssignedV4Address(CLIENT_ADDR)
                    .setAssignedV4AddressExpiry(System.currentTimeMillis() + 3_600_000)
                    .setMtu(new Integer(TEST_DEFAULT_MTU))
                    .setGroupHint(TEST_GROUPHINT)
                    .setDnsAddresses(Collections.singletonList(SERVER_ADDR))
                    .build(), true /* timeout */);
        assertTrue(packet instanceof DhcpDiscoverPacket);
    }

    @Test
    public void testDhcpClientStartWithCachedLeaseWithoutIPAddress() throws Exception {
        final DhcpPacket packet = getReplyFromDhcpLease(
                new NetworkAttributes.Builder()
                    .setMtu(new Integer(TEST_DEFAULT_MTU))
                    .setGroupHint(TEST_GROUPHINT)
                    .setDnsAddresses(Collections.singletonList(SERVER_ADDR))
                    .build(), false /* timeout */);
        assertTrue(packet instanceof DhcpDiscoverPacket);
    }

    @Test
    public void testDhcpClientRapidCommitEnabled() throws Exception {
        startIpClientProvisioning(true /* isDhcpLeaseCacheEnabled */,
                true /* isDhcpRapidCommitEnabled */, false /* isPreconnectionEnabled */);
        final DhcpPacket packet = getNextDhcpPacket();
        assertTrue(packet instanceof DhcpDiscoverPacket);
    }

    @Test
    public void testRestoreInitialInterfaceMtu() throws Exception {
        doRestoreInitialMtuTest(true /* shouldChangeMtu */, false /* shouldRemoveTapInterface */);
    }

    @Test
    public void testRestoreInitialInterfaceMtu_WithoutMtuChange() throws Exception {
        doRestoreInitialMtuTest(false /* shouldChangeMtu */, false /* shouldRemoveTapInterface */);
    }

    @Test
    public void testRestoreInitialInterfaceMtu_WithException() throws Exception {
        doThrow(new RemoteException("NetdNativeService::interfaceSetMtu")).when(mNetd)
                .interfaceSetMtu(mIfaceName, TEST_DEFAULT_MTU);

        doRestoreInitialMtuTest(true /* shouldChangeMtu */, false /* shouldRemoveTapInterface */);
        assertEquals(NetworkInterface.getByName(mIfaceName).getMTU(), TEST_MIN_MTU);
    }

    @Test
    public void testRestoreInitialInterfaceMtu_NotFoundInterfaceWhenStopping() throws Exception {
        doRestoreInitialMtuTest(true /* shouldChangeMtu */, true /* shouldRemoveTapInterface */);
    }

    @Test
    public void testRestoreInitialInterfaceMtu_NotFoundInterfaceWhenStartingProvisioning()
            throws Exception {
        removeTapInterface(mPacketReader.createFd());
        ProvisioningConfiguration config = new ProvisioningConfiguration.Builder()
                .withoutIpReachabilityMonitor()
                .withoutIPv6()
                .build();

        mIpc.startProvisioning(config);
        verify(mCb).onProvisioningFailure(any());
        verify(mCb, never()).setNeighborDiscoveryOffload(true);
    }

    private boolean isRouterSolicitation(final byte[] packetBytes) {
        ByteBuffer packet = ByteBuffer.wrap(packetBytes);
        return packet.getShort(ETHER_TYPE_OFFSET) == (short) ETH_P_IPV6
                && packet.get(ETHER_HEADER_LEN + IPV6_PROTOCOL_OFFSET) == (byte) IPPROTO_ICMPV6
                && packet.get(ETHER_HEADER_LEN + IPV6_HEADER_LEN)
                        == (byte) ICMPV6_ROUTER_SOLICITATION;
    }

    private void waitForRouterSolicitation() throws ParseException {
        byte[] packet;
        while ((packet = mPacketReader.popPacket(PACKET_TIMEOUT_MS)) != null) {
            if (isRouterSolicitation(packet)) return;
        }
        fail("No router solicitation received on interface within timeout");
    }

    // TODO: move this and the following method to a common location and use them in ApfTest.
    private static ByteBuffer buildPioOption(int valid, int preferred, String prefixString)
            throws Exception {
        final int optLen = 4;
        IpPrefix prefix = new IpPrefix(prefixString);
        ByteBuffer option = ByteBuffer.allocate(optLen * ICMPV6_ND_OPTION_LENGTH_SCALING_FACTOR);
        option.put((byte) ICMPV6_ND_OPTION_PIO);      // Type
        option.put((byte) optLen);                    // Length in 8-byte units
        option.put((byte) prefix.getPrefixLength());  // Prefix length
        option.put((byte) 0b11000000);                // L = 1, A = 1
        option.putInt(valid);
        option.putInt(preferred);
        option.putInt(0);                             // Reserved
        option.put(prefix.getRawAddress());
        option.flip();
        return option;
    }

    private static ByteBuffer buildRdnssOption(int lifetime, String... servers) throws Exception {
        final int optLen = 1 + 2 * servers.length;
        ByteBuffer option = ByteBuffer.allocate(optLen * ICMPV6_ND_OPTION_LENGTH_SCALING_FACTOR);
        option.put((byte) ICMPV6_ND_OPTION_RDNSS);  // Type
        option.put((byte) optLen);                  // Length in 8-byte units
        option.putShort((short) 0);                 // Reserved
        option.putInt(lifetime);                    // Lifetime
        for (String server : servers) {
            option.put(InetAddress.getByName(server).getAddress());
        }
        option.flip();
        return option;
    }

    // HACK: these functions are here because IpUtils#transportChecksum is private. Even if we made
    // that public, it won't be available on Q devices, and this test needs to run on Q devices.
    // TODO: move the IpUtils code to frameworks/lib/net and link it statically.
    private static int checksumFold(int sum) {
        while (sum > 0xffff) {
            sum = (sum >> 16) + (sum & 0xffff);
        }
        return sum;
    }

    private static short checksumAdjust(short checksum, short oldWord, short newWord) {
        checksum = (short) ~checksum;
        int tempSum = checksumFold(uint16(checksum) + uint16(newWord) + 0xffff - uint16(oldWord));
        return (short) ~tempSum;
    }

    private static short icmpv6Checksum(ByteBuffer buf, int ipOffset, int transportOffset,
            int transportLen) {
        // The ICMPv6 checksum is the same as the TCP checksum, except the pseudo-header uses
        // 58 (ICMPv6) instead of 6 (TCP). Calculate the TCP checksum, and then do an incremental
        // checksum adjustment  for the change in the next header byte.
        short checksum = IpUtils.tcpChecksum(buf, ipOffset, transportOffset, transportLen);
        return checksumAdjust(checksum, (short) IPPROTO_TCP, (short) IPPROTO_ICMPV6);
    }

    private static ByteBuffer buildRaPacket(ByteBuffer... options) throws Exception {
        final MacAddress srcMac = MacAddress.fromString("33:33:00:00:00:01");
        final MacAddress dstMac = MacAddress.fromString("01:02:03:04:05:06");
        final byte[] routerLinkLocal = InetAddresses.parseNumericAddress("fe80::1").getAddress();
        final byte[] allNodes = InetAddresses.parseNumericAddress("ff02::1").getAddress();

        final ByteBuffer packet = ByteBuffer.allocate(TEST_DEFAULT_MTU);
        int icmpLen = ICMPV6_RA_HEADER_LEN;

        // Ethernet header.
        packet.put(srcMac.toByteArray());
        packet.put(dstMac.toByteArray());
        packet.putShort((short) ETHER_TYPE_IPV6);

        // IPv6 header.
        packet.putInt(0x600abcde);                       // Version, traffic class, flowlabel
        packet.putShort((short) 0);                      // Length, TBD
        packet.put((byte) IPPROTO_ICMPV6);               // Next header
        packet.put((byte) 0xff);                         // Hop limit
        packet.put(routerLinkLocal);                     // Source address
        packet.put(allNodes);                            // Destination address

        // Router advertisement.
        packet.put((byte) ICMPV6_ROUTER_ADVERTISEMENT);  // ICMP type
        packet.put((byte) 0);                            // ICMP code
        packet.putShort((short) 0);                      // Checksum, TBD
        packet.put((byte) 0);                            // Hop limit, unspecified
        packet.put((byte) 0);                            // M=0, O=0
        packet.putShort((short) 1800);                   // Router lifetime
        packet.putInt(0);                                // Reachable time, unspecified
        packet.putInt(100);                              // Retrans time 100ms.

        for (ByteBuffer option : options) {
            packet.put(option);
            option.clear();  // So we can reuse it in a future packet.
            icmpLen += option.capacity();
        }

        // Populate length and checksum fields.
        final int transportOffset = ETHER_HEADER_LEN + IPV6_HEADER_LEN;
        final short checksum = icmpv6Checksum(packet, ETHER_HEADER_LEN, transportOffset, icmpLen);
        packet.putShort(ETHER_HEADER_LEN + IPV6_LEN_OFFSET, (short) icmpLen);
        packet.putShort(transportOffset + ICMPV6_CHECKSUM_OFFSET, checksum);

        packet.flip();
        return packet;
    }

    @Test
    public void testRaRdnss() throws Exception {
        // Speed up the test by removing router_solicitation_delay.
        // We don't need to restore the default value because the interface is removed in tearDown.
        // TODO: speed up further by not waiting for RA but keying off first IPv6 packet.
        mNetd.setProcSysNet(INetd.IPV6, INetd.CONF, mIfaceName, "router_solicitation_delay", "0");

        ProvisioningConfiguration config = new ProvisioningConfiguration.Builder()
                .withoutIpReachabilityMonitor()
                .withoutIPv4()
                .build();
        mIpc.startProvisioning(config);

        final String dnsServer = "2001:4860:4860::64";
        final String lowlifeDnsServer = "2001:4860:4860::6464";

        final ByteBuffer pio = buildPioOption(600, 300, "2001:db8:1::/64");
        ByteBuffer rdnss1 = buildRdnssOption(60, lowlifeDnsServer);
        ByteBuffer rdnss2 = buildRdnssOption(600, dnsServer);
        ByteBuffer ra = buildRaPacket(pio, rdnss1, rdnss2);

        waitForRouterSolicitation();
        sendResponse(ra);

        ArgumentCaptor<LinkProperties> captor = ArgumentCaptor.forClass(LinkProperties.class);
        verify(mCb, timeout(TEST_TIMEOUT_MS)).onProvisioningSuccess(captor.capture());
        LinkProperties lp = captor.getValue();

        // Expect that DNS servers with lifetimes below CONFIG_MIN_RDNSS_LIFETIME are not accepted.
        assertNotNull(lp);
        assertEquals(1, lp.getDnsServers().size());
        assertTrue(lp.getDnsServers().contains(InetAddress.getByName(dnsServer)));
        reset(mCb);

        // If the RDNSS lifetime is above the minimum, the DNS server is accepted.
        rdnss1 = buildRdnssOption(68, lowlifeDnsServer);
        ra = buildRaPacket(pio, rdnss1, rdnss2);
        sendResponse(ra);
        verify(mCb, timeout(TEST_TIMEOUT_MS)).onLinkPropertiesChange(captor.capture());
        lp = captor.getValue();
        assertNotNull(lp);
        assertEquals(2, lp.getDnsServers().size());
        assertTrue(lp.getDnsServers().contains(InetAddress.getByName(dnsServer)));
        assertTrue(lp.getDnsServers().contains(InetAddress.getByName(lowlifeDnsServer)));
        reset(mCb);

        // Expect that setting RDNSS lifetime of 0 causes loss of provisioning.
        rdnss1 = buildRdnssOption(0, dnsServer);
        rdnss2 = buildRdnssOption(0, lowlifeDnsServer);
        ra = buildRaPacket(pio, rdnss1, rdnss2);
        sendResponse(ra);

        verify(mCb, timeout(TEST_TIMEOUT_MS)).onProvisioningFailure(captor.capture());
        lp = captor.getValue();
        assertNotNull(lp);
        assertEquals(0, lp.getDnsServers().size());
        reset(mCb);
    }

    @Test
    public void testIpClientClearingIpAddressState() throws Exception {
        final long currentTime = System.currentTimeMillis();
        performDhcpHandshake(true /* isSuccessLease */, TEST_LEASE_DURATION_S,
                true /* isDhcpLeaseCacheEnabled */, false /* isDhcpRapidCommitEnabled */,
                TEST_DEFAULT_MTU);
        assertIpMemoryStoreNetworkAttributes(TEST_LEASE_DURATION_S, currentTime, TEST_DEFAULT_MTU);

        ArgumentCaptor<LinkProperties> captor = ArgumentCaptor.forClass(LinkProperties.class);
        verify(mCb, timeout(TEST_TIMEOUT_MS)).onProvisioningSuccess(captor.capture());
        LinkProperties lp = captor.getValue();
        assertNotNull(lp);
        assertEquals(1, lp.getAddresses().size());
        assertTrue(lp.getAddresses().contains(InetAddress.getByName(CLIENT_ADDR.getHostAddress())));

        // Stop IpClient and expect a final LinkProperties callback with an empty LP.
        mIpc.stop();
        verify(mCb, timeout(TEST_TIMEOUT_MS)).onLinkPropertiesChange(argThat(
                x -> x.getAddresses().size() == 0
                        && x.getRoutes().size() == 0
                        && x.getDnsServers().size() == 0));
        reset(mCb);

        // Pretend that something else (e.g., Tethering) used the interface and left an IP address
        // configured on it. When IpClient starts, it must clear this address before proceeding.
        // TODO: test IPv6 instead, since the DHCP client will remove this address by replacing it
        // with the new address.
        mNetd.interfaceAddAddress(mIfaceName, "192.0.2.99", 26);

        // start IpClient again and should enter Clearing State and wait for the message from kernel
        performDhcpHandshake(true /* isSuccessLease */, TEST_LEASE_DURATION_S,
                true /* isDhcpLeaseCacheEnabled */, false /* isDhcpRapidCommitEnabled */,
                TEST_DEFAULT_MTU);

        verify(mCb, timeout(TEST_TIMEOUT_MS)).onProvisioningSuccess(captor.capture());
        lp = captor.getValue();
        assertNotNull(lp);
        assertEquals(1, lp.getAddresses().size());
        assertTrue(lp.getAddresses().contains(InetAddress.getByName(CLIENT_ADDR.getHostAddress())));
    }

    @Test
    public void testDhcpClientPreconnectionAbort() throws Exception {
        doIpClientProvisioningWithPreconnectionTest(false /* isDhcpRapidCommitEnabled */,
                true /* shouldAbortPreconnection */);
    }

    @Test
    public void testDhcpClientPreconnectionEnabled_WithoutRapidCommit() throws Exception {
        doIpClientProvisioningWithPreconnectionTest(false /* isDhcpRapidCommitEnabled */,
                false /* shouldAbortPreconnection */);
    }

    // So far DHCPACK doesn't include Rapid Commit option(aosp/1092270 is adding the option), when
    // receiving the DHCPACK packet in DhcpPreconnectionState or DhcpInitState, dropping the DHCPACK
    // packet directly, which would cause test cases with enabled "isDhcpRapidCommitEnabled" flag
    // fail.
    @Ignore
    @Test
    public void testDhcpClientPreconnectionEnabled() throws Exception {
        doIpClientProvisioningWithPreconnectionTest(true /* isDhcpRapidCommitEnabled */,
                false /* shouldAbortPreconnection */);
    }

    @Ignore
    @Test
    public void testDhcpClientPreconnectionEnabled_WithRapidCommit() throws Exception {
        doIpClientProvisioningWithPreconnectionTest(true /* isDhcpRapidCommitEnabled */,
                true /* shouldAbortPreconnection */);
    }
}
