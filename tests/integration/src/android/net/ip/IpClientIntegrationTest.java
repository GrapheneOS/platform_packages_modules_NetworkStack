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
import static android.net.shared.Inet4AddressUtils.getBroadcastAddress;
import static android.net.shared.Inet4AddressUtils.getPrefixMaskAsInet4Address;

import static junit.framework.Assert.fail;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.never;
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
import android.net.util.NetworkStackUtils;
import android.net.util.PacketReader;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;
import android.os.RemoteException;

import androidx.annotation.Nullable;
import androidx.test.InstrumentationRegistry;
import androidx.test.filters.SmallTest;
import androidx.test.runner.AndroidJUnit4;

import com.android.server.NetworkObserverRegistry;
import com.android.server.NetworkStackService.NetworkStackServiceManager;
import com.android.server.connectivity.ipmemorystore.IpMemoryStoreService;
import com.android.testutils.HandlerUtilsKt;

import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.NetworkInterface;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Collections;
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
    @Mock private INetd mMockNetd;
    @Mock private Resources mResources;
    @Mock private IIpClientCallbacks mCb;
    @Mock private AlarmManager mAlarm;
    @Mock private ContentResolver mContentResolver;
    @Mock private NetworkStackServiceManager mNetworkStackServiceManager;
    @Mock private NetworkStackIpMemoryStore mIpMemoryStore;
    @Mock private IpMemoryStoreService mIpMemoryStoreService;

    private String mIfaceName;
    private INetd mNetd;
    private HandlerThread mPacketReaderThread;
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

        public void setDhcpLeaseCacheEnabled(final boolean enable) {
            mIsDhcpLeaseCacheEnabled = enable;
        }

        public void setDhcpRapidCommitEnabled(final boolean enable) {
            mIsDhcpRapidCommitEnabled = enable;
        }

        @Override
        public INetd getNetd(Context context) {
            return mMockNetd;
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

        setUpTapInterface();
        setUpIpClient();
    }

    @After
    public void tearDown() throws Exception {
        if (mPacketReader != null) {
            mPacketReader.stop(); // Also closes the socket
        }
        if (mPacketReaderThread != null) {
            mPacketReaderThread.quitSafely();
        }
        mIpc.shutdown();
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

        final ParcelFileDescriptor tapFd = iface.getFileDescriptor();
        mPacketReader = new TapPacketReader(mPacketReaderThread.getThreadHandler(), tapFd);
        mPacketReader.start();
    }

    private void setUpIpClient() throws Exception {
        final Instrumentation inst = InstrumentationRegistry.getInstrumentation();
        final IBinder netdIBinder =
                (IBinder) inst.getContext().getSystemService(Context.NETD_SERVICE);
        mNetd = INetd.Stub.asInterface(netdIBinder);
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
            out.write(packet.array());
        }
    }

    private void startIpClientProvisioning(final boolean isDhcpLeaseCacheEnabled,
            final boolean isDhcpRapidCommitEnabled) throws RemoteException {
        ProvisioningConfiguration config = new ProvisioningConfiguration.Builder()
                .withoutIpReachabilityMonitor()
                .withoutIPv6()
                .build();

        mDependencies.setDhcpLeaseCacheEnabled(isDhcpLeaseCacheEnabled);
        mDependencies.setDhcpRapidCommitEnabled(isDhcpRapidCommitEnabled);
        mIpc.setL2KeyAndGroupHint(TEST_L2KEY, TEST_GROUPHINT);
        mIpc.startProvisioning(config);
        verify(mCb, times(1)).setNeighborDiscoveryOffload(true);
        verify(mCb, timeout(TEST_TIMEOUT_MS).times(1)).setFallbackMulticastFilter(false);
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
        startIpClientProvisioning(isDhcpLeaseCacheEnabled, isDhcpRapidCommitEnabled);

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
                false /* isDhcpRapidCommitEnabled */);
        return getNextDhcpPacket();
    }

    private void doRestoreInitialMtuTest(final boolean shouldChangeMtu) throws Exception {
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

        mIpc.shutdown();
        HandlerUtilsKt.waitForIdle(mIpc.getHandler(), TEST_TIMEOUT_MS);
        // Verify that MTU indeed has been restored or not.
        verify(mMockNetd, times(shouldChangeMtu ? 1 : 0)).interfaceSetMtu(mIfaceName,
                TEST_DEFAULT_MTU);
    }

    @Test
    public void testDhcpInit() throws Exception {
        startIpClientProvisioning(false /* isDhcpLeaseCacheEnabled */,
                false /* isDhcpRapidCommitEnabled */);
        final DhcpPacket packet = getNextDhcpPacket();
        assertTrue(DhcpDiscoverPacket.class.isInstance(packet));
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
        assertTrue(DhcpRequestPacket.class.isInstance(packet));
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
        assertTrue(DhcpDiscoverPacket.class.isInstance(packet));
    }

    @Test
    public void testDhcpClientStartWithNullRetrieveNetworkAttributes() throws Exception {
        final DhcpPacket packet = getReplyFromDhcpLease(null /* na */, false /* timeout */);
        assertTrue(DhcpDiscoverPacket.class.isInstance(packet));
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
        assertTrue(DhcpDiscoverPacket.class.isInstance(packet));
    }

    @Test
    public void testDhcpClientStartWithCachedLeaseWithoutIPAddress() throws Exception {
        final DhcpPacket packet = getReplyFromDhcpLease(
                new NetworkAttributes.Builder()
                    .setMtu(new Integer(TEST_DEFAULT_MTU))
                    .setGroupHint(TEST_GROUPHINT)
                    .setDnsAddresses(Collections.singletonList(SERVER_ADDR))
                    .build(), false /* timeout */);
        assertTrue(DhcpDiscoverPacket.class.isInstance(packet));
    }

    @Test
    public void testDhcpClientRapidCommitEnabled() throws Exception {
        startIpClientProvisioning(true /* isDhcpLeaseCacheEnabled */,
                true /* isDhcpRapidCommitEnabled */);
        final DhcpPacket packet = getNextDhcpPacket();
        assertTrue(DhcpDiscoverPacket.class.isInstance(packet));
    }

    @Test
    public void testRestoreInitialInterfaceMtu() throws Exception {
        doRestoreInitialMtuTest(true /* shouldChangeMtu */);
    }

    @Test
    public void testRestoreInitialInterfaceMtuWithoutChange() throws Exception {
        doRestoreInitialMtuTest(false /* shouldChangeMtu */);
    }

    @Test
    public void testRestoreInitialInterfaceMtuWithException() throws Exception {
        doThrow(new RemoteException("NetdNativeService::interfaceSetMtu")).when(mMockNetd)
                .interfaceSetMtu(mIfaceName, TEST_DEFAULT_MTU);

        doRestoreInitialMtuTest(true /* shouldChangeMtu */);
        assertEquals(NetworkInterface.getByName(mIfaceName).getMTU(), TEST_MIN_MTU);
    }
}
