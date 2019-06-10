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

import static android.net.dhcp.DhcpPacket.DHCP_BOOTREQUEST;
import static android.net.dhcp.DhcpPacket.DHCP_CLIENT;
import static android.net.dhcp.DhcpPacket.DHCP_MAGIC_COOKIE;
import static android.net.dhcp.DhcpPacket.DHCP_MESSAGE_TYPE;
import static android.net.dhcp.DhcpPacket.DHCP_MESSAGE_TYPE_DISCOVER;
import static android.net.dhcp.DhcpPacket.DHCP_SERVER;
import static android.net.dhcp.DhcpPacket.ENCAP_L2;
import static android.net.dhcp.DhcpPacket.ETHER_BROADCAST;

import static com.android.server.util.NetworkStackConstants.IPV4_ADDR_ALL;

import static junit.framework.Assert.fail;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import android.app.AlarmManager;
import android.app.Instrumentation;
import android.content.ContentResolver;
import android.content.Context;
import android.content.res.Resources;
import android.net.ConnectivityManager;
import android.net.IIpMemoryStore;
import android.net.INetd;
import android.net.TestNetworkInterface;
import android.net.TestNetworkManager;
import android.net.dhcp.DhcpDiscoverPacket;
import android.net.dhcp.DhcpPacket;
import android.net.dhcp.DhcpPacket.ParseException;
import android.net.shared.ProvisioningConfiguration;
import android.net.util.InterfaceParams;
import android.net.util.PacketReader;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;

import androidx.annotation.Nullable;
import androidx.test.InstrumentationRegistry;
import androidx.test.filters.SmallTest;
import androidx.test.runner.AndroidJUnit4;

import com.android.server.NetworkObserverRegistry;
import com.android.server.NetworkStackService;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.io.FileDescriptor;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * Tests for IpClient.
 */
@RunWith(AndroidJUnit4.class)
@SmallTest
public class IpClientIntegrationTest {
    @Mock private Context mContext;
    @Mock private ConnectivityManager mCm;
    @Mock private INetd mNetd;
    @Mock private Resources mResources;
    @Mock private IIpClientCallbacks mCb;
    @Mock private AlarmManager mAlarm;
    @Mock private IpClient.Dependencies mDependencies;
    @Mock private ContentResolver mContentResolver;
    @Mock private NetworkStackService.NetworkStackServiceManager mNetworkStackServiceManager;
    @Mock private IIpMemoryStore mIpMemoryStore;
    @Mock private InterfaceParams mInterfaceParams;

    private String mIfaceName;
    private HandlerThread mPacketReaderThread;
    private TapPacketReader mPacketReader;
    private IpClient mIpc;

    private static final int DATA_BUFFER_LEN = 4096;
    private static final long PACKET_TIMEOUT_MS = 5_000;

    // Ethernet header
    private static final int ETH_HEADER_LEN = 14;
    private static final int ETH_DEST_ADDR_OFFSET = 0;
    private static final int ETH_MAC_ADDR_LEN = 6;

    // IP header
    private static final int IPV4_HEADER_LEN = 20;
    private static final int IPV4_DEST_ADDR_OFFSET = ETH_HEADER_LEN + 16;
    private static final int IPV4_ADDR_LEN = 4;

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
    private static final int DHCP_OPTION_MESSAGE_TYPE_LEN_OFFSET =
            DHCP_OPTION_MESSAGE_TYPE_OFFSET + 1;
    private static final int DHCP_OPTION_MESSAGE_TYPE_VALUE_OFFSET =
            DHCP_OPTION_MESSAGE_TYPE_OFFSET + 2;

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

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);

        when(mContext.getSystemService(eq(Context.ALARM_SERVICE))).thenReturn(mAlarm);
        when(mContext.getSystemService(eq(ConnectivityManager.class))).thenReturn(mCm);
        when(mContext.getResources()).thenReturn(mResources);
        when(mDependencies.getNetd(any())).thenReturn(mNetd);
        when(mContext.getContentResolver()).thenReturn(mContentResolver);
        when(mDependencies.getInterfaceParams(any())).thenReturn(mInterfaceParams);
        when(mNetworkStackServiceManager.getIpMemoryStoreService()).thenReturn(mIpMemoryStore);

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
        final INetd netd = INetd.Stub.asInterface(netdIBinder);
        when(mContext.getSystemService(eq(Context.NETD_SERVICE))).thenReturn(netdIBinder);
        assertNotNull(netd);

        final NetworkObserverRegistry reg = new NetworkObserverRegistry();
        reg.register(netd);
        mIpc = new IpClient(mContext, mIfaceName, mCb, reg, mNetworkStackServiceManager);
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

    private void verifyDhcpDiscoverPacketReceived(final byte[] packet)
            throws ParseException {
        assertTrue(packetContainsExpectedField(packet, ETH_DEST_ADDR_OFFSET, ETHER_BROADCAST));
        assertTrue(packetContainsExpectedField(packet, IPV4_DEST_ADDR_OFFSET,
                IPV4_ADDR_ALL.getAddress()));

        // check if received dhcp packet includes DHCP Message Type option and expected
        // type/length/value.
        assertTrue(packet[DHCP_OPTION_MESSAGE_TYPE_OFFSET] == DHCP_MESSAGE_TYPE);
        assertTrue(packet[DHCP_OPTION_MESSAGE_TYPE_OFFSET + 1] == 1);
        assertTrue(packet[DHCP_OPTION_MESSAGE_TYPE_OFFSET + 2] == DHCP_MESSAGE_TYPE_DISCOVER);
        final DhcpPacket dhcpPacket = DhcpPacket.decodeFullPacket(
                packet, packet.length, ENCAP_L2);
        assertTrue(dhcpPacket instanceof DhcpDiscoverPacket);
    }

    @Test
    public void testDhcpInit() throws Exception {
        ProvisioningConfiguration config = new ProvisioningConfiguration.Builder()
                .withoutIpReachabilityMonitor()
                .build();

        mIpc.startProvisioning(config);
        verify(mCb, times(1)).setNeighborDiscoveryOffload(true);

        byte[] packet;
        while ((packet = mPacketReader.popPacket(PACKET_TIMEOUT_MS)) != null) {
            try {
                if (!isDhcpPacket(packet)) continue;
                verifyDhcpDiscoverPacketReceived(packet);
                mIpc.shutdown();
                return;
            } catch (DhcpPacket.ParseException e) {
                fail("parse exception: " + e);
            }
        }

        fail("No DHCPDISCOVER received on interface");
    }
}
