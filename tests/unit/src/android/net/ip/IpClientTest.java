/*
 * Copyright (C) 2017 The Android Open Source Project
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

import static android.net.apf.BaseApfGenerator.APF_VERSION_6;
import static android.net.ip.IpClientLinkObserver.CONFIG_SOCKET_RECV_BUFSIZE;
import static android.net.ip.IpClientLinkObserver.SOCKET_RECV_BUFSIZE;
import static android.system.OsConstants.AF_UNSPEC;
import static android.system.OsConstants.ARPHRD_ETHER;
import static android.system.OsConstants.IFA_F_PERMANENT;
import static android.system.OsConstants.IFA_F_TENTATIVE;
import static android.system.OsConstants.RT_SCOPE_UNIVERSE;

import static com.android.net.module.util.NetworkStackConstants.ICMPV6_ROUTER_ADVERTISEMENT;
import static com.android.net.module.util.netlink.NetlinkConstants.RTM_NEWLINK;
import static com.android.net.module.util.netlink.NetlinkConstants.RTPROT_KERNEL;
import static com.android.net.module.util.netlink.NetlinkConstants.RTM_DELROUTE;
import static com.android.net.module.util.netlink.NetlinkConstants.RTM_NEWADDR;
import static com.android.net.module.util.netlink.NetlinkConstants.RTM_NEWNDUSEROPT;
import static com.android.net.module.util.netlink.NetlinkConstants.RTM_NEWROUTE;
import static com.android.net.module.util.netlink.NetlinkConstants.RTN_UNICAST;
import static com.android.net.module.util.netlink.StructNlMsgHdr.NLM_F_ACK;
import static com.android.net.module.util.netlink.StructNlMsgHdr.NLM_F_REQUEST;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyInt;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import static java.util.Collections.emptySet;

import android.annotation.SuppressLint;
import android.app.AlarmManager;
import android.content.ContentResolver;
import android.content.Context;
import android.content.res.Resources;
import android.net.ConnectivityManager;
import android.net.INetd;
import android.net.InetAddresses;
import android.net.IpPrefix;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.MacAddress;
import android.net.NetworkStackIpMemoryStore;
import android.net.RouteInfo;
import android.net.apf.AndroidPacketFilter;
import android.net.apf.ApfCapabilities;
import android.net.apf.ApfFilter.ApfConfiguration;
import android.net.ip.IpClientLinkObserver.IpClientNetlinkMonitor;
import android.net.ip.IpClientLinkObserver.IpClientNetlinkMonitor.INetlinkMessageProcessor;
import android.net.ipmemorystore.NetworkAttributes;
import android.net.metrics.IpConnectivityLog;
import android.net.shared.InitialConfiguration;
import android.net.shared.Layer2Information;
import android.net.shared.ProvisioningConfiguration;
import android.net.shared.ProvisioningConfiguration.ScanResultInfo;
import android.os.Build;
import android.system.OsConstants;

import androidx.test.filters.SmallTest;
import androidx.test.runner.AndroidJUnit4;

import com.android.modules.utils.build.SdkLevel;
import com.android.net.module.util.InterfaceParams;
import com.android.net.module.util.netlink.NduseroptMessage;
import com.android.net.module.util.netlink.RtNetlinkAddressMessage;
import com.android.net.module.util.netlink.RtNetlinkLinkMessage;
import com.android.net.module.util.netlink.RtNetlinkRouteMessage;
import com.android.net.module.util.netlink.StructIfaddrMsg;
import com.android.net.module.util.netlink.StructIfinfoMsg;
import com.android.net.module.util.netlink.StructNdOptRdnss;
import com.android.net.module.util.netlink.StructNlMsgHdr;
import com.android.net.module.util.netlink.StructRtMsg;
import com.android.networkstack.R;
import com.android.networkstack.ipmemorystore.IpMemoryStoreService;
import com.android.server.NetworkStackService;
import com.android.testutils.DevSdkIgnoreRule;
import com.android.testutils.DevSdkIgnoreRule.IgnoreAfter;
import com.android.testutils.DevSdkIgnoreRule.IgnoreUpTo;
import com.android.testutils.HandlerUtils;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;


/**
 * Tests for IpClient.
 */
@RunWith(AndroidJUnit4.class)
@SmallTest
public class IpClientTest {
    @Rule
    public final DevSdkIgnoreRule mIgnoreRule = new DevSdkIgnoreRule();

    private static final String VALID = "VALID";
    private static final String INVALID = "INVALID";
    private static final String TEST_IFNAME = "test_wlan0";
    private static final int TEST_IFINDEX = 1001;
    private static final String TEST_CLAT_IFNAME = "v4-" + TEST_IFNAME;
    private static final int TEST_CLAT_IFINDEX = 1002;
    // See RFC 7042#section-2.1.2 for EUI-48 documentation values.
    private static final MacAddress TEST_MAC = MacAddress.fromString("00:00:5E:00:53:01");
    private static final int TEST_TIMEOUT_MS = 30_000;
    private static final String TEST_L2KEY = "some l2key";
    private static final String TEST_CLUSTER = "some cluster";
    private static final String TEST_SSID = "test_ssid";
    private static final String TEST_BSSID = "00:11:22:33:44:55";
    private static final String TEST_BSSID2 = "00:1A:11:22:33:44";

    private static final String TEST_GLOBAL_ADDRESS = "1234:4321::548d:2db2:4fcf:ef75/64";
    private static final String[] TEST_LOCAL_ADDRESSES = {
            "fe80::a4be:f92:e1f7:22d1/64",
            "fe80::f04a:8f6:6a32:d756/64",
            "fd2c:4e57:8e3c:0:548d:2db2:4fcf:ef75/64"
    };
    private static final String TEST_IPV4_LINKADDRESS = "192.168.42.24/24";
    private static final String[] TEST_PREFIXES = { "fe80::/64", "fd2c:4e57:8e3c::/64" };
    private static final String[] TEST_DNSES = { "fd2c:4e57:8e3c::42" };
    private static final String TEST_IPV6_GATEWAY = "fd2c:4e57:8e3c::43";
    private static final String TEST_IPV4_GATEWAY = "192.168.42.11";
    private static final long TEST_DNS_LIFETIME = 3600;
    // `whenMs` param in processNetlinkMessage is only used to process PREF64 option in RA, which
    // is not used for RTM_NEWADDR, RTM_NEWROUTE and RDNSS option.
    private static final long TEST_UNUSED_REAL_TIME = 0;

    @Mock private Context mContext;
    @Mock private ConnectivityManager mCm;
    @Mock private INetd mNetd;
    @Mock private Resources mResources;
    @Mock private IIpClientCallbacks mCb;
    @Mock private AlarmManager mAlarm;
    @Mock private IpClient.Dependencies mDependencies;
    @Mock private ContentResolver mContentResolver;
    @Mock private NetworkStackService.NetworkStackServiceManager mNetworkStackServiceManager;
    @Mock private NetworkStackIpMemoryStore mIpMemoryStore;
    @Mock private IpMemoryStoreService mIpMemoryStoreService;
    @Mock private InterfaceParams mInterfaceParams;
    @Mock private IpConnectivityLog mMetricsLog;
    @Mock private FileDescriptor mFd;
    @Mock private PrintWriter mWriter;
    @Mock private IpClientNetlinkMonitor mNetlinkMonitor;
    @Mock private AndroidPacketFilter mApfFilter;

    private InterfaceParams mIfParams;
    private INetlinkMessageProcessor mNetlinkMessageProcessor;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);

        when(mContext.getSystemService(eq(Context.ALARM_SERVICE))).thenReturn(mAlarm);
        when(mContext.getSystemService(eq(ConnectivityManager.class))).thenReturn(mCm);
        when(mContext.getResources()).thenReturn(mResources);
        when(mDependencies.getNetd(any())).thenReturn(mNetd);
        when(mCm.shouldAvoidBadWifi()).thenReturn(true);
        when(mContext.getContentResolver()).thenReturn(mContentResolver);
        when(mNetworkStackServiceManager.getIpMemoryStoreService())
                .thenReturn(mIpMemoryStoreService);
        when(mDependencies.getInterfaceParams(any())).thenReturn(mInterfaceParams);
        when(mDependencies.getIpMemoryStore(mContext, mNetworkStackServiceManager))
                .thenReturn(mIpMemoryStore);
        when(mDependencies.getIpConnectivityLog()).thenReturn(mMetricsLog);
        when(mDependencies.getDeviceConfigPropertyInt(eq(CONFIG_SOCKET_RECV_BUFSIZE), anyInt()))
                .thenReturn(SOCKET_RECV_BUFSIZE);
        when(mDependencies.makeIpClientNetlinkMonitor(
                any(), any(), any(), anyInt(), any())).thenReturn(mNetlinkMonitor);
        when(mNetlinkMonitor.start()).thenReturn(true);

        mIfParams = null;
    }

    private void setTestInterfaceParams(String ifname) {
        mIfParams = (ifname != null)
                ? new InterfaceParams(ifname, TEST_IFINDEX, TEST_MAC)
                : null;
        when(mDependencies.getInterfaceParams(anyString())).thenReturn(mIfParams);
    }

    private IpClient makeIpClient(String ifname) throws Exception {
        setTestInterfaceParams(ifname);
        final IpClient ipc =
                new IpClient(mContext, ifname, mCb, mNetworkStackServiceManager, mDependencies);
        verify(mNetd, timeout(TEST_TIMEOUT_MS).times(1)).interfaceSetEnableIPv6(ifname, false);
        verify(mNetd, timeout(TEST_TIMEOUT_MS).times(1)).interfaceClearAddrs(ifname);
        final ArgumentCaptor<INetlinkMessageProcessor> processorCaptor =
                ArgumentCaptor.forClass(INetlinkMessageProcessor.class);
        verify(mDependencies).makeIpClientNetlinkMonitor(any(), any(), any(), anyInt(),
                processorCaptor.capture());
        mNetlinkMessageProcessor = processorCaptor.getValue();
        reset(mNetd);
        // Verify IpClient doesn't call onLinkPropertiesChange() when it starts.
        verify(mCb, never()).onLinkPropertiesChange(any());
        reset(mCb);
        return ipc;
    }

    private static LinkProperties makeEmptyLinkProperties(String iface) {
        final LinkProperties empty = new LinkProperties();
        empty.setInterfaceName(iface);
        return empty;
    }

    private void verifyNetworkAttributesStored(final String l2Key,
            final NetworkAttributes attributes) {
        // TODO : when storing is implemented, turn this on
        // verify(mIpMemoryStore).storeNetworkAttributes(eq(l2Key), eq(attributes), any());
    }

    private static StructNlMsgHdr makeNetlinkMessageHeader(short type, short flags) {
        final StructNlMsgHdr nlmsghdr = new StructNlMsgHdr();
        nlmsghdr.nlmsg_type = type;
        nlmsghdr.nlmsg_flags = flags;
        nlmsghdr.nlmsg_seq = 1;
        return nlmsghdr;
    }

    private static RtNetlinkAddressMessage buildRtmAddressMessage(short type, final LinkAddress la,
            int ifindex, int flags) {
        final StructNlMsgHdr nlmsghdr =
                makeNetlinkMessageHeader(type, (short) (NLM_F_REQUEST | NLM_F_ACK));
        InetAddress ip = la.getAddress();
        final byte family =
                (byte) ((ip instanceof Inet6Address) ? OsConstants.AF_INET6 : OsConstants.AF_INET);
        StructIfaddrMsg ifaddrMsg = new StructIfaddrMsg(family,
                (short) la.getPrefixLength(),
                (short) la.getFlags(), (short) la.getScope(), ifindex);

        return new RtNetlinkAddressMessage(nlmsghdr, ifaddrMsg, ip,
                null /* structIfacacheInfo */, flags);
    }

    private static RtNetlinkRouteMessage buildRtmRouteMessage(short type, final RouteInfo route,
            int ifindex) {
        final StructNlMsgHdr nlmsghdr =
                makeNetlinkMessageHeader(type, (short) (NLM_F_REQUEST | NLM_F_ACK));
        final IpPrefix destination = route.getDestination();
        final byte family = (byte) ((destination.getAddress() instanceof Inet6Address)
                ? OsConstants.AF_INET6
                : OsConstants.AF_INET);

        final StructRtMsg rtMsg = new StructRtMsg(family,
                (short) destination.getPrefixLength() /* dstLen */, (short) 0 /* srcLen */,
                (short) 0 /* tos */, (short) 0xfd /* main table */, RTPROT_KERNEL /* protocol */,
                (short) RT_SCOPE_UNIVERSE /* scope */, RTN_UNICAST /* type */, 0 /* flags */);
        return new RtNetlinkRouteMessage(nlmsghdr, rtMsg, null /* source */, route.getDestination(),
                route.getGateway(), 0 /* iif */, ifindex /* oif */, null /* cacheInfo */);
    }

    private static NduseroptMessage buildNduseroptMessage(int ifindex, long lifetime,
            final String[] servers) {
        final StructNlMsgHdr nlmsghdr =
                makeNetlinkMessageHeader(RTM_NEWNDUSEROPT, (short) (NLM_F_REQUEST | NLM_F_ACK));
        final Inet6Address[] serverArray = new Inet6Address[servers.length];
        for (int i = 0; i < servers.length; i++) {
            serverArray[i] = (Inet6Address) InetAddresses.parseNumericAddress(servers[i]);
        }
        final StructNdOptRdnss option = new StructNdOptRdnss(serverArray, lifetime);
        return new NduseroptMessage(nlmsghdr, (byte) OsConstants.AF_INET6 /* family */,
                0 /* opts_len */, ifindex, (byte) ICMPV6_ROUTER_ADVERTISEMENT /* icmp_type */,
                (byte) 0 /* icmp_code */, option, null /* srcaddr */);
    }

    private static RtNetlinkLinkMessage buildRtmLinkMessage(short type, int ifindex,
            String ifaceName) {
        final StructNlMsgHdr nlmsghdr =
                makeNetlinkMessageHeader(type, (short) (NLM_F_REQUEST | NLM_F_ACK));
        final StructIfinfoMsg ifInfoMsg =
                new StructIfinfoMsg(
                        (short) AF_UNSPEC,
                        ARPHRD_ETHER,
                        ifindex,
                        0 /* flags */,
                        0xffffffffL /* change */);

        return RtNetlinkLinkMessage.build(nlmsghdr, ifInfoMsg, 0 /* mtu */, TEST_MAC, ifaceName);
    }

    private void onInterfaceAddressUpdated(final LinkAddress la, int flags) {
        final RtNetlinkAddressMessage msg =
                buildRtmAddressMessage(RTM_NEWADDR, la, TEST_IFINDEX, flags);
        mNetlinkMessageProcessor.processNetlinkMessage(msg, TEST_UNUSED_REAL_TIME /* whenMs */);
    }

    private void onRouteUpdated(final RouteInfo route) {
        final RtNetlinkRouteMessage msg = buildRtmRouteMessage(RTM_NEWROUTE, route, TEST_IFINDEX);
        mNetlinkMessageProcessor.processNetlinkMessage(msg, TEST_UNUSED_REAL_TIME /* whenMs */);
    }

    private void onRouteRemoved(final RouteInfo route) {
        final RtNetlinkRouteMessage msg = buildRtmRouteMessage(RTM_DELROUTE, route, TEST_IFINDEX);
        mNetlinkMessageProcessor.processNetlinkMessage(msg, TEST_UNUSED_REAL_TIME /* whenMs */);
    }

    private void onInterfaceDnsServerInfo(long lifetime, final String[] dnsServers) {
        final NduseroptMessage msg = buildNduseroptMessage(TEST_IFINDEX, lifetime, dnsServers);
        mNetlinkMessageProcessor.processNetlinkMessage(msg, TEST_UNUSED_REAL_TIME /* whenMs */);
    }

    private void onInterfaceAdded(int ifaceIndex, String ifaceName) {
        final RtNetlinkLinkMessage msg = buildRtmLinkMessage(RTM_NEWLINK, ifaceIndex, ifaceName);
        mNetlinkMessageProcessor.processNetlinkMessage(msg, TEST_UNUSED_REAL_TIME /* whenMs */);
    }


    @Test
    public void testNullInterfaceNameMostDefinitelyThrows() throws Exception {
        setTestInterfaceParams(null);
        try {
            final IpClient ipc = new IpClient(mContext, null, mCb, mNetworkStackServiceManager,
                    mDependencies);
            ipc.shutdown();
            fail();
        } catch (NullPointerException npe) {
            // Phew; null interface names not allowed.
        }
    }

    @Test
    public void testNullCallbackMostDefinitelyThrows() throws Exception {
        final String ifname = "lo";
        setTestInterfaceParams(ifname);
        try {
            final IpClient ipc = new IpClient(mContext, ifname, null, mNetworkStackServiceManager,
                    mDependencies);
            ipc.shutdown();
            fail();
        } catch (NullPointerException npe) {
            // Phew; null callbacks not allowed.
        }
    }

    @Test
    public void testInvalidInterfaceDoesNotThrow() throws Exception {
        setTestInterfaceParams(TEST_IFNAME);
        final IpClient ipc = new IpClient(mContext, TEST_IFNAME, mCb, mNetworkStackServiceManager,
                mDependencies);
        verifyNoMoreInteractions(mIpMemoryStore);
        ipc.shutdown();
    }

    @Test
    public void testInterfaceNotFoundFailsImmediately() throws Exception {
        setTestInterfaceParams(null);
        final IpClient ipc = new IpClient(mContext, TEST_IFNAME, mCb, mNetworkStackServiceManager,
                mDependencies);
        ipc.startProvisioning(new ProvisioningConfiguration());
        verify(mCb, timeout(TEST_TIMEOUT_MS).times(1)).onProvisioningFailure(any());
        verify(mIpMemoryStore, never()).storeNetworkAttributes(any(), any(), any());
        ipc.shutdown();
    }

    private LinkProperties makeIPv6ProvisionedLinkProperties() {
        // Add local addresses, and a global address with global scope
        final Set<LinkAddress> addresses = links(TEST_LOCAL_ADDRESSES);
        addresses.add(new LinkAddress(TEST_GLOBAL_ADDRESS, 0, RT_SCOPE_UNIVERSE));

        // Add a route on the interface for each prefix, and a global route
        final Set<RouteInfo> routes = routes(TEST_PREFIXES);
        routes.add(defaultIPV6Route(TEST_IPV6_GATEWAY));

        return linkproperties(addresses, routes, ips(TEST_DNSES));
    }

    private IpClient doProvisioningWithDefaultConfiguration() throws Exception {
        final IpClient ipc = makeIpClient(TEST_IFNAME);

        ProvisioningConfiguration config = new ProvisioningConfiguration.Builder()
                .withoutIPv4()
                // TODO: mock IpReachabilityMonitor's dependencies (NetworkInterface, PowerManager)
                // and enable it in this test
                .withoutIpReachabilityMonitor()
                .build();

        ipc.startProvisioning(config);
        verify(mCb, timeout(TEST_TIMEOUT_MS).times(1)).setNeighborDiscoveryOffload(true);
        verify(mCb, timeout(TEST_TIMEOUT_MS).times(1)).setFallbackMulticastFilter(false);

        final LinkProperties lp = makeIPv6ProvisionedLinkProperties();
        lp.getRoutes().forEach(route -> onRouteUpdated(route));
        lp.getLinkAddresses().forEach(
                la -> onInterfaceAddressUpdated(la, la.getFlags()));
        onInterfaceDnsServerInfo(TEST_DNS_LIFETIME,
                lp.getDnsServers().stream().map(InetAddress::getHostAddress)
                        .toArray(String[]::new));

        HandlerUtils.waitForIdle(ipc.getHandler(), TEST_TIMEOUT_MS);
        verify(mCb, never()).onProvisioningFailure(any());
        verify(mIpMemoryStore, never()).storeNetworkAttributes(any(), any(), any());

        verify(mCb).onProvisioningSuccess(lp);
        return ipc;
    }

    @SuppressLint("NewApi")
    private void addIPv4Provisioning(LinkProperties lp) {
        final LinkAddress la = new LinkAddress(TEST_IPV4_LINKADDRESS);
        final RouteInfo defaultRoute = new RouteInfo(new IpPrefix(Inet4Address.ANY, 0),
                InetAddresses.parseNumericAddress(TEST_IPV4_GATEWAY), TEST_IFNAME);
        onInterfaceAddressUpdated(la, la.getFlags());
        onRouteUpdated(defaultRoute);

        lp.addLinkAddress(la);
        lp.addRoute(defaultRoute);
    }

    /**
     * Simulate loss of IPv6 provisioning (default route lost).
     *
     * @return The expected new LinkProperties.
     */
    private void doIPv6ProvisioningLoss(LinkProperties lp) {
        final RouteInfo defaultRoute = defaultIPV6Route(TEST_IPV6_GATEWAY);
        onRouteRemoved(defaultRoute);

        lp.removeRoute(defaultRoute);
    }

    private void doDefaultIPv6ProvisioningConfigurationAndProvisioningLossTest(boolean avoidBadWifi)
            throws Exception {
        when(mCm.shouldAvoidBadWifi()).thenReturn(avoidBadWifi);
        final IpClient ipc = doProvisioningWithDefaultConfiguration();
        final LinkProperties lp = makeIPv6ProvisionedLinkProperties();

        reset(mCb);
        doIPv6ProvisioningLoss(lp);
        HandlerUtils.waitForIdle(ipc.getHandler(), TEST_TIMEOUT_MS);
        verify(mCb).onProvisioningFailure(lp);
        verify(mCb).onLinkPropertiesChange(makeEmptyLinkProperties(TEST_IFNAME));

        verifyShutdown(ipc);
    }

    @Test
    public void testDefaultIPv6ProvisioningConfiguration_AvoidBadWifi() throws Exception {
        doDefaultIPv6ProvisioningConfigurationAndProvisioningLossTest(true /* avoidBadWifi */);
    }

    @Test
    public void testDefaultIPv6ProvisioningConfiguration_StayOnBadWifi() throws Exception {
        // Even when avoidBadWifi=false, if IPv6 only, loss of all provisioning causes
        // onProvisioningFailure to be called.
        doDefaultIPv6ProvisioningConfigurationAndProvisioningLossTest(false /* avoidBadWifi */);
    }

    private void doDefaultDualStackProvisioningConfigurationTest(
            boolean avoidBadWifi) throws Exception {
        when(mCm.shouldAvoidBadWifi()).thenReturn(avoidBadWifi);
        final IpClient ipc = doProvisioningWithDefaultConfiguration();
        final LinkProperties lp = makeIPv6ProvisionedLinkProperties();
        addIPv4Provisioning(lp);
        HandlerUtils.waitForIdle(ipc.getHandler(), TEST_TIMEOUT_MS);

        reset(mCb);
        doIPv6ProvisioningLoss(lp);
        HandlerUtils.waitForIdle(ipc.getHandler(), TEST_TIMEOUT_MS);
        if (avoidBadWifi) { // Provisioning failure is expected only when avoidBadWifi is true
            verify(mCb).onProvisioningFailure(lp);
            verify(mCb).onLinkPropertiesChange(makeEmptyLinkProperties(TEST_IFNAME));
        } else {
            verify(mCb, never()).onProvisioningFailure(any());
            verify(mCb).onLinkPropertiesChange(lp);
        }

        verifyShutdown(ipc);
    }

    @Test
    public void testDefaultDualStackProvisioningConfiguration_AvoidBadWifi() throws Exception {
        doDefaultDualStackProvisioningConfigurationTest(true /* avoidBadWifi */);
    }

    @Test
    public void testDefaultDualStackProvisioningConfiguration_StayOnBadWifi() throws Exception {
        doDefaultDualStackProvisioningConfigurationTest(false /* avoidBadWifi */);
    }

    @Test
    public void testProvisioningWithInitialConfiguration() throws Exception {
        final String iface = TEST_IFNAME;
        final IpClient ipc = makeIpClient(iface);
        final String l2Key = TEST_L2KEY;
        final String cluster = TEST_CLUSTER;

        ProvisioningConfiguration config = new ProvisioningConfiguration.Builder()
                .withoutIPv4()
                .withoutIpReachabilityMonitor()
                .withInitialConfiguration(
                        conf(links(TEST_LOCAL_ADDRESSES), prefixes(TEST_PREFIXES), ips()))
                .build();

        ipc.startProvisioning(config);
        verify(mCb, timeout(TEST_TIMEOUT_MS).times(1)).setNeighborDiscoveryOffload(true);
        verify(mCb, timeout(TEST_TIMEOUT_MS).times(1)).setFallbackMulticastFilter(false);
        verify(mCb, never()).onProvisioningFailure(any());
        ipc.setL2KeyAndCluster(l2Key, cluster);

        for (String addr : TEST_LOCAL_ADDRESSES) {
            String[] parts = addr.split("/");
            verify(mNetd, timeout(TEST_TIMEOUT_MS).times(1))
                    .interfaceAddAddress(iface, parts[0], Integer.parseInt(parts[1]));
        }

        final int lastAddr = TEST_LOCAL_ADDRESSES.length - 1;

        // Add N - 1 addresses
        for (int i = 0; i < lastAddr; i++) {
            onInterfaceAddressUpdated(new LinkAddress(TEST_LOCAL_ADDRESSES[i]), 0 /* flags */);
            verify(mCb, timeout(TEST_TIMEOUT_MS)).onLinkPropertiesChange(any());
            reset(mCb);
        }

        // Add Nth address
        onInterfaceAddressUpdated(new LinkAddress(TEST_LOCAL_ADDRESSES[lastAddr]), 0 /* flags */);
        LinkProperties want = linkproperties(links(TEST_LOCAL_ADDRESSES),
                routes(TEST_PREFIXES), emptySet() /* dnses */);
        want.setInterfaceName(iface);
        verify(mCb, timeout(TEST_TIMEOUT_MS).times(1)).onProvisioningSuccess(want);
        verifyNetworkAttributesStored(l2Key, new NetworkAttributes.Builder()
                .setCluster(cluster)
                .build());

        verifyShutdown(ipc);
    }

    private void verifyShutdown(IpClient ipc) throws Exception {
        ipc.shutdown();
        verify(mNetd, timeout(TEST_TIMEOUT_MS).times(1)).interfaceSetEnableIPv6(TEST_IFNAME, false);
        verify(mNetd, timeout(TEST_TIMEOUT_MS).times(1)).interfaceClearAddrs(TEST_IFNAME);
        verify(mCb, timeout(TEST_TIMEOUT_MS).times(1))
                .onLinkPropertiesChange(makeEmptyLinkProperties(TEST_IFNAME));
        verifyNoMoreInteractions(mIpMemoryStore);
    }

    @Test
    public void testIsProvisioned() throws Exception {
        final IpClient ipc = makeIpClient(TEST_IFNAME);
        InitialConfiguration empty = conf(links(), prefixes());
        IsProvisionedTestCase[] testcases = {
            // nothing
            notProvisionedCase(links(), routes(), dns(), null),
            notProvisionedCase(links(), routes(), dns(), empty),

            // IPv4
            provisionedCase(links("192.0.2.12/24"), routes(), dns(), empty),

            // IPv6
            notProvisionedCase(
                    links("fe80::a4be:f92:e1f7:22d1/64", "fd2c:4e57:8e3c:0:548d:2db2:4fcf:ef75/64"),
                    routes(), dns(), empty),
            notProvisionedCase(
                    links("fe80::a4be:f92:e1f7:22d1/64", "fd2c:4e57:8e3c:0:548d:2db2:4fcf:ef75/64"),
                    routes("fe80::/64", "fd2c:4e57:8e3c::/64"), dns("fd00:1234:5678::1000"), empty),
            provisionedCase(
                    links("2001:db8:dead:beef:f00::a0/64", "fe80::1/64"),
                    routes("::/0"),
                    dns("2001:db8:dead:beef:f00::02"), empty),

            // Initial configuration
            provisionedCase(
                    links("fe80::e1f7:22d1/64", "fd2c:4e57:8e3c:0:548d:2db2:4fcf:ef75/64"),
                    routes("fe80::/64", "fd2c:4e57:8e3c::/64"),
                    dns(),
                    conf(links("fe80::e1f7:22d1/64", "fd2c:4e57:8e3c:0:548d:2db2:4fcf:ef75/64"),
                        prefixes("fe80::/64", "fd2c:4e57:8e3c::/64"), ips())),

            // Test case with excluded route
            notProvisionedCase(
                    links("fe80::e1f7:22d1/64", "fd2c:4e57:8e3c:0:548d:2db2:4fcf:ef75/64"),
                    routes(
                            routes("fe80::/64"),
                            excludedRoutes("fd2c:4e57:8e3c::/64")),
                    dns(),
                    conf(links("fe80::e1f7:22d1/64", "fd2c:4e57:8e3c:0:548d:2db2:4fcf:ef75/64"),
                            prefixes("fe80::/64", "fd2c:4e57:8e3c::/64"), ips()))
        };

        for (IsProvisionedTestCase testcase : testcases) {
            if (ipc.isProvisioned(testcase.lp, testcase.config) != testcase.isProvisioned) {
                fail(testcase.errorMessage());
            }
        }

        ipc.shutdown();
    }

    static class IsProvisionedTestCase {
        boolean isProvisioned;
        LinkProperties lp;
        InitialConfiguration config;

        String errorMessage() {
            return String.format("expected %s with config %s to be %s, but was %s",
                     lp, config, provisioned(isProvisioned), provisioned(!isProvisioned));
        }

        static String provisioned(boolean isProvisioned) {
            return isProvisioned ? "provisioned" : "not provisioned";
        }
    }

    static IsProvisionedTestCase provisionedCase(Set<LinkAddress> lpAddrs, Set<RouteInfo> lpRoutes,
            Set<InetAddress> lpDns, InitialConfiguration config) {
        return provisioningTest(true, lpAddrs, lpRoutes, lpDns, config);
    }

    static IsProvisionedTestCase notProvisionedCase(Set<LinkAddress> lpAddrs,
            Set<RouteInfo> lpRoutes, Set<InetAddress> lpDns, InitialConfiguration config) {
        return provisioningTest(false, lpAddrs, lpRoutes, lpDns, config);
    }

    static IsProvisionedTestCase provisioningTest(boolean isProvisioned, Set<LinkAddress> lpAddrs,
            Set<RouteInfo> lpRoutes, Set<InetAddress> lpDns, InitialConfiguration config) {
        IsProvisionedTestCase testcase = new IsProvisionedTestCase();
        testcase.isProvisioned = isProvisioned;
        testcase.lp = makeEmptyLinkProperties(TEST_IFNAME);
        testcase.lp.setLinkAddresses(lpAddrs);
        for (RouteInfo route : lpRoutes) {
            testcase.lp.addRoute(route);
        }
        for (InetAddress dns : lpDns) {
            testcase.lp.addDnsServer(dns);
        }
        testcase.config = config;
        return testcase;
    }

    @Test
    public void testInitialConfigurations() throws Exception {
        InitialConfigurationTestCase[] testcases = {
            validConf("valid IPv4 configuration",
                    links("192.0.2.12/24"), prefixes("192.0.2.0/24"), dns("192.0.2.2")),
            validConf("another valid IPv4 configuration",
                    links("192.0.2.12/24"), prefixes("192.0.2.0/24"), dns()),
            validConf("valid IPv6 configurations",
                    links("2001:db8:dead:beef:f00::a0/64", "fe80::1/64"),
                    prefixes("2001:db8:dead:beef::/64", "fe80::/64"),
                    dns("2001:db8:dead:beef:f00::02")),
            validConf("valid IPv6 configurations",
                    links("fe80::1/64"), prefixes("fe80::/64"), dns()),
            validConf("valid IPv6/v4 configuration",
                    links("2001:db8:dead:beef:f00::a0/48", "192.0.2.12/24"),
                    prefixes("2001:db8:dead:beef::/64", "192.0.2.0/24"),
                    dns("192.0.2.2", "2001:db8:dead:beef:f00::02")),
            validConf("valid IPv6 configuration without any GUA.",
                    links("fd00:1234:5678::1/48"),
                    prefixes("fd00:1234:5678::/48"),
                    dns("fd00:1234:5678::1000")),

            invalidConf("empty configuration", links(), prefixes(), dns()),
            invalidConf("v4 addr and dns not in any prefix",
                    links("192.0.2.12/24"), prefixes("198.51.100.0/24"), dns("192.0.2.2")),
            invalidConf("v4 addr not in any prefix",
                    links("198.51.2.12/24"), prefixes("198.51.100.0/24"), dns("192.0.2.2")),
            invalidConf("v4 dns addr not in any prefix",
                    links("192.0.2.12/24"), prefixes("192.0.2.0/24"), dns("198.51.100.2")),
            invalidConf("v6 addr not in any prefix",
                    links("2001:db8:dead:beef:f00::a0/64", "fe80::1/64"),
                    prefixes("2001:db8:dead:beef::/64"),
                    dns("2001:db8:dead:beef:f00::02")),
            invalidConf("v6 dns addr not in any prefix",
                    links("fe80::1/64"), prefixes("fe80::/64"), dns("2001:db8:dead:beef:f00::02")),
            invalidConf("default ipv6 route and no GUA",
                    links("fd01:1111:2222:3333::a0/128"), prefixes("::/0"), dns()),
            invalidConf("invalid v6 prefix length",
                    links("2001:db8:dead:beef:f00::a0/128"), prefixes("2001:db8:dead:beef::/32"),
                    dns()),
            invalidConf("another invalid v6 prefix length",
                    links("2001:db8:dead:beef:f00::a0/128"), prefixes("2001:db8:dead:beef::/72"),
                    dns())
        };

        for (InitialConfigurationTestCase testcase : testcases) {
            if (testcase.config.isValid() != testcase.isValid) {
                fail(testcase.errorMessage());
            }
        }
    }

    static class InitialConfigurationTestCase {
        String descr;
        boolean isValid;
        InitialConfiguration config;
        public String errorMessage() {
            return String.format("%s: expected configuration %s to be %s, but was %s",
                    descr, config, validString(isValid), validString(!isValid));
        }
        static String validString(boolean isValid) {
            return isValid ? VALID : INVALID;
        }
    }

    static InitialConfigurationTestCase validConf(String descr, Set<LinkAddress> links,
            Set<IpPrefix> prefixes, Set<InetAddress> dns) {
        return confTestCase(descr, true, conf(links, prefixes, dns));
    }

    static InitialConfigurationTestCase invalidConf(String descr, Set<LinkAddress> links,
            Set<IpPrefix> prefixes, Set<InetAddress> dns) {
        return confTestCase(descr, false, conf(links, prefixes, dns));
    }

    static InitialConfigurationTestCase confTestCase(
            String descr, boolean isValid, InitialConfiguration config) {
        InitialConfigurationTestCase testcase = new InitialConfigurationTestCase();
        testcase.descr = descr;
        testcase.isValid = isValid;
        testcase.config = config;
        return testcase;
    }

    static LinkProperties linkproperties(Set<LinkAddress> addresses,
            Set<RouteInfo> routes, Set<InetAddress> dnses) {
        LinkProperties lp = makeEmptyLinkProperties(TEST_IFNAME);
        lp.setLinkAddresses(addresses);
        routes.forEach(lp::addRoute);
        dnses.forEach(lp::addDnsServer);
        return lp;
    }

    static InitialConfiguration conf(Set<LinkAddress> links, Set<IpPrefix> prefixes) {
        return conf(links, prefixes, new HashSet<>());
    }

    static InitialConfiguration conf(
            Set<LinkAddress> links, Set<IpPrefix> prefixes, Set<InetAddress> dns) {
        InitialConfiguration conf = new InitialConfiguration();
        conf.ipAddresses.addAll(links);
        conf.directlyConnectedRoutes.addAll(prefixes);
        conf.dnsServers.addAll(dns);
        return conf;
    }

    static Set<RouteInfo> routes(String... routes) {
        return mapIntoSet(routes, (r) -> new RouteInfo(new IpPrefix(r), null /* gateway */,
                TEST_IFNAME));
    }

    static Set<RouteInfo> excludedRoutes(String... excludedRoutes) {
        return mapIntoSet(excludedRoutes, (r) -> new RouteInfo(new IpPrefix(r), null /* gateway */,
                TEST_IFNAME, RouteInfo.RTN_THROW));
    }

    static Set<RouteInfo> routes(Set<RouteInfo> includedRoutes, Set<RouteInfo> excludedRoutes) {
        Set<RouteInfo> result = new HashSet<>(includedRoutes.size() + excludedRoutes.size());

        result.addAll(includedRoutes);
        result.addAll(excludedRoutes);

        return result;
    }

    @SuppressLint("NewApi")
    static RouteInfo defaultIPV6Route(String gateway) {
        return new RouteInfo(new IpPrefix(Inet6Address.ANY, 0),
                InetAddresses.parseNumericAddress(gateway), TEST_IFNAME);
    }

    static Set<IpPrefix> prefixes(String... prefixes) {
        return mapIntoSet(prefixes, IpPrefix::new);
    }

    static Set<LinkAddress> links(String... addresses) {
        return mapIntoSet(addresses, LinkAddress::new);
    }

    static Set<InetAddress> ips(String... addresses) {
        return mapIntoSet(addresses, InetAddress::getByName);
    }

    static Set<InetAddress> dns(String... addresses) {
        return ips(addresses);
    }

    static <A, B> Set<B> mapIntoSet(A[] in, Fn<A, B> fn) {
        Set<B> out = new HashSet<>(in.length);
        for (A item : in) {
            try {
                out.add(fn.call(item));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        return out;
    }

    private ApfConfiguration verifyApfFilterCreatedOnStart(IpClient ipc, boolean isApfSupported) {
        ProvisioningConfiguration.Builder config = new ProvisioningConfiguration.Builder()
                .withoutIPv4()
                .withoutIpReachabilityMonitor()
                .withInitialConfiguration(
                        conf(links(TEST_LOCAL_ADDRESSES), prefixes(TEST_PREFIXES), ips()));
        if (isApfSupported) {
            config.withApfCapabilities(new ApfCapabilities(4 /* version */,
                    4096 /* maxProgramSize */, ARPHRD_ETHER));
        }

        ipc.startProvisioning(config.build());
        final ArgumentCaptor<ApfConfiguration> configCaptor = ArgumentCaptor.forClass(
                ApfConfiguration.class);
        if (isApfSupported) {
            verify(mDependencies, timeout(TEST_TIMEOUT_MS)).maybeCreateApfFilter(
                    any(), any(), configCaptor.capture(), any(), any(), any(), anyBoolean());
        } else {
            verify(mDependencies, never()).maybeCreateApfFilter(
                    any(), any(), configCaptor.capture(), any(), any(), any(), anyBoolean());
        }

        return isApfSupported ? configCaptor.getValue() : null;
    }

    @Test @IgnoreAfter(Build.VERSION_CODES.R)
    public void testApfConfiguration_R() throws Exception {
        final IpClient ipc = makeIpClient(TEST_IFNAME);
        final ApfConfiguration config = verifyApfFilterCreatedOnStart(ipc,
                true /* isApfSupported */);

        assertEquals(ApfCapabilities.getApfDrop8023Frames(), config.ieee802_3Filter);
        assertArrayEquals(ApfCapabilities.getApfEtherTypeBlackList(), config.ethTypeBlackList);

        verify(mResources, never()).getBoolean(R.bool.config_apfDrop802_3Frames);
        verify(mResources, never()).getIntArray(R.array.config_apfEthTypeDenyList);

        verifyShutdown(ipc);
    }

    @Test @IgnoreUpTo(Build.VERSION_CODES.R)
    public void testApfConfiguration() throws Exception {
        doReturn(true).when(mResources).getBoolean(R.bool.config_apfDrop802_3Frames);
        final int[] ethTypeDenyList = new int[] { 0x88A2, 0x88A4 };
        doReturn(ethTypeDenyList).when(mResources).getIntArray(
                R.array.config_apfEthTypeDenyList);

        final IpClient ipc = makeIpClient(TEST_IFNAME);
        final ApfConfiguration config = verifyApfFilterCreatedOnStart(ipc,
                true /* isApfSupported */);

        assertTrue(config.ieee802_3Filter);
        assertArrayEquals(ethTypeDenyList, config.ethTypeBlackList);

        verifyShutdown(ipc);
    }

    @Test @IgnoreUpTo(Build.VERSION_CODES.R)
    public void testApfConfiguration_NoApfDrop8023Frames() throws Exception {
        doReturn(false).when(mResources).getBoolean(R.bool.config_apfDrop802_3Frames);
        final int[] ethTypeDenyList = new int[] { 0x88A3, 0x88A5 };
        doReturn(ethTypeDenyList).when(mResources).getIntArray(
                R.array.config_apfEthTypeDenyList);

        final IpClient ipc = makeIpClient(TEST_IFNAME);
        final ApfConfiguration config = verifyApfFilterCreatedOnStart(ipc,
                true /* isApfSupported */);

        assertFalse(config.ieee802_3Filter);
        assertArrayEquals(ethTypeDenyList, config.ethTypeBlackList);

        verifyShutdown(ipc);
    }

    @Test
    public void testApfUpdateCapabilities() throws Exception {
        final IpClient ipc = makeIpClient(TEST_IFNAME);
        final ApfConfiguration config = verifyApfFilterCreatedOnStart(ipc,
                false /* isApfSupported */);
        assertNull(config);

        ipc.updateApfCapabilities(new ApfCapabilities(4 /* version */, 4096 /* maxProgramSize */,
                ARPHRD_ETHER));
        HandlerUtils.waitForIdle(ipc.getHandler(), TEST_TIMEOUT_MS);

        final ArgumentCaptor<ApfConfiguration> configCaptor = ArgumentCaptor.forClass(
                ApfConfiguration.class);
        verify(mDependencies, timeout(TEST_TIMEOUT_MS)).maybeCreateApfFilter(
                any(), any(), configCaptor.capture(), any(), any(), any(), anyBoolean());
        final ApfConfiguration actual = configCaptor.getValue();
        assertNotNull(actual);
        assertEquals(SdkLevel.isAtLeastS() ? 4 : 3, actual.apfVersionSupported);
        assertEquals(4096, actual.apfRamSize);

        verifyShutdown(ipc);
    }

    @Test
    public void testDumpApfFilter_withNoException() throws Exception {
        final IpClient ipc = makeIpClient(TEST_IFNAME);
        final ApfConfiguration config = verifyApfFilterCreatedOnStart(ipc,
                true /* isApfSupported */);
        assertEquals(SdkLevel.isAtLeastS() ? 4 : 3, config.apfVersionSupported);
        assertEquals(4096, config.apfRamSize);
        clearInvocations(mDependencies);
        ipc.dump(mFd, mWriter, null /* args */);
        verifyShutdown(ipc);
    }

    @Test
    public void testApfUpdateCapabilities_nonNullInitialApfCapabilities() throws Exception {
        final IpClient ipc = makeIpClient(TEST_IFNAME);
        final ApfConfiguration config = verifyApfFilterCreatedOnStart(ipc,
                true /* isApfSupported */);
        assertEquals(SdkLevel.isAtLeastS() ? 4 : 3, config.apfVersionSupported);
        assertEquals(4096, config.apfRamSize);
        clearInvocations(mDependencies);

        final ApfCapabilities newApfCapabilities = new ApfCapabilities(4 /* version */,
                8192 /* maxProgramSize */, ARPHRD_ETHER);
        ipc.updateApfCapabilities(newApfCapabilities);
        HandlerUtils.waitForIdle(ipc.getHandler(), TEST_TIMEOUT_MS);
        verify(mDependencies, never()).maybeCreateApfFilter(any(), any(), any(), any(), any(),
                any(), anyBoolean());
        verifyShutdown(ipc);
    }

    @Test
    public void testApfUpdateCapabilities_nullNewApfCapabilities() throws Exception {
        final IpClient ipc = makeIpClient(TEST_IFNAME);
        final ApfConfiguration config = verifyApfFilterCreatedOnStart(ipc,
                true /* isApfSupported */);
        assertEquals(SdkLevel.isAtLeastS() ? 4 : 3, config.apfVersionSupported);
        assertEquals(4096, config.apfRamSize);
        clearInvocations(mDependencies);

        ipc.updateApfCapabilities(null /* apfCapabilities */);
        HandlerUtils.waitForIdle(ipc.getHandler(), TEST_TIMEOUT_MS);
        verify(mDependencies, never()).maybeCreateApfFilter(any(), any(), any(), any(), any(),
                any(), anyBoolean());
        verifyShutdown(ipc);
    }

    @Test
    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    public void testVendorNdOffloadDisabledWhenApfV6Supported() throws Exception {
        when(mDependencies.maybeCreateApfFilter(any(), any(), any(), any(), any(), any(),
                anyBoolean())).thenReturn(mApfFilter);
        when(mApfFilter.supportNdOffload()).thenReturn(true);
        final IpClient ipc = makeIpClient(TEST_IFNAME);
        ProvisioningConfiguration config = new ProvisioningConfiguration.Builder()
                .withoutIPv4()
                .withoutIpReachabilityMonitor()
                .withApfCapabilities(new ApfCapabilities(APF_VERSION_6,
                        4096 /* maxProgramSize */, ARPHRD_ETHER))
                .build();
        ipc.startProvisioning(config);
        final InOrder inOrder = inOrder(mCb);
        inOrder.verify(mCb, timeout(TEST_TIMEOUT_MS).times(1)).setNeighborDiscoveryOffload(true);
        inOrder.verify(mCb, timeout(TEST_TIMEOUT_MS).times(1)).setNeighborDiscoveryOffload(false);

        // update clat
        onInterfaceAdded(TEST_CLAT_IFINDEX, TEST_CLAT_IFNAME);
        verifyShutdown(ipc);
        inOrder.verify(mCb, never()).setNeighborDiscoveryOffload(anyBoolean());
        clearInvocations(mApfFilter);
        clearInvocations(mCb);
    }

    @Test
    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    public void testVendorNdOffloadEnabledWhenApfV6NotSupported() throws Exception {
        when(mDependencies.maybeCreateApfFilter(any(), any(), any(), any(), any(), any(),
                anyBoolean())).thenReturn(mApfFilter);
        when(mApfFilter.supportNdOffload()).thenReturn(false);
        final IpClient ipc = makeIpClient(TEST_IFNAME);
        ProvisioningConfiguration config = new ProvisioningConfiguration.Builder()
                .withoutIPv4()
                .withoutIpReachabilityMonitor()
                .withApfCapabilities(new ApfCapabilities(APF_VERSION_6,
                        4096 /* maxProgramSize */, ARPHRD_ETHER))
                .build();
        ipc.startProvisioning(config);
        verify(mCb, timeout(TEST_TIMEOUT_MS).times(1)).setNeighborDiscoveryOffload(true);

        // update clat
        onInterfaceAdded(TEST_CLAT_IFINDEX, TEST_CLAT_IFNAME);
        verifyShutdown(ipc);
        verify(mCb, times(1)).setNeighborDiscoveryOffload(true);
        clearInvocations(mApfFilter);
        clearInvocations(mCb);
    }

    @Test
    @IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    public void testVendorNdOffloadDisabledWhenApfCapabilitiesUpdated() throws Exception {
        when(mDependencies.maybeCreateApfFilter(any(), any(), any(), any(), any(), any(),
                anyBoolean())).thenReturn(mApfFilter);
        when(mApfFilter.supportNdOffload()).thenReturn(true);
        final IpClient ipc = makeIpClient(TEST_IFNAME);
        ProvisioningConfiguration config = new ProvisioningConfiguration.Builder()
                .withoutIPv4()
                .withoutIpReachabilityMonitor()
                .build();
        ipc.startProvisioning(config);
        ipc.updateApfCapabilities(
                new ApfCapabilities(APF_VERSION_6, 4096 /* maxProgramSize */, ARPHRD_ETHER));
        HandlerUtils.waitForIdle(ipc.getHandler(), TEST_TIMEOUT_MS);
        final InOrder inOrder = inOrder(mCb);
        inOrder.verify(mCb, timeout(TEST_TIMEOUT_MS).times(1)).setNeighborDiscoveryOffload(true);
        inOrder.verify(mCb, timeout(TEST_TIMEOUT_MS).times(1)).setNeighborDiscoveryOffload(false);
        verifyShutdown(ipc);
        inOrder.verify(mCb, never()).setNeighborDiscoveryOffload(anyBoolean());
        clearInvocations(mApfFilter);
        clearInvocations(mCb);
    }

    @Test
    public void testLinkPropertiesUpdate_callSetLinkPropertiesOnApfFilter() throws Exception {
        when(mDependencies.maybeCreateApfFilter(any(), any(), any(), any(), any(), any(),
                anyBoolean())).thenReturn(mApfFilter);
        final IpClient ipc = makeIpClient(TEST_IFNAME);
        verifyApfFilterCreatedOnStart(ipc, true /* isApfSupported */);
        onInterfaceAddressUpdated(
                new LinkAddress(TEST_GLOBAL_ADDRESS, IFA_F_TENTATIVE, RT_SCOPE_UNIVERSE),
                IFA_F_TENTATIVE);
        // mApfFilter.setLinkProperties() is called both in IpClient#handleLinkPropertiesUpdate()
        // and IpClient#setLinkProperties().
        verify(mApfFilter, timeout(TEST_TIMEOUT_MS).times(2)).setLinkProperties(any());
        // LinkAddress flag change will trigger mApfFilter.setLinkProperties()
        onInterfaceAddressUpdated(
                new LinkAddress(TEST_GLOBAL_ADDRESS, IFA_F_PERMANENT, RT_SCOPE_UNIVERSE),
                IFA_F_PERMANENT);
        // mApfFilter.setLinkProperties() is called only in IpClient#handleLinkPropertiesUpdate().
        // IpClient#setLinkProperties() is not called because Objects.equals(newLp,
        // mLinkProperties) returns true and IpClient#handleLinkPropertiesUpdate() is terminated.
        verify(mApfFilter, timeout(TEST_TIMEOUT_MS).times(3)).setLinkProperties(any());
        clearInvocations(mDependencies);
        clearInvocations(mApfFilter);
        verifyShutdown(ipc);
    }

    private ScanResultInfo makeScanResultInfo(final String ssid, final String bssid) {
        final ByteBuffer payload = ByteBuffer.allocate(14 /* oui + type + data */);
        final byte[] data = new byte[10];
        new Random().nextBytes(data);
        payload.put(new byte[] { 0x00, 0x1A, 0x11 });
        payload.put((byte) 0x06);
        payload.put(data);

        final ScanResultInfo.InformationElement ie =
                new ScanResultInfo.InformationElement(0xdd /* IE id */, payload);
        return new ScanResultInfo(ssid, bssid, Collections.singletonList(ie));
    }

    @Test
    public void testGetInitialBssidOnSOrAbove() throws Exception {
        final IpClient ipc = makeIpClient(TEST_IFNAME);
        final Layer2Information layer2Info = new Layer2Information(TEST_L2KEY, TEST_CLUSTER,
                MacAddress.fromString(TEST_BSSID));
        final ScanResultInfo scanResultInfo = makeScanResultInfo(TEST_SSID, TEST_BSSID2);
        final MacAddress bssid = ipc.getInitialBssid(layer2Info, scanResultInfo,
                true /* isAtLeastS */);
        assertEquals(bssid, MacAddress.fromString(TEST_BSSID));
        ipc.shutdown();
    }

    @Test
    public void testGetInitialBssidOnSOrAbove_NullScanReqsultInfo() throws Exception {
        final IpClient ipc = makeIpClient(TEST_IFNAME);
        final Layer2Information layer2Info = new Layer2Information(TEST_L2KEY, TEST_CLUSTER,
                MacAddress.fromString(TEST_BSSID));
        final MacAddress bssid = ipc.getInitialBssid(layer2Info, null /* ScanResultInfo */,
                true /* isAtLeastS */);
        assertEquals(bssid, MacAddress.fromString(TEST_BSSID));
        ipc.shutdown();
    }

    @Test
    public void testGetInitialBssidOnSOrAbove_NullBssid() throws Exception {
        final IpClient ipc = makeIpClient(TEST_IFNAME);
        final Layer2Information layer2Info = new Layer2Information(TEST_L2KEY, TEST_CLUSTER,
                null /* bssid */);
        final ScanResultInfo scanResultInfo = makeScanResultInfo(TEST_SSID, TEST_BSSID);
        final MacAddress bssid = ipc.getInitialBssid(layer2Info, scanResultInfo,
                true /* isAtLeastS */);
        assertNull(bssid);
        ipc.shutdown();
    }

    @Test
    public void testGetInitialBssidOnSOrAbove_NullLayer2Info() throws Exception {
        final IpClient ipc = makeIpClient(TEST_IFNAME);
        final ScanResultInfo scanResultInfo = makeScanResultInfo(TEST_SSID, TEST_BSSID);
        final MacAddress bssid = ipc.getInitialBssid(null /* layer2Info */, scanResultInfo,
                true /* isAtLeastS */);
        assertNull(bssid);
        ipc.shutdown();
    }

    @Test
    public void testGetInitialBssidBeforeS() throws Exception {
        final IpClient ipc = makeIpClient(TEST_IFNAME);
        final Layer2Information layer2Info = new Layer2Information(TEST_L2KEY, TEST_CLUSTER,
                MacAddress.fromString(TEST_BSSID2));
        final ScanResultInfo scanResultInfo = makeScanResultInfo(TEST_SSID, TEST_BSSID);
        final MacAddress bssid = ipc.getInitialBssid(layer2Info, scanResultInfo,
                false /* isAtLeastS */);
        assertEquals(bssid, MacAddress.fromString(TEST_BSSID));
        ipc.shutdown();
    }

    @Test
    public void testGetInitialBssidBeforeS_NullLayer2Info() throws Exception {
        final IpClient ipc = makeIpClient(TEST_IFNAME);
        final ScanResultInfo scanResultInfo = makeScanResultInfo(TEST_SSID, TEST_BSSID);
        final MacAddress bssid = ipc.getInitialBssid(null /* layer2Info */, scanResultInfo,
                false /* isAtLeastS */);
        assertEquals(bssid, MacAddress.fromString(TEST_BSSID));
        ipc.shutdown();
    }

    @Test
    public void testGetInitialBssidBeforeS_BrokenInitialBssid() throws Exception {
        final IpClient ipc = makeIpClient(TEST_IFNAME);
        final ScanResultInfo scanResultInfo = makeScanResultInfo(TEST_SSID, "00:11:22:33:44:");
        final MacAddress bssid = ipc.getInitialBssid(null /* layer2Info */, scanResultInfo,
                false /* isAtLeastS */);
        assertNull(bssid);
        ipc.shutdown();
    }

    @Test
    public void testGetInitialBssidBeforeS_BrokenInitialBssidFallback() throws Exception {
        final IpClient ipc = makeIpClient(TEST_IFNAME);
        final Layer2Information layer2Info = new Layer2Information(TEST_L2KEY, TEST_CLUSTER,
                MacAddress.fromString(TEST_BSSID));
        final ScanResultInfo scanResultInfo = makeScanResultInfo(TEST_SSID, "00:11:22:33:44:");
        final MacAddress bssid = ipc.getInitialBssid(layer2Info, scanResultInfo,
                false /* isAtLeastS */);
        assertEquals(bssid, MacAddress.fromString(TEST_BSSID));
        ipc.shutdown();
    }

    @Test
    public void testGetInitialBssidBeforeS_NullScanResultInfoFallback() throws Exception {
        final IpClient ipc = makeIpClient(TEST_IFNAME);
        final Layer2Information layer2Info = new Layer2Information(TEST_L2KEY, TEST_CLUSTER,
                MacAddress.fromString(TEST_BSSID));
        final MacAddress bssid = ipc.getInitialBssid(layer2Info, null /* scanResultInfo */,
                false /* isAtLeastS */);
        assertEquals(bssid, MacAddress.fromString(TEST_BSSID));
        ipc.shutdown();
    }

    @Test
    public void testGetInitialBssidBeforeS_NullScanResultInfoAndLayer2Info() throws Exception {
        final IpClient ipc = makeIpClient(TEST_IFNAME);
        final MacAddress bssid = ipc.getInitialBssid(null /* layer2Info */,
                null /* scanResultInfo */, false /* isAtLeastS */);
        assertNull(bssid);
        ipc.shutdown();
    }

    interface Fn<A,B> {
        B call(A a) throws Exception;
    }

    @Test
    public void testAll() {
        List<String> list1 = Arrays.asList();
        List<String> list2 = Arrays.asList("foo");
        List<String> list3 = Arrays.asList("bar", "baz");
        List<String> list4 = Arrays.asList("foo", "bar", "baz");

        assertTrue(InitialConfiguration.all(list1, (x) -> false));
        assertFalse(InitialConfiguration.all(list2, (x) -> false));
        assertTrue(InitialConfiguration.all(list3, (x) -> true));
        assertTrue(InitialConfiguration.all(list2, (x) -> x.charAt(0) == 'f'));
        assertFalse(InitialConfiguration.all(list4, (x) -> x.charAt(0) == 'f'));
    }

    @Test
    public void testAny() {
        List<String> list1 = Arrays.asList();
        List<String> list2 = Arrays.asList("foo");
        List<String> list3 = Arrays.asList("bar", "baz");
        List<String> list4 = Arrays.asList("foo", "bar", "baz");

        assertFalse(InitialConfiguration.any(list1, (x) -> true));
        assertTrue(InitialConfiguration.any(list2, (x) -> true));
        assertTrue(InitialConfiguration.any(list2, (x) -> x.charAt(0) == 'f'));
        assertFalse(InitialConfiguration.any(list3, (x) -> x.charAt(0) == 'f'));
        assertTrue(InitialConfiguration.any(list4, (x) -> x.charAt(0) == 'f'));
    }

    @Test
    public void testFindAll() {
        List<String> list1 = Arrays.asList();
        List<String> list2 = Arrays.asList("foo");
        List<String> list3 = Arrays.asList("foo", "bar", "baz");

        assertEquals(list1, IpClient.findAll(list1, (x) -> true));
        assertEquals(list1, IpClient.findAll(list3, (x) -> false));
        assertEquals(list3, IpClient.findAll(list3, (x) -> true));
        assertEquals(list2, IpClient.findAll(list3, (x) -> x.charAt(0) == 'f'));
    }
}
