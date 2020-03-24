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

package com.android.server.connectivity;

import static android.net.CaptivePortal.APP_RETURN_DISMISSED;
import static android.net.DnsResolver.TYPE_A;
import static android.net.DnsResolver.TYPE_AAAA;
import static android.net.INetworkMonitor.NETWORK_VALIDATION_PROBE_DNS;
import static android.net.INetworkMonitor.NETWORK_VALIDATION_PROBE_FALLBACK;
import static android.net.INetworkMonitor.NETWORK_VALIDATION_PROBE_HTTP;
import static android.net.INetworkMonitor.NETWORK_VALIDATION_PROBE_HTTPS;
import static android.net.INetworkMonitor.NETWORK_VALIDATION_PROBE_PRIVDNS;
import static android.net.INetworkMonitor.NETWORK_VALIDATION_RESULT_PARTIAL;
import static android.net.INetworkMonitor.NETWORK_VALIDATION_RESULT_VALID;
import static android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET;
import static android.net.util.DataStallUtils.CONFIG_DATA_STALL_CONSECUTIVE_DNS_TIMEOUT_THRESHOLD;
import static android.net.util.DataStallUtils.CONFIG_DATA_STALL_EVALUATION_TYPE;
import static android.net.util.DataStallUtils.CONFIG_DATA_STALL_MIN_EVALUATE_INTERVAL;
import static android.net.util.DataStallUtils.CONFIG_DATA_STALL_TCP_POLLING_INTERVAL;
import static android.net.util.DataStallUtils.CONFIG_DATA_STALL_VALID_DNS_TIME_THRESHOLD;
import static android.net.util.DataStallUtils.DATA_STALL_EVALUATION_TYPE_DNS;
import static android.net.util.DataStallUtils.DATA_STALL_EVALUATION_TYPE_TCP;
import static android.net.util.NetworkStackUtils.CAPTIVE_PORTAL_FALLBACK_PROBE_SPECS;
import static android.net.util.NetworkStackUtils.CAPTIVE_PORTAL_OTHER_FALLBACK_URLS;
import static android.net.util.NetworkStackUtils.CAPTIVE_PORTAL_USE_HTTPS;
import static android.net.util.NetworkStackUtils.DISMISS_PORTAL_IN_VALIDATED_NETWORK;

import static com.android.networkstack.apishim.ConstantsShim.DETECTION_METHOD_DNS_EVENTS;
import static com.android.networkstack.apishim.ConstantsShim.DETECTION_METHOD_TCP_METRICS;
import static com.android.networkstack.apishim.ConstantsShim.KEY_DNS_CONSECUTIVE_TIMEOUTS;
import static com.android.networkstack.apishim.ConstantsShim.KEY_NETWORK_PROBES_ATTEMPTED_BITMASK;
import static com.android.networkstack.apishim.ConstantsShim.KEY_NETWORK_PROBES_SUCCEEDED_BITMASK;
import static com.android.networkstack.apishim.ConstantsShim.KEY_NETWORK_VALIDATION_RESULT;
import static com.android.networkstack.apishim.ConstantsShim.KEY_TCP_METRICS_COLLECTION_PERIOD_MILLIS;
import static com.android.networkstack.apishim.ConstantsShim.KEY_TCP_PACKET_FAIL_RATE;
import static com.android.networkstack.util.DnsUtils.PRIVATE_DNS_PROBE_HOST_SUFFIX;
import static com.android.server.connectivity.NetworkMonitor.extractCharset;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertFalse;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeFalse;
import static org.junit.Assume.assumeTrue;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyInt;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import static java.lang.System.currentTimeMillis;
import static java.util.Collections.singletonList;
import static java.util.stream.Collectors.toList;

import android.annotation.NonNull;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.net.CaptivePortalData;
import android.net.ConnectivityManager;
import android.net.DnsResolver;
import android.net.INetd;
import android.net.INetworkMonitorCallbacks;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.Uri;
import android.net.captiveportal.CaptivePortalProbeResult;
import android.net.metrics.IpConnectivityLog;
import android.net.shared.PrivateDnsConfig;
import android.net.util.SharedLog;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Bundle;
import android.os.ConditionVariable;
import android.os.Handler;
import android.os.Looper;
import android.os.PersistableBundle;
import android.os.Process;
import android.os.RemoteException;
import android.os.SystemClock;
import android.provider.Settings;
import android.telephony.CellIdentityGsm;
import android.telephony.CellIdentityLte;
import android.telephony.CellInfo;
import android.telephony.CellInfoGsm;
import android.telephony.CellInfoLte;
import android.telephony.CellSignalStrength;
import android.telephony.TelephonyManager;
import android.util.ArrayMap;

import androidx.test.filters.SmallTest;
import androidx.test.runner.AndroidJUnit4;

import com.android.networkstack.NetworkStackNotifier;
import com.android.networkstack.R;
import com.android.networkstack.apishim.CaptivePortalDataShimImpl;
import com.android.networkstack.apishim.ShimUtils;
import com.android.networkstack.metrics.DataStallDetectionStats;
import com.android.networkstack.metrics.DataStallStatsUtils;
import com.android.networkstack.netlink.TcpSocketTracker;
import com.android.server.NetworkStackService.NetworkStackServiceManager;
import com.android.testutils.HandlerUtilsKt;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.Spy;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.Executor;

import javax.net.ssl.SSLHandshakeException;

@RunWith(AndroidJUnit4.class)
@SmallTest
public class NetworkMonitorTest {
    private static final String LOCATION_HEADER = "location";
    private static final String CONTENT_TYPE_HEADER = "Content-Type";

    private @Mock Context mContext;
    private @Mock Configuration mConfiguration;
    private @Mock Resources mResources;
    private @Mock IpConnectivityLog mLogger;
    private @Mock SharedLog mValidationLogger;
    private @Mock DnsResolver mDnsResolver;
    private @Mock ConnectivityManager mCm;
    private @Mock TelephonyManager mTelephony;
    private @Mock WifiManager mWifi;
    private @Mock NetworkStackServiceManager mServiceManager;
    private @Mock NetworkStackNotifier mNotifier;
    private @Mock HttpURLConnection mHttpConnection;
    private @Mock HttpURLConnection mHttpsConnection;
    private @Mock HttpURLConnection mFallbackConnection;
    private @Mock HttpURLConnection mOtherFallbackConnection;
    private @Mock HttpURLConnection mCapportApiConnection;
    private @Mock Random mRandom;
    private @Mock NetworkMonitor.Dependencies mDependencies;
    private @Mock INetworkMonitorCallbacks mCallbacks;
    private @Spy Network mCleartextDnsNetwork = new Network(TEST_NETID);
    private @Mock Network mNetwork;
    private @Mock DataStallStatsUtils mDataStallStatsUtils;
    private @Mock WifiInfo mWifiInfo;
    private @Captor ArgumentCaptor<String> mNetworkTestedRedirectUrlCaptor;
    private @Mock TcpSocketTracker.Dependencies mTstDependencies;
    private @Mock INetd mNetd;
    private @Mock TcpSocketTracker mTst;
    private HashSet<WrappedNetworkMonitor> mCreatedNetworkMonitors;
    private HashSet<BroadcastReceiver> mRegisteredReceivers;
    private @Mock Context mMccContext;
    private @Mock Resources mMccResource;

    private static final int TEST_NETID = 4242;
    private static final String TEST_HTTP_URL = "http://www.google.com/gen_204";
    private static final String TEST_HTTPS_URL = "https://www.google.com/gen_204";
    private static final String TEST_FALLBACK_URL = "http://fallback.google.com/gen_204";
    private static final String TEST_OTHER_FALLBACK_URL = "http://otherfallback.google.com/gen_204";
    private static final String TEST_CAPPORT_API_URL = "https://capport.example.com/api";
    private static final String TEST_LOGIN_URL = "https://testportal.example.com/login";
    private static final String TEST_VENUE_INFO_URL = "https://venue.example.com/info";
    private static final String TEST_MCCMNC = "123456";

    private static final int VALIDATION_RESULT_INVALID = 0;
    private static final int VALIDATION_RESULT_PORTAL = 0;
    private static final String TEST_REDIRECT_URL = "android.com";
    private static final int VALIDATION_RESULT_PARTIAL = NETWORK_VALIDATION_PROBE_DNS
            | NETWORK_VALIDATION_PROBE_HTTP
            | NETWORK_VALIDATION_RESULT_PARTIAL;
    private static final int VALIDATION_RESULT_FALLBACK_PARTIAL = NETWORK_VALIDATION_PROBE_DNS
            | NETWORK_VALIDATION_PROBE_FALLBACK
            | NETWORK_VALIDATION_RESULT_PARTIAL;
    private static final int VALIDATION_RESULT_VALID = NETWORK_VALIDATION_PROBE_DNS
            | NETWORK_VALIDATION_PROBE_HTTPS
            | NETWORK_VALIDATION_RESULT_VALID;
    private static final int VALIDATION_RESULT_VALID_ALL_PROBES =
            VALIDATION_RESULT_VALID | NETWORK_VALIDATION_PROBE_HTTP;
    private static final int VALIDATION_RESULT_PRIVDNS_VALID = NETWORK_VALIDATION_PROBE_DNS
            | NETWORK_VALIDATION_PROBE_HTTPS | NETWORK_VALIDATION_PROBE_PRIVDNS;

    private static final int RETURN_CODE_DNS_SUCCESS = 0;
    private static final int RETURN_CODE_DNS_TIMEOUT = 255;
    private static final int DEFAULT_DNS_TIMEOUT_THRESHOLD = 5;

    private static final int HANDLER_TIMEOUT_MS = 1000;

    private static final LinkProperties TEST_LINK_PROPERTIES = new LinkProperties();
    private static final LinkProperties CAPPORT_LINK_PROPERTIES = makeCapportLinkProperties();

    private static LinkProperties makeCapportLinkProperties() {
        final LinkProperties lp = new LinkProperties(TEST_LINK_PROPERTIES);
        lp.setCaptivePortalApiUrl(Uri.parse(TEST_CAPPORT_API_URL));
        return lp;
    }

    private static final NetworkCapabilities METERED_CAPABILITIES = new NetworkCapabilities()
            .addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR)
            .addCapability(NET_CAPABILITY_INTERNET);

    private static final NetworkCapabilities NOT_METERED_CAPABILITIES = new NetworkCapabilities()
            .addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR)
            .addCapability(NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED);

    private static final NetworkCapabilities NO_INTERNET_CAPABILITIES = new NetworkCapabilities()
            .addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR);

    private static final int NOTIFY_NETWORK_TESTED_VALIDATION_RESULT_MASK = 0x3;
    private static final int NOTIFY_NETWORK_TESTED_SUCCESSFUL_PROBES_MASK = 0xFFFC;

    /**
     * Fakes DNS responses.
     *
     * Allows test methods to configure the IP addresses that will be resolved by
     * Network#getAllByName and by DnsResolver#query.
     */
    class FakeDns {
        /** Data class to record the Dns entry. */
        class DnsEntry {
            final String mHostname;
            final int mType;
            final List<InetAddress> mAddresses;
            DnsEntry(String host, int type, List<InetAddress> addr) {
                mHostname = host;
                mType = type;
                mAddresses = addr;
            }
            // Full match or partial match that target host contains the entry hostname to support
            // random private dns probe hostname.
            private boolean matches(String hostname, int type) {
                return hostname.endsWith(mHostname) && type == mType;
            }
        }
        private final ArrayList<DnsEntry> mAnswers = new ArrayList<DnsEntry>();
        private boolean mNonBypassPrivateDnsWorking = true;

        /** Whether DNS queries on mNonBypassPrivateDnsWorking should succeed. */
        private void setNonBypassPrivateDnsWorking(boolean working) {
            mNonBypassPrivateDnsWorking = working;
        }

        /** Clears all DNS entries. */
        private synchronized void clearAll() {
            mAnswers.clear();
        }

        /** Returns the answer for a given name and type on the given mock network. */
        private synchronized List<InetAddress> getAnswer(Object mock, String hostname, int type) {
            if (mock == mNetwork && !mNonBypassPrivateDnsWorking) {
                return null;
            }

            return mAnswers.stream().filter(e -> e.matches(hostname, type))
                    .map(answer -> answer.mAddresses).findFirst().orElse(null);
        }

        /** Sets the answer for a given name and type. */
        private synchronized void setAnswer(String hostname, String[] answer, int type)
                throws UnknownHostException {
            DnsEntry record = new DnsEntry(hostname, type, generateAnswer(answer));
            // Remove the existing one.
            mAnswers.removeIf(entry -> entry.matches(hostname, type));
            // Add or replace a new record.
            mAnswers.add(record);
        }

        private List<InetAddress> generateAnswer(String[] answer) {
            if (answer == null) return new ArrayList<>();
            return Arrays.stream(answer).map(addr -> InetAddress.parseNumericAddress(addr))
                    .collect(toList());
        }

        /** Simulates a getAllByName call for the specified name on the specified mock network. */
        private InetAddress[] getAllByName(Object mock, String hostname)
                throws UnknownHostException {
            List<InetAddress> answer = queryAllTypes(mock, hostname);
            if (answer == null || answer.size() == 0) {
                throw new UnknownHostException(hostname);
            }
            return answer.toArray(new InetAddress[0]);
        }

        // Regardless of the type, depends on what the responses contained in the network.
        private List<InetAddress> queryAllTypes(Object mock, String hostname) {
            List<InetAddress> answer = new ArrayList<>();
            addAllIfNotNull(answer, getAnswer(mock, hostname, TYPE_A));
            addAllIfNotNull(answer, getAnswer(mock, hostname, TYPE_AAAA));
            return answer;
        }

        private void addAllIfNotNull(List<InetAddress> list, List<InetAddress> c) {
            if (c != null) {
                list.addAll(c);
            }
        }

        /** Starts mocking DNS queries. */
        private void startMocking() throws UnknownHostException {
            // Queries on mNetwork using getAllByName.
            doAnswer(invocation -> {
                return getAllByName(invocation.getMock(), invocation.getArgument(0));
            }).when(mNetwork).getAllByName(any());

            // Queries on mCleartextDnsNetwork using DnsResolver#query.
            doAnswer(invocation -> {
                return mockQuery(invocation, 1 /* posHostname */, 3 /* posExecutor */,
                        5 /* posCallback */, -1 /* posType */);
            }).when(mDnsResolver).query(any(), any(), anyInt(), any(), any(), any());

            // Queries on mCleartextDnsNetwork using DnsResolver#query with QueryType.
            doAnswer(invocation -> {
                return mockQuery(invocation, 1 /* posHostname */, 4 /* posExecutor */,
                        6 /* posCallback */, 2 /* posType */);
            }).when(mDnsResolver).query(any(), any(), anyInt(), anyInt(), any(), any(), any());
        }

        // Mocking queries on DnsResolver#query.
        private Answer mockQuery(InvocationOnMock invocation, int posHostname, int posExecutor,
                int posCallback, int posType) {
            String hostname = (String) invocation.getArgument(posHostname);
            Executor executor = (Executor) invocation.getArgument(posExecutor);
            DnsResolver.Callback<List<InetAddress>> callback = invocation.getArgument(posCallback);
            List<InetAddress> answer;

            answer = posType != -1
                    ? getAnswer(invocation.getMock(), hostname, invocation.getArgument(posType)) :
                    queryAllTypes(invocation.getMock(), hostname);

            if (answer != null && answer.size() > 0) {
                new Handler(Looper.getMainLooper()).post(() -> {
                    executor.execute(() -> callback.onAnswer(answer, 0));
                });
            }
            // If no answers, do nothing. sendDnsProbeWithTimeout will time out and throw UHE.
            return null;
        }
    }

    private FakeDns mFakeDns;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        when(mDependencies.getPrivateDnsBypassNetwork(any())).thenReturn(mCleartextDnsNetwork);
        when(mDependencies.getDnsResolver()).thenReturn(mDnsResolver);
        when(mDependencies.getRandom()).thenReturn(mRandom);
        when(mDependencies.getSetting(any(), eq(Settings.Global.CAPTIVE_PORTAL_MODE), anyInt()))
                .thenReturn(Settings.Global.CAPTIVE_PORTAL_MODE_PROMPT);
        when(mDependencies.getDeviceConfigPropertyInt(any(), eq(CAPTIVE_PORTAL_USE_HTTPS),
                anyInt())).thenReturn(1);
        when(mDependencies.getSetting(any(), eq(Settings.Global.CAPTIVE_PORTAL_HTTP_URL), any()))
                .thenReturn(TEST_HTTP_URL);
        when(mDependencies.getSetting(any(), eq(Settings.Global.CAPTIVE_PORTAL_HTTPS_URL), any()))
                .thenReturn(TEST_HTTPS_URL);

        doReturn(mCleartextDnsNetwork).when(mNetwork).getPrivateDnsBypassingCopy();

        when(mContext.getSystemService(Context.CONNECTIVITY_SERVICE)).thenReturn(mCm);
        when(mContext.getSystemService(Context.TELEPHONY_SERVICE)).thenReturn(mTelephony);
        when(mContext.getSystemService(Context.WIFI_SERVICE)).thenReturn(mWifi);
        when(mContext.getResources()).thenReturn(mResources);

        when(mServiceManager.getNotifier()).thenReturn(mNotifier);

        when(mResources.getString(anyInt())).thenReturn("");
        when(mResources.getStringArray(anyInt())).thenReturn(new String[0]);
        doReturn(mConfiguration).when(mResources).getConfiguration();
        when(mMccContext.getResources()).thenReturn(mMccResource);

        setFallbackUrl(TEST_FALLBACK_URL);
        setOtherFallbackUrls(TEST_OTHER_FALLBACK_URL);
        setFallbackSpecs(null); // Test with no fallback spec by default
        when(mRandom.nextInt()).thenReturn(0);

        when(mTstDependencies.getNetd()).thenReturn(mNetd);
        // DNS probe timeout should not be defined more than half of HANDLER_TIMEOUT_MS. Otherwise,
        // it will fail the test because of timeout expired for querying AAAA and A sequentially.
        when(mResources.getInteger(eq(R.integer.config_captive_portal_dns_probe_timeout)))
                .thenReturn(200);

        doAnswer((invocation) -> {
            URL url = invocation.getArgument(0);
            switch(url.toString()) {
                case TEST_HTTP_URL:
                    return mHttpConnection;
                case TEST_HTTPS_URL:
                    return mHttpsConnection;
                case TEST_FALLBACK_URL:
                    return mFallbackConnection;
                case TEST_OTHER_FALLBACK_URL:
                    return mOtherFallbackConnection;
                case TEST_CAPPORT_API_URL:
                    return mCapportApiConnection;
                default:
                    fail("URL not mocked: " + url.toString());
                    return null;
            }
        }).when(mCleartextDnsNetwork).openConnection(any());
        when(mHttpConnection.getRequestProperties()).thenReturn(new ArrayMap<>());
        when(mHttpsConnection.getRequestProperties()).thenReturn(new ArrayMap<>());

        mFakeDns = new FakeDns();
        mFakeDns.startMocking();
        // Set private dns suffix answer. sendPrivateDnsProbe() in NetworkMonitor send probe with
        // one time hostname. The hostname will be [random generated UUID] + HOST_SUFFIX differently
        // each time. That means the host answer cannot be pre-set into the answer list. Thus, set
        // the host suffix and use partial match in FakeDns to match the target host and reply the
        // intended answer.
        mFakeDns.setAnswer(PRIVATE_DNS_PROBE_HOST_SUFFIX, new String[]{"192.0.2.2"}, TYPE_A);
        mFakeDns.setAnswer(PRIVATE_DNS_PROBE_HOST_SUFFIX, new String[]{"2001:db8::1"}, TYPE_AAAA);

        when(mContext.registerReceiver(any(BroadcastReceiver.class), any())).then((invocation) -> {
            mRegisteredReceivers.add(invocation.getArgument(0));
            return new Intent();
        });

        doAnswer((invocation) -> {
            mRegisteredReceivers.remove(invocation.getArgument(0));
            return null;
        }).when(mContext).unregisterReceiver(any());

        resetCallbacks();

        setMinDataStallEvaluateInterval(500);
        setDataStallEvaluationType(DATA_STALL_EVALUATION_TYPE_DNS);
        setValidDataStallDnsTimeThreshold(500);
        setConsecutiveDnsTimeoutThreshold(5);

        mCreatedNetworkMonitors = new HashSet<>();
        mRegisteredReceivers = new HashSet<>();
        setDismissPortalInValidatedNetwork(false);
    }

    @After
    public void tearDown() {
        mFakeDns.clearAll();
        // Make a local copy of mCreatedNetworkMonitors because during the iteration below,
        // WrappedNetworkMonitor#onQuitting will delete elements from it on the handler threads.
        WrappedNetworkMonitor[] networkMonitors = mCreatedNetworkMonitors.toArray(
                new WrappedNetworkMonitor[0]);
        for (WrappedNetworkMonitor nm : networkMonitors) {
            nm.notifyNetworkDisconnected();
            nm.awaitQuit();
        }
        assertEquals("NetworkMonitor still running after disconnect",
                0, mCreatedNetworkMonitors.size());
        assertEquals("BroadcastReceiver still registered after disconnect",
                0, mRegisteredReceivers.size());
    }

    private void resetCallbacks() {
        resetCallbacks(6);
    }

    private void resetCallbacks(int interfaceVersion) {
        reset(mCallbacks);
        try {
            when(mCallbacks.getInterfaceVersion()).thenReturn(interfaceVersion);
        } catch (RemoteException e) {
            // Can't happen as mCallbacks is a mock
            fail("Error mocking getInterfaceVersion" + e);
        }
    }

    private class WrappedNetworkMonitor extends NetworkMonitor {
        private long mProbeTime = 0;
        private final ConditionVariable mQuitCv = new ConditionVariable(false);

        WrappedNetworkMonitor() {
            super(mContext, mCallbacks, mNetwork, mLogger, mValidationLogger, mServiceManager,
                    mDependencies, mDataStallStatsUtils, mTst);
        }

        @Override
        protected long getLastProbeTime() {
            return mProbeTime;
        }

        protected void setLastProbeTime(long time) {
            mProbeTime = time;
        }

        @Override
        protected TcpSocketTracker getTcpSocketTracker() {
            return mTst;
        }

        @Override
        protected void addDnsEvents(@NonNull final DataStallDetectionStats.Builder stats) {
            generateTimeoutDnsEvent(stats, DEFAULT_DNS_TIMEOUT_THRESHOLD);
        }

        @Override
        protected void onQuitting() {
            assertTrue(mCreatedNetworkMonitors.remove(this));
            mQuitCv.open();
        }

        protected void awaitQuit() {
            assertTrue("NetworkMonitor did not quit after " + HANDLER_TIMEOUT_MS + "ms",
                    mQuitCv.block(HANDLER_TIMEOUT_MS));
        }

        protected Context getContext() {
            return mContext;
        }
    }

    private WrappedNetworkMonitor makeMonitor(NetworkCapabilities nc) {
        final WrappedNetworkMonitor nm = new WrappedNetworkMonitor();
        nm.start();
        setNetworkCapabilities(nm, nc);
        HandlerUtilsKt.waitForIdle(nm.getHandler(), HANDLER_TIMEOUT_MS);
        mCreatedNetworkMonitors.add(nm);
        when(mTstDependencies.isTcpInfoParsingSupported()).thenReturn(false);

        return nm;
    }

    private WrappedNetworkMonitor makeMeteredNetworkMonitor() {
        final WrappedNetworkMonitor nm = makeMonitor(METERED_CAPABILITIES);
        return nm;
    }

    private WrappedNetworkMonitor makeNotMeteredNetworkMonitor() {
        final WrappedNetworkMonitor nm = makeMonitor(NOT_METERED_CAPABILITIES);
        return nm;
    }

    private void setNetworkCapabilities(NetworkMonitor nm, NetworkCapabilities nc) {
        nm.notifyNetworkCapabilitiesChanged(nc);
        HandlerUtilsKt.waitForIdle(nm.getHandler(), HANDLER_TIMEOUT_MS);
    }

    @Test
    public void testGetLocationMcc() throws Exception {
        final WrappedNetworkMonitor wnm = makeNotMeteredNetworkMonitor();
        doReturn(PackageManager.PERMISSION_DENIED).when(mContext).checkPermission(
                eq(android.Manifest.permission.ACCESS_FINE_LOCATION),  anyInt(), anyInt());
        assertNull(wnm.getLocationMcc());
        doReturn(PackageManager.PERMISSION_GRANTED).when(mContext).checkPermission(
                eq(android.Manifest.permission.ACCESS_FINE_LOCATION),  anyInt(), anyInt());
        doReturn(new ContextWrapper(mContext)).when(mContext).createConfigurationContext(any());
        // Prepare CellInfo and check if the vote mechanism is working or not.
        final List<CellInfo> cellList = new ArrayList<CellInfo>();
        cellList.add(makeTestCellInfoGsm("460"));
        cellList.add(makeTestCellInfoGsm("460"));
        cellList.add(makeTestCellInfoLte("466"));
        doReturn(cellList).when(mTelephony).getAllCellInfo();
        // The count of 460 is 2 and the count of 466 is 1, so the getLocationMcc() should return
        // 460.
        assertEquals("460", wnm.getLocationMcc());
        // getContextByMccIfNoSimCardOrDefault() shouldn't return mContext when using neighbor mcc
        // is enabled and the sim is not ready.
        doReturn(true).when(mResources).getBoolean(R.bool.config_no_sim_card_uses_neighbor_mcc);
        doReturn(TelephonyManager.SIM_STATE_ABSENT).when(mTelephony).getSimState();
        assertEquals(460,
                wnm.getContextByMccIfNoSimCardOrDefault().getResources().getConfiguration().mcc);
        doReturn(false).when(mResources).getBoolean(R.bool.config_no_sim_card_uses_neighbor_mcc);
        assertEquals(wnm.getContext(), wnm.getContextByMccIfNoSimCardOrDefault());
    }

    private CellInfoGsm makeTestCellInfoGsm(String mcc) throws Exception {
        final CellInfoGsm info = new CellInfoGsm();
        final CellIdentityGsm ci = makeCellIdentityGsm(0, 0, 0, 0, mcc, "01", "", "");
        info.setCellIdentity(ci);
        return info;
    }

    private CellInfoLte makeTestCellInfoLte(String mcc) throws Exception {
        final CellInfoLte info = new CellInfoLte();
        final CellIdentityLte ci = makeCellIdentityLte(0, 0, 0, 0, 0, mcc, "01", "", "");
        info.setCellIdentity(ci);
        return info;
    }

    @Test
    public void testMakeFallbackUrls() throws Exception {
        final WrappedNetworkMonitor wnm = makeNotMeteredNetworkMonitor();
        // Value exist in setting provider.
        URL[] urls = wnm.makeCaptivePortalFallbackUrls();
        assertEquals(urls[0].toString(), TEST_FALLBACK_URL);

        // Clear setting provider value. Verify it to get configuration from resource instead.
        setFallbackUrl(null);
        // Verify that getting resource with exception.
        when(mResources.getStringArray(R.array.config_captive_portal_fallback_urls))
                .thenThrow(Resources.NotFoundException.class);
        urls = wnm.makeCaptivePortalFallbackUrls();
        assertEquals(urls.length, 0);

        // Verify resource return 2 different URLs.
        doReturn(new String[] {"http://testUrl1.com", "http://testUrl2.com"}).when(mResources)
                .getStringArray(R.array.config_captive_portal_fallback_urls);
        urls = wnm.makeCaptivePortalFallbackUrls();
        assertEquals(urls.length, 2);
        assertEquals("http://testUrl1.com", urls[0].toString());
        assertEquals("http://testUrl2.com", urls[1].toString());

        // Value is expected to be replaced by location resource.
        doReturn(true).when(mResources).getBoolean(R.bool.config_no_sim_card_uses_neighbor_mcc);

        final List<CellInfo> cellList = new ArrayList<CellInfo>();
        final int testMcc = 460;
        cellList.add(makeTestCellInfoGsm(Integer.toString(testMcc)));
        doReturn(cellList).when(mTelephony).getAllCellInfo();
        final Configuration config = mResources.getConfiguration();
        config.mcc = testMcc;
        doReturn(mMccContext).when(mContext).createConfigurationContext(eq(config));
        doReturn(new String[] {"http://testUrl3.com"}).when(mMccResource)
                .getStringArray(R.array.config_captive_portal_fallback_urls);
        urls = wnm.makeCaptivePortalFallbackUrls();
        assertEquals(urls.length, 1);
        assertEquals("http://testUrl3.com", urls[0].toString());
    }

    private static CellIdentityGsm makeCellIdentityGsm(int lac, int cid, int arfcn, int bsic,
            String mccStr, String mncStr, String alphal, String alphas)
            throws ReflectiveOperationException {
        if (ShimUtils.isReleaseOrDevelopmentApiAbove(Build.VERSION_CODES.Q)) {
            return new CellIdentityGsm(lac, cid, arfcn, bsic, mccStr, mncStr, alphal, alphas,
                    Collections.emptyList() /* additionalPlmns */);
        } else {
            // API <= Q does not have the additionalPlmns parameter
            final Constructor<CellIdentityGsm> constructor = CellIdentityGsm.class.getConstructor(
                    int.class, int.class, int.class, int.class, String.class, String.class,
                    String.class, String.class);
            return constructor.newInstance(lac, cid, arfcn, bsic, mccStr, mncStr, alphal, alphas);
        }
    }

    private static CellIdentityLte makeCellIdentityLte(int ci, int pci, int tac, int earfcn,
            int bandwidth, String mccStr, String mncStr, String alphal, String alphas)
            throws ReflectiveOperationException {
        if (ShimUtils.isReleaseOrDevelopmentApiAbove(Build.VERSION_CODES.Q)) {
            return new CellIdentityLte(ci, pci, tac, earfcn, Collections.emptyList() /* bands */,
                    bandwidth, mccStr, mncStr, alphal, alphas,
                    Collections.emptyList() /* additionalPlmns */, null /* csgInfo */);
        } else {
            // API <= Q does not have the additionalPlmns and csgInfo parameters
            final Constructor<CellIdentityLte> constructor = CellIdentityLte.class.getConstructor(
                    int.class, int.class, int.class, int.class, int.class, String.class,
                    String.class, String.class, String.class);
            return constructor.newInstance(ci, pci, tac, earfcn, bandwidth, mccStr, mncStr, alphal,
                    alphas);
        }
    }

    @Test
    public void testGetIntSetting() throws Exception {
        WrappedNetworkMonitor wnm = makeNotMeteredNetworkMonitor();

        // No config resource, no device config. Expect to get default resource.
        doThrow(new Resources.NotFoundException())
                .when(mResources).getInteger(eq(R.integer.config_captive_portal_dns_probe_timeout));
        doAnswer(invocation -> {
            int defaultValue = invocation.getArgument(2);
            return defaultValue;
        }).when(mDependencies).getDeviceConfigPropertyInt(any(),
                eq(NetworkMonitor.CONFIG_CAPTIVE_PORTAL_DNS_PROBE_TIMEOUT),
                anyInt());
        when(mResources.getInteger(eq(R.integer.default_captive_portal_dns_probe_timeout)))
                .thenReturn(42);
        assertEquals(42, wnm.getIntSetting(mContext,
                R.integer.config_captive_portal_dns_probe_timeout,
                NetworkMonitor.CONFIG_CAPTIVE_PORTAL_DNS_PROBE_TIMEOUT,
                R.integer.default_captive_portal_dns_probe_timeout));

        // Set device config. Expect to get device config.
        when(mDependencies.getDeviceConfigPropertyInt(any(),
                eq(NetworkMonitor.CONFIG_CAPTIVE_PORTAL_DNS_PROBE_TIMEOUT), anyInt()))
                        .thenReturn(1234);
        assertEquals(1234, wnm.getIntSetting(mContext,
                R.integer.config_captive_portal_dns_probe_timeout,
                NetworkMonitor.CONFIG_CAPTIVE_PORTAL_DNS_PROBE_TIMEOUT,
                R.integer.default_captive_portal_dns_probe_timeout));

        // Set config resource. Expect to get config resource.
        when(mResources.getInteger(eq(R.integer.config_captive_portal_dns_probe_timeout)))
                .thenReturn(5678);
        assertEquals(5678, wnm.getIntSetting(mContext,
                R.integer.config_captive_portal_dns_probe_timeout,
                NetworkMonitor.CONFIG_CAPTIVE_PORTAL_DNS_PROBE_TIMEOUT,
                R.integer.default_captive_portal_dns_probe_timeout));
    }

    @Test
    public void testIsCaptivePortal_HttpProbeIsPortal() throws IOException {
        setSslException(mHttpsConnection);
        setPortal302(mHttpConnection);
        runPortalNetworkTest(VALIDATION_RESULT_PORTAL);
    }

    @Test
    public void testIsCaptivePortal_HttpsProbeIsNotPortal() throws IOException {
        setStatus(mHttpsConnection, 204);
        setStatus(mHttpConnection, 500);

        runNotPortalNetworkTest();
    }

    @Test
    public void testIsCaptivePortal_FallbackProbeIsPortal() throws IOException {
        setSslException(mHttpsConnection);
        setStatus(mHttpConnection, 500);
        setPortal302(mFallbackConnection);
        runPortalNetworkTest(VALIDATION_RESULT_INVALID);
    }

    @Test
    public void testIsCaptivePortal_FallbackProbeIsNotPortal() throws IOException {
        setSslException(mHttpsConnection);
        setStatus(mHttpConnection, 500);
        setStatus(mFallbackConnection, 500);

        // Fallback probe did not see portal, HTTPS failed -> inconclusive
        runFailedNetworkTest();
    }

    @Test
    public void testIsCaptivePortal_OtherFallbackProbeIsPortal() throws IOException {
        // Set all fallback probes but one to invalid URLs to verify they are being skipped
        setFallbackUrl(TEST_FALLBACK_URL);
        setOtherFallbackUrls(TEST_FALLBACK_URL + "," + TEST_OTHER_FALLBACK_URL);

        setSslException(mHttpsConnection);
        setStatus(mHttpConnection, 500);
        setStatus(mFallbackConnection, 500);
        setPortal302(mOtherFallbackConnection);

        // TEST_OTHER_FALLBACK_URL is third
        when(mRandom.nextInt()).thenReturn(2);

        // First check always uses the first fallback URL: inconclusive
        final NetworkMonitor monitor = runNetworkTest(VALIDATION_RESULT_INVALID);
        assertNull(mNetworkTestedRedirectUrlCaptor.getValue());
        verify(mFallbackConnection, times(1)).getResponseCode();
        verify(mOtherFallbackConnection, never()).getResponseCode();

        // Second check uses the URL chosen by Random
        final CaptivePortalProbeResult result = monitor.isCaptivePortal();
        assertTrue(result.isPortal());
        verify(mOtherFallbackConnection, times(1)).getResponseCode();
    }

    @Test
    public void testIsCaptivePortal_AllProbesFailed() throws IOException {
        setSslException(mHttpsConnection);
        setStatus(mHttpConnection, 500);
        setStatus(mFallbackConnection, 404);

        runFailedNetworkTest();
        verify(mFallbackConnection, times(1)).getResponseCode();
        verify(mOtherFallbackConnection, never()).getResponseCode();
    }

    @Test
    public void testIsCaptivePortal_InvalidUrlSkipped() throws IOException {
        setFallbackUrl("invalid");
        setOtherFallbackUrls("otherinvalid," + TEST_OTHER_FALLBACK_URL + ",yetanotherinvalid");

        setSslException(mHttpsConnection);
        setStatus(mHttpConnection, 500);
        setPortal302(mOtherFallbackConnection);
        runPortalNetworkTest(VALIDATION_RESULT_INVALID);
        verify(mOtherFallbackConnection, times(1)).getResponseCode();
        verify(mFallbackConnection, never()).getResponseCode();
    }

    @Test
    public void testIsCaptivePortal_CapportApiIsPortal() throws Exception {
        assumeTrue(CaptivePortalDataShimImpl.isSupported());
        setSslException(mHttpsConnection);
        final long bytesRemaining = 10_000L;
        final long secondsRemaining = 500L;

        setApiContent(mCapportApiConnection, "{'captive': true,"
                + "'user-portal-url': '" + TEST_LOGIN_URL + "',"
                + "'venue-info-url': '" + TEST_VENUE_INFO_URL + "',"
                + "'bytes-remaining': " + bytesRemaining + ","
                + "'seconds-remaining': " + secondsRemaining + "}");

        runNetworkTest(CAPPORT_LINK_PROPERTIES, METERED_CAPABILITIES, VALIDATION_RESULT_PORTAL);

        verify(mHttpConnection, never()).getResponseCode();
        verify(mCapportApiConnection).getResponseCode();
        assertNotNull(mNetworkTestedRedirectUrlCaptor.getValue());

        final ArgumentCaptor<CaptivePortalData> capportDataCaptor =
                ArgumentCaptor.forClass(CaptivePortalData.class);
        verify(mCallbacks).notifyCaptivePortalDataChanged(capportDataCaptor.capture());
        final CaptivePortalData p = capportDataCaptor.getValue();
        assertTrue(p.isCaptive());
        assertEquals(Uri.parse(TEST_LOGIN_URL), p.getUserPortalUrl());
        assertEquals(Uri.parse(TEST_VENUE_INFO_URL), p.getVenueInfoUrl());
        assertEquals(bytesRemaining, p.getByteLimit());
        final long expectedExpiry = currentTimeMillis() + secondsRemaining * 1000;
        // Actual expiry will be slightly lower as some time as passed
        assertTrue(p.getExpiryTimeMillis() <= expectedExpiry);
        assertTrue(p.getExpiryTimeMillis() > expectedExpiry - 30_000);
    }

    @Test
    public void testIsCaptivePortal_CapportApiRevalidation() throws Exception {
        assumeTrue(CaptivePortalDataShimImpl.isSupported());
        final NetworkMonitor nm = runValidatedNetworkTest();

        setApiContent(mCapportApiConnection, "{'captive': true, "
                + "'user-portal-url': '" + TEST_LOGIN_URL + "'}");
        nm.notifyLinkPropertiesChanged(CAPPORT_LINK_PROPERTIES);

        verifyNetworkTested(VALIDATION_RESULT_PORTAL);
        verify(mCallbacks).notifyCaptivePortalDataChanged(
                argThat(data -> Uri.parse(TEST_LOGIN_URL).equals(data.getUserPortalUrl())));
        assertEquals(TEST_LOGIN_URL, mNetworkTestedRedirectUrlCaptor.getValue());

        // HTTP probe was sent on first validation but not re-sent when there was a portal URL.
        verify(mHttpConnection, times(1)).getResponseCode();
        verify(mCapportApiConnection, times(1)).getResponseCode();
    }

    @Test
    public void testIsCaptivePortal_CapportApiNotPortalNotValidated() throws Exception {
        assumeTrue(CaptivePortalDataShimImpl.isSupported());
        setSslException(mHttpsConnection);
        setStatus(mHttpConnection, 500);
        setApiContent(mCapportApiConnection, "{'captive': false,"
                + "'venue-info-url': '" + TEST_VENUE_INFO_URL + "'}");
        runNetworkTest(CAPPORT_LINK_PROPERTIES, METERED_CAPABILITIES, VALIDATION_RESULT_INVALID);

        verify(mCallbacks).notifyCaptivePortalDataChanged(argThat(data ->
                Uri.parse(TEST_VENUE_INFO_URL).equals(data.getVenueInfoUrl())));
    }

    @Test
    public void testIsCaptivePortal_CapportApiNotPortalPartial() throws Exception {
        assumeTrue(CaptivePortalDataShimImpl.isSupported());
        setSslException(mHttpsConnection);
        setStatus(mHttpConnection, 204);
        setApiContent(mCapportApiConnection, "{'captive': false,"
                + "'venue-info-url': '" + TEST_VENUE_INFO_URL + "'}");
        runNetworkTest(CAPPORT_LINK_PROPERTIES, METERED_CAPABILITIES, VALIDATION_RESULT_PARTIAL);

        verify(mCallbacks).notifyCaptivePortalDataChanged(argThat(data ->
                Uri.parse(TEST_VENUE_INFO_URL).equals(data.getVenueInfoUrl())));
    }

    @Test
    public void testIsCaptivePortal_CapportApiNotPortalValidated() throws Exception {
        assumeTrue(CaptivePortalDataShimImpl.isSupported());
        setStatus(mHttpsConnection, 204);
        setStatus(mHttpConnection, 204);
        setApiContent(mCapportApiConnection, "{'captive': false,"
                + "'venue-info-url': '" + TEST_VENUE_INFO_URL + "'}");
        runNetworkTest(CAPPORT_LINK_PROPERTIES, METERED_CAPABILITIES,
                VALIDATION_RESULT_VALID_ALL_PROBES);

        verify(mCallbacks).notifyCaptivePortalDataChanged(argThat(data ->
                Uri.parse(TEST_VENUE_INFO_URL).equals(data.getVenueInfoUrl())));
    }

    @Test
    public void testIsCaptivePortal_CapportApiInvalidContent() throws Exception {
        assumeTrue(CaptivePortalDataShimImpl.isSupported());
        setStatus(mHttpsConnection, 204);
        setPortal302(mHttpConnection);
        setApiContent(mCapportApiConnection, "{SomeInvalidText");
        runNetworkTest(CAPPORT_LINK_PROPERTIES, METERED_CAPABILITIES, VALIDATION_RESULT_PORTAL);

        verify(mCallbacks, never()).notifyCaptivePortalDataChanged(any());
        verify(mHttpConnection).getResponseCode();
    }

    @Test
    public void testIsCaptivePortal_CapportApiNotSupported() throws Exception {
        assumeFalse(CaptivePortalDataShimImpl.isSupported());
        setSslException(mHttpsConnection);
        setPortal302(mHttpConnection);
        setApiContent(mCapportApiConnection, "{'captive': false,"
                + "'venue-info-url': '" + TEST_VENUE_INFO_URL + "'}");
        runNetworkTest(CAPPORT_LINK_PROPERTIES, METERED_CAPABILITIES, VALIDATION_RESULT_PORTAL);

        verify(mCallbacks, never()).notifyCaptivePortalDataChanged(any());
        verify(mHttpConnection).getResponseCode();
    }

    private void setupFallbackSpec() throws IOException {
        setFallbackSpecs("http://example.com@@/@@204@@/@@"
                + "@@,@@"
                + TEST_OTHER_FALLBACK_URL + "@@/@@30[12]@@/@@https://(www\\.)?google.com/?.*");

        setSslException(mHttpsConnection);
        setStatus(mHttpConnection, 500);

        // Use the 2nd fallback spec
        when(mRandom.nextInt()).thenReturn(1);
    }

    @Test
    public void testIsCaptivePortal_FallbackSpecIsPartial() throws IOException {
        setupFallbackSpec();
        set302(mOtherFallbackConnection, "https://www.google.com/test?q=3");

        // HTTPS failed, fallback spec went through -> partial connectivity
        runPartialConnectivityNetworkTest(VALIDATION_RESULT_FALLBACK_PARTIAL);
        verify(mOtherFallbackConnection, times(1)).getResponseCode();
        verify(mFallbackConnection, never()).getResponseCode();
    }

    @Test
    public void testIsCaptivePortal_FallbackSpecIsPortal() throws IOException {
        setupFallbackSpec();
        set302(mOtherFallbackConnection, "http://login.portal.example.com");
        runPortalNetworkTest(VALIDATION_RESULT_INVALID);
    }

    @Test
    public void testIsCaptivePortal_IgnorePortals() throws IOException {
        setCaptivePortalMode(Settings.Global.CAPTIVE_PORTAL_MODE_IGNORE);
        setSslException(mHttpsConnection);
        setPortal302(mHttpConnection);

        runNoValidationNetworkTest();
    }

    @Test
    public void testIsDataStall_EvaluationDisabled() {
        setDataStallEvaluationType(0);
        WrappedNetworkMonitor wrappedMonitor = makeMeteredNetworkMonitor();
        wrappedMonitor.setLastProbeTime(SystemClock.elapsedRealtime() - 100);
        assertFalse(wrappedMonitor.isDataStall());
    }

    @Test
    public void testIsDataStall_EvaluationDnsOnNotMeteredNetwork() throws Exception {
        WrappedNetworkMonitor wrappedMonitor = makeNotMeteredNetworkMonitor();
        wrappedMonitor.setLastProbeTime(SystemClock.elapsedRealtime() - 100);
        makeDnsTimeoutEvent(wrappedMonitor, DEFAULT_DNS_TIMEOUT_THRESHOLD);
        assertTrue(wrappedMonitor.isDataStall());
        verify(mCallbacks).notifyDataStallSuspected(anyLong(), eq(DETECTION_METHOD_DNS_EVENTS),
                bundleForDnsDataStall(DEFAULT_DNS_TIMEOUT_THRESHOLD));
    }

    @Test
    public void testIsDataStall_EvaluationDnsOnMeteredNetwork() throws Exception {
        WrappedNetworkMonitor wrappedMonitor = makeMeteredNetworkMonitor();
        wrappedMonitor.setLastProbeTime(SystemClock.elapsedRealtime() - 100);
        assertFalse(wrappedMonitor.isDataStall());

        wrappedMonitor.setLastProbeTime(SystemClock.elapsedRealtime() - 1000);
        makeDnsTimeoutEvent(wrappedMonitor, DEFAULT_DNS_TIMEOUT_THRESHOLD);
        assertTrue(wrappedMonitor.isDataStall());
        verify(mCallbacks).notifyDataStallSuspected(anyLong(), eq(DETECTION_METHOD_DNS_EVENTS),
                bundleForDnsDataStall(DEFAULT_DNS_TIMEOUT_THRESHOLD));
    }

    @Test
    public void testIsDataStall_EvaluationDnsWithDnsTimeoutCount() throws Exception {
        WrappedNetworkMonitor wrappedMonitor = makeMeteredNetworkMonitor();
        wrappedMonitor.setLastProbeTime(SystemClock.elapsedRealtime() - 1000);
        makeDnsTimeoutEvent(wrappedMonitor, 3);
        assertFalse(wrappedMonitor.isDataStall());
        // Reset consecutive timeout counts.
        makeDnsSuccessEvent(wrappedMonitor, 1);
        makeDnsTimeoutEvent(wrappedMonitor, 2);
        assertFalse(wrappedMonitor.isDataStall());

        makeDnsTimeoutEvent(wrappedMonitor, 3);
        assertTrue(wrappedMonitor.isDataStall());

        // The expected timeout count is the previous 2 DNS timeouts + the most recent 3 timeouts
        verify(mCallbacks).notifyDataStallSuspected(anyLong(), eq(DETECTION_METHOD_DNS_EVENTS),
                bundleForDnsDataStall(5));

        // Set the value to larger than the default dns log size.
        setConsecutiveDnsTimeoutThreshold(51);
        wrappedMonitor = makeMeteredNetworkMonitor();
        wrappedMonitor.setLastProbeTime(SystemClock.elapsedRealtime() - 1000);
        makeDnsTimeoutEvent(wrappedMonitor, 50);
        assertFalse(wrappedMonitor.isDataStall());

        makeDnsTimeoutEvent(wrappedMonitor, 1);
        assertTrue(wrappedMonitor.isDataStall());

        // The expected timeout count is the previous 50 DNS timeouts + the most recent timeout
        verify(mCallbacks).notifyDataStallSuspected(anyLong(), eq(DETECTION_METHOD_DNS_EVENTS),
                bundleForDnsDataStall(51));
    }

    @Test
    public void testIsDataStall_SkipEvaluateOnValidationNotRequiredNetwork() {
        // Make DNS and TCP stall condition satisfied.
        setDataStallEvaluationType(DATA_STALL_EVALUATION_TYPE_DNS | DATA_STALL_EVALUATION_TYPE_TCP);
        when(mTstDependencies.isTcpInfoParsingSupported()).thenReturn(true);
        when(mTst.getLatestReceivedCount()).thenReturn(0);
        when(mTst.isDataStallSuspected()).thenReturn(true);
        final WrappedNetworkMonitor nm = makeMonitor(NO_INTERNET_CAPABILITIES);
        nm.setLastProbeTime(SystemClock.elapsedRealtime() - 1000);
        makeDnsTimeoutEvent(nm, DEFAULT_DNS_TIMEOUT_THRESHOLD);
        assertFalse(nm.isDataStall());
    }

    @Test
    public void testIsDataStall_EvaluationDnsWithDnsTimeThreshold() throws Exception {
        // Test dns events happened in valid dns time threshold.
        WrappedNetworkMonitor wrappedMonitor = makeMeteredNetworkMonitor();
        wrappedMonitor.setLastProbeTime(SystemClock.elapsedRealtime() - 100);
        makeDnsTimeoutEvent(wrappedMonitor, DEFAULT_DNS_TIMEOUT_THRESHOLD);
        assertFalse(wrappedMonitor.isDataStall());
        wrappedMonitor.setLastProbeTime(SystemClock.elapsedRealtime() - 1000);
        assertTrue(wrappedMonitor.isDataStall());
        verify(mCallbacks).notifyDataStallSuspected(anyLong(), eq(DETECTION_METHOD_DNS_EVENTS),
                bundleForDnsDataStall(DEFAULT_DNS_TIMEOUT_THRESHOLD));

        // Test dns events happened before valid dns time threshold.
        setValidDataStallDnsTimeThreshold(0);
        wrappedMonitor = makeMeteredNetworkMonitor();
        wrappedMonitor.setLastProbeTime(SystemClock.elapsedRealtime() - 100);
        makeDnsTimeoutEvent(wrappedMonitor, DEFAULT_DNS_TIMEOUT_THRESHOLD);
        assertFalse(wrappedMonitor.isDataStall());
        wrappedMonitor.setLastProbeTime(SystemClock.elapsedRealtime() - 1000);
        assertFalse(wrappedMonitor.isDataStall());
    }

    @Test
    public void testIsDataStall_EvaluationTcp() throws Exception {
        // Evaluate TCP only. Expect ignoring DNS signal.
        setDataStallEvaluationType(DATA_STALL_EVALUATION_TYPE_TCP);
        WrappedNetworkMonitor wrappedMonitor = makeMonitor(METERED_CAPABILITIES);
        assertFalse(wrappedMonitor.isDataStall());
        // Packet received.
        when(mTstDependencies.isTcpInfoParsingSupported()).thenReturn(true);
        when(mTst.getLatestReceivedCount()).thenReturn(5);
        // Trigger a tcp event immediately.
        setTcpPollingInterval(0);
        wrappedMonitor.sendTcpPollingEvent();
        HandlerUtilsKt.waitForIdle(wrappedMonitor.getHandler(), HANDLER_TIMEOUT_MS);
        assertFalse(wrappedMonitor.isDataStall());

        when(mTst.getLatestReceivedCount()).thenReturn(0);
        when(mTst.isDataStallSuspected()).thenReturn(true);
        // Trigger a tcp event immediately.
        setTcpPollingInterval(0);
        wrappedMonitor.sendTcpPollingEvent();
        HandlerUtilsKt.waitForIdle(wrappedMonitor.getHandler(), HANDLER_TIMEOUT_MS);
        assertTrue(wrappedMonitor.isDataStall());
        verify(mCallbacks).notifyDataStallSuspected(anyLong(), eq(DETECTION_METHOD_TCP_METRICS),
                bundleForTcpDataStall());
    }

    @Test
    public void testIsDataStall_DisableTcp() {
        // Disable tcp detection with only DNS detect. keep the tcp signal but set to no DNS signal.
        setDataStallEvaluationType(DATA_STALL_EVALUATION_TYPE_DNS);
        WrappedNetworkMonitor wrappedMonitor = makeMonitor(METERED_CAPABILITIES);
        makeDnsSuccessEvent(wrappedMonitor, 1);
        wrappedMonitor.sendTcpPollingEvent();
        HandlerUtilsKt.waitForIdle(wrappedMonitor.getHandler(), HANDLER_TIMEOUT_MS);
        assertFalse(wrappedMonitor.isDataStall());
        verify(mTst, never()).isDataStallSuspected();
        verify(mTst, never()).pollSocketsInfo();
    }

    @Test
    public void testBrokenNetworkNotValidated() throws Exception {
        setSslException(mHttpsConnection);
        setStatus(mHttpConnection, 500);
        setStatus(mFallbackConnection, 404);

        runFailedNetworkTest();
    }

    @Test
    public void testNoInternetCapabilityValidated() throws Exception {
        runNetworkTest(TEST_LINK_PROPERTIES, NO_INTERNET_CAPABILITIES,
                NETWORK_VALIDATION_RESULT_VALID);
        verify(mCleartextDnsNetwork, never()).openConnection(any());
    }

    @Test
    public void testLaunchCaptivePortalApp() throws Exception {
        setSslException(mHttpsConnection);
        setPortal302(mHttpConnection);
        when(mHttpConnection.getHeaderField(eq("location"))).thenReturn(TEST_LOGIN_URL);
        final NetworkMonitor nm = makeMonitor(METERED_CAPABILITIES);
        notifyNetworkConnected(nm, METERED_CAPABILITIES);

        verify(mCallbacks, timeout(HANDLER_TIMEOUT_MS).times(1))
                .showProvisioningNotification(any(), any());

        assertEquals(1, mRegisteredReceivers.size());

        // Check that startCaptivePortalApp sends the expected intent.
        nm.launchCaptivePortalApp();

        final ArgumentCaptor<Bundle> bundleCaptor = ArgumentCaptor.forClass(Bundle.class);
        final ArgumentCaptor<Network> networkCaptor = ArgumentCaptor.forClass(Network.class);
        verify(mCm, timeout(HANDLER_TIMEOUT_MS).times(1))
                .startCaptivePortalApp(networkCaptor.capture(), bundleCaptor.capture());
        verify(mNotifier).notifyCaptivePortalValidationPending(networkCaptor.getValue());
        final Bundle bundle = bundleCaptor.getValue();
        final Network bundleNetwork = bundle.getParcelable(ConnectivityManager.EXTRA_NETWORK);
        assertEquals(TEST_NETID, bundleNetwork.netId);
        // network is passed both in bundle and as parameter, as the bundle is opaque to the
        // framework and only intended for the captive portal app, but the framework needs
        // the network to identify the right NetworkMonitor.
        assertEquals(TEST_NETID, networkCaptor.getValue().netId);
        // Portal URL should be detection URL.
        final String redirectUrl = bundle.getString(ConnectivityManager.EXTRA_CAPTIVE_PORTAL_URL);
        assertEquals(TEST_HTTP_URL, redirectUrl);

        // Have the app report that the captive portal is dismissed, and check that we revalidate.
        setStatus(mHttpsConnection, 204);
        setStatus(mHttpConnection, 204);

        final int expectedResult = NETWORK_VALIDATION_PROBE_DNS | NETWORK_VALIDATION_PROBE_HTTP
                | NETWORK_VALIDATION_RESULT_VALID;
        resetCallbacks();
        nm.notifyCaptivePortalAppFinished(APP_RETURN_DISMISSED);
        verify(mCallbacks, timeout(HANDLER_TIMEOUT_MS).atLeastOnce())
                .notifyNetworkTestedWithExtras(eq(expectedResult), any(), anyLong(),
                        bundleForNotifyNetworkTested(expectedResult));
        assertEquals(0, mRegisteredReceivers.size());
    }

    @Test
    public void testPrivateDnsSuccess() throws Exception {
        setStatus(mHttpsConnection, 204);
        setStatus(mHttpConnection, 204);

        final int expectedResult = VALIDATION_RESULT_VALID | NETWORK_VALIDATION_PROBE_PRIVDNS;

        // Verify dns query only get v6 address.
        mFakeDns.setAnswer("dns6.google", new String[]{"2001:db8::53"}, TYPE_AAAA);
        WrappedNetworkMonitor wnm = makeNotMeteredNetworkMonitor();
        wnm.notifyPrivateDnsSettingsChanged(new PrivateDnsConfig("dns6.google",
                new InetAddress[0]));
        notifyNetworkConnected(wnm, NOT_METERED_CAPABILITIES);
        verify(mCallbacks, timeout(HANDLER_TIMEOUT_MS).times(1))
                .notifyNetworkTestedWithExtras(eq(expectedResult), eq(null), anyLong(),
                        bundleForNotifyNetworkTested(expectedResult));
        verify(mCallbacks, timeout(HANDLER_TIMEOUT_MS).times(1)).notifyProbeStatusChanged(
                eq(VALIDATION_RESULT_PRIVDNS_VALID), eq(VALIDATION_RESULT_PRIVDNS_VALID));

        // Verify dns query only get v4 address.
        resetCallbacks();
        mFakeDns.setAnswer("dns4.google", new String[]{"192.0.2.1"}, TYPE_A);
        wnm.notifyPrivateDnsSettingsChanged(new PrivateDnsConfig("dns4.google",
                new InetAddress[0]));
        verify(mCallbacks, timeout(HANDLER_TIMEOUT_MS).times(1))
                .notifyNetworkTestedWithExtras(eq(expectedResult), eq(null), anyLong(),
                        bundleForNotifyNetworkTested(expectedResult));
        // NetworkMonitor will check if the probes has changed or not, if the probes has not
        // changed, the callback won't be fired.
        verify(mCallbacks, never()).notifyProbeStatusChanged(
                eq(VALIDATION_RESULT_PRIVDNS_VALID), eq(VALIDATION_RESULT_PRIVDNS_VALID));

        // Verify dns query get both v4 and v6 address.
        resetCallbacks();
        mFakeDns.setAnswer("dns.google", new String[]{"2001:db8::54"}, TYPE_AAAA);
        mFakeDns.setAnswer("dns.google", new String[]{"192.0.2.3"}, TYPE_A);
        wnm.notifyPrivateDnsSettingsChanged(new PrivateDnsConfig("dns.google", new InetAddress[0]));
        verify(mCallbacks, timeout(HANDLER_TIMEOUT_MS).times(1))
                .notifyNetworkTestedWithExtras(eq(expectedResult), eq(null), anyLong(),
                        bundleForNotifyNetworkTested(expectedResult));
        verify(mCallbacks, never()).notifyProbeStatusChanged(
                eq(VALIDATION_RESULT_PRIVDNS_VALID), eq(VALIDATION_RESULT_PRIVDNS_VALID));
    }

    @Test
    public void testProbeStatusChanged() throws Exception {
        // Set no record in FakeDns and expect validation to fail.
        setStatus(mHttpsConnection, 204);
        setStatus(mHttpConnection, 204);

        WrappedNetworkMonitor wnm = makeNotMeteredNetworkMonitor();
        wnm.notifyPrivateDnsSettingsChanged(new PrivateDnsConfig("dns.google", new InetAddress[0]));
        wnm.notifyNetworkConnected(TEST_LINK_PROPERTIES, NOT_METERED_CAPABILITIES);
        verify(mCallbacks, timeout(HANDLER_TIMEOUT_MS).times(1)).notifyNetworkTestedWithExtras(
                eq(NETWORK_VALIDATION_PROBE_DNS | NETWORK_VALIDATION_PROBE_HTTPS), eq(null),
                anyLong(), bundleForNotifyNetworkTested(NETWORK_VALIDATION_PROBE_DNS
                | NETWORK_VALIDATION_PROBE_HTTPS));
        verify(mCallbacks, timeout(HANDLER_TIMEOUT_MS).times(1)).notifyProbeStatusChanged(
                eq(VALIDATION_RESULT_PRIVDNS_VALID), eq(NETWORK_VALIDATION_PROBE_DNS
                | NETWORK_VALIDATION_PROBE_HTTPS));
        // Fix DNS and retry, expect validation to succeed.
        resetCallbacks();
        mFakeDns.setAnswer("dns.google", new String[]{"2001:db8::1"}, TYPE_AAAA);

        wnm.forceReevaluation(Process.myUid());
        // ProbeCompleted should be reset to 0
        HandlerUtilsKt.waitForIdle(wnm.getHandler(), HANDLER_TIMEOUT_MS);
        assertEquals(wnm.getEvaluationState().getProbeCompletedResult(), 0);
        verify(mCallbacks, timeout(HANDLER_TIMEOUT_MS).times(1))
                .notifyNetworkTestedWithExtras(eq(VALIDATION_RESULT_VALID
                        | NETWORK_VALIDATION_PROBE_PRIVDNS), eq(null), anyLong(),
                        bundleForNotifyNetworkTested(VALIDATION_RESULT_VALID
                        | NETWORK_VALIDATION_PROBE_PRIVDNS));
        verify(mCallbacks, timeout(HANDLER_TIMEOUT_MS).times(1)).notifyProbeStatusChanged(
                eq(VALIDATION_RESULT_PRIVDNS_VALID), eq(VALIDATION_RESULT_PRIVDNS_VALID));
    }

    @Test
    public void testPrivateDnsResolutionRetryUpdate() throws Exception {
        // Set no record in FakeDns and expect validation to fail.
        setStatus(mHttpsConnection, 204);
        setStatus(mHttpConnection, 204);

        WrappedNetworkMonitor wnm = makeNotMeteredNetworkMonitor();
        wnm.notifyPrivateDnsSettingsChanged(new PrivateDnsConfig("dns.google", new InetAddress[0]));
        wnm.notifyNetworkConnected(TEST_LINK_PROPERTIES, NOT_METERED_CAPABILITIES);
        verify(mCallbacks, timeout(HANDLER_TIMEOUT_MS)).notifyNetworkTestedWithExtras(
                eq(NETWORK_VALIDATION_PROBE_DNS | NETWORK_VALIDATION_PROBE_HTTPS), eq(null),
                anyLong(), bundleForNotifyNetworkTested(NETWORK_VALIDATION_PROBE_DNS
                | NETWORK_VALIDATION_PROBE_HTTPS));
        verify(mCallbacks, timeout(HANDLER_TIMEOUT_MS).times(1)).notifyProbeStatusChanged(
                eq(VALIDATION_RESULT_PRIVDNS_VALID), eq(NETWORK_VALIDATION_PROBE_DNS
                | NETWORK_VALIDATION_PROBE_HTTPS));

        // Fix DNS and retry, expect validation to succeed.
        resetCallbacks();
        mFakeDns.setAnswer("dns.google", new String[]{"2001:db8::1"}, TYPE_AAAA);

        wnm.forceReevaluation(Process.myUid());
        verify(mCallbacks, timeout(HANDLER_TIMEOUT_MS).atLeastOnce())
                .notifyNetworkTestedWithExtras(eq(VALIDATION_RESULT_VALID
                        | NETWORK_VALIDATION_PROBE_PRIVDNS), eq(null), anyLong(),
                        bundleForNotifyNetworkTested(VALIDATION_RESULT_VALID
                        | NETWORK_VALIDATION_PROBE_PRIVDNS));
        verify(mCallbacks, timeout(HANDLER_TIMEOUT_MS).times(1)).notifyProbeStatusChanged(
                eq(VALIDATION_RESULT_PRIVDNS_VALID), eq(VALIDATION_RESULT_PRIVDNS_VALID));

        // Change configuration to an invalid DNS name, expect validation to fail.
        resetCallbacks();
        mFakeDns.setAnswer("dns.bad", new String[0], TYPE_A);
        mFakeDns.setAnswer("dns.bad", new String[0], TYPE_AAAA);
        wnm.notifyPrivateDnsSettingsChanged(new PrivateDnsConfig("dns.bad", new InetAddress[0]));
        // Strict mode hostname resolve fail. Expect only notification for evaluation fail. No probe
        // notification.
        verify(mCallbacks, timeout(HANDLER_TIMEOUT_MS))
                .notifyNetworkTestedWithExtras(eq(NETWORK_VALIDATION_PROBE_DNS
                        | NETWORK_VALIDATION_PROBE_HTTPS), eq(null), anyLong(),
                        bundleForNotifyNetworkTested(NETWORK_VALIDATION_PROBE_DNS
                        | NETWORK_VALIDATION_PROBE_HTTPS));
        verify(mCallbacks, timeout(HANDLER_TIMEOUT_MS).times(1)).notifyProbeStatusChanged(
                eq(VALIDATION_RESULT_PRIVDNS_VALID), eq(NETWORK_VALIDATION_PROBE_DNS
                | NETWORK_VALIDATION_PROBE_HTTPS));

        // Change configuration back to working again, but make private DNS not work.
        // Expect validation to fail.
        resetCallbacks();
        mFakeDns.setNonBypassPrivateDnsWorking(false);
        wnm.notifyPrivateDnsSettingsChanged(new PrivateDnsConfig("dns.google",
                new InetAddress[0]));
        verify(mCallbacks, timeout(HANDLER_TIMEOUT_MS)).notifyNetworkTestedWithExtras(
                eq(NETWORK_VALIDATION_PROBE_DNS | NETWORK_VALIDATION_PROBE_HTTPS), eq(null),
                anyLong(), bundleForNotifyNetworkTested(NETWORK_VALIDATION_PROBE_DNS
                | NETWORK_VALIDATION_PROBE_HTTPS));
        // NetworkMonitor will check if the probes has changed or not, if the probes has not
        // changed, the callback won't be fired.
        verify(mCallbacks, never()).notifyProbeStatusChanged(
                eq(VALIDATION_RESULT_PRIVDNS_VALID), eq(NETWORK_VALIDATION_PROBE_DNS
                | NETWORK_VALIDATION_PROBE_HTTPS));

        // Make private DNS work again. Expect validation to succeed.
        resetCallbacks();
        mFakeDns.setNonBypassPrivateDnsWorking(true);
        wnm.forceReevaluation(Process.myUid());
        verify(mCallbacks, timeout(HANDLER_TIMEOUT_MS).atLeastOnce())
                .notifyNetworkTestedWithExtras(
                        eq(VALIDATION_RESULT_VALID | NETWORK_VALIDATION_PROBE_PRIVDNS), eq(null),
                        anyLong(), bundleForNotifyNetworkTested(VALIDATION_RESULT_VALID
                        | NETWORK_VALIDATION_PROBE_PRIVDNS));
        verify(mCallbacks, timeout(HANDLER_TIMEOUT_MS).times(1)).notifyProbeStatusChanged(
                eq(VALIDATION_RESULT_PRIVDNS_VALID), eq(VALIDATION_RESULT_PRIVDNS_VALID));
    }

    @Test
    public void testDataStall_StallSuspectedAndSendMetrics() throws IOException {
        WrappedNetworkMonitor wrappedMonitor = makeNotMeteredNetworkMonitor();
        wrappedMonitor.setLastProbeTime(SystemClock.elapsedRealtime() - 1000);
        makeDnsTimeoutEvent(wrappedMonitor, 5);
        assertTrue(wrappedMonitor.isDataStall());
        verify(mDataStallStatsUtils, times(1)).write(makeEmptyDataStallDetectionStats(), any());
    }

    @Test
    public void testDataStall_NoStallSuspectedAndSendMetrics() throws IOException {
        WrappedNetworkMonitor wrappedMonitor = makeNotMeteredNetworkMonitor();
        wrappedMonitor.setLastProbeTime(SystemClock.elapsedRealtime() - 1000);
        makeDnsTimeoutEvent(wrappedMonitor, 3);
        assertFalse(wrappedMonitor.isDataStall());
        verify(mDataStallStatsUtils, never()).write(makeEmptyDataStallDetectionStats(), any());
    }

    @Test
    public void testCollectDataStallMetrics() {
        WrappedNetworkMonitor wrappedMonitor = makeNotMeteredNetworkMonitor();

        when(mTelephony.getDataNetworkType()).thenReturn(TelephonyManager.NETWORK_TYPE_LTE);
        when(mTelephony.getNetworkOperator()).thenReturn(TEST_MCCMNC);
        when(mTelephony.getSimOperator()).thenReturn(TEST_MCCMNC);

        DataStallDetectionStats.Builder stats =
                new DataStallDetectionStats.Builder()
                .setEvaluationType(DATA_STALL_EVALUATION_TYPE_DNS)
                .setNetworkType(NetworkCapabilities.TRANSPORT_CELLULAR)
                .setCellData(TelephonyManager.NETWORK_TYPE_LTE /* radioType */,
                        true /* roaming */,
                        TEST_MCCMNC /* networkMccmnc */,
                        TEST_MCCMNC /* simMccmnc */,
                        CellSignalStrength.SIGNAL_STRENGTH_NONE_OR_UNKNOWN /* signalStrength */);
        generateTimeoutDnsEvent(stats, DEFAULT_DNS_TIMEOUT_THRESHOLD);

        assertEquals(wrappedMonitor.buildDataStallDetectionStats(
                 NetworkCapabilities.TRANSPORT_CELLULAR), stats.build());

        when(mWifi.getConnectionInfo()).thenReturn(mWifiInfo);

        stats = new DataStallDetectionStats.Builder()
                .setEvaluationType(DATA_STALL_EVALUATION_TYPE_DNS)
                .setNetworkType(NetworkCapabilities.TRANSPORT_WIFI)
                .setWiFiData(mWifiInfo);
        generateTimeoutDnsEvent(stats, DEFAULT_DNS_TIMEOUT_THRESHOLD);

        assertEquals(
                wrappedMonitor.buildDataStallDetectionStats(NetworkCapabilities.TRANSPORT_WIFI),
                stats.build());
    }

    @Test
    public void testIgnoreHttpsProbe() throws Exception {
        setSslException(mHttpsConnection);
        setStatus(mHttpConnection, 204);
        // Expect to send HTTP, HTTPS, FALLBACK probe and evaluation result notifications to CS.
        final NetworkMonitor nm = runNetworkTest(VALIDATION_RESULT_PARTIAL);

        final int expectedResult = VALIDATION_RESULT_PARTIAL | NETWORK_VALIDATION_RESULT_VALID;
        resetCallbacks();
        nm.setAcceptPartialConnectivity();
        // Expect to update evaluation result notifications to CS.
        verify(mCallbacks, timeout(HANDLER_TIMEOUT_MS).times(1)).notifyNetworkTestedWithExtras(
                eq(expectedResult), eq(null), anyLong(), bundleForNotifyNetworkTested(
                expectedResult));
    }

    @Test
    public void testIsPartialConnectivity() throws IOException {
        setStatus(mHttpsConnection, 500);
        setStatus(mHttpConnection, 204);
        setStatus(mFallbackConnection, 500);
        runPartialConnectivityNetworkTest(VALIDATION_RESULT_PARTIAL);

        resetCallbacks();
        setStatus(mHttpsConnection, 500);
        setStatus(mHttpConnection, 500);
        setStatus(mFallbackConnection, 204);
        runPartialConnectivityNetworkTest(VALIDATION_RESULT_FALLBACK_PARTIAL);
    }

    private void assertIpAddressArrayEquals(String[] expected, InetAddress[] actual) {
        String[] actualStrings = new String[actual.length];
        for (int i = 0; i < actual.length; i++) {
            actualStrings[i] = actual[i].getHostAddress();
        }
        assertArrayEquals("Array of IP addresses differs", expected, actualStrings);
    }

    @Test
    public void testSendDnsProbeWithTimeout() throws Exception {
        WrappedNetworkMonitor wnm = makeNotMeteredNetworkMonitor();
        final int shortTimeoutMs = 200;
        // v6 only.
        String[] expected = new String[]{"2001:db8::"};
        mFakeDns.setAnswer("www.google.com", expected, TYPE_AAAA);
        InetAddress[] actual = wnm.sendDnsProbeWithTimeout("www.google.com", shortTimeoutMs);
        assertIpAddressArrayEquals(expected, actual);
        // v4 only.
        expected = new String[]{"192.0.2.1"};
        mFakeDns.setAnswer("www.android.com", expected, TYPE_A);
        actual = wnm.sendDnsProbeWithTimeout("www.android.com", shortTimeoutMs);
        assertIpAddressArrayEquals(expected, actual);
        // Both v4 & v6.
        expected = new String[]{"192.0.2.1", "2001:db8::"};
        mFakeDns.setAnswer("www.googleapis.com", new String[]{"192.0.2.1"}, TYPE_A);
        mFakeDns.setAnswer("www.googleapis.com", new String[]{"2001:db8::"}, TYPE_AAAA);
        actual = wnm.sendDnsProbeWithTimeout("www.googleapis.com", shortTimeoutMs);
        assertIpAddressArrayEquals(expected, actual);
        // Clear DNS response.
        mFakeDns.setAnswer("www.android.com", new String[0], TYPE_A);
        try {
            actual = wnm.sendDnsProbeWithTimeout("www.android.com", shortTimeoutMs);
            fail("No DNS results, expected UnknownHostException");
        } catch (UnknownHostException e) {
        }

        mFakeDns.setAnswer("www.android.com", null, TYPE_A);
        mFakeDns.setAnswer("www.android.com", null, TYPE_AAAA);
        try {
            wnm.sendDnsProbeWithTimeout("www.android.com", shortTimeoutMs);
            fail("DNS query timed out, expected UnknownHostException");
        } catch (UnknownHostException e) {
        }
    }

    @Test
    public void testNotifyNetwork_WithforceReevaluation() throws Exception {
        final int expectedResult = NETWORK_VALIDATION_PROBE_DNS | NETWORK_VALIDATION_PROBE_FALLBACK
                | NETWORK_VALIDATION_RESULT_PARTIAL;

        final NetworkMonitor nm = runValidatedNetworkTest();
        // Verify forceReevalution will not reset the validation result but only probe result until
        // getting the validation result.
        resetCallbacks();
        setSslException(mHttpsConnection);
        setStatus(mHttpConnection, 500);
        setStatus(mFallbackConnection, 204);
        nm.forceReevaluation(Process.myUid());
        final ArgumentCaptor<Integer> intCaptor = ArgumentCaptor.forClass(Integer.class);
        // Expect to send HTTP, HTTPs, FALLBACK and evaluation results.
        verify(mCallbacks, timeout(HANDLER_TIMEOUT_MS))
                .notifyNetworkTestedWithExtras(eq(expectedResult), any(), anyLong(),
                        bundleForNotifyNetworkTested(expectedResult));
    }

    @Test
    public void testNotifyNetwork_NotifyNetworkTestedOldInterfaceVersion() throws Exception {
        // Use old interface version so notifyNetworkTested is used over
        // notifyNetworkTestedWithExtras
        resetCallbacks(4);

        // Trigger Network validation
        setStatus(mHttpsConnection, 204);
        setStatus(mHttpConnection, 204);
        final NetworkMonitor nm = makeMonitor(METERED_CAPABILITIES);
        nm.notifyNetworkConnected(TEST_LINK_PROPERTIES, METERED_CAPABILITIES);

        verify(mCallbacks, timeout(HANDLER_TIMEOUT_MS))
                .notifyNetworkTested(eq(VALIDATION_RESULT_VALID), any());
    }

    @Test
    public void testDismissPortalInValidatedNetworkEnabledOsSupported() throws Exception {
        assumeTrue(ShimUtils.isReleaseOrDevelopmentApiAbove(Build.VERSION_CODES.Q));
        testDismissPortalInValidatedNetworkEnabled(TEST_LOGIN_URL);
    }

    @Test
    public void testDismissPortalInValidatedNetworkEnabledOsNotSupported() throws Exception {
        assumeFalse(ShimUtils.isReleaseOrDevelopmentApiAbove(Build.VERSION_CODES.Q));
        testDismissPortalInValidatedNetworkEnabled(TEST_HTTP_URL);
    }

    private void testDismissPortalInValidatedNetworkEnabled(String portalUrl) throws Exception {
        setDismissPortalInValidatedNetwork(true);
        setSslException(mHttpsConnection);
        setPortal302(mHttpConnection);
        when(mHttpConnection.getHeaderField(eq("location"))).thenReturn(TEST_LOGIN_URL);
        final NetworkMonitor nm = makeMonitor(METERED_CAPABILITIES);
        notifyNetworkConnected(nm, METERED_CAPABILITIES);

        verify(mCallbacks, timeout(HANDLER_TIMEOUT_MS).times(1))
            .showProvisioningNotification(any(), any());

        assertEquals(1, mRegisteredReceivers.size());
        // Check that startCaptivePortalApp sends the expected intent.
        nm.launchCaptivePortalApp();

        final ArgumentCaptor<Bundle> bundleCaptor = ArgumentCaptor.forClass(Bundle.class);
        final ArgumentCaptor<Network> networkCaptor = ArgumentCaptor.forClass(Network.class);
        verify(mCm, timeout(HANDLER_TIMEOUT_MS).times(1))
            .startCaptivePortalApp(networkCaptor.capture(), bundleCaptor.capture());
        verify(mNotifier).notifyCaptivePortalValidationPending(networkCaptor.getValue());
        final Bundle bundle = bundleCaptor.getValue();
        final Network bundleNetwork = bundle.getParcelable(ConnectivityManager.EXTRA_NETWORK);
        assertEquals(TEST_NETID, bundleNetwork.netId);
        // Network is passed both in bundle and as parameter, as the bundle is opaque to the
        // framework and only intended for the captive portal app, but the framework needs
        // the network to identify the right NetworkMonitor.
        assertEquals(TEST_NETID, networkCaptor.getValue().netId);
        // Portal URL should be redirect URL.
        final String redirectUrl = bundle.getString(ConnectivityManager.EXTRA_CAPTIVE_PORTAL_URL);
        assertEquals(portalUrl, redirectUrl);
    }

    @Test
    public void testEvaluationState_clearProbeResults() throws Exception {
        final NetworkMonitor nm = runValidatedNetworkTest();
        nm.getEvaluationState().clearProbeResults();
        // Verify probe results are all reset and only evaluation result left.
        assertEquals(NETWORK_VALIDATION_RESULT_VALID,
                nm.getEvaluationState().getNetworkTestResult());
    }

    @Test
    public void testEvaluationState_reportProbeResult() throws Exception {
        final NetworkMonitor nm = runValidatedNetworkTest();

        resetCallbacks();

        nm.reportHttpProbeResult(NETWORK_VALIDATION_PROBE_HTTP, CaptivePortalProbeResult.SUCCESS);
        // Verify result should be appended and notifyNetworkTestedWithExtras callback is triggered
        // once.
        assertEquals(nm.getEvaluationState().getNetworkTestResult(),
                VALIDATION_RESULT_VALID | NETWORK_VALIDATION_PROBE_HTTP);

        nm.reportHttpProbeResult(NETWORK_VALIDATION_PROBE_HTTP, CaptivePortalProbeResult.FAILED);
        // Verify DNS probe result should not be cleared.
        assertTrue((nm.getEvaluationState().getNetworkTestResult() & NETWORK_VALIDATION_PROBE_DNS)
                == NETWORK_VALIDATION_PROBE_DNS);
    }

    @Test
    public void testEvaluationState_reportEvaluationResult() throws Exception {
        final NetworkMonitor nm = runValidatedNetworkTest();

        nm.getEvaluationState().reportEvaluationResult(NETWORK_VALIDATION_RESULT_PARTIAL,
                null /* redirectUrl */);
        verify(mCallbacks, timeout(HANDLER_TIMEOUT_MS).times(1)).notifyNetworkTestedWithExtras(
                eq(NETWORK_VALIDATION_PROBE_DNS | NETWORK_VALIDATION_PROBE_HTTPS
                | NETWORK_VALIDATION_RESULT_PARTIAL), eq(null), anyLong(),
                bundleForNotifyNetworkTested(NETWORK_VALIDATION_PROBE_DNS
                | NETWORK_VALIDATION_PROBE_HTTPS | NETWORK_VALIDATION_RESULT_PARTIAL));

        nm.getEvaluationState().reportEvaluationResult(
                NETWORK_VALIDATION_RESULT_VALID | NETWORK_VALIDATION_RESULT_PARTIAL,
                null /* redirectUrl */);
        verify(mCallbacks, timeout(HANDLER_TIMEOUT_MS).times(1)).notifyNetworkTestedWithExtras(
                eq(VALIDATION_RESULT_VALID | NETWORK_VALIDATION_RESULT_PARTIAL), eq(null),
                anyLong(), bundleForNotifyNetworkTested(VALIDATION_RESULT_VALID
                | NETWORK_VALIDATION_RESULT_PARTIAL));

        nm.getEvaluationState().reportEvaluationResult(VALIDATION_RESULT_INVALID,
                TEST_REDIRECT_URL);
        verify(mCallbacks, timeout(HANDLER_TIMEOUT_MS).times(1)).notifyNetworkTestedWithExtras(
                eq(NETWORK_VALIDATION_PROBE_DNS | NETWORK_VALIDATION_PROBE_HTTPS),
                eq(TEST_REDIRECT_URL), anyLong(), bundleForNotifyNetworkTested(
                NETWORK_VALIDATION_PROBE_DNS | NETWORK_VALIDATION_PROBE_HTTPS));
    }

    @Test
    public void testExtractCharset() {
        assertEquals(StandardCharsets.UTF_8, extractCharset(null));
        assertEquals(StandardCharsets.UTF_8, extractCharset("text/html;charset=utf-8"));
        assertEquals(StandardCharsets.UTF_8, extractCharset("text/html;charset=UtF-8"));
        assertEquals(StandardCharsets.UTF_8, extractCharset("text/html; Charset=\"utf-8\""));
        assertEquals(StandardCharsets.UTF_8, extractCharset("image/png"));
        assertEquals(StandardCharsets.UTF_8, extractCharset("Text/HTML;"));
        assertEquals(StandardCharsets.UTF_8, extractCharset("multipart/form-data; boundary=-aa*-"));
        assertEquals(StandardCharsets.UTF_8, extractCharset("text/plain;something=else"));
        assertEquals(StandardCharsets.UTF_8, extractCharset("text/plain;charset=ImNotACharset"));

        assertEquals(StandardCharsets.ISO_8859_1, extractCharset("text/plain; CharSeT=ISO-8859-1"));
        assertEquals(Charset.forName("Shift_JIS"), extractCharset("text/plain;charset=Shift_JIS"));
        assertEquals(Charset.forName("Windows-1251"), extractCharset(
                "text/plain;charset=Windows-1251 ; somethingelse"));
    }

    @Test
    public void testReadAsString() throws IOException {
        final String repeatedString = "1aテスト-?";
        // Infinite stream repeating characters
        class TestInputStream extends InputStream {
            private final byte[] mBytes = repeatedString.getBytes(StandardCharsets.UTF_8);
            private int mPosition = -1;

            @Override
            public int read() {
                mPosition = (mPosition + 1) % mBytes.length;
                return mBytes[mPosition];
            }
        }

        final String readString = NetworkMonitor.readAsString(new TestInputStream(),
                1500 /* maxLength */, StandardCharsets.UTF_8);

        assertEquals(1500, readString.length());
        for (int i = 0; i < readString.length(); i++) {
            assertEquals(repeatedString.charAt(i % repeatedString.length()), readString.charAt(i));
        }
    }

    private void makeDnsTimeoutEvent(WrappedNetworkMonitor wrappedMonitor, int count) {
        for (int i = 0; i < count; i++) {
            wrappedMonitor.getDnsStallDetector().accumulateConsecutiveDnsTimeoutCount(
                    RETURN_CODE_DNS_TIMEOUT);
        }
    }

    private void makeDnsSuccessEvent(WrappedNetworkMonitor wrappedMonitor, int count) {
        for (int i = 0; i < count; i++) {
            wrappedMonitor.getDnsStallDetector().accumulateConsecutiveDnsTimeoutCount(
                    RETURN_CODE_DNS_SUCCESS);
        }
    }

    private DataStallDetectionStats makeEmptyDataStallDetectionStats() {
        return new DataStallDetectionStats.Builder().build();
    }

    private void setDataStallEvaluationType(int type) {
        when(mDependencies.getDeviceConfigPropertyInt(any(),
            eq(CONFIG_DATA_STALL_EVALUATION_TYPE), anyInt())).thenReturn(type);
    }

    private void setMinDataStallEvaluateInterval(int time) {
        when(mDependencies.getDeviceConfigPropertyInt(any(),
            eq(CONFIG_DATA_STALL_MIN_EVALUATE_INTERVAL), anyInt())).thenReturn(time);
    }

    private void setValidDataStallDnsTimeThreshold(int time) {
        when(mDependencies.getDeviceConfigPropertyInt(any(),
            eq(CONFIG_DATA_STALL_VALID_DNS_TIME_THRESHOLD), anyInt())).thenReturn(time);
    }

    private void setConsecutiveDnsTimeoutThreshold(int num) {
        when(mDependencies.getDeviceConfigPropertyInt(any(),
            eq(CONFIG_DATA_STALL_CONSECUTIVE_DNS_TIMEOUT_THRESHOLD), anyInt())).thenReturn(num);
    }

    private void setTcpPollingInterval(int time) {
        when(mDependencies.getDeviceConfigPropertyInt(any(),
                eq(CONFIG_DATA_STALL_TCP_POLLING_INTERVAL), anyInt())).thenReturn(time);
    }

    private void setFallbackUrl(String url) {
        when(mDependencies.getSetting(any(),
                eq(Settings.Global.CAPTIVE_PORTAL_FALLBACK_URL), any())).thenReturn(url);
    }

    private void setOtherFallbackUrls(String urls) {
        when(mDependencies.getDeviceConfigProperty(any(),
                eq(CAPTIVE_PORTAL_OTHER_FALLBACK_URLS), any())).thenReturn(urls);
    }

    private void setFallbackSpecs(String specs) {
        when(mDependencies.getDeviceConfigProperty(any(),
                eq(CAPTIVE_PORTAL_FALLBACK_PROBE_SPECS), any())).thenReturn(specs);
    }

    private void setCaptivePortalMode(int mode) {
        when(mDependencies.getSetting(any(),
                eq(Settings.Global.CAPTIVE_PORTAL_MODE), anyInt())).thenReturn(mode);
    }

    private void setDismissPortalInValidatedNetwork(boolean enabled) {
        when(mDependencies.isFeatureEnabled(any(), any(),
                eq(DISMISS_PORTAL_IN_VALIDATED_NETWORK), anyBoolean())).thenReturn(enabled);
    }

    private void runPortalNetworkTest(int result) {
        runNetworkTest(result);
        assertEquals(1, mRegisteredReceivers.size());
        assertNotNull(mNetworkTestedRedirectUrlCaptor.getValue());
    }

    private void runNotPortalNetworkTest() {
        runNetworkTest(VALIDATION_RESULT_VALID);
        assertEquals(0, mRegisteredReceivers.size());
        assertNull(mNetworkTestedRedirectUrlCaptor.getValue());
    }

    private void runNoValidationNetworkTest() {
        runNetworkTest(NETWORK_VALIDATION_RESULT_VALID);
        assertEquals(0, mRegisteredReceivers.size());
        assertNull(mNetworkTestedRedirectUrlCaptor.getValue());
    }

    private void runFailedNetworkTest() {
        runNetworkTest(VALIDATION_RESULT_INVALID);
        assertEquals(0, mRegisteredReceivers.size());
        assertNull(mNetworkTestedRedirectUrlCaptor.getValue());
    }

    private void runPartialConnectivityNetworkTest(int result) {
        runNetworkTest(result);
        assertEquals(0, mRegisteredReceivers.size());
        assertNull(mNetworkTestedRedirectUrlCaptor.getValue());
    }

    private NetworkMonitor runValidatedNetworkTest() throws IOException {
        setStatus(mHttpsConnection, 204);
        setStatus(mHttpConnection, 204);
        // Expect to send HTTPs and evaluation results.
        return runNetworkTest(VALIDATION_RESULT_VALID);
    }

    private NetworkMonitor runNetworkTest(int testResult) {
        return runNetworkTest(TEST_LINK_PROPERTIES, METERED_CAPABILITIES, testResult);
    }

    private NetworkMonitor runNetworkTest(LinkProperties lp, NetworkCapabilities nc,
            int testResult) {
        final NetworkMonitor monitor = makeMonitor(nc);
        monitor.notifyNetworkConnected(lp, nc);
        verifyNetworkTested(testResult);
        HandlerUtilsKt.waitForIdle(monitor.getHandler(), HANDLER_TIMEOUT_MS);

        return monitor;
    }

    private void verifyNetworkTested(int testResult) {
        try {
            verify(mCallbacks, timeout(HANDLER_TIMEOUT_MS))
                    .notifyNetworkTestedWithExtras(eq(testResult),
                            mNetworkTestedRedirectUrlCaptor.capture(), anyLong(),
                            bundleForNotifyNetworkTested(testResult));
        } catch (RemoteException e) {
            fail("Unexpected exception: " + e);
        }
    }

    private void notifyNetworkConnected(NetworkMonitor nm, NetworkCapabilities nc) {
        nm.notifyNetworkConnected(TEST_LINK_PROPERTIES, nc);
    }

    private void setSslException(HttpURLConnection connection) throws IOException {
        doThrow(new SSLHandshakeException("Invalid cert")).when(connection).getResponseCode();
    }

    private void set302(HttpURLConnection connection, String location) throws IOException {
        setStatus(connection, 302);
        doReturn(location).when(connection).getHeaderField(LOCATION_HEADER);
    }

    private void setPortal302(HttpURLConnection connection) throws IOException {
        set302(connection, "http://login.example.com");
    }

    private void setApiContent(HttpURLConnection connection, String content) throws IOException {
        setStatus(connection, 200);
        final Map<String, List<String>> headerFields = new HashMap<>();
        headerFields.put(
                CONTENT_TYPE_HEADER, singletonList("application/captive+json;charset=UTF-8"));
        doReturn(headerFields).when(connection).getHeaderFields();
        doReturn(new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8)))
                .when(connection).getInputStream();
    }

    private void setStatus(HttpURLConnection connection, int status) throws IOException {
        doReturn(status).when(connection).getResponseCode();
    }

    private void generateTimeoutDnsEvent(DataStallDetectionStats.Builder stats, int num) {
        for (int i = 0; i < num; i++) {
            stats.addDnsEvent(RETURN_CODE_DNS_TIMEOUT, 123456789 /* timeMs */);
        }
    }

    private PersistableBundle bundleForNotifyNetworkTested(final int result) {
        // result = KEY_NETWORK_PROBES_SUCCEEDED_BITMASK | KEY_NETWORK_VALIDATION_RESULT
        // See NetworkMonitor.EvaluationState#getNetworkTestResult
        final int validationResult = result & NOTIFY_NETWORK_TESTED_VALIDATION_RESULT_MASK;
        final int probesSucceeded = result & NOTIFY_NETWORK_TESTED_SUCCESSFUL_PROBES_MASK;

        return argThat(bundle ->
                bundle.containsKey(KEY_NETWORK_PROBES_ATTEMPTED_BITMASK)
                && bundle.containsKey(KEY_NETWORK_PROBES_SUCCEEDED_BITMASK)
                && (bundle.getInt(KEY_NETWORK_PROBES_SUCCEEDED_BITMASK) & probesSucceeded)
                        == probesSucceeded
                && bundle.containsKey(KEY_NETWORK_VALIDATION_RESULT)
                && (bundle.getInt(KEY_NETWORK_VALIDATION_RESULT) & validationResult)
                        == validationResult);
    }

    private PersistableBundle bundleForDnsDataStall(final int timeoutCount) {
        return argThat(bundle ->
                bundle.containsKey(KEY_DNS_CONSECUTIVE_TIMEOUTS)
                && bundle.getInt(KEY_DNS_CONSECUTIVE_TIMEOUTS) == timeoutCount);
    }

    private PersistableBundle bundleForTcpDataStall() {
        return argThat(bundle ->
                bundle.containsKey(KEY_TCP_METRICS_COLLECTION_PERIOD_MILLIS)
                && bundle.containsKey(KEY_TCP_PACKET_FAIL_RATE));
    }
}

