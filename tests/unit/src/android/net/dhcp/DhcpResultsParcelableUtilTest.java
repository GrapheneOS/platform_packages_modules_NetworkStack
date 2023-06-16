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

package android.net.dhcp;

import static android.net.InetAddresses.parseNumericAddress;
import static android.net.dhcp.DhcpResultsParcelableUtil.fromStableParcelable;
import static android.net.dhcp.DhcpResultsParcelableUtil.toStableParcelable;

import static com.android.testutils.MiscAsserts.assertFieldCountEquals;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import android.net.DhcpResults;
import android.net.LinkAddress;
import android.net.shared.IpConfigurationParcelableUtil;

import androidx.test.filters.SmallTest;
import androidx.test.runner.AndroidJUnit4;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.net.Inet4Address;

/**
 * Tests for {@link IpConfigurationParcelableUtil}.
 */
@RunWith(AndroidJUnit4.class)
@SmallTest
public class DhcpResultsParcelableUtilTest {
    private DhcpResults mDhcpResults;

    @Before
    public void setUp() {
        mDhcpResults = new DhcpResults();
        mDhcpResults.ipAddress = new LinkAddress(parseNumericAddress("192.168.42.19"), 25);
        mDhcpResults.gateway = parseNumericAddress("192.168.42.42");
        mDhcpResults.dnsServers.add(parseNumericAddress("8.8.8.8"));
        mDhcpResults.dnsServers.add(parseNumericAddress("192.168.43.43"));
        mDhcpResults.domains = "example.com";
        mDhcpResults.serverAddress = (Inet4Address) parseNumericAddress("192.168.44.44");
        mDhcpResults.vendorInfo = "TEST_VENDOR_INFO";
        mDhcpResults.leaseDuration = 3600;
        mDhcpResults.serverHostName = "dhcp.example.com";
        mDhcpResults.mtu = 1450;
        mDhcpResults.captivePortalApiUrl = "https://example.com/testapi";
        // Any added DhcpResults field must be included in equals() to be tested properly
        assertFieldCountEquals(10, DhcpResults.class);
    }

    @Test
    public void testParcelUnparcelDhcpResults() {
        doDhcpResultsParcelUnparcelTest();
    }

    @Test
    public void testParcelUnparcelDhcpResults_NullIpAddress() {
        mDhcpResults.ipAddress = null;
        doDhcpResultsParcelUnparcelTest();
    }

    @Test
    public void testParcelUnparcelDhcpResults_NullGateway() {
        mDhcpResults.gateway = null;
        doDhcpResultsParcelUnparcelTest();
    }

    @Test
    public void testParcelUnparcelDhcpResults_NullDomains() {
        mDhcpResults.domains = null;
        doDhcpResultsParcelUnparcelTest();
    }

    @Test
    public void testParcelUnparcelDhcpResults_EmptyDomains() {
        mDhcpResults.domains = "";
        doDhcpResultsParcelUnparcelTest();
    }

    @Test
    public void testParcelUnparcelDhcpResults_NullServerAddress() {
        mDhcpResults.serverAddress = null;
        doDhcpResultsParcelUnparcelTest();
    }

    @Test
    public void testParcelUnparcelDhcpResults_NullVendorInfo() {
        mDhcpResults.vendorInfo = null;
        doDhcpResultsParcelUnparcelTest();
    }

    @Test
    public void testParcelUnparcelDhcpResults_NullServerHostName() {
        mDhcpResults.serverHostName = null;
        doDhcpResultsParcelUnparcelTest();
    }

    @Test
    public void testParcelUnparcelDhcpResults_NullCaptivePortalApiUrl() {
        mDhcpResults.captivePortalApiUrl = null;
        doDhcpResultsParcelUnparcelTest();
    }

    private void doDhcpResultsParcelUnparcelTest() {
        final DhcpResults unparceled = fromStableParcelable(toStableParcelable(mDhcpResults));
        assertEquals(mDhcpResults, unparceled);
    }

    @Test
    public void testToString() {
        final String str = toStableParcelable(mDhcpResults).toString();

        // check a few fields. Comprehensive toString tests exist in aidl_integration_test,
        // but we want to make sure that the toString function requested in the AIDL file
        // is there
        assertTrue(str, str.contains("baseConfiguration"));
        assertTrue(str, str.contains("IP address 192.168.42.19/25"));
        assertTrue(str, str.contains("serverAddress"));
        assertTrue(str, str.contains("192.168.44.44"));
    }
}
