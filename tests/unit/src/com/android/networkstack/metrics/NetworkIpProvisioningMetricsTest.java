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

package com.android.networkstack.metrics;

import android.net.metrics.DhcpErrorEvent;
import android.stats.connectivity.DhcpErrorCode;
import android.stats.connectivity.DhcpFeature;
import android.stats.connectivity.DisconnectCode;
import android.stats.connectivity.HostnameTransResult;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import androidx.test.filters.SmallTest;
import androidx.test.runner.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;


/**
 * Tests for IpProvisioningMetrics.
 */
@RunWith(AndroidJUnit4.class)
@SmallTest
public class NetworkIpProvisioningMetricsTest {
    @Test
    public void testIpProvisioningMetrics_setHostnameTransinfo() throws Exception {
        NetworkIpProvisioningReported mStats;
        final IpProvisioningMetrics mMetrics = new IpProvisioningMetrics();

        mMetrics.reset();
        mMetrics.setHostnameTransinfo(false /* isOptionEnabled */, false /* transSuccess */);
        mStats = mMetrics.statsWrite();
        assertEquals(HostnameTransResult.HTR_DISABLE, mStats.getDhcpSession().getHtResult());

        mMetrics.reset();
        mMetrics.setHostnameTransinfo(true /* isOptionEnabled */, false /* transSuccess */);
        mStats = mMetrics.statsWrite();
        assertEquals(HostnameTransResult.HTR_FAILURE, mStats.getDhcpSession().getHtResult());

        mMetrics.reset();
        mMetrics.setHostnameTransinfo(true /* isOptionEnabled */, true /* transSuccess */);
        mStats = mMetrics.statsWrite();
        assertEquals(HostnameTransResult.HTR_SUCCESS, mStats.getDhcpSession().getHtResult());
    }

    @Test
    public void testIpProvisioningMetrics_addDhcpErrorCode() throws Exception {
        final NetworkIpProvisioningReported mStats;
        final IpProvisioningMetrics mMetrics = new IpProvisioningMetrics();
        mMetrics.reset();
        mMetrics.addDhcpErrorCode(DhcpErrorEvent.DHCP_ERROR);
        mMetrics.addDhcpErrorCode(DhcpErrorEvent.L2_WRONG_ETH_TYPE);
        mMetrics.addDhcpErrorCode(DhcpErrorEvent.L3_INVALID_IP);
        mMetrics.addDhcpErrorCode(DhcpErrorEvent.L4_WRONG_PORT);
        mMetrics.addDhcpErrorCode(DhcpErrorEvent.BOOTP_TOO_SHORT);
        mMetrics.addDhcpErrorCode(DhcpErrorEvent.DHCP_NO_COOKIE);
        for (int i = 0; i < mMetrics.MAX_DHCP_ERROR_COUNT; i++) {
            mMetrics.addDhcpErrorCode(DhcpErrorEvent.PARSING_ERROR);
        }
        mStats = mMetrics.statsWrite();
        assertEquals(DhcpErrorCode.ET_DHCP_ERROR, mStats.getDhcpSession().getErrorCode(0));
        assertEquals(DhcpErrorCode.ET_L2_WRONG_ETH_TYPE, mStats.getDhcpSession().getErrorCode(1));
        assertEquals(DhcpErrorCode.ET_L3_INVALID_IP, mStats.getDhcpSession().getErrorCode(2));
        assertEquals(DhcpErrorCode.ET_L4_WRONG_PORT, mStats.getDhcpSession().getErrorCode(3));
        assertEquals(DhcpErrorCode.ET_BOOTP_TOO_SHORT, mStats.getDhcpSession().getErrorCode(4));
        assertEquals(DhcpErrorCode.ET_DHCP_NO_COOKIE, mStats.getDhcpSession().getErrorCode(5));
        // Check can record the same error code
        assertEquals(DhcpErrorCode.ET_PARSING_ERROR, mStats.getDhcpSession().getErrorCode(6));
        assertEquals(DhcpErrorCode.ET_PARSING_ERROR, mStats.getDhcpSession().getErrorCode(6));
        // The maximum number of DHCP error code counts is MAX_DHCP_ERROR_COUNT
        assertEquals(mMetrics.MAX_DHCP_ERROR_COUNT, mStats.getDhcpSession().getErrorCodeCount());
    }
    @Test
    public void testIpProvisioningMetrics_CollectMetrics() throws Exception {
        final NetworkIpProvisioningReported mStats;
        final IpProvisioningMetrics mMetrics = new IpProvisioningMetrics();
        mMetrics.reset();
        // Entering 3 DISCOVER_SEND_COUNTs
        mMetrics.incrementCountForDiscover();
        mMetrics.incrementCountForDiscover();
        mMetrics.incrementCountForDiscover();

        // Entering 2 SEND_REQUEST_COUNTs
        mMetrics.incrementCountForRequest();
        mMetrics.incrementCountForRequest();

        // Entering 1 IP_CONFLICT_COUNT
        mMetrics.incrementCountForIpConflict();

        // Entering 4 DhcpFeatures and one is repeated, so it should only count to 3
        mMetrics.setDhcpEnabledFeature(DhcpFeature.DF_INITREBOOT);
        mMetrics.setDhcpEnabledFeature(DhcpFeature.DF_RAPIDCOMMIT);
        mMetrics.setDhcpEnabledFeature(DhcpFeature.DF_DAD);
        mMetrics.setDhcpEnabledFeature(DhcpFeature.DF_DAD);

        // Entering 6 DhcpErrorCodes
        mMetrics.addDhcpErrorCode(DhcpErrorEvent.L3_TOO_SHORT);
        mMetrics.addDhcpErrorCode(DhcpErrorEvent.DHCP_INVALID_OPTION_LENGTH);
        mMetrics.addDhcpErrorCode(DhcpErrorEvent.RECEIVE_ERROR);
        mMetrics.addDhcpErrorCode(DhcpErrorEvent.RECEIVE_ERROR);
        mMetrics.addDhcpErrorCode(DhcpErrorEvent.PARSING_ERROR);
        mMetrics.addDhcpErrorCode(DhcpErrorEvent.PARSING_ERROR);

        mMetrics.setHostnameTransinfo(true /* isOptionEnabled */, true /* transSuccess */);

        // Only the first IP provisioning disconnect code is recorded.
        mMetrics.setDisconnectCode(DisconnectCode.DC_PROVISIONING_TIMEOUT);
        mMetrics.setDisconnectCode(DisconnectCode.DC_ERROR_STARTING_IPV4);

        mMetrics.setIPv4ProvisionedLatencyOnFirstTime(true);
        mMetrics.setIPv6ProvisionedLatencyOnFirstTime(true);

        // Writing the metrics into statsd
        mStats = mMetrics.statsWrite();

        // Verifing the result of the metrics.
        assertEquals(3, mStats.getDhcpSession().getDiscoverCount());
        assertEquals(2, mStats.getDhcpSession().getRequestCount());
        assertEquals(1, mStats.getDhcpSession().getConflictCount());
        assertEquals(3, mStats.getDhcpSession().getUsedFeaturesCount());
        assertEquals(6, mStats.getDhcpSession().getErrorCodeCount());
        assertEquals(HostnameTransResult.HTR_SUCCESS, mStats.getDhcpSession().getHtResult());
        assertEquals(DisconnectCode.DC_PROVISIONING_TIMEOUT, mStats.getDisconnectCode());
        assertTrue(mStats.getIpv4LatencyMicros() >= 0);
        assertTrue(mStats.getIpv6LatencyMicros() >= 0);
        assertTrue(mStats.getProvisioningDurationMicros() >= 0);
    }

    @Test
    public void testIpProvisioningMetrics_VerifyConsecutiveMetricsLatency() throws Exception {
        final IpProvisioningMetrics metrics = new IpProvisioningMetrics();
        for (int i = 0; i < 2; i++) {
            metrics.reset();
            // delay 1 msec.
            Thread.sleep(1);
            metrics.setIPv4ProvisionedLatencyOnFirstTime(true);
            metrics.setIPv6ProvisionedLatencyOnFirstTime(true);
            NetworkIpProvisioningReported mStats = metrics.statsWrite();
            // Each timer should be greater than 1000.
            assertTrue(mStats.getIpv4LatencyMicros() >= 1000);
            assertTrue(mStats.getIpv6LatencyMicros() >= 1000);
            assertTrue(mStats.getProvisioningDurationMicros() >= 1000);
        }
    }
}
