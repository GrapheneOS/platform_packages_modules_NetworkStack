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

import static android.net.NetworkCapabilities.TRANSPORT_BLUETOOTH;
import static android.net.NetworkCapabilities.TRANSPORT_CELLULAR;
import static android.net.NetworkCapabilities.TRANSPORT_ETHERNET;
import static android.net.NetworkCapabilities.TRANSPORT_LOWPAN;
import static android.net.NetworkCapabilities.TRANSPORT_VPN;
import static android.net.NetworkCapabilities.TRANSPORT_WIFI;
import static android.net.NetworkCapabilities.TRANSPORT_WIFI_AWARE;

import static java.lang.System.currentTimeMillis;

import android.net.INetworkMonitor;
import android.net.NetworkCapabilities;
import android.net.captiveportal.CaptivePortalProbeResult;
import android.net.metrics.ValidationProbeEvent;
import android.net.util.NetworkStackUtils;
import android.net.util.Stopwatch;
import android.stats.connectivity.ProbeResult;
import android.stats.connectivity.ProbeType;
import android.stats.connectivity.TransportType;
import android.stats.connectivity.ValidationResult;

import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;

import com.android.networkstack.apishim.common.CaptivePortalDataShim;

/**
 * Class to record the network validation into statsd.
 * 1. Fill in NetworkValidationReported proto.
 * 2. Write the NetworkValidationReported proto into statsd.
 * @hide
 */

public class NetworkValidationMetrics {
    private final NetworkValidationReported.Builder mStatsBuilder =
            NetworkValidationReported.newBuilder();
    private final ProbeEvents.Builder mProbeEventsBuilder = ProbeEvents.newBuilder();
    private final CapportApiData.Builder mCapportApiDataBuilder = CapportApiData.newBuilder();
    private final Stopwatch mWatch = new Stopwatch();
    private int mValidationIndex = 0;
    // Define a maximum size that can store events.
    public static final int MAX_PROBE_EVENTS_COUNT = 20;

    /**
     *  Reset this NetworkValidationMetrics.
     */
    public void reset(@Nullable NetworkCapabilities nc) {
        mStatsBuilder.clear();
        mProbeEventsBuilder.clear();
        mCapportApiDataBuilder.clear();
        mWatch.restart();
        mStatsBuilder.setTransportType(getTransportTypeFromNC(nc));
        mValidationIndex++;
    }

    /**
     * Returns the enum TransportType
     *
     * @param NetworkCapabilities
     * @return the TransportType which is defined in
     * core/proto/android/stats/connectivity/network_stack.proto
     */
    @VisibleForTesting
    public static TransportType getTransportTypeFromNC(
            @Nullable NetworkCapabilities nc) {
        if (nc == null) return TransportType.TT_UNKNOWN;
        boolean hasCellular = nc.hasTransport(TRANSPORT_CELLULAR);
        boolean hasWifi = nc.hasTransport(TRANSPORT_WIFI);
        boolean hasBT = nc.hasTransport(TRANSPORT_BLUETOOTH);
        boolean hasEthernet = nc.hasTransport(TRANSPORT_ETHERNET);
        boolean hasVpn = nc.hasTransport(TRANSPORT_VPN);
        boolean hasWifiAware = nc.hasTransport(TRANSPORT_WIFI_AWARE);
        boolean hasLopan = nc.hasTransport(TRANSPORT_LOWPAN);

        if (hasCellular && hasWifi && hasVpn) return TransportType.TT_WIFI_CELLULAR_VPN;
        if (hasWifi) return hasVpn ? TransportType.TT_WIFI_VPN : TransportType.TT_WIFI;
        if (hasCellular) return hasVpn ? TransportType.TT_CELLULAR_VPN : TransportType.TT_CELLULAR;
        if (hasBT) return hasVpn ? TransportType.TT_BLUETOOTH_VPN : TransportType.TT_BLUETOOTH;
        if (hasEthernet) return hasVpn ? TransportType.TT_ETHERNET_VPN : TransportType.TT_ETHERNET;
        if (hasWifiAware) return TransportType.TT_WIFI_AWARE;
        if (hasLopan) return TransportType.TT_LOWPAN;
        return TransportType.TT_UNKNOWN;
    }

    /**
     * Map {@link ValidationProbeEvent} to {@link ProbeType}.
     */
    public static ProbeType probeTypeToEnum(final int probeType) {
        switch(probeType) {
            case ValidationProbeEvent.PROBE_DNS:
                return ProbeType.PT_DNS;
            case ValidationProbeEvent.PROBE_HTTP:
                return ProbeType.PT_HTTP;
            case ValidationProbeEvent.PROBE_HTTPS:
                return ProbeType.PT_HTTPS;
            case ValidationProbeEvent.PROBE_PAC:
                return ProbeType.PT_PAC;
            case ValidationProbeEvent.PROBE_FALLBACK:
                return ProbeType.PT_FALLBACK;
            case ValidationProbeEvent.PROBE_PRIVDNS:
                return ProbeType.PT_PRIVDNS;
            default:
                return ProbeType.PT_UNKNOWN;
        }
    }

    /**
     * Map {@link CaptivePortalProbeResult} to {@link ProbeResult}.
     */
    public static ProbeResult httpProbeResultToEnum(final CaptivePortalProbeResult result) {
        if (result == null) return ProbeResult.PR_UNKNOWN;

        if (result.isSuccessful()) {
            return ProbeResult.PR_SUCCESS;
        } else if (result.isDnsPrivateIpResponse()) {
            return ProbeResult.PR_PRIVATE_IP_DNS;
        } else if (result.isFailed()) {
            return ProbeResult.PR_FAILURE;
        } else if (result.isPortal()) {
            return ProbeResult.PR_PORTAL;
        } else {
            return ProbeResult.PR_UNKNOWN;
        }
    }

    /**
     * Map  validation result (as per INetworkMonitor) to {@link ValidationResult}.
     */
    @VisibleForTesting
    public static ValidationResult validationResultToEnum(int result, String redirectUrl) {
        if ((result & INetworkMonitor.NETWORK_VALIDATION_RESULT_VALID) != 0) {
            return ValidationResult.VR_SUCCESS;
        } else if (redirectUrl != null) {
            return ValidationResult.VR_PORTAL;
        } else if ((result & INetworkMonitor.NETWORK_VALIDATION_RESULT_PARTIAL) != 0) {
            return ValidationResult.VR_PARTIAL;
        } else {
            return ValidationResult.VR_FAILURE;
        }
    }

    /**
     * Write each network probe event to mProbeEventsBuilder.
     */
    public void setProbeEvent(final ProbeType type, final long durationUs, final ProbeResult result,
            @Nullable final CaptivePortalDataShim capportData) {
        // When the number of ProbeEvents of mProbeEventsBuilder exceeds
        // MAX_PROBE_EVENTS_COUNT, stop adding ProbeEvent.
        if (mProbeEventsBuilder.getProbeEventCount() >= MAX_PROBE_EVENTS_COUNT) return;

        int latencyUs = NetworkStackUtils.saturatedCast(durationUs);

        final ProbeEvent.Builder probeEventBuilder = ProbeEvent.newBuilder()
                .setLatencyMicros(latencyUs)
                .setProbeType(type)
                .setProbeResult(result);

        if (capportData != null) {
            final long secondsRemaining =
                    (capportData.getExpiryTimeMillis() - currentTimeMillis()) / 1000;
            mCapportApiDataBuilder
                .setRemainingTtlSecs(NetworkStackUtils.saturatedCast(secondsRemaining))
                .setRemainingBytes(NetworkStackUtils.saturatedCast(capportData.getByteLimit()))
                .setHasPortalUrl((capportData.getUserPortalUrl() != null))
                .setHasVenueInfo((capportData.getVenueInfoUrl() != null));
            probeEventBuilder.setCapportApiData(mCapportApiDataBuilder);
        }

        mProbeEventsBuilder.addProbeEvent(probeEventBuilder);
    }

    /**
     * Write the network validation info to mStatsBuilder.
     */
    public void setValidationResult(int result, String redirectUrl) {
        mStatsBuilder.setValidationResult(validationResultToEnum(result, redirectUrl));
    }

    /**
     * Write the NetworkValidationReported proto to statsd.
     */
    public NetworkValidationReported sendValidationStats() {
        if (!mWatch.isStarted()) return null;
        mStatsBuilder.setProbeEvents(mProbeEventsBuilder);
        mStatsBuilder.setLatencyMicros(NetworkStackUtils.saturatedCast(mWatch.stop()));
        mStatsBuilder.setValidationIndex(mValidationIndex);
        // write a random value(0 ~ 999) for sampling.
        mStatsBuilder.setRandomNumber((int) (Math.random() * 1000));
        final NetworkValidationReported mStats = mStatsBuilder.build();
        final byte[] probeEvents = mStats.getProbeEvents().toByteArray();

        NetworkStackStatsLog.write(NetworkStackStatsLog.NETWORK_VALIDATION_REPORTED,
                mStats.getTransportType().getNumber(),
                probeEvents,
                mStats.getValidationResult().getNumber(),
                mStats.getLatencyMicros(),
                mStats.getValidationIndex(),
                mStats.getRandomNumber());
        mWatch.reset();
        return mStats;
    }
}
