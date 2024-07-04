/*
 * Copyright (C) 2023 The Android Open Source Project
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

import static android.net.apf.ApfCounterTracker.Counter.DROPPED_802_3_FRAME;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_ARP_NON_IPV4;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_ARP_OTHER_HOST;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_ARP_REPLY_SPA_NO_HOST;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_ARP_REQUEST_ANYHOST;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_ARP_REQUEST_REPLIED;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_ARP_UNKNOWN;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_ARP_V6_ONLY;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_ETHERTYPE_NOT_ALLOWED;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_ETH_BROADCAST;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_GARP_REPLY;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_BROADCAST_ADDR;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_BROADCAST_NET;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_KEEPALIVE_ACK;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_L2_BROADCAST;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_MULTICAST;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_NATT_KEEPALIVE;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_NON_DHCP4;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV4_TCP_PORT7_UNICAST;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_KEEPALIVE_ACK;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_MULTICAST;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_MULTICAST_NA;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_MULTICAST_PING;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_NON_ICMP_MULTICAST;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_NS_INVALID;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_NS_OTHER_HOST;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_NS_REPLIED_NON_DAD;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_ROUTER_SOLICITATION;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_MDNS;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_RA;
import static android.net.apf.ApfCounterTracker.Counter.PASSED_ARP;
import static android.net.apf.ApfCounterTracker.Counter.PASSED_ARP_BROADCAST_REPLY;
import static android.net.apf.ApfCounterTracker.Counter.PASSED_ARP_NON_IPV4;
import static android.net.apf.ApfCounterTracker.Counter.PASSED_ARP_REQUEST;
import static android.net.apf.ApfCounterTracker.Counter.PASSED_ARP_UNICAST_REPLY;
import static android.net.apf.ApfCounterTracker.Counter.PASSED_ARP_UNKNOWN;
import static android.net.apf.ApfCounterTracker.Counter.PASSED_DHCP;
import static android.net.apf.ApfCounterTracker.Counter.PASSED_IPV4;
import static android.net.apf.ApfCounterTracker.Counter.PASSED_IPV4_FROM_DHCPV4_SERVER;
import static android.net.apf.ApfCounterTracker.Counter.PASSED_IPV4_UNICAST;
import static android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_ICMP;
import static android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_NON_ICMP;
import static android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_NS_DAD;
import static android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_NS_NO_ADDRESS;
import static android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_NS_NO_SLLA_OPTION;
import static android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_NS_TENTATIVE;
import static android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_UNICAST_NON_ICMP;
import static android.net.apf.ApfCounterTracker.Counter.PASSED_MDNS;
import static android.net.apf.ApfCounterTracker.Counter.PASSED_MLD;
import static android.net.apf.ApfCounterTracker.Counter.PASSED_NON_IP_UNICAST;
import static android.net.apf.ApfCounterTracker.Counter.TOTAL_PACKETS;
import static android.stats.connectivity.CounterName.CN_DROPPED_802_3_FRAME;
import static android.stats.connectivity.CounterName.CN_DROPPED_ARP_NON_IPV4;
import static android.stats.connectivity.CounterName.CN_DROPPED_ARP_OTHER_HOST;
import static android.stats.connectivity.CounterName.CN_DROPPED_ARP_REPLY_SPA_NO_HOST;
import static android.stats.connectivity.CounterName.CN_DROPPED_ARP_REQUEST_ANYHOST;
import static android.stats.connectivity.CounterName.CN_DROPPED_ARP_REQUEST_REPLIED;
import static android.stats.connectivity.CounterName.CN_DROPPED_ARP_UNKNOWN;
import static android.stats.connectivity.CounterName.CN_DROPPED_ARP_V6_ONLY;
import static android.stats.connectivity.CounterName.CN_DROPPED_ETHERTYPE_NOT_ALLOWED;
import static android.stats.connectivity.CounterName.CN_DROPPED_ETH_BROADCAST;
import static android.stats.connectivity.CounterName.CN_DROPPED_GARP_REPLY;
import static android.stats.connectivity.CounterName.CN_DROPPED_IPV4_BROADCAST_ADDR;
import static android.stats.connectivity.CounterName.CN_DROPPED_IPV4_BROADCAST_NET;
import static android.stats.connectivity.CounterName.CN_DROPPED_IPV4_KEEPALIVE_ACK;
import static android.stats.connectivity.CounterName.CN_DROPPED_IPV4_L2_BROADCAST;
import static android.stats.connectivity.CounterName.CN_DROPPED_IPV4_MULTICAST;
import static android.stats.connectivity.CounterName.CN_DROPPED_IPV4_NATT_KEEPALIVE;
import static android.stats.connectivity.CounterName.CN_DROPPED_IPV4_NON_DHCP4;
import static android.stats.connectivity.CounterName.CN_DROPPED_IPV6_KEEPALIVE_ACK;
import static android.stats.connectivity.CounterName.CN_DROPPED_IPV6_MULTICAST;
import static android.stats.connectivity.CounterName.CN_DROPPED_IPV6_MULTICAST_NA;
import static android.stats.connectivity.CounterName.CN_DROPPED_IPV6_MULTICAST_PING;
import static android.stats.connectivity.CounterName.CN_DROPPED_IPV6_NON_ICMP_MULTICAST;
import static android.stats.connectivity.CounterName.CN_DROPPED_IPV6_NS_INVALID;
import static android.stats.connectivity.CounterName.CN_DROPPED_IPV6_NS_OTHER_HOST;
import static android.stats.connectivity.CounterName.CN_DROPPED_IPV6_NS_REPLIED_NON_DAD;
import static android.stats.connectivity.CounterName.CN_DROPPED_IPV6_ROUTER_SOLICITATION;
import static android.stats.connectivity.CounterName.CN_DROPPED_MDNS;
import static android.stats.connectivity.CounterName.CN_DROPPED_RA;
import static android.stats.connectivity.CounterName.CN_PASSED_ARP;
import static android.stats.connectivity.CounterName.CN_PASSED_ARP_BROADCAST_REPLY;
import static android.stats.connectivity.CounterName.CN_PASSED_ARP_REQUEST;
import static android.stats.connectivity.CounterName.CN_PASSED_ARP_UNICAST_REPLY;
import static android.stats.connectivity.CounterName.CN_PASSED_DHCP;
import static android.stats.connectivity.CounterName.CN_PASSED_IPV4;
import static android.stats.connectivity.CounterName.CN_PASSED_IPV4_FROM_DHCPV4_SERVER;
import static android.stats.connectivity.CounterName.CN_PASSED_IPV4_UNICAST;
import static android.stats.connectivity.CounterName.CN_PASSED_IPV6_ICMP;
import static android.stats.connectivity.CounterName.CN_PASSED_IPV6_NON_ICMP;
import static android.stats.connectivity.CounterName.CN_PASSED_IPV6_NS_DAD;
import static android.stats.connectivity.CounterName.CN_PASSED_IPV6_NS_NO_ADDRESS;
import static android.stats.connectivity.CounterName.CN_PASSED_IPV6_NS_NO_SLLA_OPTION;
import static android.stats.connectivity.CounterName.CN_PASSED_IPV6_NS_TENTATIVE;
import static android.stats.connectivity.CounterName.CN_PASSED_IPV6_UNICAST_NON_ICMP;
import static android.stats.connectivity.CounterName.CN_PASSED_MDNS;
import static android.stats.connectivity.CounterName.CN_PASSED_MLD;
import static android.stats.connectivity.CounterName.CN_PASSED_NON_IP_UNICAST;
import static android.stats.connectivity.CounterName.CN_TOTAL_PACKETS;
import static android.stats.connectivity.CounterName.CN_UNKNOWN;

import android.net.apf.ApfCounterTracker.Counter;
import android.stats.connectivity.CounterName;

import androidx.annotation.VisibleForTesting;

import java.util.EnumMap;
import java.util.Map;

/**
 * Class to record the network stack ApfSessionInfo metrics into statsd.
 *
 * This class is not thread-safe, and should always be accessed from the same thread.
 *
 * @hide
 */
public class ApfSessionInfoMetrics {
    // Define the maximum size of the counter list
    public static final int MAX_NUM_OF_COUNTERS = Counter.class.getEnumConstants().length - 1;
    private static final EnumMap<Counter, CounterName> apfCounterMetricsMap = new EnumMap<>(
            Map.ofEntries(
                Map.entry(TOTAL_PACKETS, CN_TOTAL_PACKETS),
                // The counter sequence should be keep the same in ApfCounterTracker.java
                Map.entry(PASSED_ARP, CN_PASSED_ARP),
                Map.entry(PASSED_ARP_BROADCAST_REPLY, CN_PASSED_ARP_BROADCAST_REPLY),
                // deprecated in ApfFilter, PASSED_ARP_NON_IPV4 ==> DROPPED_ARP_NON_IPV4
                Map.entry(PASSED_ARP_NON_IPV4, CN_UNKNOWN),
                Map.entry(PASSED_ARP_REQUEST, CN_PASSED_ARP_REQUEST),
                Map.entry(PASSED_ARP_UNICAST_REPLY, CN_PASSED_ARP_UNICAST_REPLY),
                // deprecated in ApfFilter, PASSED_ARP_UNKNOWN  ==> DROPPED_ARP_UNKNOWN
                Map.entry(PASSED_ARP_UNKNOWN, CN_UNKNOWN),
                Map.entry(PASSED_DHCP, CN_PASSED_DHCP),
                Map.entry(PASSED_IPV4, CN_PASSED_IPV4),
                Map.entry(PASSED_IPV4_FROM_DHCPV4_SERVER, CN_PASSED_IPV4_FROM_DHCPV4_SERVER),
                Map.entry(PASSED_IPV4_UNICAST, CN_PASSED_IPV4_UNICAST),
                Map.entry(PASSED_IPV6_ICMP, CN_PASSED_IPV6_ICMP),
                Map.entry(PASSED_IPV6_NON_ICMP, CN_PASSED_IPV6_NON_ICMP),
                Map.entry(PASSED_IPV6_NS_DAD, CN_PASSED_IPV6_NS_DAD),
                Map.entry(PASSED_IPV6_NS_NO_ADDRESS, CN_PASSED_IPV6_NS_NO_ADDRESS),
                Map.entry(PASSED_IPV6_NS_NO_SLLA_OPTION, CN_PASSED_IPV6_NS_NO_SLLA_OPTION),
                Map.entry(PASSED_IPV6_NS_TENTATIVE, CN_PASSED_IPV6_NS_TENTATIVE),
                Map.entry(PASSED_IPV6_UNICAST_NON_ICMP, CN_PASSED_IPV6_UNICAST_NON_ICMP),
                Map.entry(PASSED_NON_IP_UNICAST, CN_PASSED_NON_IP_UNICAST),
                Map.entry(PASSED_MDNS, CN_PASSED_MDNS),
                Map.entry(PASSED_MLD, CN_PASSED_MLD),
                Map.entry(DROPPED_ETH_BROADCAST, CN_DROPPED_ETH_BROADCAST),
                Map.entry(DROPPED_RA, CN_DROPPED_RA),
                Map.entry(DROPPED_IPV4_L2_BROADCAST, CN_DROPPED_IPV4_L2_BROADCAST),
                Map.entry(DROPPED_IPV4_BROADCAST_ADDR, CN_DROPPED_IPV4_BROADCAST_ADDR),
                Map.entry(DROPPED_IPV4_BROADCAST_NET, CN_DROPPED_IPV4_BROADCAST_NET),
                Map.entry(DROPPED_IPV4_MULTICAST, CN_DROPPED_IPV4_MULTICAST),
                Map.entry(DROPPED_IPV4_NON_DHCP4, CN_DROPPED_IPV4_NON_DHCP4),
                Map.entry(DROPPED_IPV6_ROUTER_SOLICITATION, CN_DROPPED_IPV6_ROUTER_SOLICITATION),
                Map.entry(DROPPED_IPV6_MULTICAST_NA, CN_DROPPED_IPV6_MULTICAST_NA),
                Map.entry(DROPPED_IPV6_MULTICAST, CN_DROPPED_IPV6_MULTICAST),
                Map.entry(DROPPED_IPV6_MULTICAST_PING, CN_DROPPED_IPV6_MULTICAST_PING),
                Map.entry(DROPPED_IPV6_NON_ICMP_MULTICAST, CN_DROPPED_IPV6_NON_ICMP_MULTICAST),
                Map.entry(DROPPED_IPV6_NS_INVALID, CN_DROPPED_IPV6_NS_INVALID),
                Map.entry(DROPPED_IPV6_NS_OTHER_HOST, CN_DROPPED_IPV6_NS_OTHER_HOST),
                Map.entry(DROPPED_IPV6_NS_REPLIED_NON_DAD, CN_DROPPED_IPV6_NS_REPLIED_NON_DAD),
                Map.entry(DROPPED_802_3_FRAME, CN_DROPPED_802_3_FRAME),
                Map.entry(DROPPED_ETHERTYPE_NOT_ALLOWED, CN_DROPPED_ETHERTYPE_NOT_ALLOWED),
                Map.entry(DROPPED_IPV4_KEEPALIVE_ACK, CN_DROPPED_IPV4_KEEPALIVE_ACK),
                Map.entry(DROPPED_IPV6_KEEPALIVE_ACK, CN_DROPPED_IPV6_KEEPALIVE_ACK),
                Map.entry(DROPPED_IPV4_NATT_KEEPALIVE, CN_DROPPED_IPV4_NATT_KEEPALIVE),
                Map.entry(DROPPED_MDNS, CN_DROPPED_MDNS),
                // TODO: Not supported yet in the metrics backend.
                Map.entry(DROPPED_IPV4_TCP_PORT7_UNICAST, CN_UNKNOWN),
                Map.entry(DROPPED_ARP_NON_IPV4, CN_DROPPED_ARP_NON_IPV4),
                Map.entry(DROPPED_ARP_OTHER_HOST, CN_DROPPED_ARP_OTHER_HOST),
                Map.entry(DROPPED_ARP_REPLY_SPA_NO_HOST, CN_DROPPED_ARP_REPLY_SPA_NO_HOST),
                Map.entry(DROPPED_ARP_REQUEST_ANYHOST, CN_DROPPED_ARP_REQUEST_ANYHOST),
                Map.entry(DROPPED_ARP_REQUEST_REPLIED, CN_DROPPED_ARP_REQUEST_REPLIED),
                Map.entry(DROPPED_ARP_UNKNOWN, CN_DROPPED_ARP_UNKNOWN),
                Map.entry(DROPPED_ARP_V6_ONLY, CN_DROPPED_ARP_V6_ONLY),
                Map.entry(DROPPED_GARP_REPLY, CN_DROPPED_GARP_REPLY)
            )
    );
    private final ApfSessionInfoReported.Builder mStatsBuilder =
            ApfSessionInfoReported.newBuilder();
    private final ApfCounterList.Builder mApfCounterListBuilder = ApfCounterList.newBuilder();

    /**
     * Write the version to mStatsBuilder.
     */
    public void setVersion(final int version) {
        mStatsBuilder.setVersion(version);
    }

    /**
     * Write the memory size to mStatsBuilder.
     */
    public void setMemorySize(final int memorySize) {
        mStatsBuilder.setMemorySize(memorySize);
    }

    /**
     * Add an APF counter to the metrics builder.
     */
    public void addApfCounter(final Counter counter, final long value) {
        if (mApfCounterListBuilder.getApfCounterCount() >= MAX_NUM_OF_COUNTERS) return;
        final ApfCounter.Builder apfCounterBuilder = ApfCounter.newBuilder()
                .setCounterName(apfFilterCounterToEnum(counter))
                .setCounterValue(value);

        mApfCounterListBuilder.addApfCounter(apfCounterBuilder);
    }

    /**
     * Write the session duration to mStatsBuilder.
     */
    public void setApfSessionDurationSeconds(final int durationSeconds) {
        mStatsBuilder.setApfSessionDurationSeconds(durationSeconds);
    }

    /**
     * Write the number of times APF program updated to mStatsBuilder.
     */
    public void setNumOfTimesApfProgramUpdated(final int updatedTimes) {
        mStatsBuilder.setNumOfTimesApfProgramUpdated(updatedTimes);
    }

    /**
     * Write the maximum program size to mStatsBuilder.
     */
    public void setMaxProgramSize(final int programSize) {
        mStatsBuilder.setMaxProgramSize(programSize);
    }

    /**
     * Write the ApfSessionInfoReported proto into statsd.
     */
    public ApfSessionInfoReported statsWrite() {
        mStatsBuilder.setApfCounterList(mApfCounterListBuilder);
        final ApfSessionInfoReported stats = mStatsBuilder.build();
        final byte[] apfCounterList = stats.getApfCounterList().toByteArray();
        NetworkStackStatsLog.write(NetworkStackStatsLog.APF_SESSION_INFO_REPORTED,
                stats.getVersion(),
                stats.getMemorySize(),
                apfCounterList,
                stats.getApfSessionDurationSeconds(),
                stats.getNumOfTimesApfProgramUpdated(),
                stats.getMaxProgramSize());
        return stats;
    }

    /**
     *  Map ApfCounterTracker.Counter to {@link CounterName}.
     */
    @VisibleForTesting
    public static CounterName apfFilterCounterToEnum(final Counter counter) {
        return apfCounterMetricsMap.getOrDefault(counter, CN_UNKNOWN);
    }
}
