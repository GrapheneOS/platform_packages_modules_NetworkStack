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

package android.net.apf;

import android.util.ArrayMap;
import android.util.Log;

import com.android.internal.annotations.VisibleForTesting;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * Common counter class for {@code ApfFilter} and {@code LegacyApfFilter}.
 *
 * @hide
 */
public class ApfCounterTracker {
    /**
     * APF packet counters.
     *
     * Packet counters are 32bit big-endian values, and allocated near the end of the APF data
     * buffer, using negative byte offsets, where -4 is equivalent to maximumApfProgramSize - 4,
     * the last writable 32bit word.
     */
    public enum Counter {
        RESERVED_OOB,  // Points to offset 0 from the end of the buffer (out-of-bounds)
        ENDIANNESS,              // APFv6 interpreter stores 0x12345678 here
        TOTAL_PACKETS,           // hardcoded in APFv6 interpreter
        PASSED_ALLOCATE_FAILURE, // hardcoded in APFv6 interpreter
        PASSED_TRANSMIT_FAILURE, // hardcoded in APFv6 interpreter
        CORRUPT_DNS_PACKET,      // hardcoded in APFv6 interpreter
        FILTER_AGE_SECONDS,
        FILTER_AGE_16384THS,
        APF_VERSION,
        APF_PROGRAM_ID,
        // TODO: removing PASSED_ARP after remove LegacyApfFilter.java
        // The counter sequence should keep the same as ApfSessionInfoMetrics.java
        PASSED_ARP,  // see also MIN_PASS_COUNTER below.
        PASSED_ARP_BROADCAST_REPLY,
        // TODO: removing PASSED_ARP_NON_IPV4 after remove LegacyApfFilter.java
        PASSED_ARP_NON_IPV4,
        PASSED_ARP_REQUEST,
        PASSED_ARP_UNICAST_REPLY,
        PASSED_ARP_UNKNOWN,
        PASSED_DHCP,
        PASSED_ETHER_OUR_SRC_MAC,
        PASSED_IPV4,
        PASSED_IPV4_FROM_DHCPV4_SERVER,
        PASSED_IPV4_UNICAST,
        PASSED_IPV6_ICMP,
        PASSED_IPV6_NON_ICMP,
        PASSED_IPV6_NS_DAD,
        PASSED_IPV6_NS_NO_ADDRESS,
        PASSED_IPV6_NS_NO_SLLA_OPTION,
        PASSED_IPV6_NS_TENTATIVE,
        PASSED_IPV6_UNICAST_NON_ICMP,
        PASSED_NON_IP_UNICAST,
        PASSED_MDNS,
        PASSED_MLD,  // see also MAX_PASS_COUNTER below
        DROPPED_ETH_BROADCAST,  // see also MIN_DROP_COUNTER below
        DROPPED_RA,
        DROPPED_IPV4_L2_BROADCAST,
        DROPPED_IPV4_BROADCAST_ADDR,
        DROPPED_IPV4_BROADCAST_NET,
        DROPPED_IPV4_MULTICAST,
        DROPPED_IPV4_NON_DHCP4,
        DROPPED_IPV6_ROUTER_SOLICITATION,
        DROPPED_IPV6_MULTICAST_NA,
        DROPPED_IPV6_MULTICAST,
        DROPPED_IPV6_MULTICAST_PING,
        DROPPED_IPV6_NON_ICMP_MULTICAST,
        DROPPED_IPV6_NS_INVALID,
        DROPPED_IPV6_NS_OTHER_HOST,
        DROPPED_IPV6_NS_REPLIED_NON_DAD,
        DROPPED_802_3_FRAME,
        DROPPED_ETHERTYPE_NOT_ALLOWED,
        DROPPED_IPV4_KEEPALIVE_ACK,
        DROPPED_IPV6_KEEPALIVE_ACK,
        DROPPED_IPV4_NATT_KEEPALIVE,
        DROPPED_MDNS,
        DROPPED_IPV4_TCP_PORT7_UNICAST,
        DROPPED_ARP_NON_IPV4,
        DROPPED_ARP_OTHER_HOST,
        DROPPED_ARP_REPLY_SPA_NO_HOST,
        DROPPED_ARP_REQUEST_ANYHOST,
        DROPPED_ARP_REQUEST_REPLIED,
        DROPPED_ARP_UNKNOWN,
        DROPPED_ARP_V6_ONLY,
        DROPPED_GARP_REPLY;  // see also MAX_DROP_COUNTER below

        /**
         * Returns the negative byte offset from the end of the APF data segment for
         * a given counter.
         */
        public int offset() {
            return -this.ordinal() * 4;  // Currently, all counters are 32bit long.
        }

        /**
         * Returns the counter sequence number from the end of the APF data segment for
         * a given counter.
         */
        public int value() {
            return this.ordinal();
        }

        /**
         * Returns the total size of the data segment in bytes.
         */
        public static int totalSize() {
            return (Counter.class.getEnumConstants().length - 1) * 4;
        }

        /**
         * Returns the counter enum based on the offset.
         */
        @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
        public static Counter getCounterEnumFromOffset(int offset) {
            for (Counter cnt : Counter.class.getEnumConstants()) {
                if (cnt.offset() == offset) {
                    return cnt;
                }
            }
            return RESERVED_OOB;
        }
    }

    public static final Counter MIN_DROP_COUNTER = Counter.DROPPED_ETH_BROADCAST;
    public static final Counter MAX_DROP_COUNTER = Counter.DROPPED_GARP_REPLY;
    public static final Counter MIN_PASS_COUNTER = Counter.PASSED_ARP;
    public static final Counter MAX_PASS_COUNTER = Counter.PASSED_MLD;

    private static final String TAG = ApfCounterTracker.class.getSimpleName();

    private final List<Counter> mCounterList;
    // Store the counters' value
    private final Map<Counter, Long> mCounters = new ArrayMap<>();

    public ApfCounterTracker() {
        Counter[] counters = Counter.class.getEnumConstants();
        mCounterList = Arrays.asList(counters).subList(1, counters.length);
    }

    /**
     * Get the value of a counter from APF data.
     */
    public static long getCounterValue(byte[] data, Counter counter)
            throws ArrayIndexOutOfBoundsException {
        int offset = data.length + Counter.ENDIANNESS.offset();
        int endianness = 0;
        for (int i = 0; i < 4; i++) {
            endianness = endianness << 8 | (data[offset + i] & 0xff);
        }
        // Follow the same wrap-around addressing scheme of the interpreter.
        offset = data.length + counter.offset();

        boolean isBe = true;
        switch (endianness) {
            case 0:
            case 0x12345678:
                isBe = true;
                break;
            case 0x78563412:
                isBe = false;
                break;
            default:
                Log.wtf(TAG, "Unknown endianness: 0x" + Integer.toHexString(endianness));
        }

        // Decode 32bit big-endian integer into a long so we can count up beyond 2^31.
        long value = 0;
        for (int i = 0; i < 4; i++) {
            value = value << 8 | (data[offset + (isBe ? i : 3 - i)] & 0xff);
        }
        return value;
    }

    /**
     * Update counters from APF data.
     */
    public void updateCountersFromData(byte[] data) {
        if (data == null) return;
        for (Counter counter : mCounterList) {
            long value;
            try {
                value = getCounterValue(data, counter);
            } catch (ArrayIndexOutOfBoundsException e) {
                value = 0;
            }
            long oldValue = mCounters.getOrDefault(counter, 0L);
            // All counters are incremental
            if (value > oldValue) {
                mCounters.put(counter, value);
            }
        }
    }

    /**
     * Get counters map.
     */
    public Map<Counter, Long> getCounters() {
        return mCounters;
    }

    /**
     * Clear all counters.
     */
    public void clearCounters() {
        mCounters.clear();
    }
}
