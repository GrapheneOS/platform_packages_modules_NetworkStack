/*
 * Copyright (C) 2024 The Android Open Source Project
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

import static com.android.net.module.util.ConnectivitySettingsUtils.PRIVATE_DNS_MODE_OFF;
import static com.android.net.module.util.ConnectivitySettingsUtils.PRIVATE_DNS_MODE_OPPORTUNISTIC;
import static com.android.net.module.util.ConnectivitySettingsUtils.PRIVATE_DNS_MODE_PROVIDER_HOSTNAME;

import android.annotation.IntDef;
import android.annotation.NonNull;
import android.net.LinkProperties;
import android.net.shared.PrivateDnsConfig;
import android.text.TextUtils;

import com.android.internal.annotations.VisibleForTesting;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * A class to perform DDR on a given network (to be implemented).
 *
 */
class DdrTracker {
    @IntDef(prefix = { "PRIVATE_DNS_MODE_" }, value = {
        PRIVATE_DNS_MODE_OFF,
        PRIVATE_DNS_MODE_OPPORTUNISTIC,
        PRIVATE_DNS_MODE_PROVIDER_HOSTNAME
    })
    @Retention(RetentionPolicy.SOURCE)
    private @interface PrivateDnsMode {}

    // Stores the DNS information that is synced with current DNS configuration.
    @NonNull
    private DnsInfo mDnsInfo;

    // Stores the DoT servers discovered from strict mode hostname resolution.
    @NonNull
    private final List<InetAddress> mDotServers;

    DdrTracker() {
        mDnsInfo = new DnsInfo(new PrivateDnsConfig(false /* useTls */), new ArrayList<>());
        mDotServers = new ArrayList<>();
    }

    /**
     * If the private DNS settings on the network has changed, this function updates
     * the DnsInfo and returns true; otherwise, the DnsInfo remains the same and this function
     * returns false.
     */
    boolean notifyPrivateDnsSettingsChanged(@NonNull PrivateDnsConfig cfg) {
        if (arePrivateDnsSettingsEquals(cfg, mDnsInfo.cfg)) return false;

        mDnsInfo = new DnsInfo(cfg, mDnsInfo.dnsServers);
        resetStrictModeHostnameResolutionResult();
        return true;
    }

    /**
     * If the unencrypted DNS server list on the network has changed (even if only the order has
     * changed), this function updates the DnsInfo and returns true; otherwise, the DnsInfo remains
     * unchanged and this function returns false.
     *
     * The reason that this method returns true even if only the order has changed is that
     * DnsResolver returns a DNS answer to app side as soon as it receives a DNS response from
     * a DNS server. Therefore, the DNS response from the first DNS server that supports DDR
     * determines the DDR result.
     */
    boolean notifyLinkPropertiesChanged(@NonNull LinkProperties lp) {
        final List<InetAddress> servers = lp.getDnsServers();

        if (servers.equals(mDnsInfo.dnsServers)) return false;

        mDnsInfo = new DnsInfo(mDnsInfo.cfg, servers);
        return true;
    }

    void setStrictModeHostnameResolutionResult(@NonNull InetAddress[] ips) {
        resetStrictModeHostnameResolutionResult();
        mDotServers.addAll(Arrays.asList(ips));
    }

    void resetStrictModeHostnameResolutionResult() {
        mDotServers.clear();
    }

    @VisibleForTesting
    @PrivateDnsMode int getPrivateDnsMode() {
        return mDnsInfo.cfg.mode;
    }

    // Returns a non-empty string (strict mode) or an empty string (off/opportunistic mode) .
    @VisibleForTesting
    @NonNull
    String getStrictModeHostname() {
        return mDnsInfo.cfg.hostname;
    }

    @VisibleForTesting
    @NonNull
    List<InetAddress> getDnsServers() {
        return mDnsInfo.dnsServers;
    }

    private static boolean arePrivateDnsSettingsEquals(@NonNull PrivateDnsConfig a,
            @NonNull PrivateDnsConfig b) {
        return a.mode == b.mode && TextUtils.equals(a.hostname, b.hostname);
    }

    /**
     * A class to store current DNS configuration. Only the information relevant to DDR is stored.
     *   1. Private DNS setting.
     *   2. A list of Unencrypted DNS servers.
     */
    private static class DnsInfo {
        @NonNull
        public final PrivateDnsConfig cfg;
        @NonNull
        public final List<InetAddress> dnsServers;

        DnsInfo(@NonNull PrivateDnsConfig cfg, @NonNull List<InetAddress> dnsServers) {
            this.cfg = cfg;
            this.dnsServers = dnsServers;
        }
    }
}
