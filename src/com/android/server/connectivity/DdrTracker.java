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

import static android.net.DnsResolver.CLASS_IN;

import static com.android.net.module.util.CollectionUtils.isEmpty;
import static com.android.net.module.util.ConnectivitySettingsUtils.PRIVATE_DNS_MODE_OFF;
import static com.android.net.module.util.ConnectivitySettingsUtils.PRIVATE_DNS_MODE_OPPORTUNISTIC;
import static com.android.net.module.util.ConnectivitySettingsUtils.PRIVATE_DNS_MODE_PROVIDER_HOSTNAME;
import static com.android.net.module.util.DnsPacket.TYPE_SVCB;

import android.annotation.IntDef;
import android.annotation.NonNull;
import android.annotation.Nullable;
import android.net.DnsResolver;
import android.net.LinkProperties;
import android.net.Network;
import android.net.shared.PrivateDnsConfig;
import android.os.CancellationSignal;
import android.text.TextUtils;
import android.util.Log;

import com.android.internal.annotations.VisibleForTesting;
import com.android.net.module.util.DnsPacket;
import com.android.net.module.util.DnsSvcbPacket;
import com.android.net.module.util.SharedLog;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Executor;

/**
 * A class to perform DDR on a given network.
 *
 * Caller can use startSvcbLookup() to perform DNS SVCB lookup asynchronously. The result of the
 * lookup will be passed to callers through the callback onSvcbLookupComplete(). If the result is
 * stale, the callback won't be invoked. A result becomes stale once there's a new call to
 * startSvcbLookup().
 *
 * Threading:
 *
 * 1. DdrTracker is not thread-safe. All public methods must be executed on the same thread to
 *    guarantee that all DdrTracker members are synchronized.
 * 2. In DdrTracker constructor, an Executor is provided as the execution thread on which the
 *    callback onSvcbLookupComplete() will be executed. The execution thread must be the same
 *    as the thread mentioned in 1.
 */
class DdrTracker {
    private static final String TAG = "DDR";
    private static final boolean DBG  = true;

    @IntDef(prefix = { "PRIVATE_DNS_MODE_" }, value = {
        PRIVATE_DNS_MODE_OFF,
        PRIVATE_DNS_MODE_OPPORTUNISTIC,
        PRIVATE_DNS_MODE_PROVIDER_HOSTNAME
    })
    @Retention(RetentionPolicy.SOURCE)
    private @interface PrivateDnsMode {}

    @VisibleForTesting
    static final String DDR_HOSTNAME = "_dns.resolver.arpa";

    private static final String ALPN_DOH3 = "h3";

    interface Callback {
        /**
         * Called on a given execution thread `mExecutor` when a SVCB lookup finishes, unless
         * the lookup result is stale.
         * The parameter `result` contains the aggregated result that contains both DoH and DoT
         * information.
         */
        void onSvcbLookupComplete(@NonNull PrivateDnsConfig result);
    }

    @NonNull
    private final Network mCleartextDnsNetwork;
    @NonNull
    private final DnsResolver mDnsResolver;
    @NonNull
    private final Callback mCallback;

    // The execution thread the callback will be executed on.
    @NonNull
    private final Executor mExecutor;

    // Stores the DNS information that is synced with current DNS configuration.
    @NonNull
    private DnsInfo mDnsInfo;

    // Stores the DoT servers discovered from strict mode hostname resolution.
    @NonNull
    private final List<InetAddress> mDotServers;

    // Stores the result of latest SVCB lookup.
    // It is set to null if the result is invalid, for example, lookup timeout or invalid
    // SVCB responses.
    @Nullable
    private DnsSvcbPacket mLatestSvcbPacket = null;

    // Used to check whether a DDR result is stale.
    // Given the Threading section documented near the beginning of this file, `mTokenId` ensures
    // that mLatestSvcbRecord is always fresh.
    @NonNull
    private int mTokenId;

    // Used to cancel the in-progress SVCB lookup.
    @NonNull
    CancellationSignal mCancelSignal;

    private final SharedLog mValidationLogs;

    DdrTracker(@NonNull Network cleartextDnsNetwork, @NonNull DnsResolver dnsResolver,
            @NonNull Executor executor, @NonNull Callback callback, SharedLog validationLog) {
        mCleartextDnsNetwork = cleartextDnsNetwork;
        mDnsResolver = dnsResolver;
        mExecutor = executor;
        mCallback = callback;
        final PrivateDnsConfig privateDnsDisabled = new PrivateDnsConfig(PRIVATE_DNS_MODE_OFF,
                null /* hostname */, null /* ips */, true /* ddrEnabled */, null /* dohName */,
                null /* dohIps */, null /* dohPath */, -1 /* dohPort */);
        mDnsInfo = new DnsInfo(privateDnsDisabled, new ArrayList<>());
        mDotServers = new ArrayList<>();
        mCancelSignal = new CancellationSignal();
        mValidationLogs = validationLog.forSubComponent(TAG);
    }

    /**
     * If the private DNS settings on the network has changed, this function updates
     * the DnsInfo and returns true; otherwise, the DnsInfo remains the same and this function
     * returns false.
     */
    boolean notifyPrivateDnsSettingsChanged(@NonNull PrivateDnsConfig cfg) {
        if (mDnsInfo.cfg.areSettingsSameAs(cfg)) return false;

        ++mTokenId;
        mDnsInfo = new DnsInfo(cfg, getDnsServers());
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

        if (servers.equals(getDnsServers())) return false;

        ++mTokenId;
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

    private boolean hasSvcbAnswer(@NonNull String alpn) {
        return (mLatestSvcbPacket != null) ? mLatestSvcbPacket.isSupported(alpn) : false;
    }

    @Nullable
    private String getTargetNameFromSvcbAnswer(@NonNull String alpn) {
        return (mLatestSvcbPacket != null) ? mLatestSvcbPacket.getTargetName(alpn) : null;
    }

    // Returns a list of IP addresses for the target name from the latest SVCB packet.
    // These may be either from the A/AAAA records in the additional section or from the
    // ipv4hint/ipv6hint keys in the SVCB record.
    private List<InetAddress> getServersFromSvcbAnswer(@NonNull String alpn) {
        return (mLatestSvcbPacket != null) ? mLatestSvcbPacket.getAddresses(alpn)
                : Collections.emptyList();
    }

    private int getPortFromSvcbAnswer(@NonNull String alpn) {
        return (mLatestSvcbPacket != null) ? mLatestSvcbPacket.getPort(alpn) : -1;
    }

    @Nullable
    private String getDohPathFromSvcbAnswer(@NonNull String alpn) {
        return (mLatestSvcbPacket != null) ? mLatestSvcbPacket.getDohPath(alpn) : null;
    }

    @NonNull
    private String createHostnameForSvcbQuery() {
        final String hostname = getStrictModeHostname();
        if (!TextUtils.isEmpty(hostname)) {
            return "_dns." + hostname;
        }
        return DDR_HOSTNAME;
    }

    /** Performs a DNS SVCB Lookup asynchronously. */
    void startSvcbLookup() {
        if (getPrivateDnsMode() == PRIVATE_DNS_MODE_OFF) {
            // Ensure getResultForReporting returns reasonable results.
            mLatestSvcbPacket = null;
            // We do not need to increment the token. The token is used to ignore stale results.
            // But there can only be lookups in flight if the mode was previously on. Because the
            // mode is now off,  that means the mode changed, and that incremented the token.
            return;
        }
        // There are some cases where startSvcbLookup() is called twice in a row that
        // are likely to lead to the same result, for example:
        //   1. A network is connected when private DNS mode is strict mode.
        //   2. Private DNS mode is switched to strict mode.
        // To avoid duplicate lookups, cancel the in-progress SVCB lookup (if any).
        //
        // Note that cancelling is not currently very useful because the DNS resolver still
        // continues to retry until the query completes or fails. It does prevent the query callback
        // from being called, but that's not necessary because the token will not match.
        // We still do attempt to cancel the query so future improvements to the DNS resolver could
        // use that to do less work.
        mCancelSignal.cancel();
        mCancelSignal = new CancellationSignal();

        // Increment the token ID to stale all in-flight lookups.
        // This is for network revalidation in strict mode that a SVCB lookup can be performed
        // and its result can be accepted even if there is no DNS configuration change.
        final int token = ++mTokenId;
        final String hostname = createHostnameForSvcbQuery();
        final DnsResolver.Callback<byte[]> callback = new DnsResolver.Callback<byte[]>() {
            boolean isResultFresh() {
                return token == mTokenId;
            }

            void updateSvcbAnswerAndInvokeUserCallback(@Nullable DnsSvcbPacket result) {
                mLatestSvcbPacket = result;
                mCallback.onSvcbLookupComplete(getResultForReporting());
            }

            @Override
            public void onAnswer(@NonNull byte[] answer, int rcode) {
                if (!isResultFresh()) {
                    validationLog("Ignoring stale SVCB answer");
                    return;
                }

                if (rcode != 0 || answer.length == 0) {
                    validationLog("Ignoring invalid SVCB answer: rcode=" + rcode
                            + " len=" + answer.length);
                    updateSvcbAnswerAndInvokeUserCallback(null);
                    return;
                }

                final DnsSvcbPacket pkt;
                try {
                    pkt = DnsSvcbPacket.fromResponse(answer);
                } catch (DnsPacket.ParseException e) {
                    validationLog("Ignoring malformed SVCB answer: " + e);
                    updateSvcbAnswerAndInvokeUserCallback(null);
                    return;
                }

                validationLog("Processing SVCB response: " + pkt);
                updateSvcbAnswerAndInvokeUserCallback(pkt);
            }

            @Override
            public void onError(@NonNull DnsResolver.DnsException e) {
                validationLog("DNS error resolving SVCB record for " + hostname + ": " + e);
                if (isResultFresh()) {
                    updateSvcbAnswerAndInvokeUserCallback(null);
                }
            }
        };
        sendDnsSvcbQuery(hostname, mCancelSignal, callback);
    }

    /**
     * Returns candidate IP addresses to use for DoH.
     *
     * These can come from A/AAAA records returned by strict mode hostname resolution, from A/AAAA
     * records in the additional section of the SVCB response, or from the ipv4hint/ipv6hint keys in
     * the H3 ALPN of the SVCB record itself.
     *
     * RFC 9460 §7.3 says that if A and AAAA records for TargetName are locally available, the
     * client SHOULD ignore the hints.
     *
     * - In opportunistic mode, strict name hostname resolution does not happen, so always use the
     *   addresses in the SVCB response
     * - In strict mode:
     *   - If the target name in the H3 ALPN matches the strict mode hostname, prefer the result of
     *     strict mode hostname resolution.
     *   - If not, prefer the addresses from the SVCB response, but fall back to A/AAAA records if
     *     there are none. This ensures that:
     *     - If the strict mode hostname has A/AAAA addresses, those are used even if there are no
     *       addresses in the SVCB record.
     *
     * Note that in strict mode, this class always uses the user-specified hostname and ignores the
     * target hostname in the SVCB record (see getResultForReporting). In this case, preferring the
     * addresses in the SVCB record at ensures that those addresses are used, even if the target
     * hostname is not.
     */
    private List<InetAddress> getTargetNameIpAddresses(@NonNull String alpn) {
        final List<InetAddress> serversFromSvcbAnswer = getServersFromSvcbAnswer(alpn);
        final String hostname = getStrictModeHostname();
        if (TextUtils.isEmpty(hostname)) {
            return serversFromSvcbAnswer;
        }
        // Strict mode can use either A/AAAA records coming from strict mode resolution or the
        // addresses from the SVCB response (which could be A/AAAA records in the additional section
        // or the hints in the SVCB record itself).
        final String targetName = getTargetNameFromSvcbAnswer(alpn);
        if (TextUtils.equals(targetName, hostname) && !mDotServers.isEmpty()) {
            return mDotServers;
        }
        if (isEmpty(serversFromSvcbAnswer)) {
            return mDotServers;
        }
        return serversFromSvcbAnswer;
    }

    /**
     * To follow the design of private DNS opportunistic mode, which is similar to RFC 9462 §4.3,
     * don't use a designated resolver if its IP address differs from all the unencrypted resolvers'
     * IP addresses.
     *
     * TODO: simplify the code by merging this method with getTargetNameIpAddresses above.
     */
    private InetAddress[] getDohServers(@NonNull String alpn) {
        final List<InetAddress> candidates = getTargetNameIpAddresses(alpn);
        if (isEmpty(candidates)) return null;
        if (getPrivateDnsMode() == PRIVATE_DNS_MODE_PROVIDER_HOSTNAME) return toArray(candidates);

        candidates.retainAll(getDnsServers());
        return toArray(candidates);
    }

    /**
     * Returns the aggregated private DNS discovery result as a PrivateDnsConfig.
     * getResultForReporting() is called in the following cases:
     * 1. when the hostname lookup completes.
     * 2. when the SVCB lookup completes.
     *
     * There is no guarantee which lookup will complete first. Therefore, depending on the private
     * DNS mode and the SVCB answer, the return PrivateDnsConfig might be set with DoT, DoH,
     * DoT+DoH, or even no servers.
     */
    @NonNull
    PrivateDnsConfig getResultForReporting() {
        final String strictModeHostname = getStrictModeHostname();
        final InetAddress[] dotIps = toArray(mDotServers);
        final PrivateDnsConfig candidateResultWithDotOnly =
                new PrivateDnsConfig(getPrivateDnsMode(), strictModeHostname, dotIps,
                        true /* ddrEnabled */, null /* dohName */, null /* dohIps */,
                        null /* dohPath */, -1 /* dohPort */);

        if (!hasSvcbAnswer(ALPN_DOH3)) {
            // TODO(b/240259333): Consider not invoking notifyPrivateDnsConfigResolved() if
            // DoT server list is empty.
            return candidateResultWithDotOnly;
        }

        // The SVCB answer should be fresh.

        final String dohName = (getPrivateDnsMode() == PRIVATE_DNS_MODE_PROVIDER_HOSTNAME)
                ? strictModeHostname : getTargetNameFromSvcbAnswer(ALPN_DOH3);
        final InetAddress[] dohIps = getDohServers(ALPN_DOH3);
        final String dohPath = getDohPathFromSvcbAnswer(ALPN_DOH3);
        final int dohPort = getPortFromSvcbAnswer(ALPN_DOH3);

        return new PrivateDnsConfig(getPrivateDnsMode(), strictModeHostname, dotIps, true,
                dohName, dohIps, dohPath, dohPort);
    }

    private void validationLog(String s) {
        log(s);
        mValidationLogs.log(s);
    }

    private void log(String s) {
        if (DBG) Log.d(TAG + "/" + mCleartextDnsNetwork.toString(), s);
    }

    /**
     * A non-blocking call doing DNS SVCB lookup.
     */
    private void sendDnsSvcbQuery(String host, @NonNull CancellationSignal cancelSignal,
            @NonNull DnsResolver.Callback<byte[]> callback) {
        // Note: the even though this code does not pass FLAG_NO_CACHE_LOOKUP, the query is
        // currently not cached, because the DNS resolver cache does not cache SVCB records.
        // TODO: support caching SVCB records in the DNS resolver cache.
        // This should just work but will need testing.
        mDnsResolver.rawQuery(mCleartextDnsNetwork, host, CLASS_IN, TYPE_SVCB, 0 /* flags */,
                mExecutor, cancelSignal, callback);
    }

    private static InetAddress[] toArray(List<InetAddress> list) {
        if (list == null) {
            return null;
        }
        return list.toArray(new InetAddress[0]);
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
