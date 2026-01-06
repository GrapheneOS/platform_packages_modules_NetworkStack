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
package android.net.apf;

import static android.net.nsd.OffloadEngine.OFFLOAD_TYPE_FILTER_REPLIES;
import static android.net.nsd.OffloadEngine.OFFLOAD_TYPE_REPLY;

import static com.android.net.module.util.NetworkStackConstants.TYPE_A;
import static com.android.net.module.util.NetworkStackConstants.TYPE_AAAA;
import static com.android.net.module.util.NetworkStackConstants.TYPE_PTR;
import static com.android.net.module.util.NetworkStackConstants.TYPE_SRV;
import static com.android.net.module.util.NetworkStackConstants.TYPE_TXT;

import android.annotation.NonNull;
import android.annotation.RequiresApi;
import android.net.nsd.OffloadServiceInfo;
import android.os.Build;
import android.util.ArraySet;

import com.android.net.module.util.CollectionUtils;
import com.android.net.module.util.DnsUtils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

/**
 * Collection of utilities for APF mDNS functionalities.
 *
 * @hide
 */
public class ApfMdnsUtils {

    public static class MdnsRules {
        public final List<MdnsOffloadRule> offloadRules;
        public final List<MdnsOffloadRule> filterRules;
        public MdnsRules(List<MdnsOffloadRule> offloadRules, List<MdnsOffloadRule> filterRules) {
            this.offloadRules = offloadRules;
            this.filterRules = filterRules;
        }
    }

    private static final int MAX_SUPPORTED_SUBTYPES = 3;
    private ApfMdnsUtils() {}

    private static void addMatcherIfNotExist(@NonNull Set<MdnsOffloadRule.Matcher> allMatchers,
            @NonNull List<MdnsOffloadRule.Matcher> matcherGroup,
            @NonNull MdnsOffloadRule.Matcher matcher) {
        if (allMatchers.contains(matcher)) {
            return;
        }
        matcherGroup.add(matcher);
        allMatchers.add(matcher);
    }

    private static boolean isOffloadTypeMatched(@NonNull OffloadServiceInfo info, int offloadType) {
        return (info.getOffloadType() & offloadType) != 0;
    }

    private static byte[] getEncodedWildcardSubtypeService(@NonNull String[] serviceTypeLabels)
            throws IOException {
        final String[] serviceTypeSuffix = CollectionUtils.prependArray(String.class,
            serviceTypeLabels, "_sub");
        final ByteArrayOutputStream buf = new ByteArrayOutputStream();
        // byte = 0xff is used as a wildcard.
        buf.write(-1);
        return encodeQname(buf, serviceTypeSuffix);
    }

    /**
     * Determines if an mDNS request is a discovery request based on the service name.
     *
     * In mDNS, a request with an empty service name is used to discover available services
     * rather than targeting a specific service instance. In contrast, service registration and
     * service resolution requests will always include a non-empty service name.
     *
     * @param serviceName The service name from the mDNS request.
     * @return {@code true} if the {@code serviceName} is empty, which is a discovery request.
     */
    private static boolean isDiscoveryRequest(@NonNull String serviceName) {
        return serviceName.isEmpty();
    }

    /**
     * Determines if the provided list contains any valid subtype.
     *
     * A list is considered to NOT have a valid subtype if it is either completely empty
     * or if it contains exactly one element that is an empty string. Any other list
     * composition implies that a subtype exists.
     *
     * @param subtypes The list of potential subtype strings.
     * @return {@code true} if the list contains elements and is not equal to [" "],
     *         {@code false} otherwise.
     */
    private static boolean isSubTypeExist(@NonNull List<String> subtypes) {
        if (subtypes.isEmpty()) {
            return false;
        }

        return !subtypes.equals(Arrays.asList(""));
    }

    private static void processOffloadRules(
            @NonNull List<MdnsOffloadRule> rules,
            @NonNull Set<MdnsOffloadRule.Matcher> allMatchers,
            @NonNull OffloadServiceInfo info)  throws IOException {
        List<MdnsOffloadRule.Matcher> matcherGroup = new ArrayList<>();
        final OffloadServiceInfo.Key key = info.getKey();
        final String[] serviceTypeLabels = CollectionUtils.appendArray(String.class,
            key.getServiceType().split("\\.", 0), "local");
        final String[] fullQualifiedName = CollectionUtils.prependArray(String.class,
            serviceTypeLabels, key.getServiceName());
        final byte[] replyPayload = info.getOffloadPayload();
        final byte[] encodedServiceType = encodeQname(serviceTypeLabels);
        // If (QTYPE == PTR) and (QNAME == mServiceName + mServiceType), then reply.
        MdnsOffloadRule.Matcher ptrMatcher = new MdnsOffloadRule.Matcher(
                encodedServiceType,
                new int[] { TYPE_PTR }
        );
        addMatcherIfNotExist(allMatchers, matcherGroup, ptrMatcher);
        final List<String> subTypes = info.getSubtypes();
        // If subtype list is less than MAX_SUPPORTED_SUBTYPES, then matching each subtype.
        // Otherwise, use wildcard matching and fail open.
        boolean tooManySubtypes = subTypes.size() > MAX_SUPPORTED_SUBTYPES;
        if (tooManySubtypes) {
            // If (QTYPE == PTR) and (QNAME == wildcard + _sub + mServiceType),
            // then fail open.
            final byte[] encodedFullServiceType =
                    getEncodedWildcardSubtypeService(serviceTypeLabels);
            final MdnsOffloadRule.Matcher subtypePtrMatcher = new MdnsOffloadRule.Matcher(
                    encodedFullServiceType, new int[] { TYPE_PTR });
            addMatcherIfNotExist(allMatchers, matcherGroup, subtypePtrMatcher);
        } else {
            // If (QTYPE == PTR) and (QNAME == subType + _sub + mServiceType), then reply.
            for (String subType : subTypes) {
                final String[] fullServiceType = CollectionUtils.prependArray(String.class,
                    serviceTypeLabels, subType, "_sub");
                final byte[] encodedFullServiceType = encodeQname(fullServiceType);
                // If (QTYPE == PTR) and (QNAME == subType + "_sub" + mServiceType),
                // then reply.
                final MdnsOffloadRule.Matcher subtypePtrMatcher =
                        new MdnsOffloadRule.Matcher(
                                encodedFullServiceType,
                                new int[] { TYPE_PTR }
                        );
                addMatcherIfNotExist(allMatchers, matcherGroup, subtypePtrMatcher);
            }
        }
        final byte[] encodedFullQualifiedNameQname = encodeQname(fullQualifiedName);
        // If (QTYPE == SRV) and (QNAME == mServiceName + mServiceType), then reply.
        // If (QTYPE == TXT) and (QNAME == mServiceName + mServiceType), then reply.
        addMatcherIfNotExist(allMatchers, matcherGroup,
                new MdnsOffloadRule.Matcher(encodedFullQualifiedNameQname,
                    new int[] { TYPE_SRV, TYPE_TXT }));
        // If (QTYPE == A or AAAA) and (QNAME == mDeviceHostName), then reply.
        final String[] hostNameLabels = info.getHostname().split("\\.", 0);
        final byte[] encodedHostName = encodeQname(hostNameLabels);
        addMatcherIfNotExist(allMatchers, matcherGroup,
                new MdnsOffloadRule.Matcher(encodedHostName,
                    new int[] { TYPE_A, TYPE_AAAA }));
        if (!matcherGroup.isEmpty()) {
            rules.add(new MdnsOffloadRule(
                    key.getServiceName() + "." + key.getServiceType(),
                    matcherGroup, tooManySubtypes ? null : replyPayload));
        }
    }

    /**
     * Processes a single {@link OffloadServiceInfo} to generate mDNS filter rules and matchers.
     *
     * This method creates {@link MdnsOffloadRule.Matcher} instances based on the type of mDNS
     * request represented by the {@code info}:
     *  - Discovery Requests: (Empty service name) Matches PTR records for the service type
     *       and, if subtypes are present, for wildcard subtype queries.
     *  - Advertise/Resolve Requests: (Non-empty service name) Matches SRV/TXT records
     *       based on the full service instance name (serviceName.serviceType).
     *  - Hostname Resolution: If a hostname is provided in {@code info}, matches A/AAAA
     *       records for the hostname.
     *
     * Note on QTYPE Matching: The generated matchers only consider the QNAME. QTYPE is not
     * used for filtering in the underlying APF (Android Packet Filter) layer. This is because
     * the APF instruction {@code ApfV6GeneratorBase#addJumpIfPktAtR0ContainDnsA} matches DNS
     * records in the answer section based solely on the name, regardless of the question type or
     * the record type (SRV, TXT, A, AAAA, PTR).
     *
     * @param rules The list to add the generated {@link MdnsOffloadRule} to.
     * @param allMatchers A set to keep track of all unique matchers created to avoid duplicates.
     * @param info The {@link OffloadServiceInfo} containing the details of the service to filter.
     * @throws IOException if encoding the QNAME fails.
     */
    private static void processFilterRules(
            @NonNull List<MdnsOffloadRule> rules,
            @NonNull Set<MdnsOffloadRule.Matcher> allMatchers,
            @NonNull OffloadServiceInfo info)  throws IOException  {
        final String serviceType = info.getKey().getServiceType();
        final String serviceName = info.getKey().getServiceName();
        List<MdnsOffloadRule.Matcher> matcherGroup = new ArrayList<>();
        final String[] serviceTypeLabels = CollectionUtils.appendArray(String.class,
            serviceType.split("\\.", 0), "local");

        if (!isDiscoveryRequest(serviceName)) {
            // For advertise request, the OffloadServiceInfo should be structured as follows:
            // - Non-empty: mServiceName, mServiceType
            // - Might be null or empty: mSubTypes, mHostName
            // We need to match baseType for conflict detection.
            // If (QTYPE == SRV) and (QNAME == mService + mServiceType), then pass.
            // For resolve request, the OffloadServiceInfo should be structured as follows:
            // - Non-empty: mServiceName, mServiceType
            // - Might be empty: mHostName
            // - Empty: mSubTypes
            // If (QTYPE == SRV or TXT) and (QNAME == mService + mServiceType), then pass.
            final String[] fullQualifiedName = CollectionUtils.prependArray(String.class,
                serviceTypeLabels, serviceName);
            addMatcherIfNotExist(allMatchers, matcherGroup,
                    new MdnsOffloadRule.Matcher(encodeQname(fullQualifiedName))
            );
        } else {
            // For discover request, the OffloadServiceInfo should be structured as follows:
            // - Non-empty: mServiceType
            // - Might be empty: mSubTypes
            // - Empty: mServiceName, mHostName
            final List<String> subTypes = info.getSubtypes();
            // For updates to match PTR record with baseType
            // if QNAME matches mServiceType exactly.
            // If (QTYPE == PTR) and (QNAME == mServiceType), then pass.
            final byte[] encodedServiceType = encodeQname(serviceTypeLabels);
            MdnsOffloadRule.Matcher serviceTypeMatcher =
                    new MdnsOffloadRule.Matcher(encodedServiceType);
            addMatcherIfNotExist(allMatchers, matcherGroup, serviceTypeMatcher);
            if (isSubTypeExist(subTypes)) {
                // If multiple subtypes are present in OffloadServiceInfo, match PTR records
                // with QNAMEs formatted as: <subtype>._sub.<mServiceType>, where <subtype>
                // is one of the specified subtypes.
                // If (QTYPE == PTR) and (QNAME == wildcard + ._sub + mServiceType), then pass.
                final byte[] encodedFullServiceType =
                    getEncodedWildcardSubtypeService(serviceTypeLabels);
                final MdnsOffloadRule.Matcher subtypePtrMatcher =
                        new MdnsOffloadRule.Matcher(encodedFullServiceType);
                addMatcherIfNotExist(allMatchers, matcherGroup, subtypePtrMatcher);
            }
        }

        final String hostName = info.getHostname();
        if (!hostName.isEmpty()) {
            // For resolve request, the OffloadServiceInfo should be structured as follows:
            // - Non-empty: mServiceName, mServiceType
            // - Might be empty: mHostName
            // - Empty: mSubTypes
            // If (QTYPE == A or AAAA) and (QNAME == mHostName), then pass.
            final String[] hostNameLabels = hostName.split("\\.", 0);
            final byte[] encodedHostName = encodeQname(hostNameLabels);
            addMatcherIfNotExist(allMatchers, matcherGroup,
                    new MdnsOffloadRule.Matcher(encodedHostName)
            );
        }

        if (!matcherGroup.isEmpty()) {
            rules.add(new MdnsOffloadRule(
                    serviceName + "." + serviceType,
                    matcherGroup, null /* replyPayload */)
            );
        }
    }

    /**
     * Extracts and categorizes mDNS offload rules from a list of OffloadServiceInfo objects.
     *
     * This method processes each OffloadServiceInfo to generate two types of rules:
     *   - Rules to reply to mDNS query packet: Used to directly respond to mDNS queries matching
     *     specific criteria (e.g., service type, name, subtypes). Generated from infos with type
     *     OFFLOAD_TYPE_REPLY and returned The rules are returned in priority order
     *     (most important first).
     *   - Rules for filtering mDNS replies: Used to allow certain mDNS replies to pass through.
     *     Generated from infos with type OFFLOAD_TYPE_FILTER_REPLIES. The rules in this category
     *     do not have priority.
     *
     * @param offloadServiceInfos A list of {@link OffloadServiceInfo} to process.
     * @return A {@link MdnsRules} contains two types of rules.
     * @throws IOException if an error occurs during domain name encoding.
     */
    @RequiresApi(Build.VERSION_CODES.VANILLA_ICE_CREAM)
    @NonNull
    public static MdnsRules extractReplyRule(
            @NonNull List<OffloadServiceInfo> offloadServiceInfos) throws IOException {
        final List<OffloadServiceInfo> sortedOffloadServiceInfos =
                new ArrayList<>(offloadServiceInfos);
        sortedOffloadServiceInfos.sort((a, b) -> {
            int priorityA = a.getPriority();
            int priorityB = b.getPriority();
            return Integer.compare(priorityA, priorityB);
        });
        final List<MdnsOffloadRule> offloadRules = new ArrayList<>();
        final List<MdnsOffloadRule> filterRules = new ArrayList<>();
        final Set<MdnsOffloadRule.Matcher> allOffloadMatchers = new ArraySet<>();
        final Set<MdnsOffloadRule.Matcher> allFilterMatchers = new ArraySet<>();
        for (OffloadServiceInfo info : sortedOffloadServiceInfos) {
            if (isOffloadTypeMatched(info, OFFLOAD_TYPE_REPLY)) {
                processOffloadRules(offloadRules, allOffloadMatchers, info);
            } else if (isOffloadTypeMatched(info, OFFLOAD_TYPE_FILTER_REPLIES)) {
                processFilterRules(filterRules, allFilterMatchers, info);
            }
        }
        return new MdnsRules(offloadRules, filterRules);
    }

    private static byte[] encodeQname(@NonNull ByteArrayOutputStream buf, @NonNull String[] labels)
            throws IOException {
        final String[] upperCaseLabel = DnsUtils.toDnsLabelsUpperCase(labels);
        for (final String label : upperCaseLabel) {
            int labelLength = label.length();
            if (labelLength < 1 || labelLength > 63) {
                throw new IOException("Label is too long: " + label);
            }
            buf.write(labelLength);
            buf.write(label.getBytes(StandardCharsets.UTF_8));
        }
        // APF take array of qnames as input, each qname is terminated by a 0 byte.
        // A 0 byte is required to mark the end of the list.
        // This method always writes 1-item lists, as there isn't currently a use-case for
        // multiple qnames of the same type using the same offload packet.
        buf.write(0);
        buf.write(0);
        return buf.toByteArray();
    }

    private static byte[] encodeQname(@NonNull String[] labels) throws IOException {
        final ByteArrayOutputStream buf = new ByteArrayOutputStream();
        return encodeQname(buf, labels);
    }
}
