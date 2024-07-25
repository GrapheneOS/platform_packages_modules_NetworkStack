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

import com.android.net.module.util.DnsUtils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Collection of utilities for APF mDNS functionalities.
 *
 * @hide
 */
public class ApfMdnsUtils {

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

    private static String[] prepend(String[] suffix, String... prefixes) {
        String[] result = new String[prefixes.length + suffix.length];
        System.arraycopy(prefixes, 0, result, 0, prefixes.length);
        System.arraycopy(suffix, 0, result, prefixes.length, suffix.length);
        return result;
    }


    /**
     * Extract the offload rules from the list of offloadServiceInfos. The rules are returned in
     * priority order (most important first). If there are too many rules, APF could decide only
     * offload the rules with the higher priority.
     */
    @RequiresApi(Build.VERSION_CODES.VANILLA_ICE_CREAM)
    @NonNull
    public static List<MdnsOffloadRule> extractOffloadReplyRule(
            @NonNull List<OffloadServiceInfo> offloadServiceInfos) throws IOException {
        final List<OffloadServiceInfo> sortedOffloadServiceInfos = new ArrayList<>(
                offloadServiceInfos);
        sortedOffloadServiceInfos.sort((a, b) -> {
            int priorityA = a.getPriority();
            int priorityB = b.getPriority();
            return Integer.compare(priorityA, priorityB);
        });
        final List<MdnsOffloadRule> rules = new ArrayList<>();
        final Set<MdnsOffloadRule.Matcher> allMatchers = new ArraySet<>();
        for (OffloadServiceInfo info : sortedOffloadServiceInfos) {
            // Don't offload the records if the priority is not configured.
            int priority = info.getPriority();
            if (priority == Integer.MAX_VALUE) {
                continue;
            }
            List<MdnsOffloadRule.Matcher> matcherGroup = new ArrayList<>();
            final OffloadServiceInfo.Key key = info.getKey();
            final String[] serviceTypeLabels = key.getServiceType().split("\\.", 0);
            final String[] fullQualifiedName = prepend(serviceTypeLabels, key.getServiceName());
            final byte[] replyPayload = info.getOffloadPayload();
            final byte[] encodedServiceType = encodeQname(serviceTypeLabels);
           // If (QTYPE == PTR) and (QNAME == mServiceName + mServiceType), then reply.
            MdnsOffloadRule.Matcher ptrMatcher = new MdnsOffloadRule.Matcher(
                    encodedServiceType,
                    TYPE_PTR
            );
            addMatcherIfNotExist(allMatchers, matcherGroup, ptrMatcher);
            final List<String> subTypes = info.getSubtypes();
            // If subtype list is less than MAX_SUPPORTED_SUBTYPES, then matching each subtype.
            // Otherwise, use wildcard matching and fail open.
            boolean tooManySubtypes = subTypes.size() > MAX_SUPPORTED_SUBTYPES;
            if (tooManySubtypes) {
                // If (QTYPE == PTR) and (QNAME == wildcard + _sub + mServiceType), then fail open.
                final String[] serviceTypeSuffix = prepend(serviceTypeLabels, "_sub");
                final ByteArrayOutputStream buf = new ByteArrayOutputStream();
                // byte = 0xff is used as a wildcard.
                buf.write(-1);
                final byte[] encodedFullServiceType = encodeQname(buf, serviceTypeSuffix);
                final MdnsOffloadRule.Matcher subtypePtrMatcher = new MdnsOffloadRule.Matcher(
                        encodedFullServiceType, TYPE_PTR);
                addMatcherIfNotExist(allMatchers, matcherGroup, subtypePtrMatcher);
            } else {
                // If (QTYPE == PTR) and (QNAME == subType + _sub + mServiceType), then reply.
                for (String subType : subTypes) {
                    final String[] fullServiceType = prepend(serviceTypeLabels, subType, "_sub");
                    final byte[] encodedFullServiceType = encodeQname(fullServiceType);
                    // If (QTYPE == PTR) and (QNAME == subType + "_sub" + mServiceType), then reply.
                    final MdnsOffloadRule.Matcher subtypePtrMatcher = new MdnsOffloadRule.Matcher(
                            encodedFullServiceType, TYPE_PTR);
                    addMatcherIfNotExist(allMatchers, matcherGroup, subtypePtrMatcher);
                }
            }
            final byte[] encodedFullQualifiedNameQname = encodeQname(fullQualifiedName);
            // If (QTYPE == SRV) and (QNAME == mServiceName + mServiceType), then reply.
            addMatcherIfNotExist(allMatchers, matcherGroup,
                    new MdnsOffloadRule.Matcher(encodedFullQualifiedNameQname, TYPE_SRV));
            // If (QTYPE == TXT) and (QNAME == mServiceName + mServiceType), then reply.
            addMatcherIfNotExist(allMatchers, matcherGroup,
                    new MdnsOffloadRule.Matcher(encodedFullQualifiedNameQname, TYPE_TXT));
            // If (QTYPE == A or AAAA) and (QNAME == mDeviceHostName), then reply.
            final String[] hostNameLabels = info.getHostname().split("\\.", 0);
            final byte[] encodedHostName = encodeQname(hostNameLabels);
            addMatcherIfNotExist(allMatchers, matcherGroup,
                    new MdnsOffloadRule.Matcher(encodedHostName, TYPE_A));
            addMatcherIfNotExist(allMatchers, matcherGroup,
                    new MdnsOffloadRule.Matcher(encodedHostName, TYPE_AAAA));
            if (!matcherGroup.isEmpty()) {
                rules.add(new MdnsOffloadRule(matcherGroup, tooManySubtypes ? null : replyPayload));
            }
        }
        return rules;
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
