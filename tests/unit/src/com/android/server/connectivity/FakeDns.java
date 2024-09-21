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

import static android.net.DnsResolver.TYPE_A;
import static android.net.DnsResolver.TYPE_AAAA;
import static android.net.InetAddresses.parseNumericAddress;

import static com.android.net.module.util.DnsPacket.TYPE_SVCB;

import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyInt;
import static org.mockito.Mockito.doAnswer;

import android.net.DnsResolver;
import android.net.Network;
import android.os.Handler;
import android.os.Looper;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.android.testutils.DnsSvcbUtils;

import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Fakes DNS responses.
 *
 * Allows test methods to configure the IP addresses that will be resolved by
 * Network#getAllByName and by various DnsResolver query methods.
 */
public class FakeDns {
    private static final int HANDLER_TIMEOUT_MS = 1000;

    @NonNull
    private final Network mNetwork;
    @NonNull
    private final DnsResolver mDnsResolver;
    private final ArrayList<DnsEntry> mAnswers = new ArrayList<>();
    private boolean mNonBypassPrivateDnsWorking = true;

    public FakeDns(@NonNull Network network, @NonNull DnsResolver dnsResolver) {
        mNetwork = Objects.requireNonNull(network);
        mDnsResolver = Objects.requireNonNull(dnsResolver);
    }

    /** Data class to record the Dns entry. */
    private static class DnsEntry {
        final String mHostname;
        final int mType;
        final AnswerSupplier mAnswerSupplier;
        DnsEntry(String host, int type, AnswerSupplier answerSupplier) {
            mHostname = host;
            mType = type;
            mAnswerSupplier = answerSupplier;
        }
        // Full match or partial match that target host contains the entry hostname to support
        // random private dns probe hostname.
        private boolean matches(String hostname, int type) {
            return hostname.endsWith(mHostname) && type == mType;
        }
    }

    public interface AnswerSupplier {
        /** Supplies the answer to one DnsResolver query method call. */
        @Nullable
        String[] get() throws DnsResolver.DnsException;
    }

    private static class InstantAnswerSupplier implements AnswerSupplier {
        private final String[] mAnswers;
        InstantAnswerSupplier(String[] answers) {
            mAnswers = answers;
        }
        @Override
        @Nullable
        public String[] get() {
            return mAnswers;
        }
    }

    /** Whether DNS queries on mNonBypassPrivateDnsWorking should succeed. */
    public void setNonBypassPrivateDnsWorking(boolean working) {
        mNonBypassPrivateDnsWorking = working;
    }

    /** Clears all DNS entries. */
    public void clearAll() {
        synchronized (mAnswers) {
            mAnswers.clear();
        }
    }

    /** Returns the answer for a given name and type on the given mock network. */
    private CompletableFuture<String[]> getAnswer(Network mockNetwork, String hostname,
            int type) {
        if (mNetwork.equals(mockNetwork) && !mNonBypassPrivateDnsWorking) {
            return CompletableFuture.completedFuture(null);
        }

        final AnswerSupplier answerSupplier;

        synchronized (mAnswers) {
            answerSupplier = mAnswers.stream()
                    .filter(e -> e.matches(hostname, type))
                    .map(answer -> answer.mAnswerSupplier).findFirst().orElse(null);
        }
        if (answerSupplier == null) {
            return CompletableFuture.completedFuture(null);
        }

        if (answerSupplier instanceof InstantAnswerSupplier) {
            // Save latency waiting for a query thread if the answer is hardcoded.
            return CompletableFuture.completedFuture(
                    ((InstantAnswerSupplier) answerSupplier).get());
        }
        final CompletableFuture<String[]> answerFuture = new CompletableFuture<>();
        new Thread(() -> {
            try {
                answerFuture.complete(answerSupplier.get());
            } catch (DnsResolver.DnsException e) {
                answerFuture.completeExceptionally(e);
            }
        }).start();
        return answerFuture;
    }

    /** Sets the answer for a given name and type. */
    public void setAnswer(String hostname, String[] answer, int type) {
        setAnswer(hostname, new InstantAnswerSupplier(answer), type);
    }

    /** Sets the answer for a given name and type. */
    public void setAnswer(String hostname, AnswerSupplier answerSupplier, int type) {
        DnsEntry record = new DnsEntry(hostname, type, answerSupplier);
        synchronized (mAnswers) {
            // Remove the existing one.
            mAnswers.removeIf(entry -> entry.matches(hostname, type));
            // Add or replace a new record.
            mAnswers.add(record);
        }
    }

    private byte[] makeSvcbResponse(String hostname, String[] answer) {
        try {
            return DnsSvcbUtils.makeSvcbResponse(hostname, answer);
        } catch (IOException e) {
            throw new AssertionError("Invalid test data building SVCB response for: "
                    + Arrays.toString(answer));
        }
    }

    /** Simulates a getAllByName call for the specified name on the specified mock network. */
    private InetAddress[] getAllByName(Network mockNetwork, String hostname)
            throws UnknownHostException {
        final List<InetAddress> answer;
        try {
            answer = stringsToInetAddresses(queryAllTypes(mockNetwork, hostname).get(
                    HANDLER_TIMEOUT_MS, TimeUnit.MILLISECONDS));
        } catch (ExecutionException | InterruptedException | TimeoutException e) {
            throw new AssertionError("No mock DNS reply within timeout", e);
        }
        if (answer == null || answer.size() == 0) {
            throw new UnknownHostException(hostname);
        }
        return answer.toArray(new InetAddress[0]);
    }

    // Regardless of the type, depends on what the responses contained in the network.
    @SuppressWarnings("FutureReturnValueIgnored")
    private CompletableFuture<String[]> queryAllTypes(
            Network mockNetwork, String hostname) {
        if (mNetwork.equals(mockNetwork) && !mNonBypassPrivateDnsWorking) {
            return CompletableFuture.completedFuture(null);
        }

        final CompletableFuture<String[]> aFuture =
                getAnswer(mockNetwork, hostname, TYPE_A)
                        .exceptionally(e -> new String[0]);
        final CompletableFuture<String[]> aaaaFuture =
                getAnswer(mockNetwork, hostname, TYPE_AAAA)
                        .exceptionally(e -> new String[0]);

        final CompletableFuture<String[]> combinedFuture = new CompletableFuture<>();
        aFuture.thenAcceptBoth(aaaaFuture, (res1, res2) -> {
            final List<String> answerList = new ArrayList<>();
            if (res1 != null) answerList.addAll(Arrays.asList(res1));
            if (res2 != null) answerList.addAll(Arrays.asList(res2));
            combinedFuture.complete(answerList.toArray(new String[0]));
        });
        return combinedFuture;
    }

    /** Starts mocking DNS queries. */
    public void startMocking() throws UnknownHostException {
        // Queries on mNetwork using getAllByName.
        doAnswer(invocation -> {
            return getAllByName((Network) invocation.getMock(), invocation.getArgument(0));
        }).when(mNetwork).getAllByName(any());

        // Queries on mCleartextDnsNetwork using DnsResolver#query.
        doAnswer(invocation -> {
            return mockQuery(invocation, 0 /* posNetwork */, 1 /* posHostname */,
                    3 /* posExecutor */, 5 /* posCallback */, -1 /* posType */);
        }).when(mDnsResolver).query(any(), any(), anyInt(), any(), any(), any());

        // Queries on mCleartextDnsNetwork using DnsResolver#query with QueryType.
        doAnswer(invocation -> {
            return mockQuery(invocation, 0 /* posNetwork */, 1 /* posHostname */,
                    4 /* posExecutor */, 6 /* posCallback */, 2 /* posType */);
        }).when(mDnsResolver).query(any(), any(), anyInt(), anyInt(), any(), any(), any());

        // Queries using rawQuery. Currently, mockQuery only supports TYPE_SVCB.
        doAnswer(invocation -> {
            return mockQuery(invocation, 0 /* posNetwork */, 1 /* posHostname */,
                    5 /* posExecutor */, 7 /* posCallback */, 3 /* posType */);
        }).when(mDnsResolver).rawQuery(any(), any(), anyInt(), anyInt(), anyInt(), any(),
                any(), any());
    }

    private List<InetAddress> stringsToInetAddresses(String[] addrs) {
        if (addrs == null) return null;
        final List<InetAddress> out = new ArrayList<>();
        for (String addr : addrs) {
            out.add(parseNumericAddress(addr));
        }
        return out;
    }

    // Mocks all the DnsResolver query methods used in this test.
    @SuppressWarnings("FutureReturnValueIgnored")
    private Answer mockQuery(InvocationOnMock invocation, int posNetwork, int posHostname,
            int posExecutor, int posCallback, int posType) {
        String hostname = invocation.getArgument(posHostname);
        Executor executor = invocation.getArgument(posExecutor);
        Network network = invocation.getArgument(posNetwork);
        DnsResolver.Callback callback = invocation.getArgument(posCallback);

        final CompletableFuture<String[]> answerFuture = (posType != -1)
                ? getAnswer(network, hostname, invocation.getArgument(posType))
                : queryAllTypes(network, hostname);

        answerFuture.whenComplete((answer, exception) -> {
            new Handler(Looper.getMainLooper()).post(() -> executor.execute(() -> {
                if (exception != null) {
                    if (!(exception instanceof DnsResolver.DnsException)) {
                        throw new AssertionError("Test error building DNS response", exception);
                    }
                    callback.onError((DnsResolver.DnsException) exception);
                    return;
                }
                if (answer != null && answer.length > 0) {
                    final int qtype = (posType != -1)
                            ? invocation.getArgument(posType) : TYPE_AAAA;
                    switch (qtype) {
                        // Assume A and AAAA queries use the List<InetAddress> callback.
                        case TYPE_A:
                        case TYPE_AAAA:
                            callback.onAnswer(stringsToInetAddresses(answer), 0);
                            break;
                        case TYPE_SVCB:
                            callback.onAnswer(makeSvcbResponse(hostname, answer), 0);
                            break;
                        default:
                            throw new UnsupportedOperationException(
                                    "Unsupported qtype: " + qtype + ", update this fake");
                    }
                }
            }));
        });
        // If the future does not complete or has no answer do nothing. The timeout should fire.
        return null;
    }
}
