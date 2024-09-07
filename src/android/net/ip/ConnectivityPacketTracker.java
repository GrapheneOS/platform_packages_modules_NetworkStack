/*
 * Copyright (C) 2016 The Android Open Source Project
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

package android.net.ip;

import static android.net.util.SocketUtils.closeSocket;
import static android.net.util.SocketUtils.makePacketSocketAddress;
import static android.system.OsConstants.AF_PACKET;
import static android.system.OsConstants.ETH_P_ALL;
import static android.system.OsConstants.SOCK_NONBLOCK;
import static android.system.OsConstants.SOCK_RAW;

import static com.android.internal.annotations.VisibleForTesting.Visibility.PRIVATE;

import android.net.util.ConnectivityPacketSummary;
import android.os.Handler;
import android.os.SystemClock;
import android.system.ErrnoException;
import android.system.Os;
import android.text.TextUtils;
import android.util.LocalLog;
import android.util.Log;
import android.util.LruCache;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.android.internal.annotations.VisibleForTesting;
import com.android.internal.util.HexDump;
import com.android.internal.util.TokenBucket;
import com.android.net.module.util.InterfaceParams;
import com.android.net.module.util.PacketReader;
import com.android.networkstack.util.NetworkStackUtils;

import java.io.FileDescriptor;
import java.io.IOException;
import java.util.Arrays;
import java.util.Objects;


/**
 * Critical connectivity packet tracking daemon.
 *
 * Tracks ARP, DHCPv4, and IPv6 RS/RA/NS/NA packets.
 *
 * This class's constructor, start() and stop() methods must only be called
 * from the same thread on which the passed in |log| is accessed.
 *
 * Log lines include a hexdump of the packet, which can be decoded via:
 *
 *     echo -n H3XSTR1NG | sed -e 's/\([0-9A-F][0-9A-F]\)/\1 /g' -e 's/^/000000 /'
 *                       | text2pcap - -
 *                       | tcpdump -n -vv -e -r -
 *
 * @hide
 */
public class ConnectivityPacketTracker {
    /**
     * Dependencies class for testing.
     */
    @VisibleForTesting(visibility = PRIVATE)
    public static class Dependencies {
        private final LocalLog mLog;
        public Dependencies(final LocalLog log) {
            mLog = log;
        }

        /**
         * Create a socket to read RAs.
         */
        @Nullable
        public FileDescriptor createPacketReaderSocket(int ifIndex) {
            FileDescriptor socket = null;
            try {
                socket = Os.socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, 0);
                NetworkStackUtils.attachControlPacketFilter(socket);
                Os.bind(socket, makePacketSocketAddress(ETH_P_ALL, ifIndex));
            } catch (ErrnoException | IOException e) {
                final String msg = "Failed to create packet tracking socket: ";
                Log.e(TAG, msg, e);
                mLog.log(msg + e);
                closeFd(socket);
                return null;
            }
            return socket;
        }

        public int getMaxCapturePktSize() {
            return MAX_CAPTURE_PACKET_SIZE;
        }

        private void closeFd(FileDescriptor fd) {
            try {
                closeSocket(fd);
            } catch (IOException e) {
                Log.e(TAG, "failed to close socket");
            }
        }
    }

    private static final String TAG = ConnectivityPacketTracker.class.getSimpleName();
    private static final boolean DBG = false;
    private static final String MARK_START = "--- START ---";
    private static final String MARK_STOP = "--- STOP ---";
    private static final String MARK_NAMED_START = "--- START (%s) ---";
    private static final String MARK_NAMED_STOP = "--- STOP (%s) ---";
    // Use a TokenBucket to limit CPU usage of logging packets in steady state.
    private static final int TOKEN_FILL_RATE = 50;   // Maximum one packet every 20ms.
    private static final int MAX_BURST_LENGTH = 100; // Maximum burst 100 packets.
    private static final int MAX_CAPTURE_PACKET_SIZE = 100; // Maximum capture packet size

    private final String mTag;
    private final LocalLog mLog;
    private final PacketReader mPacketListener;
    private final TokenBucket mTokenBucket = new TokenBucket(TOKEN_FILL_RATE, MAX_BURST_LENGTH);
    // store packet hex string in uppercase as key, receive packet count as value
    private final LruCache<String, Integer> mPacketCache;
    private final Dependencies mDependencies;
    private long mLastRateLimitLogTimeMs = 0;
    private boolean mRunning;
    private boolean mCapturing;
    private String mDisplayName;

    public ConnectivityPacketTracker(Handler h, InterfaceParams ifParams, LocalLog log) {
        this(h, ifParams, log, new Dependencies(log));
    }

    /**
     * Sets the capture state.
     *
     * <p>This method controls whether packet capture is enabled. If capture is disabled,
     * the internal packet map is cleared.</p>
     *
     * @param isCapture {@code true} to enable capture, {@code false} to disable capture
     */
    public void setCapture(boolean isCapture) {
        mCapturing = isCapture;
        if (!isCapture) {
            mPacketCache.evictAll();
        }
    }

    /**
     * Gets the count of matched packets for a given pattern.
     *
     * <p>This method searches the internal packet map for packets matching the specified pattern
     * and returns the count of such packets.</p>
     *
     * @param packet The hex string pattern to match against
     * @return The count of packets matching the pattern, or 0 if no matches are found
     */
    public int getMatchedPacketCount(String packet) {
        final Integer count = mPacketCache.get(packet);
        return (count != null) ? count : 0;
    }

    public void start(String displayName) {
        mRunning = true;
        mDisplayName = displayName;
        mPacketListener.start();
    }

    public void stop() {
        mPacketListener.stop();
        mRunning = false;
        mDisplayName = null;
    }

    @VisibleForTesting(visibility = PRIVATE)
    public int getCapturePacketTypeCount() {
        return mPacketCache.size();
    }

    @VisibleForTesting(visibility = PRIVATE)
    public ConnectivityPacketTracker(
            @NonNull Handler handler,
            @NonNull InterfaceParams ifParams,
            @NonNull LocalLog log,
            @NonNull Dependencies dependencies) {
        mTag = TAG + "." + Objects.requireNonNull(ifParams).name;
        mLog = log;
        mPacketListener = new PacketListener(handler, ifParams);
        mDependencies = dependencies;
        mPacketCache = new LruCache<>(mDependencies.getMaxCapturePktSize());
    }

    private final class PacketListener extends PacketReader {
        private final InterfaceParams mInterface;

        PacketListener(Handler h, InterfaceParams ifParams) {
            super(h, ifParams.defaultMtu);
            mInterface = ifParams;
        }

        @Override
        protected FileDescriptor createFd() {
            return mDependencies.createPacketReaderSocket(mInterface.index);
        }

        @Override
        protected void handlePacket(byte[] recvbuf, int length) {
            capturePacket(recvbuf, length);

            if (!mTokenBucket.get()) {
                // Rate limited. Log once every second so the user knows packets are missing.
                final long now = SystemClock.elapsedRealtime();
                if (now >= mLastRateLimitLogTimeMs + 1000) {
                    addLogEntry("Warning: too many packets, rate-limiting to one every " +
                                TOKEN_FILL_RATE + "ms");
                    mLastRateLimitLogTimeMs = now;
                }
                return;
            }

            final String summary;
            try {
                summary = ConnectivityPacketSummary.summarize(mInterface.macAddr, recvbuf, length);
                if (summary == null) return;
            } catch (Exception e) {
                if (DBG) Log.d(mTag, "Error creating packet summary", e);
                return;
            }

            if (DBG) Log.d(mTag, summary);
            addLogEntry(summary + "\n[" + HexDump.toHexString(recvbuf, 0, length) + "]");
        }

        @Override
        protected void onStart() {
            final String msg = TextUtils.isEmpty(mDisplayName)
                    ? MARK_START
                    : String.format(MARK_NAMED_START, mDisplayName);
            mLog.log(msg);
        }

        @Override
        protected void onStop() {
            String msg = TextUtils.isEmpty(mDisplayName)
                    ? MARK_STOP
                    : String.format(MARK_NAMED_STOP, mDisplayName);
            if (!mRunning) msg += " (packet listener stopped unexpectedly)";
            mLog.log(msg);
        }

        @Override
        protected void logError(String msg, Exception e) {
            Log.e(mTag, msg, e);
            addLogEntry(msg + e);
        }

        private void addLogEntry(String entry) {
            mLog.log(entry);
        }

        private void capturePacket(byte[] recvbuf, int length) {
            if (!mCapturing) {
                return;
            }

            byte[] pkt = Arrays.copyOfRange(
                    recvbuf, 0, Math.min(recvbuf.length, length));
            final String pktHexString = HexDump.toHexString(pkt);
            final Integer pktCnt = mPacketCache.get(pktHexString);
            if (pktCnt == null) {
                mPacketCache.put(pktHexString, 1);
            } else {
                mPacketCache.put(pktHexString, pktCnt + 1);
            }
        }
    }
}
