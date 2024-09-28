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

package android.net.util;

import static com.android.internal.annotations.VisibleForTesting.Visibility.PRIVATE;

import android.net.ip.ConnectivityPacketTracker;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.Message;
import android.util.ArrayMap;
import android.util.LocalLog;
import android.util.Log;

import androidx.annotation.NonNull;

import com.android.internal.annotations.VisibleForTesting;
import com.android.net.module.util.InterfaceParams;

import java.util.Objects;

/**
 * Tracks and manages raw packet captures on a network interface.
 *
 * <p>This class is not a thread-safe and should be only run on the handler thread.
 * It utilizes a dedicated {@link HandlerThread} to perform capture operations, allowing
 * the caller to interact with it asynchronously through methods like
 * {@link #startCapture(String, long)}, {@link #stopCapture(String)},
 * and {@link #getMatchedPacketCount(String, String)}.</p>
 *
 */
public class RawPacketTracker {
    /**
     * Dependencies class for testing.
     */
    @VisibleForTesting(visibility = PRIVATE)
    static class Dependencies {
        public @NonNull ConnectivityPacketTracker createPacketTracker(
                Handler handler, InterfaceParams ifParams, int maxPktRecords) {
            return new ConnectivityPacketTracker(
                    handler, ifParams, new LocalLog(maxPktRecords));
        }

        public @NonNull HandlerThread createHandlerThread() {
            final HandlerThread handlerThread = new HandlerThread(TAG + "-handler");
            handlerThread.start();
            return handlerThread;
        }

        public @NonNull Looper getLooper(HandlerThread handlerThread) {
            return handlerThread.getLooper();
        }
    }

    // Maximum number of packet records to store.
    private static final int MAX_PACKET_RECORDS = 100;
    // Maximum duration for a packet capture session in milliseconds.
    public static final long MAX_CAPTURE_TIME_MS = 300_000;
    @VisibleForTesting(visibility = PRIVATE)
    public static final int CMD_STOP_CAPTURE = 1;
    private static final String TAG = RawPacketTracker.class.getSimpleName();

    private final @NonNull HandlerThread mHandlerThread;
    private final @NonNull Dependencies mDeps;
    private final @NonNull Handler mHandler;

    /**
     * A map that stores ConnectivityPacketTracker objects, keyed by their associated
     * network interface name, e.g: wlan0. This allows for tracking connectivity
     * packets on a per-interface basis. This is only accessed by handler thread.
     */
    private final ArrayMap<String, ConnectivityPacketTracker> mTrackerMap = new ArrayMap<>();

    public RawPacketTracker() {
        this(new Dependencies());
    }

    @VisibleForTesting(visibility = PRIVATE)
    public RawPacketTracker(
            @NonNull Dependencies deps
    ) {
        mDeps = deps;
        mHandlerThread = deps.createHandlerThread();
        mHandler = new RawPacketTrackerHandler(deps.getLooper(mHandlerThread), this);
    }

    private static class RawPacketTrackerHandler extends Handler {
        private final RawPacketTracker mRawPacketTracker;
        private RawPacketTrackerHandler(
                @NonNull Looper looper,
                @NonNull RawPacketTracker rawPacketTracker) {
            super(looper);
            mRawPacketTracker = rawPacketTracker;
        }

        @Override
        public void handleMessage(Message msg) {
            final String ifaceName;
            switch (msg.what) {
                case CMD_STOP_CAPTURE:
                    ifaceName = (String) msg.obj;
                    mRawPacketTracker.processStopCapture(ifaceName);
                    break;
                default:
                    Log.e(TAG, "unrecognized message: " + msg.what);
            }
        }
    }

    /**
     * Starts capturing packets on the specified network interface.
     *
     * <p>Initiates a packet capture session if one is not already running for the given interface.
     * A capture timeout is set to automatically stop the capture after {@code maxCaptureTimeMs}
     * milliseconds. If a previous stop capture event was scheduled, it is canceled.</p>
     *
     * @param ifaceName      The name of the network interface to capture packets on.
     * @param maxCaptureTimeMs The maximum capture duration in milliseconds.
     * @throws IllegalArgumentException If {@code maxCaptureTimeMs} is less than or equal to 0.
     * @throws RuntimeException If a capture is already running on the specified interface.
     * @throws IllegalStateException If this method is not running on handler thread
     */
    public void startCapture(
            String ifaceName, long maxCaptureTimeMs
    ) throws IllegalArgumentException, RuntimeException, IllegalStateException {
        ensureRunOnHandlerThread();
        if (maxCaptureTimeMs <= 0) {
            throw new IllegalArgumentException("maxCaptureTimeMs " + maxCaptureTimeMs + " <= 0");
        }

        if (mTrackerMap.containsKey(ifaceName)) {
            throw new RuntimeException(ifaceName + " is already capturing");
        }

        final InterfaceParams ifParams = InterfaceParams.getByName(ifaceName);
        Objects.requireNonNull(ifParams, "invalid interface " + ifaceName);

        final ConnectivityPacketTracker tracker =
                mDeps.createPacketTracker(mHandler, ifParams, MAX_PACKET_RECORDS);
        tracker.start(TAG + "." + ifaceName);
        mTrackerMap.putIfAbsent(ifaceName, tracker);
        tracker.setCapture(true);

        // remove scheduled stop events if it already in the queue
        mHandler.removeMessages(CMD_STOP_CAPTURE, ifaceName);

        // capture up to configured capture time and stop capturing
        final Message stopMsg = mHandler.obtainMessage(CMD_STOP_CAPTURE, ifaceName);
        mHandler.sendMessageDelayed(stopMsg, maxCaptureTimeMs);
    }

    /**
     * Stops capturing packets on the specified network interface.
     *
     * <p>Terminates the packet capture session if one is active for the given interface.
     * Any pending stop capture events for the interface are canceled.</p>
     *
     * @param ifaceName The name of the network interface to stop capturing on.
     * @throws RuntimeException If no capture is running on the specified interface.
     * @throws IllegalStateException If this method is not running on handler thread
     */
    public void stopCapture(String ifaceName) throws RuntimeException, IllegalStateException {
        ensureRunOnHandlerThread();
        if (!mTrackerMap.containsKey(ifaceName)) {
            throw new RuntimeException(ifaceName + " is already stopped");
        }

        final Message msg = mHandler.obtainMessage(CMD_STOP_CAPTURE, ifaceName);
        // remove scheduled stop events if it already in the queue
        mHandler.removeMessages(CMD_STOP_CAPTURE, ifaceName);
        mHandler.sendMessage(msg);
    }

    /**
     * Returns the {@link Handler} associated with this RawTracker.
     *
     * <p>This handler is used for posting tasks to the RawTracker's internal thread.
     * You can use it to execute code that needs to interact with the RawTracker
     * in a thread-safe manner.
     *
     * @return The non-null {@link Handler} instance.
     */
    public @NonNull Handler getHandler() {
        return mHandler;
    }

    /**
     * Retrieves the number of captured packets matching a specific pattern.
     *
     * <p>Queries the packet capture data for the specified interface and counts the occurrences
     * of packets that match the provided {@code packet} string. The count is performed
     * asynchronously on the capture thread.</p>
     *
     * @param ifaceName The name of the network interface.
     * @param packetPattern The packet pattern to match.
     * @return The number of matched packets, or 0 if an error occurs or no matching packets are
     *         found.
     * @throws RuntimeException If no capture is running on the specified interface.
     * @throws IllegalStateException If this method is not running on handler thread
     */
    public int getMatchedPacketCount(
            String ifaceName, String packetPattern
    ) throws RuntimeException, IllegalStateException {
        ensureRunOnHandlerThread();
        final ConnectivityPacketTracker tracker;
        tracker = mTrackerMap.getOrDefault(ifaceName, null);
        if (tracker == null) {
            throw new RuntimeException(ifaceName + " is not capturing");
        }

        return tracker.getMatchedPacketCount(packetPattern);
    }

    private void processStopCapture(String ifaceName) {
        final ConnectivityPacketTracker tracker = mTrackerMap.get(ifaceName);
        mTrackerMap.remove(ifaceName);
        tracker.setCapture(false);
    }

    private void ensureRunOnHandlerThread() {
        if (mHandler.getLooper() != Looper.myLooper()) {
            throw new IllegalStateException(
                "Not running on Handler thread: " + Thread.currentThread().getName()
            );
        }
    }
}
