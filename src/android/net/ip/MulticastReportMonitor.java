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


package android.net.ip;

import android.os.Handler;

import androidx.annotation.NonNull;

import com.android.net.module.util.InterfaceParams;
import com.android.net.module.util.PacketReader;

import java.io.FileDescriptor;

/**
 * Monitor IGMP/MLD report packets and notify listeners the multicast address changes.
 *
 * <p>This class uses a {@link PacketReader} to listen for IGMP/MLD report packets on a given
 * interface. When a packet is received, it notifies the provided {@link Callback} of the change
 * in the multicast address.
 *
 * <p>To use this class, create a new instance with the desired {@link Handler},
 * {@link InterfaceParams}, {@link Callback}, and {@link FileDescriptor}. Then, call {@link #start()}
 * to start listening for packets. To stop listening, call {@link #stop()}.
 */
public class MulticastReportMonitor {
    public interface Callback {
        /**
         * Notifies the system or other components about a change in the multicast address.
         */
        void notifyMulticastAddrChange();
    }

    private static final String TAG = MulticastReportMonitor.class.getSimpleName();
    private final PacketReader mPacketListener;

    /**
     * Creates a new {@link MulticastReportMonitor}.
     *
     * @param handler The {@link Handler} to use for the {@link PacketReader}.
     * @param ifParams The {@link InterfaceParams} for the interface to listen on.
     * @param callback The {@link Callback} to notify the multicast address changes.
     * @param fd The {@link FileDescriptor} to use for the {@link PacketReader}.
     */
    public MulticastReportMonitor(
            @NonNull Handler handler,
            @NonNull InterfaceParams ifParams,
            @NonNull Callback callback,
            @NonNull FileDescriptor fd) {
        mPacketListener = new PacketListener(handler, ifParams, callback, fd);
    }

    /**
     * Starts the packet listener.
     */
    public void start() {
        mPacketListener.start();
    }

    /**
     * Stops the packet listener.
     */
    public void stop() {
        mPacketListener.stop();
    }

    private static final class PacketListener extends PacketReader {
        private final Callback mCallback;
        private final FileDescriptor mFd;

        PacketListener(Handler h, InterfaceParams ifParams, Callback callback, FileDescriptor fd) {
            super(h, ifParams.defaultMtu);
            mCallback = callback;
            mFd = fd;
        }

        @Override
        protected FileDescriptor createFd() {
            return mFd;
        }

        @Override
        protected void handlePacket(@NonNull byte[] recvbuf, int length) {
            mCallback.notifyMulticastAddrChange();
        }
    }
}
