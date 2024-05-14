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

package com.android.networkstack.apishim.common;

import android.net.TetheringManager.TetheringRequest;
import android.net.wifi.WifiManager;
import android.net.wifi.WifiManager.SoftApCallback;

import java.util.concurrent.Executor;

/**
 * Interface used to access API methods in {@link android.net.wifi.WifiManager}, with
 * appropriate fallbacks if the methods are not yet part of the released API.
 *
 * <p>This interface makes it easier for callers to use
 * com.android.networkstack.apishim.WifiManagerShimImpl, as it's more obvious what methods must be
 * implemented on each API level, and it abstracts from callers the need to reference classes that
 * have different implementations (which also does not work well with IDEs).
 */
public interface WifiManagerShim {
    /**
     * Shim for {@link SoftApCallback#onStateChanged(SoftApState)}.
     */
    interface SoftApCallbackShim {
        /**
         * See {@link SoftApCallback#onStateChanged(SoftApState)}.
         */
        void onStateChanged(SoftApStateShim softApState);
    }

    /**
     * Shim for android.net.wifi.SoftApState.
     */
    interface SoftApStateShim {
        /**
         * See SoftApState#getState().
         */
        int getState();

        /**
         * See SoftApState#getFailureReason().
         */
        int getFailureReason();

        /**
         * See SoftApState#getIface().
         */
        String getIface();

        /**
         * See SoftApState#getTetheringRequest().
         */
        TetheringRequest getTetheringRequest();
    }

    /** @see WifiManager#startTetheredHotspot(TetheringRequest, Executor, SoftApCallback)  */
    default void startTetheredHotspot(
            TetheringRequest request, Executor executor, SoftApCallbackShim callbackShim)
            throws UnsupportedApiLevelException {
        throw new UnsupportedApiLevelException("Only supported starting from API 35");
    }
}
