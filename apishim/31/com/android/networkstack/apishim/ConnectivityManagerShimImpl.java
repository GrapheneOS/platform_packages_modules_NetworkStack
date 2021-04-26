/*
 * Copyright (C) 2021 The Android Open Source Project
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

package com.android.networkstack.apishim;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.ConnectivityManager.NetworkCallback;
import android.net.NetworkRequest;
import android.os.Build;
import android.os.Handler;
import android.util.Range;

import androidx.annotation.NonNull;

import com.android.networkstack.apishim.common.ConnectivityManagerShim;
import com.android.networkstack.apishim.common.ShimUtils;

import java.util.Collection;

/**
 * Implementation of {@link ConnectivityManagerShim} for API 31.
 */
public class ConnectivityManagerShimImpl
        extends com.android.networkstack.apishim.api30.ConnectivityManagerShimImpl  {
    private final ConnectivityManager mCm;

    protected ConnectivityManagerShimImpl(Context context) {
        super(context);
        mCm = context.getSystemService(ConnectivityManager.class);
    }

    /**
     * Get a new instance of {@link ConnectivityManagerShim}.
     */
    public static ConnectivityManagerShim newInstance(Context context) {
        if (!ShimUtils.isReleaseOrDevelopmentApiAbove(Build.VERSION_CODES.R)) {
            return com.android.networkstack.apishim.api30.ConnectivityManagerShimImpl
                    .newInstance(context);
        }
        return new ConnectivityManagerShimImpl(context);
    }

    /**
     * See android.net.ConnectivityManager#requestBackgroundNetwork
     */
    @Override
    public void requestBackgroundNetwork(@NonNull NetworkRequest request,
            @NonNull NetworkCallback networkCallback, @NonNull Handler handler) {
        mCm.requestBackgroundNetwork(request, networkCallback, handler);
    }

    /**
     * See android.net.ConnectivityManager#registerSystemDefaultNetworkCallback
     */
    @Override
    public void registerSystemDefaultNetworkCallback(
            @NonNull NetworkCallback networkCallback, @NonNull Handler handler) {
        mCm.registerSystemDefaultNetworkCallback(networkCallback, handler);
    }

    /**
     * See android.net.ConnectivityManager#registerDefaultNetworkCallbackAsUid
     */
    @Override
    public void registerDefaultNetworkCallbackForUid(
            int uid, @NonNull NetworkCallback networkCallback, @NonNull Handler handler) {
        mCm.registerDefaultNetworkCallbackForUid(uid, networkCallback, handler);
    }

    /**
     * See android.net.ConnectivityManager#setLegacyLockdownVpnEnabled
     */
    @Override
    public void setLegacyLockdownVpnEnabled(boolean enabled) {
        mCm.setLegacyLockdownVpnEnabled(enabled);
    }

    /**
     * See android.net.ConnectivityManager#setRequireVpnForUids
     */
    @Override
    public void setRequireVpnForUids(boolean requireVpn, Collection<Range<Integer>> ranges) {
        mCm.setRequireVpnForUids(requireVpn, ranges);
    }
}
