/*
 * Copyright (C) 2019 The Android Open Source Project
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

import android.net.LinkProperties;
import android.net.NetworkCapabilities;
import android.net.Uri;
import android.os.Build;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;

/**
 * Compatibility implementation of {@link NetworkInformationShim}.
 */
public class NetworkInformationShimImpl extends
        com.android.networkstack.apishim.api29.NetworkInformationShimImpl {
    protected NetworkInformationShimImpl() {}

    /**
     * Get a new instance of {@link NetworkInformationShim}.
     */
    public static NetworkInformationShim newInstance() {
        if (!useApiAboveQ()) {
            return com.android.networkstack.apishim.api29.NetworkInformationShimImpl.newInstance();
        }
        return new NetworkInformationShimImpl();
    }

    /**
     * Indicates whether the shim can use APIs above the Q SDK.
     */
    @VisibleForTesting
    public static boolean useApiAboveQ() {
        return ShimUtils.isReleaseOrDevelopmentApiAbove(Build.VERSION_CODES.Q);
    }

    @Nullable
    @Override
    public Uri getCaptivePortalApiUrl(@Nullable LinkProperties lp) {
        if (lp == null) return null;
        return lp.getCaptivePortalApiUrl();
    }

    @Override
    public void setCaptivePortalApiUrl(@NonNull LinkProperties lp, @Nullable Uri url) {
        lp.setCaptivePortalApiUrl(url);
    }

    @Nullable
    @Override
    public CaptivePortalDataShim getCaptivePortalData(@Nullable LinkProperties lp) {
        if (lp == null || lp.getCaptivePortalData() == null) return null;
        return new CaptivePortalDataShimImpl(lp.getCaptivePortalData());
    }

    @Nullable
    @Override
    public String getSSID(@Nullable NetworkCapabilities nc) {
        if (nc == null) return null;
        return nc.getSSID();
    }
}
