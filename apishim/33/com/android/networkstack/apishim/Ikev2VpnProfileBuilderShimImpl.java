/*
 * Copyright (C) 2022 The Android Open Source Project
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

import android.net.Ikev2VpnProfile;
import android.net.ipsec.ike.IkeTunnelConnectionParams;
import android.os.Build;

import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;

import com.android.modules.utils.build.SdkLevel;
import com.android.networkstack.apishim.common.Ikev2VpnProfileBuilderShim;

/**
 * A shim for Ikev2VpnProfile.Builder
 */
@RequiresApi(Build.VERSION_CODES.TIRAMISU)
public class Ikev2VpnProfileBuilderShimImpl
        extends com.android.networkstack.apishim.api31.Ikev2VpnProfileBuilderShimImpl {
    private Ikev2VpnProfileBuilderShimImpl(@Nullable String serverAddr,
            @Nullable String identity, @Nullable Object params) {
        super(serverAddr, identity, params);

        if (serverAddr == null && identity == null && params == null) {
            throw new IllegalArgumentException(
                    "serverAddr, identity and params should not be all null");
        }
        // Support building the Builder with an IkeTunnelConnectionParams from API 33.
        if (params != null) {
            if (!(params instanceof IkeTunnelConnectionParams)) {
                throw new IllegalArgumentException("params should be an IkeTunnelConnectionParams");
            }
            mBuilder = new Ikev2VpnProfile.Builder((IkeTunnelConnectionParams) params);
        } else {
            mBuilder = new Ikev2VpnProfile.Builder(serverAddr, identity);
        }
    }

    /**
     * Returns a new instance of this shim impl.
     */
    @RequiresApi(Build.VERSION_CODES.R)
    public static Ikev2VpnProfileBuilderShim<Ikev2VpnProfile.Builder> newInstance(
            @Nullable String serverAddr, @Nullable String identity, @Nullable Object params) {
        if (SdkLevel.isAtLeastT()) {
            return new Ikev2VpnProfileBuilderShimImpl(serverAddr, identity, params);
        } else {
            return com.android.networkstack.apishim.api31.Ikev2VpnProfileBuilderShimImpl
                    .newInstance(serverAddr, identity, params);
        }
    }

    /**
     * @see Ikev2VpnProfile.Builder#setRequiresInternetValidation(boolean)
     */
    @Override
    public Ikev2VpnProfileBuilderShim<Ikev2VpnProfile.Builder> setRequiresInternetValidation(
            boolean requiresInternetValidation) {
        mBuilder.setRequiresInternetValidation(requiresInternetValidation);
        return this;
    }

    /**
     * @see Ikev2VpnProfile.Builder#setLocalRoutesExcluded(boolean)
     */
    @Override
    public Ikev2VpnProfileBuilderShim<Ikev2VpnProfile.Builder> setLocalRoutesExcluded(
            boolean excludeLocalRoutes) {
        mBuilder.setLocalRoutesExcluded(excludeLocalRoutes);
        return this;
    }
}
