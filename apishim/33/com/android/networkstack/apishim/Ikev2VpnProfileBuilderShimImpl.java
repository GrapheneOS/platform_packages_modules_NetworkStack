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
import android.os.Build;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;

import com.android.modules.utils.build.SdkLevel;
import com.android.networkstack.apishim.common.Ikev2VpnProfileBuilderShim;

/**
 * A shim for Ikev2VpnProfile.Builder
 */
@RequiresApi(Build.VERSION_CODES.TIRAMISU)
public class Ikev2VpnProfileBuilderShimImpl
        extends com.android.networkstack.apishim.api31.Ikev2VpnProfileBuilderShimImpl {
    /**
     * Returns a new instance of this shim impl.
     */
    @RequiresApi(Build.VERSION_CODES.R)
    public static Ikev2VpnProfileBuilderShim<Ikev2VpnProfile.Builder> newInstance() {
        if (SdkLevel.isAtLeastT()) {
            return new Ikev2VpnProfileBuilderShimImpl();
        } else {
            return com.android.networkstack.apishim.api31.Ikev2VpnProfileBuilderShimImpl
                    .newInstance();
        }
    }

    /**
     * @see Ikev2VpnProfile.Builder#setRequiresInternetValidation(boolean)
     */
    @Override
    public Ikev2VpnProfile.Builder setRequiresInternetValidation(
            @NonNull final Ikev2VpnProfile.Builder builder, boolean requiresInternetValidation) {
        builder.setRequiresInternetValidation(requiresInternetValidation);
        return builder;
    }
}
