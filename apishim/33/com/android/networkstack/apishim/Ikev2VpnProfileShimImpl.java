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
import com.android.networkstack.apishim.common.Ikev2VpnProfileShim;

/**
 * A shim for Ikev2VpnProfile
 */
@RequiresApi(Build.VERSION_CODES.TIRAMISU)
public class Ikev2VpnProfileShimImpl
        extends com.android.networkstack.apishim.api31.Ikev2VpnProfileShimImpl {
    /**
     * Returns a new instance of this shim impl.
     */
    @RequiresApi(Build.VERSION_CODES.R)
    public static Ikev2VpnProfileShim<Ikev2VpnProfile> newInstance() {
        if (SdkLevel.isAtLeastT()) {
            return new Ikev2VpnProfileShimImpl();
        } else {
            return com.android.networkstack.apishim.api31.Ikev2VpnProfileShimImpl.newInstance();
        }
    }

    /**
     * @see Ikev2VpnProfile#getRequiresInternetValidation()
     */
    @Override
    public boolean getRequiresInternetValidation(@NonNull final Ikev2VpnProfile profile) {
        return profile.getRequiresInternetValidation();
    }
}
