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

package com.android.networkstack.apishim.api34;

import android.net.wifi.WifiManager;
import android.os.Build;

import androidx.annotation.RequiresApi;

import com.android.modules.utils.build.SdkLevel;
import com.android.networkstack.apishim.common.WifiManagerShim;

/**
 * Implementation of {@link WifiManagerShim}.
 */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
public class WifiManagerShimImpl
        extends com.android.networkstack.apishim.api29.WifiManagerShimImpl {
    // Currently identical to the API 33 shim, so inherit everything
    protected WifiManagerShimImpl(WifiManager wifiManager) {
        super(wifiManager);
    }

    /**
     * Get a new instance of {@link WifiManagerShimImpl}.
     */
    public static WifiManagerShim newInstance(final WifiManager wifiManager) {
        if (!SdkLevel.isAtLeastU()) {
            return com.android.networkstack.apishim.api29.WifiManagerShimImpl.newInstance(
                    wifiManager);
        }
        return new WifiManagerShimImpl(wifiManager);
    }
}
