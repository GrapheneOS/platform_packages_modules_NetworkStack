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

package com.android.networkstack.apishim.api29;

import android.net.wifi.WifiManager;

import com.android.networkstack.apishim.common.WifiManagerShim;

/**
 * Implementation of {@link WifiManagerShim}.
 */
public class WifiManagerShimImpl implements WifiManagerShim {
    protected final WifiManager mWifiManager;
    protected WifiManagerShimImpl(WifiManager wifiManager) {
        mWifiManager = wifiManager;
    }

    /**
     * Get a new instance of {@link WifiManagerShimImpl}.
     */
    public static WifiManagerShim newInstance(final WifiManager wifiManager) {
        return new WifiManagerShimImpl(wifiManager);
    }
}
