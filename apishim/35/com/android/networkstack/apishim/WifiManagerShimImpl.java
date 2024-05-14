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

package com.android.networkstack.apishim;

import static com.android.modules.utils.build.SdkLevel.isAtLeastV;

import android.net.NetworkStack;
import android.net.TetheringManager.TetheringRequest;
import android.net.wifi.SoftApState;
import android.net.wifi.WifiManager;
import android.os.Build;

import androidx.annotation.RequiresApi;
import androidx.annotation.RequiresPermission;

import com.android.networkstack.apishim.common.UnsupportedApiLevelException;
import com.android.networkstack.apishim.common.WifiManagerShim;

import java.util.concurrent.Executor;

/**
 * Implementation of {@link WifiManagerShim}.
 */
// TODO: when available in all active branches: @RequiresApi(Build.VERSION_CODES.VANILLA_ICE_CREAM)
@RequiresApi(Build.VERSION_CODES.CUR_DEVELOPMENT)
public class WifiManagerShimImpl
        extends com.android.networkstack.apishim.api34.WifiManagerShimImpl {
    protected WifiManagerShimImpl(WifiManager wifiManager) {
        super(wifiManager);
    }

    /**
     * Get a new instance of {@link com.android.networkstack.apishim.WifiManagerShimImpl}.
     */
    public static WifiManagerShim newInstance(WifiManager wifiManager) {
        if (!isAtLeastV()) {
            return com.android.networkstack.apishim.api34.WifiManagerShimImpl.newInstance(
                    wifiManager);
        }
        return new WifiManagerShimImpl(wifiManager);
    }

    @RequiresPermission(anyOf = {
            android.Manifest.permission.NETWORK_STACK,
            NetworkStack.PERMISSION_MAINLINE_NETWORK_STACK
    })
    @Override
    public void startTetheredHotspot(
            TetheringRequest request, Executor executor, SoftApCallbackShim callbackShim)
            throws UnsupportedApiLevelException {
        WifiManager.SoftApCallback callback = new WifiManager.SoftApCallback() {
            @Override
            public void onStateChanged(SoftApState state) {
                callbackShim.onStateChanged(new SoftApStateShim() {
                    @Override
                    public int getState() {
                        return state.getState();
                    }

                    @Override
                    public int getFailureReason() {
                        return state.getFailureReason();
                    }

                    @Override
                    public String getIface() {
                        return state.getIface();
                    }

                    @Override
                    public TetheringRequest getTetheringRequest() {
                        return state.getTetheringRequest();
                    }
                });
            }
        };
        mWifiManager.startTetheredHotspot(request, executor, callback);
    }
}
