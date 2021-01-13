/*
 * Copyright (C) 2020 The Android Open Source Project
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

import android.net.CaptivePortalData;

import androidx.annotation.NonNull;

import com.android.networkstack.apishim.common.CaptivePortalDataShim;

/**
 * Compatibility implementation of {@link CaptivePortalDataShim}.
 */
public class CaptivePortalDataShimImpl
        extends com.android.networkstack.apishim.api30.CaptivePortalDataShimImpl {
    protected CaptivePortalDataShimImpl(@NonNull CaptivePortalData data) {
        super(data);
    }

    @Override
    public String getVenueFriendlyName() {
        return mData.getVenueFriendlyName();
    }

    /**
     * Generate a {@link CaptivePortalData} object with a friendly name set
     *
     * @param friendlyName The friendly name to set
     * @return a {@link CaptivePortalData} object with a friendly name set
     */
    public CaptivePortalData withVenueFriendlyName(String friendlyName) {
        return new CaptivePortalData.Builder(mData)
                .setVenueFriendlyName(friendlyName)
                .build();
    }
}
