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
package android.net.captiveportal;

import android.net.CaptivePortalData;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

/**
 * Captive portal probe detection result including capport API detection result.
 * @hide
 */
public class CapportApiProbeResult extends CaptivePortalProbeResult {
    // CaptivePortalData may be null if the capport API does not send any valid reply.
    @Nullable
    private final CaptivePortalData mCapportData;

    public CapportApiProbeResult(@NonNull CaptivePortalProbeResult result,
            @Nullable CaptivePortalData capportData) {
        this(result.mHttpResponseCode, result.redirectUrl, result.detectUrl, capportData,
                result.probeType);
    }

    public CapportApiProbeResult(int httpResponseCode, @Nullable String redirectUrl,
            @Nullable String detectUrl, @Nullable CaptivePortalData capportData,
            int probeType) {
        super(httpResponseCode, redirectUrl, detectUrl, probeType);
        mCapportData = capportData;
    }

    public CaptivePortalData getCaptivePortalData() {
        return mCapportData;
    }
}
