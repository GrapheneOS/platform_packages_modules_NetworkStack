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

package com.android.networkstack.apishim.api31;

import android.net.CaptivePortalData;
import android.net.Uri;
import android.os.Build;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;

import com.android.modules.utils.build.SdkLevel;
import com.android.networkstack.apishim.common.CaptivePortalDataShim;
import com.android.networkstack.apishim.common.UnsupportedApiLevelException;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.function.Predicate;

/**
 * Compatibility implementation of {@link CaptivePortalDataShim}.
 */
@RequiresApi(Build.VERSION_CODES.S)
public class CaptivePortalDataShimImpl
        extends com.android.networkstack.apishim.api30.CaptivePortalDataShimImpl {
    // Copy this value from CaptivePortalData to avoid needing an API bump, which would slow
    // down this work by many months and have to be maintained forever. See the constant with
    // the same name in CaptivePortalData.
    public static final int CAPTIVE_PORTAL_DATA_SOURCE_CAPPORT_WITH_CUSTOM_TABS_OPTIN = 2;

    public CaptivePortalDataShimImpl(@NonNull CaptivePortalData data) {
        super(data);
    }

    @Override
    public CharSequence getVenueFriendlyName() {
        return mData.getVenueFriendlyName();
    }

    /**
     * Get the information source of the User portal
     * @return The source that the User portal was obtained from
     */
    @Override
    public int getUserPortalUrlSource() {
        return mData.getUserPortalUrlSource();
    }

    /**
     * Generate a {@link CaptivePortalDataShim} object with a friendly name set
     *
     * @param friendlyName The friendly name to set
     * @return a {@link CaptivePortalDataShim} object with a friendly name set
     */
    @Override
    public CaptivePortalDataShim withVenueFriendlyName(String friendlyName) {
        return new CaptivePortalDataShimImpl(new CaptivePortalData.Builder(mData)
                .setVenueFriendlyName(friendlyName)
                .build());
    }

    /**
     * Parse a {@link CaptivePortalDataShim} from a JSON object.
     * @throws JSONException The JSON is not a representation of correct captive portal data.
     */
    @NonNull
    public static CaptivePortalDataShim fromJson(JSONObject obj,
                Predicate<String> evaluateCustomTabOptIn)
            throws JSONException, UnsupportedApiLevelException {
        if (!SdkLevel.isAtLeastS()) {
            return com.android.networkstack.apishim.api30.CaptivePortalDataShimImpl.fromJson(obj,
                    evaluateCustomTabOptIn);
        }
        final long refreshTimeMs = System.currentTimeMillis();
        final long secondsRemaining = getLongOrDefault(obj, "seconds-remaining", -1L);
        final long millisRemaining = secondsRemaining <= Long.MAX_VALUE / 1000
                ? secondsRemaining * 1000
                : Long.MAX_VALUE;
        final long expiryTimeMs = secondsRemaining == -1L ? -1L :
                refreshTimeMs + Math.min(Long.MAX_VALUE - refreshTimeMs, millisRemaining);
        final String optInToCustomTabsString = obj.optString("x-android-use-custom-tabs", null);
        final boolean optInToCustomTabs = evaluateCustomTabOptIn.test(optInToCustomTabsString);
        Log.i("CapportParsing", "Opt-in to custom tabs : \"" + optInToCustomTabsString
                + "\" = " + (optInToCustomTabs ? "true" : "false"));
        final int userPortalSource = optInToCustomTabs
                ? CAPTIVE_PORTAL_DATA_SOURCE_CAPPORT_WITH_CUSTOM_TABS_OPTIN
                : CaptivePortalData.CAPTIVE_PORTAL_DATA_SOURCE_OTHER;
        return new CaptivePortalDataShimImpl(new CaptivePortalData.Builder()
                .setRefreshTime(refreshTimeMs)
                // captive is mandatory; throws JSONException if absent
                .setCaptive(obj.getBoolean("captive"))
                .setUserPortalUrl(getUriOrNull(obj, "user-portal-url"), userPortalSource)
                .setVenueInfoUrl(getUriOrNull(obj, "venue-info-url"))
                .setBytesRemaining(getLongOrDefault(obj, "bytes-remaining", -1L))
                .setExpiryTime(expiryTimeMs)
                .build());
    }

    /**
     * Generate a {@link CaptivePortalDataShim} object with a friendly name and Passpoint external
     * URLs set
     *
     * @param friendlyName The friendly name to set
     * @param venueInfoUrl Venue information URL
     * @param termsAndConditionsUrl Terms and conditions URL
     *
     * @return a {@link CaptivePortalDataShim} object with friendly name, venue info URL and terms
     * and conditions URL set
     */
    @Override
    public CaptivePortalDataShim withPasspointInfo(@NonNull String friendlyName,
            @NonNull Uri venueInfoUrl, @NonNull Uri termsAndConditionsUrl) {
        return new CaptivePortalDataShimImpl(new CaptivePortalData.Builder(mData)
                .setVenueFriendlyName(friendlyName)
                .setVenueInfoUrl(venueInfoUrl, ConstantsShim.CAPTIVE_PORTAL_DATA_SOURCE_PASSPOINT)
                .setUserPortalUrl(termsAndConditionsUrl,
                        ConstantsShim.CAPTIVE_PORTAL_DATA_SOURCE_PASSPOINT)
                .build());
    }
}
