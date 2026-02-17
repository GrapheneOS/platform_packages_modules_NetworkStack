/*
 * Copyright (C) 2025 The Android Open Source Project
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
package com.android.networkstack.util;

import android.net.CaptivePortalData;
import android.net.Uri;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.android.networkstack.apishim.common.UnsupportedApiLevelException;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.function.Predicate;

/**
 * Collection of utilities for CaptivePortalData.
 */
public class CaptivePortalDataUtils {

    // TODO(b/441185733): do not abuse the data source field to store the custom tab opt-in status.
    // Instead, add a boolean in CaptivePortalProbeResults, and have NetworkMonitor
    // include an EXTRA_CUSTOM_TABS_OPTIN in the intent built in CMD_LAUNCH_CAPTIVE_PORTAL_APP.
    public static final int CAPTIVE_PORTAL_DATA_SOURCE_CAPPORT_WITH_CUSTOM_TABS_OPTIN = 2;

    private static long getLongOrDefault(JSONObject o, String key, long def)
            throws JSONException {
        if (!o.has(key)) return def;
        return o.getLong(key);
    }

    private static Uri getUriOrNull(JSONObject o, String key) throws JSONException {
        if (!o.has(key)) return null;
        return Uri.parse(o.getString(key));
    }

    /**
     * Parse a {@link CaptivePortalData} from a JSON object.
     * @throws JSONException The JSON is not a representation of correct captive portal data.
     */
    @NonNull
    public static CaptivePortalData fromJson(JSONObject obj,
            Predicate<String> evaluateCustomTabOptIn)
            throws JSONException, UnsupportedApiLevelException {
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
        return new CaptivePortalData.Builder()
                .setRefreshTime(refreshTimeMs)
                // captive is mandatory; throws JSONException if absent
                .setCaptive(obj.getBoolean("captive"))
                .setUserPortalUrl(getUriOrNull(obj, "user-portal-url"), userPortalSource)
                .setVenueInfoUrl(getUriOrNull(obj, "venue-info-url"))
                .setBytesRemaining(getLongOrDefault(obj, "bytes-remaining", -1L))
                .setExpiryTime(expiryTimeMs)
                .build();
    }

    /**
     * Redact the venue info URL from the captive portal data if necessary.
     */
    @Nullable
    public static CaptivePortalData redactVenueInfoUrl(CaptivePortalData capportData) {
        if (capportData == null) {
            return null;
        }
        return new CaptivePortalData.Builder(capportData)
                .setVenueInfoUrl(null)
                .build();
    }

}
