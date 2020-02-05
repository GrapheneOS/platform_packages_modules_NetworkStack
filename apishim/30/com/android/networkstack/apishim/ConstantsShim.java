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

import static android.net.ConnectivityDiagnosticsManager.ConnectivityReport;
import static android.net.ConnectivityDiagnosticsManager.DataStallReport;

/**
 * Utility class for defining and importing constants from the Android platform.
 */
public class ConstantsShim extends com.android.networkstack.apishim.api29.ConstantsShim {
    public static final int DETECTION_METHOD_DNS_EVENTS =
            DataStallReport.DETECTION_METHOD_DNS_EVENTS;
    public static final int DETECTION_METHOD_TCP_METRICS =
            DataStallReport.DETECTION_METHOD_TCP_METRICS;
    public static final String KEY_DNS_CONSECUTIVE_TIMEOUTS =
            DataStallReport.KEY_DNS_CONSECUTIVE_TIMEOUTS;
    public static final String KEY_NETWORK_PROBES_ATTEMPTED_BITMASK =
            ConnectivityReport.KEY_NETWORK_PROBES_ATTEMPTED_BITMASK;
    public static final String KEY_NETWORK_PROBES_SUCCEEDED_BITMASK =
            ConnectivityReport.KEY_NETWORK_PROBES_SUCCEEDED_BITMASK;
    public static final String KEY_NETWORK_VALIDATION_RESULT =
            ConnectivityReport.KEY_NETWORK_VALIDATION_RESULT;
    public static final String KEY_TCP_METRICS_COLLECTION_PERIOD_MILLIS =
            DataStallReport.KEY_TCP_METRICS_COLLECTION_PERIOD_MILLIS;
    public static final String KEY_TCP_PACKET_FAIL_RATE = DataStallReport.KEY_TCP_PACKET_FAIL_RATE;
}
