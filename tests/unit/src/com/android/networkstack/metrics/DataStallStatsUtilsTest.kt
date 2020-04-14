/*
 * Copyright (C) 2019 The Android Open Source Project
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

package com.android.networkstack.metrics

import android.net.captiveportal.CaptivePortalProbeResult
import androidx.test.filters.SmallTest
import androidx.test.runner.AndroidJUnit4
import com.android.server.connectivity.nano.DataStallEventProto
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import android.net.metrics.ValidationProbeEvent

@RunWith(AndroidJUnit4::class)
@SmallTest
class DataStallStatsUtilsTest {
    @Test
    fun testProbeResultToEnum() {
        assertEquals(DataStallStatsUtils.probeResultToEnum(null), DataStallEventProto.INVALID)
        // Metrics cares only http response code.
        assertEquals(DataStallStatsUtils.probeResultToEnum(
                CaptivePortalProbeResult.failed(ValidationProbeEvent.PROBE_HTTP)),
                DataStallEventProto.INVALID)
        assertEquals(DataStallStatsUtils.probeResultToEnum(
                CaptivePortalProbeResult.failed(ValidationProbeEvent.PROBE_HTTPS)),
                DataStallEventProto.INVALID)
        assertEquals(DataStallStatsUtils.probeResultToEnum(
                CaptivePortalProbeResult.success(ValidationProbeEvent.PROBE_HTTP)),
                DataStallEventProto.VALID)
        assertEquals(DataStallStatsUtils.probeResultToEnum(
                CaptivePortalProbeResult.success(ValidationProbeEvent.PROBE_HTTP)),
                DataStallEventProto.VALID)
        assertEquals(DataStallStatsUtils.probeResultToEnum(CaptivePortalProbeResult.PARTIAL),
                DataStallEventProto.PARTIAL)
        assertEquals(DataStallStatsUtils.probeResultToEnum(CaptivePortalProbeResult(
                CaptivePortalProbeResult.PORTAL_CODE, ValidationProbeEvent.PROBE_HTTP)),
                DataStallEventProto.PORTAL)
        assertEquals(DataStallStatsUtils.probeResultToEnum(CaptivePortalProbeResult(
                CaptivePortalProbeResult.PORTAL_CODE, ValidationProbeEvent.PROBE_HTTPS)),
                DataStallEventProto.PORTAL)
    }
}
