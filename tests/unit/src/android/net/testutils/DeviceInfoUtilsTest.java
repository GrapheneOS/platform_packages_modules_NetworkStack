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

package com.android.testutils;

import static org.junit.Assert.assertEquals;

import androidx.test.filters.SmallTest;

import org.junit.Test;

@SmallTest
public final class DeviceInfoUtilsTest {
    /**
     * Verifies that version string compare logic returns expected result for various cases.
     * Note that only major and minor number are compared.
     */
    @Test
    public void testMajorMinorVersionCompare() {
        assertEquals(0, DeviceInfoUtils.compareMajorMinorVersion("4.8.1", "4.8"));
        assertEquals(1, DeviceInfoUtils.compareMajorMinorVersion("4.9", "4.8.1"));
        assertEquals(1, DeviceInfoUtils.compareMajorMinorVersion("5.0", "4.8"));
        assertEquals(1, DeviceInfoUtils.compareMajorMinorVersion("5", "4.8"));
        assertEquals(0, DeviceInfoUtils.compareMajorMinorVersion("5", "5.0"));
        assertEquals(1, DeviceInfoUtils.compareMajorMinorVersion("5-beta1", "4.8"));
        assertEquals(0, DeviceInfoUtils.compareMajorMinorVersion("4.8.0.0", "4.8"));
        assertEquals(0, DeviceInfoUtils.compareMajorMinorVersion("4.8-RC1", "4.8"));
        assertEquals(0, DeviceInfoUtils.compareMajorMinorVersion("4.8", "4.8"));
        assertEquals(-1, DeviceInfoUtils.compareMajorMinorVersion("3.10", "4.8.0"));
        assertEquals(-1, DeviceInfoUtils.compareMajorMinorVersion("4.7.10.10", "4.8"));
    }
}
