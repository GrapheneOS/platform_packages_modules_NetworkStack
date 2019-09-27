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

package android.net.util;

import static com.android.dx.mockito.inline.extended.ExtendedMockito.doReturn;
import static com.android.dx.mockito.inline.extended.ExtendedMockito.mockitoSession;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.anyInt;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.eq;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.provider.DeviceConfig;

import androidx.test.filters.SmallTest;
import androidx.test.runner.AndroidJUnit4;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.MockitoSession;


/**
 * Tests for NetworkStackUtils.
 *
 */
@RunWith(AndroidJUnit4.class)
@SmallTest
public class NetworkStackUtilsTest {
    private static final String TEST_NAME_SPACE = "connectivity";
    private static final String TEST_EXPERIMENT_FLAG = "experiment_flag";
    private static final int TEST_FLAG_VERSION = 28;
    private static final String TEST_FLAG_VERSION_STRING = "28";
    private static final int TEST_DEFAULT_FLAG_VERSION = 0;
    private static final long TEST_PACKAGE_VERSION = 290000000;
    private static final String TEST_PACKAGE_NAME = "NetworkStackUtilsTest";
    private MockitoSession mSession;

    @Mock private Context mContext;
    @Mock private PackageManager mPm;
    @Mock private PackageInfo mPi;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        mSession = mockitoSession().spyStatic(DeviceConfig.class).startMocking();

        final PackageInfo pi = new PackageInfo();
        pi.setLongVersionCode(TEST_PACKAGE_VERSION);

        doReturn(mPm).when(mContext).getPackageManager();
        doReturn(TEST_PACKAGE_NAME).when(mContext).getPackageName();
        doReturn(pi).when(mPm).getPackageInfo(anyString(), anyInt());
    }

    @After
    public void tearDown() {
        mSession.finishMocking();
    }

    @Test
    public void testGetDeviceConfigPropertyInt_Null() {
        doReturn(null).when(() -> DeviceConfig.getProperty(eq(TEST_NAME_SPACE),
                eq(TEST_EXPERIMENT_FLAG)));
        assertEquals(TEST_DEFAULT_FLAG_VERSION, NetworkStackUtils.getDeviceConfigPropertyInt(
                TEST_NAME_SPACE, TEST_EXPERIMENT_FLAG,
                TEST_DEFAULT_FLAG_VERSION /* default value */));
    }

    @Test
    public void testGetDeviceConfigPropertyInt_NotNull() {
        doReturn(TEST_FLAG_VERSION_STRING).when(() -> DeviceConfig.getProperty(eq(TEST_NAME_SPACE),
                eq(TEST_EXPERIMENT_FLAG)));
        assertEquals(TEST_FLAG_VERSION, NetworkStackUtils.getDeviceConfigPropertyInt(
                TEST_NAME_SPACE, TEST_EXPERIMENT_FLAG,
                TEST_DEFAULT_FLAG_VERSION /* default value */));
    }

    @Test
    public void testGetDeviceConfigPropertyBoolean_Null() {
        doReturn(null).when(() -> DeviceConfig.getProperty(eq(TEST_NAME_SPACE),
                eq(TEST_EXPERIMENT_FLAG)));
        assertFalse(NetworkStackUtils.getDeviceConfigPropertyBoolean(
                TEST_NAME_SPACE, TEST_EXPERIMENT_FLAG,
                false /* default value */));
    }

    @Test
    public void testGetDeviceConfigPropertyBoolean_NotNull() {
        doReturn("true").when(() -> DeviceConfig.getProperty(eq(TEST_NAME_SPACE),
                eq(TEST_EXPERIMENT_FLAG)));
        assertTrue(NetworkStackUtils.getDeviceConfigPropertyBoolean(
                TEST_NAME_SPACE, TEST_EXPERIMENT_FLAG,
                false /* default value */));
    }

    @Test
    public void testFeatureIsEnabledWithExceptionsEnabled() {
        doReturn(TEST_FLAG_VERSION_STRING).when(() -> DeviceConfig.getProperty(eq(TEST_NAME_SPACE),
                eq(TEST_EXPERIMENT_FLAG)));
        assertTrue(NetworkStackUtils.isFeatureEnabled(mContext, TEST_NAME_SPACE,
                TEST_EXPERIMENT_FLAG));
    }

    @Test
    public void testFeatureIsNotEnabled() {
        doReturn(null).when(() -> DeviceConfig.getProperty(eq(TEST_NAME_SPACE),
                eq(TEST_EXPERIMENT_FLAG)));
        assertFalse(NetworkStackUtils.isFeatureEnabled(mContext, TEST_NAME_SPACE,
                TEST_EXPERIMENT_FLAG));
    }

    @Test
    public void testFeatureIsEnabledWithException() throws Exception {
        doReturn(TEST_FLAG_VERSION_STRING).when(() -> DeviceConfig.getProperty(eq(TEST_NAME_SPACE),
                eq(TEST_EXPERIMENT_FLAG)));
        doThrow(NameNotFoundException.class).when(mPm).getPackageInfo(anyString(), anyInt());
        assertFalse(NetworkStackUtils.isFeatureEnabled(mContext, TEST_NAME_SPACE,
                TEST_EXPERIMENT_FLAG));
    }
}
