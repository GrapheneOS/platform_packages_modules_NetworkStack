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

package com.android.server.connectivity;

import static android.net.ConnectivitySettingsManager.PRIVATE_DNS_MODE_OFF;
import static android.net.ConnectivitySettingsManager.PRIVATE_DNS_MODE_OPPORTUNISTIC;
import static android.net.ConnectivitySettingsManager.PRIVATE_DNS_MODE_PROVIDER_HOSTNAME;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import android.annotation.NonNull;
import android.net.shared.PrivateDnsConfig;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.MockitoAnnotations;

import java.net.InetAddress;

@RunWith(JUnit4.class)
public final class DdrTrackerTest {
    private static final int OFF_MODE = PRIVATE_DNS_MODE_OFF;
    private static final int OPPORTUNISTIC_MODE = PRIVATE_DNS_MODE_OPPORTUNISTIC;
    private static final int STRICT_MODE = PRIVATE_DNS_MODE_PROVIDER_HOSTNAME;

    private DdrTracker mDdrTracker;

    private static class PrivateDnsConfigBuilder {
        private int mMode = OFF_MODE;
        private String mHostname = null;
        private final InetAddress[] mIps = null;
        private final String mDohName = null;
        private final InetAddress[] mDohIps = null;
        private final String mDohPath = null;
        private final int mDohPort = -1;

        PrivateDnsConfigBuilder setMode(int mode) {
            mMode = mode;
            return this;
        }
        PrivateDnsConfigBuilder setHostname(String value) {
            mHostname = value;
            return this;
        }
        PrivateDnsConfig build() {
            return new PrivateDnsConfig(mMode, mHostname, mIps, mDohName, mDohIps, mDohPath,
                    mDohPort);
        }
    }

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        mDdrTracker = new DdrTracker();
    }

    private void testNotifyPrivateDnsSettingsChangedHelper(int mode, @NonNull String dnsProvider)
            throws Exception {
        final PrivateDnsConfig cfg =
                new PrivateDnsConfigBuilder().setMode(mode).setHostname(dnsProvider).build();

        assertTrue(mDdrTracker.notifyPrivateDnsSettingsChanged(cfg));
        assertEquals(mode, mDdrTracker.getPrivateDnsMode());
        assertEquals(dnsProvider, mDdrTracker.getStrictModeHostname());
        assertFalse(mDdrTracker.notifyPrivateDnsSettingsChanged(cfg));
    }

    @Test
    public void testNotifyPrivateDnsSettingsChanged() throws Exception {
        // Tests the initial private DNS setting in DdrTracker.
        assertEquals(OFF_MODE, mDdrTracker.getPrivateDnsMode());

        assertEquals("", mDdrTracker.getStrictModeHostname());
        assertFalse(mDdrTracker.notifyPrivateDnsSettingsChanged(new PrivateDnsConfigBuilder()
                .setMode(OFF_MODE).build()));

        testNotifyPrivateDnsSettingsChangedHelper(OPPORTUNISTIC_MODE, "");
        testNotifyPrivateDnsSettingsChangedHelper(STRICT_MODE, "example1.com");
        testNotifyPrivateDnsSettingsChangedHelper(STRICT_MODE, "example2.com");
        testNotifyPrivateDnsSettingsChangedHelper(OFF_MODE, "");
    }
}
