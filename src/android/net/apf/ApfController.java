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

package android.net.apf;

import static android.system.OsConstants.ARPHRD_ETHER;

import android.system.ErrnoException;
import android.system.OsConstants;

import androidx.annotation.Nullable;

import com.android.net.module.util.SharedLog;
import com.android.networkstack.util.NetworkStackUtils;

/**
 * A controller class for APF (Android Packet Filtering) related operations.
 *
 * This class contains the glue logic for ApfFilter related logic management.
 * @hide
 */
public class ApfController {

    /**
     * Get the APF capabilities for the specified interface through Non-HAL API.
     */
    @Nullable
    public static ApfCapabilities getApfCapabilities(String ifName, SharedLog log) {
        try {
            final long caps = NetworkStackUtils.getApfCapabilities(ifName);
            if (caps < 0) return null;
            // The lower 32 bits is the APF version, the upper 32 bit is the RAM size.
            final int version = (int) caps;
            final int size = (int) (caps >> 32);
            return new ApfCapabilities(version, size, ARPHRD_ETHER);
        } catch (ErrnoException e) {
            // Do not log an error if the native API is not implemented.
            if (e.errno != OsConstants.ENOSYS) {
                log.e("[Non-HAL API] Cannot get APF capabilities: ", e);
            }
            return null;
        }
    }

    /**
     * Install a packet filter on the specified interface through Non-HAL API.
     */
    public static boolean installPacketFilter(String ifName, byte[] filter, SharedLog log) {
        try {
            NetworkStackUtils.installPacketFilter(ifName, filter);
            return true;
        } catch (ErrnoException e) {
            log.e("[Non-HAL API] Failed to install packet filter", e);
            return false;
        }
    }

    /**
     * Read the packet filter RAM from the specified interface through Non-HAL API.
     */
    public static boolean readPacketFilterRam(String ifName, byte[] output, SharedLog log) {
        try {
            return NetworkStackUtils.readPacketFilterRam(ifName, output);
        } catch (ErrnoException e) {
            log.e("[Non-HAL API] Failed to read packet filter RAM", e);
            return false;
        }
    }
}
