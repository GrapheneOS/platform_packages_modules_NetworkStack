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

package com.android.networkstack.apishim;

import android.os.Build;
import android.telephony.TelephonyManager;
import android.telephony.TelephonyManager.CarrierPrivilegesListener;

import androidx.annotation.RequiresApi;

import com.android.networkstack.apishim.common.TelephonyManagerShim;
import com.android.networkstack.apishim.common.UnsupportedApiLevelException;

import java.util.HashMap;
import java.util.List;
import java.util.concurrent.Executor;

/**
 * Implementation of {@link TelephonyManagerShim} for API 33.
 */
@RequiresApi(Build.VERSION_CODES.TIRAMISU)
public class TelephonyManagerShimImpl extends
        com.android.networkstack.apishim.api31.TelephonyManagerShimImpl {
    private HashMap<CarrierPrivilegesListenerShim, CarrierPrivilegesListener> mListenerMap =
            new HashMap<>();
    public TelephonyManagerShimImpl(TelephonyManager telephonyManager) {
        super(telephonyManager);
    }

    /** See android.telephony.TelephonyManager#addCarrierPrivilegesListener */
    public void addCarrierPrivilegesListener(
            int logicalSlotIndex,
            Executor executor,
            CarrierPrivilegesListenerShim listener)
            throws UnsupportedApiLevelException {
        CarrierPrivilegesListener carrierPrivilegesListener = new CarrierPrivilegesListener() {
            public void onCarrierPrivilegesChanged(
                    List<String> privilegedPackageNames,
                    int[] privilegedUids) {
                listener.onCarrierPrivilegesChanged(privilegedPackageNames, privilegedUids);
            }
        };
        mTm.addCarrierPrivilegesListener(logicalSlotIndex, executor, carrierPrivilegesListener);
        mListenerMap.put(listener, carrierPrivilegesListener);
    }

    /** See android.telephony.TelephonyManager#addCarrierPrivilegesListener */
    public void removeCarrierPrivilegesListener(
            CarrierPrivilegesListenerShim listener)
            throws UnsupportedApiLevelException {
        mTm.removeCarrierPrivilegesListener(mListenerMap.get(listener));
        mListenerMap.remove(listener);
    }

    /** See android.telephony.TelephonyManager#getCarrierServicePackageNameForLogicalSlot */
    public String getCarrierServicePackageNameForLogicalSlot(int logicalSlotIndex) {
        return mTm.getCarrierServicePackageNameForLogicalSlot(logicalSlotIndex);
    }
}
