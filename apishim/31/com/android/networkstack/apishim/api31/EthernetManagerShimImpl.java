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

package com.android.networkstack.apishim.api31;

import static com.android.modules.utils.build.SdkLevel.isAtLeastS;

import android.content.Context;
import android.os.Build;

import androidx.annotation.RequiresApi;

import com.android.networkstack.apishim.common.EthernetManagerShim;

/**
 * Implementation of {@link EthernetManagerShim} for API 31.
 *
 * Doesn't have any methods, but must exist because the stable shim API level is currently 31.
 * TODO: delete when the stable shim API level becomes 33.
 */
@RequiresApi(Build.VERSION_CODES.S)
public class EthernetManagerShimImpl
        extends com.android.networkstack.apishim.api29.EthernetManagerShimImpl {
    /**
     * Get a new instance of {@link EthernetManagerShim}.
     */
    @RequiresApi(Build.VERSION_CODES.Q)
    public static EthernetManagerShim newInstance(Context context) {
        if (!isAtLeastS()) {
            return com.android.networkstack.apishim.api29.EthernetManagerShimImpl
                    .newInstance(context);
        }
        return new EthernetManagerShimImpl();
    }
}
