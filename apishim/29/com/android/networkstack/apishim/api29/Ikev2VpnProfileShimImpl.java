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

package com.android.networkstack.apishim.api29;

import com.android.networkstack.apishim.common.Ikev2VpnProfileShim;
import com.android.networkstack.apishim.common.UnsupportedApiLevelException;

/**
 * Implementation of Ikev2VpnProfileShim for API 29.
 * @param <T> type of profile, typically Ikev2VpnProfile
 */
public class Ikev2VpnProfileShimImpl<T> implements Ikev2VpnProfileShim<T> {
    /**
     * @see Ikev2VpnProfile#getRequiresInternetValidation(boolean)
     */
    @Override
    public boolean getRequiresInternetValidation(T profile)
            throws UnsupportedApiLevelException {
        throw new UnsupportedApiLevelException("Only supported from API level 33.");
    }
}
