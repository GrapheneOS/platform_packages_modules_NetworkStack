/*
 * Copyright (C) 2023 The Android Open Source Project
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

import android.net.Ikev2VpnProfile;
import android.os.Build;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;

/**
 * Implementation of Ikev2VpnProfileBuilderShim for API 31.
 */
@RequiresApi(Build.VERSION_CODES.S)
public class Ikev2VpnProfileBuilderShimImpl
        extends com.android.networkstack.apishim.api30.Ikev2VpnProfileBuilderShimImpl {
    protected Ikev2VpnProfileBuilderShimImpl(@NonNull Ikev2VpnProfile.Builder builder) {
        super(builder);
    }

    protected Ikev2VpnProfileBuilderShimImpl(@NonNull String serverAddr,
            @NonNull String identity) {
        super(serverAddr, identity);
    }
}
