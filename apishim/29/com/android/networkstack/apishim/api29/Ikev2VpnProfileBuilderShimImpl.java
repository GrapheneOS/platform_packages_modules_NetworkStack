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

package com.android.networkstack.apishim.api29;

import android.os.Build;

import androidx.annotation.RequiresApi;

import com.android.networkstack.apishim.common.Ikev2VpnProfileBuilderShim;

/**
 * Implementation of Ikev2VpnProfileBuilderShim for API 29.
 *
 * @param <T> type of builder, typically Ikev2VpnProfile.Builder. This is necessary because at
 *            compile time, shims for older releases will not have access to this class as it
 *            debuted in SDK30. So the user of the shim has to pass it in.
 */
// NOTE: The trick with the formal parameter only works because when this shim was introduced,
// the stable API already contained the class that the caller needs to pass in; this won't
// work for a class added in the latest API level.
@RequiresApi(Build.VERSION_CODES.Q)
public class Ikev2VpnProfileBuilderShimImpl<T> implements Ikev2VpnProfileBuilderShim<T> {
}
