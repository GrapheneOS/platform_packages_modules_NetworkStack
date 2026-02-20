/*
 * Copyright (C) 2026 The Android Open Source Project
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
package com.android.server.util;

import com.android.net.module.util.ModuleFlagProvider;

import java.util.Objects;

/**
 * The module flag provider for NetworkStackService.
 */
public class NetworkStackModuleFlagProvider implements ModuleFlagProvider.FlagProvider {
    @Override
    public boolean isFeatureFlagEnabled(String featureName) {
        if (Objects.equals(featureName, ModuleFlagProvider.FLAG_NETLINK_NO_TIMEOUTS)) {
            return com.android.networkstack.flags.Flags.netlinkNoTimeout();
        }
        throw new IllegalArgumentException("Unknown feature flag: " + featureName);
    }
}
