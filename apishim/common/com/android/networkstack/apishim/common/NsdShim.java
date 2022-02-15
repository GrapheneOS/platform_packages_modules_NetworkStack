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

package com.android.networkstack.apishim.common;

import android.net.Network;
import android.net.NetworkRequest;
import android.net.nsd.NsdManager;
import android.net.nsd.NsdServiceInfo;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

/** Shim for NSD APIs, including {@link android.net.nsd.NsdManager} and
 * {@link android.net.nsd.NsdServiceInfo}. */
public interface NsdShim {
    /**
     * @see NsdServiceInfo#getNetwork()
     */
    @Nullable
    Network getNetwork(@NonNull NsdServiceInfo serviceInfo);

    /**
     * @see NsdServiceInfo#setNetwork(Network)
     */
    void setNetwork(@NonNull NsdServiceInfo serviceInfo, @Nullable Network network);

    /**
     * @see NsdManager#discoverServices(String, int, Network, NsdManager.DiscoveryListener)
     */
    void discoverServices(@NonNull NsdManager nsdManager, @NonNull String serviceType,
            int protocolType, @Nullable Network network,
            @NonNull NsdManager.DiscoveryListener listener) throws UnsupportedApiLevelException;

    /**
     * @see NsdManager#discoverServices(String, int, NetworkRequest, NsdManager.DiscoveryListener)
     */
    void discoverServices(@NonNull NsdManager nsdManager, @NonNull String serviceType,
            int protocolType, @Nullable NetworkRequest request,
            @NonNull NsdManager.DiscoveryListener listener) throws UnsupportedApiLevelException;
}
