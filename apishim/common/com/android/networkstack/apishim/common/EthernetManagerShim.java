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

import android.net.IpConfiguration;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.List;
import java.util.concurrent.Executor;

/** API shim for EthernetManager */
public interface EthernetManagerShim {
    int STATE_ABSENT = 0;
    int STATE_LINK_DOWN = 1;
    int STATE_LINK_UP = 2;
    int ROLE_NONE = 0;
    int ROLE_CLIENT = 1;
    int ROLE_SERVER = 2;

    /** Shim for EthernetManager#InterfaceStateListener. */
    interface InterfaceStateListener {
        void onInterfaceStateChanged(@NonNull String iface, int state, int role,
                @Nullable IpConfiguration configuration);
    }

    /** Shim for EthernetManager#addInterfaceStateListener */
    default void addInterfaceStateListener(@NonNull Executor executor,
            @NonNull InterfaceStateListener listener) throws UnsupportedApiLevelException {
        throw new UnsupportedApiLevelException();
    }

    /** Shim for EthernetManager#removeInterfaceStateListener */
    default void removeInterfaceStateListener(@NonNull InterfaceStateListener listener)
            throws UnsupportedApiLevelException {
        throw new UnsupportedApiLevelException("Not supported until API 33");
    }

    /** Shim for EthernetManager#setIncludeTestInterfaces */
    default void setIncludeTestInterfaces(boolean include) throws UnsupportedApiLevelException {
        throw new UnsupportedApiLevelException("Not supported until API 30");
    }

    /** Shim for EthernetManager#getInterfaceList */
    default List<String> getInterfaceList() throws UnsupportedApiLevelException {
        throw new UnsupportedApiLevelException("Not supported until API 33");
    }
}
