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

import static com.android.modules.utils.build.SdkLevel.isAtLeastT;

import android.content.Context;
import android.net.EthernetManager;
import android.os.Build;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;

import com.android.networkstack.apishim.common.EthernetManagerShim;

import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;

/**
 * Implementation of {@link EthernetManagerShim} for API 33.
 */
@RequiresApi(Build.VERSION_CODES.TIRAMISU)
public class EthernetManagerShimImpl
        extends com.android.networkstack.apishim.api31.EthernetManagerShimImpl {

    protected final EthernetManager mEm;

    // This is needed because callers of the shim cannot use EthernetManager.InterfaceStateListener,
    // they need to use EthernetManagerShim.InterfaceStateListener instead. But when actually
    // registering a callback, the callback type passed to EthernetManager must be a real
    // listener, not a shim. This map keeps track of the mapping between the two objects so that
    // when a caller calls removeInterfaceStateListener with a shim listener, this class knows what
    // real listener to pass to EthernetManager.
    private final ConcurrentHashMap<InterfaceStateListener, EthernetManager.InterfaceStateListener>
            mListeners = new ConcurrentHashMap<>();

    protected EthernetManagerShimImpl(Context context) {
        mEm = context.getSystemService(EthernetManager.class);
    }

    /**
     * Get a new instance of {@link EthernetManagerShim}.
     */
    @RequiresApi(Build.VERSION_CODES.Q)
    public static EthernetManagerShim newInstance(Context context) {
        if (!isAtLeastT()) {
            return com.android.networkstack.apishim.api31.EthernetManagerShimImpl
                    .newInstance(context);
        }
        return new EthernetManagerShimImpl(context);
    }

    @Override
    public void addInterfaceStateListener(@NonNull Executor executor,
            @NonNull InterfaceStateListener listener) {
        final EthernetManager.InterfaceStateListener wrapper = (a, b, c, d) -> {
            listener.onInterfaceStateChanged(a, b, c, d);
        };
        // EthernetManager#addInterfaceStateListener will allow registering the same listener twice,
        // but this does not seem very useful and is difficult to support with the wrapper scheme
        // used by this shim. Don't allow it.
        final EthernetManager.InterfaceStateListener existing =
                mListeners.putIfAbsent(listener, wrapper);
        if (existing != null) {
            throw new IllegalStateException("Attempt to register duplicate listener");
        }
        mEm.addInterfaceStateListener(executor, wrapper);
    }

    @Override
    public void removeInterfaceStateListener(@NonNull InterfaceStateListener listener) {
        final EthernetManager.InterfaceStateListener wrapper = mListeners.remove(listener);
        if (wrapper != null) {
            mEm.removeInterfaceStateListener(wrapper);
        }
    }

    @Override
    // This method existed in R and S, but as @TestApi, so should not appear in the shims before T
    // because otherwise it could be used by production code on R and S.
    public void setIncludeTestInterfaces(boolean include) {
        mEm.setIncludeTestInterfaces(include);
    }

    @Override
    @NonNull
    public List<String> getInterfaceList() {
        return mEm.getInterfaceList();
    }
}
