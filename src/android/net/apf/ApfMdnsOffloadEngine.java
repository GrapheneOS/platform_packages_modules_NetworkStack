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

import android.annotation.NonNull;
import android.annotation.RequiresApi;
import android.net.nsd.NsdManager;
import android.net.nsd.OffloadEngine;
import android.net.nsd.OffloadServiceInfo;
import android.os.Build;
import android.os.Handler;
import android.util.Log;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * APF offload engine implementation for managing mDNS offloads.
 */
@RequiresApi(Build.VERSION_CODES.VANILLA_ICE_CREAM)
public class ApfMdnsOffloadEngine implements OffloadEngine {

    private static final String TAG = ApfMdnsOffloadEngine.class.getSimpleName();

    /**
     * Callback interface for receiving notifications about offload rule updates.
     */
    public interface Callback {
        /**
         * Called when the offload rules are updated.
         * <p>
         * This method is called on the handler thread.
         *
         * @param allRules The updated list of MDNS offload rules.
         */
        void onOffloadRulesUpdated(@NonNull List<MdnsOffloadRule> allRules);
    }

    @NonNull
    private final List<OffloadServiceInfo> mOffloadServiceInfos = new ArrayList<>();
    @NonNull
    private final String mInterfaceName;
    @NonNull
    private final Handler mHandler;
    @NonNull
    private final NsdManager mNsdManager;
    @NonNull
    private final Callback mCallback;

    /**
     * Constructor for ApfOffloadEngine.
     */
    public ApfMdnsOffloadEngine(@NonNull String interfaceName, @NonNull Handler handler,
            @NonNull NsdManager nsdManager, @NonNull Callback callback) {
        mInterfaceName = interfaceName;
        mHandler = handler;
        mNsdManager = nsdManager;
        mCallback = callback;
    }

    @Override
    public void onOffloadServiceUpdated(@NonNull OffloadServiceInfo info) {
        handleOffloadServiceUpdated(info, false /* isRemoved */);
    }

    @Override
    public void onOffloadServiceRemoved(@NonNull OffloadServiceInfo info) {
        handleOffloadServiceUpdated(info, true /* isRemoved */);
    }

    private void handleOffloadServiceUpdated(@NonNull OffloadServiceInfo info, boolean isRemoved) {
        if (isRemoved) {
            mOffloadServiceInfos.removeIf(i -> i.getKey().equals(info.getKey()));
        } else {
            mOffloadServiceInfos.removeIf(i -> i.getKey().equals(info.getKey()));
            mOffloadServiceInfos.add(info);
        }
        try {
            List<MdnsOffloadRule> offloadRules = ApfMdnsUtils.extractOffloadReplyRule(
                    mOffloadServiceInfos);
            mCallback.onOffloadRulesUpdated(offloadRules);
        } catch (IOException e) {
            Log.e(TAG, "Failed to extract offload reply rule", e);
        }
    }

    /**
     * Registers the offload engine with the NsdManager.
     */
    public void registerOffloadEngine() {
        mNsdManager.registerOffloadEngine(mInterfaceName, OFFLOAD_TYPE_REPLY,
                OFFLOAD_CAPABILITY_BYPASS_MULTICAST_LOCK, mHandler::post, this);
    }

    /**
     * Unregisters the offload engine with the NsdManager.
     */
    public void unregisterOffloadEngine() {
        mNsdManager.unregisterOffloadEngine(this);
        mOffloadServiceInfos.clear();
    }
}
