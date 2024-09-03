/*
 * Copyright (C) 2024 The Android Open Source Project
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

package android.net.ipmemorystore;

import android.annotation.NonNull;

/**
 * A listener for the IpMemoryStore to return specific network event counts.
 * @hide
 */
public interface OnNetworkEventCountRetrievedListener {
    /**
     * The memory store has come up with the answer to a query that was sent.
     */
    void onNetworkEventCountRetrieved(Status status, int[] counts);

    /** Converts this OnNetworkEventCountRetrievedListener to a parcelable object */
    @NonNull
    static IOnNetworkEventCountRetrievedListener toAIDL(
            @NonNull final OnNetworkEventCountRetrievedListener listener) {
        return new IOnNetworkEventCountRetrievedListener.Stub() {
            @Override
            public void onNetworkEventCountRetrieved(
                    final StatusParcelable statusParcelable,
                    final int[] counts) {
                // NonNull, but still don't crash the system server if null
                if (null != listener) {
                    listener.onNetworkEventCountRetrieved(new Status(statusParcelable), counts);
                }
            }

            @Override
            public int getInterfaceVersion() {
                return this.VERSION;
            }

            @Override
            public String getInterfaceHash() {
                return this.HASH;
            }
        };
    }
}
