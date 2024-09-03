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

import android.net.ipmemorystore.StatusParcelable;

/**
 * A listener for the IpMemoryStore to return the counts of network event that matches the query.
 * {@hide}
 */
oneway interface IOnNetworkEventCountRetrievedListener {
    /**
     * The network event counts were fetched for a specified cluster and network event types
     * (IIpMemoryStore#NETWORK_EVENT_* constants) since one or more timestamps in the past.
     *
     * See {@link IIpMemoryStore#retrieveNetworkEventCount} parameter description for more details.
     */
    void onNetworkEventCountRetrieved(in StatusParcelable status, in int[] counts);
}
