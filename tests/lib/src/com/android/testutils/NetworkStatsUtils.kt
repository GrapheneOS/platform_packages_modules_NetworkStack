/*
 * Copyright (C) 2020 The Android Open Source Project
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

package com.android.testutils

import android.net.NetworkStats

fun orderInsensitiveEquals(
    leftStats: NetworkStats,
    rightStats: NetworkStats
): Boolean {
    if (leftStats == rightStats) return true
    if (leftStats.getElapsedRealtime() != rightStats.getElapsedRealtime() ||
            leftStats.size() != rightStats.size()) return false
    val left = NetworkStats.Entry()
    val right = NetworkStats.Entry()
    // Order insensitive compare.
    for (i in 0 until leftStats.size()) {
        leftStats.getValues(i, left)
        val j: Int = rightStats.findIndexHinted(left.iface, left.uid, left.set, left.tag,
                left.metered, left.roaming, left.defaultNetwork, i)
        rightStats.getValues(j, right)
        if (left != right) return false
    }
    return true
}
