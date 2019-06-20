/*
 * Copyright (C) 2019 The Android Open Source Project
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

import android.os.Parcel
import android.os.Parcelable
import kotlin.test.assertEquals
import kotlin.test.fail

/**
 * Return a new instance of `T` after being parceled then unparceled.
 */
fun <T: Parcelable> parcelingRoundTrip(source: T): T {
    val creator: Parcelable.Creator<T>
    try {
        creator = source.javaClass.getField("CREATOR").get(null) as Parcelable.Creator<T>
    } catch (e: IllegalAccessException) {
        fail("Missing CREATOR field: " + e.message)
    } catch (e: NoSuchFieldException) {
        fail("Missing CREATOR field: " + e.message)
    }

    var p = Parcel.obtain()
    source.writeToParcel(p, /* flags */ 0)
    p.setDataPosition(0)
    val marshalled = p.marshall()
    p = Parcel.obtain()
    p.unmarshall(marshalled, 0, marshalled.size)
    p.setDataPosition(0)
    return creator.createFromParcel(p)
}

/**
 * Assert that after being parceled then unparceled, `source` is equal to the original
 * object.
 */
fun <T: Parcelable> assertParcelingIsLossless(source: T) {
    assertEquals(source, parcelingRoundTrip(source))
}

fun <T: Parcelable> assertParcelSane(obj: T, fieldCount: Int) {
    assertFieldCountEquals(fieldCount, obj::class.java)
    assertParcelingIsLossless(obj)
}
