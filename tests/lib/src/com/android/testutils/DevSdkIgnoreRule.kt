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

import android.os.Build
import org.junit.Assume.assumeTrue
import org.junit.rules.TestRule
import org.junit.runner.Description
import org.junit.runners.model.Statement

/**
 * A test rule to ignore tests based on the development SDK level.
 *
 * If the device is not using a release SDK, the development SDK is considered to be higher than
 * [Build.VERSION.SDK_INT].
 *
 * @param ignoreClassUpTo Skip all tests in the class if the device dev SDK is <= this value.
 * @param ignoreClassAfter Skip all tests in the class if the device dev SDK is > this value.
 */
class DevSdkIgnoreRule @JvmOverloads constructor(
    private val ignoreClassUpTo: Int? = null,
    private val ignoreClassAfter: Int? = null
) : TestRule {
    override fun apply(base: Statement, description: Description): Statement {
        return IgnoreBySdkStatement(base, description)
    }

    /**
     * Ignore the test for any development SDK that is strictly after [value].
     *
     * If the device is not using a release SDK, the development SDK is considered to be higher
     * than [Build.VERSION.SDK_INT].
     */
    annotation class IgnoreAfter(val value: Int)

    /**
     * Ignore the test for any development SDK that lower than or equal to [value].
     *
     * If the device is not using a release SDK, the development SDK is considered to be higher
     * than [Build.VERSION.SDK_INT].
     */
    annotation class IgnoreUpTo(val value: Int)

    private inner class IgnoreBySdkStatement(
        private val base: Statement,
        private val description: Description
    ) : Statement() {
        override fun evaluate() {
            val ignoreAfter = description.getAnnotation(IgnoreAfter::class.java)
            val ignoreUpTo = description.getAnnotation(IgnoreUpTo::class.java)

            // In-development API n+1 will have SDK_INT == n and CODENAME != REL.
            // Stable API n has SDK_INT == n and CODENAME == REL.
            val release = "REL" == Build.VERSION.CODENAME
            val sdkInt = Build.VERSION.SDK_INT
            val devApiLevel = sdkInt + if (release) 0 else 1
            val message = "Skipping test for ${if (!release) "non-" else ""}release SDK $sdkInt"
            assumeTrue(message, ignoreClassAfter == null || devApiLevel <= ignoreClassAfter)
            assumeTrue(message, ignoreClassUpTo == null || devApiLevel > ignoreClassUpTo)
            assumeTrue(message, ignoreAfter == null || devApiLevel <= ignoreAfter.value)
            assumeTrue(message, ignoreUpTo == null || devApiLevel > ignoreUpTo.value)
            base.evaluate()
        }
    }
}