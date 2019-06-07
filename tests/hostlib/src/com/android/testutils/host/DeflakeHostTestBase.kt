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
 * limitations under the License
 */

package com.android.testutils.host

import com.android.tests.util.ModuleTestUtils
import com.android.tradefed.testtype.DeviceJUnit4ClassRunner
import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test
import com.android.tradefed.util.AaptParser
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import kotlin.test.assertTrue
import kotlin.test.fail

@RunWith(DeviceJUnit4ClassRunner::class)
abstract class DeflakeHostTestBase : BaseHostJUnit4Test() {

    /**
     * Number of times the device test will be run.
     */
    protected abstract val runCount: Int

    /**
     * Filename of the APK to run as part of the test.
     *
     * <p>Typically the java_test_host build rule will have a 'data: [":DeviceTest"]' dependency
     * on the build rule for the device tests. In that case the filename will be "DeviceTest.apk".
     */
    protected abstract val testApkFilename: String

    /**
     * Timeout for each run of the test, in milliseconds. The host-driven test will fail if any run
     * takes more than the specified timeout.
     */
    protected open val singleRunTimeoutMs = 5 * 60_000L

    /**
     * List of classes to run in the test package. If empty, all classes in the package will be run.
     */
    protected open val testClasses: List<String> = emptyList()

    @Before
    fun setUp() {
        // APK will be auto-cleaned
        installPackage(testApkFilename)
    }

    @Test
    fun testDeflake() {
        val apkFile = ModuleTestUtils(this).getTestFile(testApkFilename)
        val pkgName = AaptParser.parse(apkFile)?.packageName ?:
                fail("Could not parse test package name")
        // null class name runs all classes in the package
        val tc = if (testClasses.isEmpty()) listOf(null) else testClasses

        repeat(runCount) {
            // TODO: improve reporting by always running all tests and counting flakes
            tc.forEach {
                assertTrue(runDeviceTests(pkgName, it, singleRunTimeoutMs))
            }
        }
    }
}