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
package android.net.apf

import android.net.apf.ApfMdnsUtils.extractOffloadReplyRule
import android.net.nsd.OffloadEngine
import android.net.nsd.OffloadServiceInfo
import android.net.nsd.OffloadServiceInfo.Key
import android.os.Build
import androidx.test.filters.SmallTest
import com.android.net.module.util.NetworkStackConstants.TYPE_A
import com.android.net.module.util.NetworkStackConstants.TYPE_AAAA
import com.android.net.module.util.NetworkStackConstants.TYPE_PTR
import com.android.net.module.util.NetworkStackConstants.TYPE_SRV
import com.android.net.module.util.NetworkStackConstants.TYPE_TXT
import com.android.testutils.DevSdkIgnoreRule
import com.android.testutils.DevSdkIgnoreRule.IgnoreUpTo
import com.android.testutils.DevSdkIgnoreRunner
import java.io.IOException
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Tests for Apf mDNS utility functions.
 */
@RunWith(DevSdkIgnoreRunner::class)
@SmallTest
@IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class ApfMdnsUtilsTest {
    @get:Rule
    val ignoreRule = DevSdkIgnoreRule()

    private val testServiceName1 = "NsdChat"
    private val testServiceName2 = "NsdCall"
    private val testServiceType = "_http._tcp.local"
    private val testSubType = "tsub"
    private val testHostName = "Android.local"
    private val testRawPacket1 = byteArrayOf(1, 2, 3, 4, 5)
    private val testRawPacket2 = byteArrayOf(6, 7, 8, 9)
    private val encodedFullServiceName1 = intArrayOf(
            7, 'N'.code, 'S'.code, 'D'.code, 'C'.code, 'H'.code, 'A'.code, 'T'.code,
            5, '_'.code, 'H'.code, 'T'.code, 'T'.code, 'P'.code,
            4, '_'.code, 'T'.code, 'C'.code, 'P'.code,
            5, 'L'.code, 'O'.code, 'C'.code, 'A'.code, 'L'.code,
            0, 0).map { it.toByte() }.toByteArray()
    private val encodedFullServiceName2 = intArrayOf(
            7, 'N'.code, 'S'.code, 'D'.code, 'C'.code, 'A'.code, 'L'.code, 'L'.code,
            5, '_'.code, 'H'.code, 'T'.code, 'T'.code, 'P'.code,
            4, '_'.code, 'T'.code, 'C'.code, 'P'.code,
            5, 'L'.code, 'O'.code, 'C'.code, 'A'.code, 'L'.code,
            0, 0).map { it.toByte() }.toByteArray()
    private val encodedServiceType = intArrayOf(
            5, '_'.code, 'H'.code, 'T'.code, 'T'.code, 'P'.code,
            4, '_'.code, 'T'.code, 'C'.code, 'P'.code,
            5, 'L'.code, 'O'.code, 'C'.code, 'A'.code, 'L'.code,
            0, 0).map { it.toByte() }.toByteArray()
    private val encodedServiceTypeWithSub1 = intArrayOf(
            4, 'T'.code, 'S'.code, 'U'.code, 'B'.code,
            4, '_'.code, 'S'.code, 'U'.code, 'B'.code,
            5, '_'.code, 'H'.code, 'T'.code, 'T'.code, 'P'.code,
            4, '_'.code, 'T'.code, 'C'.code, 'P'.code,
            5, 'L'.code, 'O'.code, 'C'.code, 'A'.code, 'L'.code,
            0, 0).map { it.toByte() }.toByteArray()
    private val encodedServiceTypeWithWildCard = intArrayOf(
            0xff,
            4, '_'.code, 'S'.code, 'U'.code, 'B'.code,
            5, '_'.code, 'H'.code, 'T'.code, 'T'.code, 'P'.code,
            4, '_'.code, 'T'.code, 'C'.code, 'P'.code,
            5, 'L'.code, 'O'.code, 'C'.code, 'A'.code, 'L'.code,
            0, 0).map { it.toByte() }.toByteArray()
    private val encodedTestHostName = intArrayOf(
            7, 'A'.code, 'N'.code, 'D'.code, 'R'.code, 'O'.code, 'I'.code, 'D'.code,
            5, 'L'.code, 'O'.code, 'C'.code, 'A'.code, 'L'.code,
            0, 0).map { it.toByte() }.toByteArray()

    @Test
    fun testExtractOffloadReplyRule_noPriorityReturnsEmptySet() {
        val info = createOffloadServiceInfo(Int.MAX_VALUE)
        val rules = extractOffloadReplyRule(listOf(info))
        assertTrue(rules.isEmpty())
    }

    @Test
    fun testExtractOffloadReplyRule_extractRulesWithValidPriority() {
        val info1 = createOffloadServiceInfo(10)
        val info2 = createOffloadServiceInfo(
                11,
                testServiceName2,
                listOf("a", "b", "c", "d"),
                testRawPacket2
        )
        val rules = extractOffloadReplyRule(listOf(info2, info1))
        val expectedResult = listOf(
                MdnsOffloadRule(
                        listOf(
                                MdnsOffloadRule.Matcher(encodedServiceType, TYPE_PTR),
                                MdnsOffloadRule.Matcher(encodedServiceTypeWithSub1, TYPE_PTR),
                                MdnsOffloadRule.Matcher(encodedFullServiceName1, TYPE_SRV),
                                MdnsOffloadRule.Matcher(encodedFullServiceName1, TYPE_TXT),
                                MdnsOffloadRule.Matcher(encodedTestHostName, TYPE_A),
                                MdnsOffloadRule.Matcher(encodedTestHostName, TYPE_AAAA),

                        ),
                        testRawPacket1,
                ),
                MdnsOffloadRule(
                        listOf(
                                MdnsOffloadRule.Matcher(encodedServiceTypeWithWildCard, TYPE_PTR),
                                MdnsOffloadRule.Matcher(encodedFullServiceName2, TYPE_SRV),
                                MdnsOffloadRule.Matcher(encodedFullServiceName2, TYPE_TXT),

                        ),
                        null,
                )
        )
        assertContentEquals(expectedResult, rules)
    }

    @Test
    fun testExtractOffloadReplyRule_longLabelThrowsException() {
        val info = createOffloadServiceInfo(10, "a".repeat(256))
        assertFailsWith<IOException> { extractOffloadReplyRule(listOf(info)) }
    }

    private fun createOffloadServiceInfo(
            priority: Int,
            serviceName: String = testServiceName1,
            subTypes: List<String> = listOf(testSubType),
            rawPacket1: ByteArray = testRawPacket1
    ): OffloadServiceInfo = OffloadServiceInfo(
            Key(serviceName, testServiceType),
            subTypes,
            testHostName,
            rawPacket1,
            priority,
            OffloadEngine.OFFLOAD_TYPE_REPLY.toLong()
        )
}
