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

import android.net.apf.ApfMdnsUtils.extractRules
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
import kotlin.test.assertFalse
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
    private val testHttpServiceType = "_http._tcp"
    private val testSshServiceType = "_ssh._tcp"
    private val testSubType = "tsub"
    private val testAndroidHostName = "Android.local"
    private val testLaptopHostName = "Laptop.local"
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
    private val encodedHttpServiceType = intArrayOf(
            5, '_'.code, 'H'.code, 'T'.code, 'T'.code, 'P'.code,
            4, '_'.code, 'T'.code, 'C'.code, 'P'.code,
            5, 'L'.code, 'O'.code, 'C'.code, 'A'.code, 'L'.code,
            0, 0).map { it.toByte() }.toByteArray()
    private val encodedSshServiceType = intArrayOf(
            4, '_'.code, 'S'.code, 'S'.code, 'H'.code,
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
    private val encodedHttpServiceTypeWithWildCard = intArrayOf(
            0xff,
            4, '_'.code, 'S'.code, 'U'.code, 'B'.code,
            5, '_'.code, 'H'.code, 'T'.code, 'T'.code, 'P'.code,
            4, '_'.code, 'T'.code, 'C'.code, 'P'.code,
            5, 'L'.code, 'O'.code, 'C'.code, 'A'.code, 'L'.code,
            0, 0).map { it.toByte() }.toByteArray()
    private val encodedSshServiceTypeWithWildCard = intArrayOf(
            0xff,
            4, '_'.code, 'S'.code, 'U'.code, 'B'.code,
            4, '_'.code, 'S'.code, 'S'.code, 'H'.code,
            4, '_'.code, 'T'.code, 'C'.code, 'P'.code,
            5, 'L'.code, 'O'.code, 'C'.code, 'A'.code, 'L'.code,
            0, 0).map { it.toByte() }.toByteArray()
    private val encodedTestAndroidHostName = intArrayOf(
            7, 'A'.code, 'N'.code, 'D'.code, 'R'.code, 'O'.code, 'I'.code, 'D'.code,
            5, 'L'.code, 'O'.code, 'C'.code, 'A'.code, 'L'.code,
            0, 0).map { it.toByte() }.toByteArray()
    private val encodedTestLaptopHostName = intArrayOf(
            6, 'L'.code, 'A'.code, 'P'.code, 'T'.code, 'O'.code, 'P'.code,
            5, 'L'.code, 'O'.code, 'C'.code, 'A'.code, 'L'.code,
            0, 0).map { it.toByte() }.toByteArray()

    private fun isMdnsRulesAndHashCodeEqual(
            rules1: ApfMdnsUtils.MdnsRules,
            rules2: ApfMdnsUtils.MdnsRules
    ): Boolean {
        return (rules1 == rules2) && (rules1.hashCode() == rules2.hashCode())
    }

    @Test
    fun testExtractOffloadRules_extractRules() {
        val info1 = createOffloadServiceInfo(10)
        val info2 = createOffloadServiceInfo(
                Integer.MAX_VALUE,
                serviceName = testServiceName2,
                subTypes = listOf("a", "b", "c", "d"),
                rawPacket1 = testRawPacket2
        )
        val rules = extractRules(listOf(info2, info1)).offloadRules
        val expectedResult = listOf(
                MdnsOffloadRule(
                        "${info1.key.serviceName}.${info1.key.serviceType}",
                        listOf(
                                MdnsOffloadRule.Matcher(
                                    encodedHttpServiceType,
                                    intArrayOf(TYPE_PTR)
                                ),
                                MdnsOffloadRule.Matcher(
                                    encodedServiceTypeWithSub1,
                                    intArrayOf(TYPE_PTR)
                                ),
                                MdnsOffloadRule.Matcher(
                                    encodedFullServiceName1,
                                    intArrayOf(TYPE_SRV, TYPE_TXT)
                                ),
                                MdnsOffloadRule.Matcher(
                                    encodedTestAndroidHostName,
                                    intArrayOf(TYPE_A, TYPE_AAAA)
                                ),

                        ),
                        testRawPacket1,
                ),
                MdnsOffloadRule(
                        "${info2.key.serviceName}.${info2.key.serviceType}",
                        listOf(
                                MdnsOffloadRule.Matcher(
                                    encodedHttpServiceTypeWithWildCard,
                                    intArrayOf(TYPE_PTR)
                                ),
                                MdnsOffloadRule.Matcher(
                                    encodedFullServiceName2,
                                    intArrayOf(TYPE_SRV, TYPE_TXT)
                                ),

                        ),
                        null,
                )
        )
        assertContentEquals(expectedResult, rules)
    }

    @Test
    fun testExtractFilterRules_extractRules() {
        // For advertise and resolve service with non-empty hostName
        val info1 = createOffloadServiceInfo(
                priority = 10,
                serviceName = testServiceName2,
                serviceType = testHttpServiceType,
                subTypes = listOf(),
                hostName = testAndroidHostName,
                offloadType = OffloadEngine.OFFLOAD_TYPE_FILTER_REPLIES.toLong(),
                rawPacket1 = null
        )

        // For advertise and resolve service with empty hostName
        val info2 = createOffloadServiceInfo(
                priority = 10,
                serviceName = testServiceName1,
                serviceType = testHttpServiceType,
                subTypes = listOf(),
                hostName = "",
                offloadType = OffloadEngine.OFFLOAD_TYPE_FILTER_REPLIES.toLong(),
                rawPacket1 = null
        )

        // For discover service with subtype containing only empty string ""
        val info3 = createOffloadServiceInfo(
                priority = 10,
                serviceName = "",
                serviceType = testHttpServiceType,
                subTypes = listOf(""),
                hostName = testAndroidHostName,
                offloadType = OffloadEngine.OFFLOAD_TYPE_FILTER_REPLIES.toLong(),
                rawPacket1 = null
        )

        // For discover service with subtypes containing empty string ""
        val info4 = createOffloadServiceInfo(
                priority = 10,
                serviceName = "",
                serviceType = testSshServiceType,
                subTypes = listOf("", testSubType),
                hostName = testAndroidHostName,
                offloadType = OffloadEngine.OFFLOAD_TYPE_FILTER_REPLIES.toLong(),
                rawPacket1 = null
        )

        // For discover service with non-empty subTypes
        val info5 = createOffloadServiceInfo(
                priority = 10,
                serviceName = "",
                serviceType = testHttpServiceType,
                hostName = testLaptopHostName,
                offloadType = OffloadEngine.OFFLOAD_TYPE_FILTER_REPLIES.toLong(),
                rawPacket1 = null
        )

        // For different offloadType
        val infoIgnoredType = createOffloadServiceInfo(
                priority = 10,
                serviceName = "IgnoredType",
                serviceType = "_ignored._tcp",
                hostName = "Test.local",
                offloadType = OffloadEngine.OFFLOAD_TYPE_REPLY.toLong(),
                rawPacket1 = null
        )

        val rules = extractRules(
            listOf(
                info1,
                info2,
                info3,
                info4,
                info5,
                infoIgnoredType
            )
        ).filterRules

        val expectedResult = listOf(
                MdnsOffloadRule(
                        "${info1.key.serviceName}.${info1.key.serviceType}",
                        listOf(
                                MdnsOffloadRule.Matcher(encodedFullServiceName2),
                                MdnsOffloadRule.Matcher(encodedTestAndroidHostName)
                        ),
                        null /* replyPayload */
                ),
                MdnsOffloadRule(
                        "${info2.key.serviceName}.${info2.key.serviceType}",
                        listOf(
                                MdnsOffloadRule.Matcher(encodedFullServiceName1)
                        ),
                        null /* replyPayload */
                ),
                MdnsOffloadRule(
                        "${info3.key.serviceName}.${info3.key.serviceType}",
                        listOf(
                                MdnsOffloadRule.Matcher(encodedHttpServiceType)
                        ),
                        null /* replyPayload */
                ),
                MdnsOffloadRule(
                        "${info4.key.serviceName}.${info4.key.serviceType}",
                        listOf(
                                MdnsOffloadRule.Matcher(encodedSshServiceType),
                                MdnsOffloadRule.Matcher(encodedSshServiceTypeWithWildCard)
                        ),
                        null /* replyPayload */
                ),
                MdnsOffloadRule(
                        "${info5.key.serviceName}.${info5.key.serviceType}",
                        listOf(
                                MdnsOffloadRule.Matcher(encodedHttpServiceTypeWithWildCard),
                                MdnsOffloadRule.Matcher(encodedTestLaptopHostName)
                        ),
                        null /* replyPayload */
                )
        )

        assertContentEquals(expectedResult, rules)
    }

    @Test
    fun testExtractOffloadRules_longLabelThrowsException() {
        val info = createOffloadServiceInfo(10, "a".repeat(256))
        assertFailsWith<IOException> { extractRules(listOf(info)).offloadRules }
    }

    @Test
    fun testExtractOffloadAndFilterRules() {
        val info = createOffloadServiceInfo(
            priority = 10,
            offloadType =
                (OffloadEngine.OFFLOAD_TYPE_REPLY or OffloadEngine.OFFLOAD_TYPE_FILTER_REPLIES)
                    .toLong()
        )

        val expectedOffloadRules = listOf(
            MdnsOffloadRule(
                "${info.key.serviceName}.${info.key.serviceType}",
                listOf(
                    MdnsOffloadRule.Matcher(
                        encodedHttpServiceType,
                        intArrayOf(TYPE_PTR)
                    ),
                    MdnsOffloadRule.Matcher(
                        encodedServiceTypeWithSub1,
                        intArrayOf(TYPE_PTR)
                    ),
                    MdnsOffloadRule.Matcher(
                        encodedFullServiceName1,
                        intArrayOf(TYPE_SRV, TYPE_TXT)
                    ),
                    MdnsOffloadRule.Matcher(
                        encodedTestAndroidHostName,
                        intArrayOf(TYPE_A, TYPE_AAAA)
                    ),
                ),
                testRawPacket1,
            ),
        )
        val expectedFilterRules = listOf(
            MdnsOffloadRule(
                "${info.key.serviceName}.${info.key.serviceType}",
                listOf(
                    MdnsOffloadRule.Matcher(encodedFullServiceName1),
                    MdnsOffloadRule.Matcher(encodedTestAndroidHostName),
                ),
                null,
            )
        )

        assertTrue(isMdnsRulesAndHashCodeEqual(
            ApfMdnsUtils.MdnsRules(expectedOffloadRules, expectedFilterRules),
            extractRules(listOf(info))
        ))
    }

    @Test
    fun testMdnsRulesEquals() {
        val rule1 = MdnsOffloadRule(
                "",
                listOf(
                    MdnsOffloadRule.Matcher(encodedFullServiceName1),
                    MdnsOffloadRule.Matcher(encodedTestAndroidHostName)
                ),
                null
            )

        val rule2 = MdnsOffloadRule(
            "",
            listOf(
                MdnsOffloadRule.Matcher(encodedFullServiceName2),
                MdnsOffloadRule.Matcher(encodedTestAndroidHostName)
            ),
            null
        )

        val rule3 = MdnsOffloadRule(
            "",
            listOf(
                MdnsOffloadRule.Matcher(encodedFullServiceName2),
                MdnsOffloadRule.Matcher(encodedTestAndroidHostName)
            ),
            testRawPacket1
        )

        assertTrue(isMdnsRulesAndHashCodeEqual(
                ApfMdnsUtils.MdnsRules(listOf(rule1), listOf(rule2)),
                ApfMdnsUtils.MdnsRules(listOf(rule1), listOf(rule2))
        ))

        assertFalse(isMdnsRulesAndHashCodeEqual(
            ApfMdnsUtils.MdnsRules(listOf(rule1), listOf(rule2)),
            ApfMdnsUtils.MdnsRules(listOf(rule2), listOf(rule1))
        ))

        assertTrue(isMdnsRulesAndHashCodeEqual(
            ApfMdnsUtils.MdnsRules(listOf(rule1, rule2), listOf(rule3)),
            ApfMdnsUtils.MdnsRules(listOf(rule1, rule2), listOf(rule3))
        ))

        assertFalse(isMdnsRulesAndHashCodeEqual(
            ApfMdnsUtils.MdnsRules(listOf(rule1, rule2), listOf(rule3)),
            ApfMdnsUtils.MdnsRules(listOf(rule2, rule1), listOf(rule3))
        ))

        assertTrue(isMdnsRulesAndHashCodeEqual(
            ApfMdnsUtils.MdnsRules(null, listOf(rule1)),
            ApfMdnsUtils.MdnsRules(null, listOf(rule1)),
        ))

        assertFalse(isMdnsRulesAndHashCodeEqual(
            ApfMdnsUtils.MdnsRules(null, listOf(rule1)),
            ApfMdnsUtils.MdnsRules(listOf(rule2), listOf(rule1)),
        ))

        assertTrue(isMdnsRulesAndHashCodeEqual(
            ApfMdnsUtils.MdnsRules(listOf(rule1), null),
            ApfMdnsUtils.MdnsRules(listOf(rule1), null)
        ))

        assertFalse(isMdnsRulesAndHashCodeEqual(
            ApfMdnsUtils.MdnsRules(listOf(rule1), null),
            ApfMdnsUtils.MdnsRules(listOf(rule2), listOf(rule2))
        ))
    }

    private fun createOffloadServiceInfo(
            priority: Int,
            serviceName: String = testServiceName1,
            serviceType: String = testHttpServiceType,
            subTypes: List<String> = listOf(testSubType),
            hostName: String = testAndroidHostName,
            rawPacket1: ByteArray? = testRawPacket1,
            offloadType: Long = OffloadEngine.OFFLOAD_TYPE_REPLY.toLong()
    ): OffloadServiceInfo = OffloadServiceInfo(
            Key(serviceName, serviceType),
            subTypes,
            hostName,
            rawPacket1,
            priority,
            offloadType
        )
}
