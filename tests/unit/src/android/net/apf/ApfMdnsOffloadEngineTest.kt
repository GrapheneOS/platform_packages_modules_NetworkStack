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
package android.net.apf

import android.net.apf.ApfMdnsOffloadEngine.Callback
import android.net.apf.ApfMdnsUtils.extractOffloadReplyRule
import android.net.nsd.NsdManager
import android.net.nsd.OffloadEngine
import android.net.nsd.OffloadServiceInfo
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import androidx.test.filters.SmallTest
import com.android.testutils.DevSdkIgnoreRule
import com.android.testutils.DevSdkIgnoreRule.IgnoreUpTo
import com.android.testutils.DevSdkIgnoreRunner
import com.android.testutils.visibleOnHandlerThread
import org.junit.After
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.ArgumentMatchers.any
import org.mockito.ArgumentMatchers.anyLong
import org.mockito.ArgumentMatchers.eq
import org.mockito.Mock
import org.mockito.Mockito
import org.mockito.Mockito.mock
import org.mockito.Mockito.never
import org.mockito.Mockito.verify
import org.mockito.MockitoAnnotations

private const val TIMEOUT_MS: Long = 1000

/**
 * Tests for ApfMdnsOffloadEngine.
 */
@RunWith(DevSdkIgnoreRunner::class)
@SmallTest
@IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class ApfMdnsOffloadEngineTest {

    @get:Rule
    val ignoreRule = DevSdkIgnoreRule()

    private val TAG = ApfMdnsOffloadEngineTest::class.java.simpleName

    private val handlerThread by lazy {
        HandlerThread("$TAG handler thread").apply { start() }
    }
    private val handler by lazy { Handler(handlerThread.looper) }

    private val interfaceName = "test_interface"

    @Mock
    private lateinit var nsdManager: NsdManager

    @Before
    fun setUp() {
        MockitoAnnotations.initMocks(this)
    }

    @After
    fun tearDown() {
        handlerThread.quitSafely()
        handlerThread.join()
        Mockito.framework().clearInlineMocks()
    }

    @Test
    fun testOffloadEngineRegistration() {
        val callback = mock(Callback::class.java)
        val apfOffloadEngine = ApfMdnsOffloadEngine(interfaceName, handler, nsdManager, callback)
        apfOffloadEngine.registerOffloadEngine()
        verify(nsdManager).registerOffloadEngine(
            eq(interfaceName),
            anyLong(),
            anyLong(),
            any(),
            eq(apfOffloadEngine)
        )
        val info1 = OffloadServiceInfo(
            OffloadServiceInfo.Key("TestServiceName", "_advertisertest._tcp"),
            listOf(),
            "Android_test.local",
            byteArrayOf(0x01, 0x02, 0x03, 0x04),
            0,
            OffloadEngine.OFFLOAD_TYPE_REPLY.toLong()
        )
        val info2 = OffloadServiceInfo(
            OffloadServiceInfo.Key("TestServiceName2", "_advertisertest._tcp"),
            listOf(),
            "Android_test.local",
            byteArrayOf(0x01, 0x02, 0x03, 0x04),
            0,
            OffloadEngine.OFFLOAD_TYPE_REPLY.toLong()
        )
        val updatedInfo1 = OffloadServiceInfo(
            OffloadServiceInfo.Key("TestServiceName", "_advertisertest._tcp"),
            listOf(),
            "Android_test.local",
            byteArrayOf(),
            0,
            OffloadEngine.OFFLOAD_TYPE_REPLY.toLong()
        )
        visibleOnHandlerThread(handler) { apfOffloadEngine.onOffloadServiceUpdated(info1) }
        verify(callback).onOffloadRulesUpdated(eq(extractOffloadReplyRule(listOf(info1))))
        visibleOnHandlerThread(handler) { apfOffloadEngine.onOffloadServiceUpdated(info2) }
        verify(callback).onOffloadRulesUpdated(eq(extractOffloadReplyRule(listOf(info1, info2))))
        visibleOnHandlerThread(handler) { apfOffloadEngine.onOffloadServiceUpdated(updatedInfo1) }
        verify(callback).onOffloadRulesUpdated(
            eq(extractOffloadReplyRule(listOf(info2, updatedInfo1)))
        )
        visibleOnHandlerThread(handler) { apfOffloadEngine.onOffloadServiceRemoved(updatedInfo1) }
        verify(callback).onOffloadRulesUpdated(eq(extractOffloadReplyRule(listOf(info2))))

        visibleOnHandlerThread(handler) { apfOffloadEngine.unregisterOffloadEngine() }
        verify(nsdManager).unregisterOffloadEngine(eq(apfOffloadEngine))
    }

    @Test
    fun testCorruptedOffloadServiceInfoUpdateNotTriggerUpdate() {
        val callback = mock(Callback::class.java)
        val apfOffloadEngine = ApfMdnsOffloadEngine(interfaceName, handler, nsdManager, callback)
        apfOffloadEngine.registerOffloadEngine()
        val corruptedOffloadInfo = OffloadServiceInfo(
            OffloadServiceInfo.Key("gambit", "_${"a".repeat(63)}._tcp"),
            listOf(),
            "Android_f47ac10b58cc4b88bc3f5e7a81e59872.local",
            byteArrayOf(0x01, 0x02, 0x03, 0x04),
            0,
            OffloadEngine.OFFLOAD_TYPE_REPLY.toLong()
        )
        visibleOnHandlerThread(handler) {
            apfOffloadEngine.onOffloadServiceUpdated(corruptedOffloadInfo)
        }
        verify(callback, never()).onOffloadRulesUpdated(any())
    }
}
