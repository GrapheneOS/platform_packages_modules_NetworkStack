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
package android.net.util

import android.net.ip.ConnectivityPacketTracker
import android.os.HandlerThread
import androidx.test.filters.SmallTest
import com.android.testutils.DevSdkIgnoreRunner
import com.android.testutils.FunctionalUtils.ThrowingSupplier
import com.android.testutils.assertThrows
import com.android.testutils.visibleOnHandlerThread
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.mockito.ArgumentMatchers.any
import org.mockito.ArgumentMatchers.anyInt
import org.mockito.ArgumentMatchers.eq
import org.mockito.Mockito
import org.mockito.Mockito.clearInvocations
import org.mockito.Mockito.doReturn
import org.mockito.Mockito.mock
import org.mockito.Mockito.timeout
import org.mockito.Mockito.verify
import org.mockito.Mockito.verifyZeroInteractions

/**
 * Test for RawPacketTracker.
 */
@SmallTest
@DevSdkIgnoreRunner.MonitorThreadLeak
class RawPacketTrackerTest {
    companion object {
        private const val TEST_TIMEOUT_MS: Long = 1000
        private const val TEST_MAX_CAPTURE_TIME_MS: Long = 1000
        private const val TAG = "RawPacketTrackerTest"
    }

    private val deps = mock(RawPacketTracker.Dependencies::class.java)
    private val tracker = mock(ConnectivityPacketTracker::class.java)
    private val ifaceName = "lo"
    private val handlerThread by lazy {
        HandlerThread("$TAG-handler-thread").apply { start() }
    }
    private lateinit var rawTracker: RawPacketTracker

    @Before
    fun setUp() {
        doReturn(handlerThread).`when`(deps).createHandlerThread()
        doReturn(handlerThread.looper).`when`(deps).getLooper(any())
        doReturn(tracker).`when`(deps).createPacketTracker(any(), any(), anyInt())
        rawTracker = RawPacketTracker(deps)
    }

    @After
    fun tearDown() {
        Mockito.framework().clearInlineMocks()
        handlerThread.quitSafely()
        handlerThread.join()
    }

    @Test
    fun testStartCapture() {
        // start capturing
        startCaptureOnHandler(ifaceName)
        verifySetCapture(true, 1)

        assertTrue(rawTracker.handler.hasMessages(RawPacketTracker.CMD_STOP_CAPTURE))
    }

    @Test
    fun testInvalidStartCapture() {
        // start capturing with negative timeout
        assertThrows(IllegalArgumentException::class.java) {
            startCaptureOnHandler(ifaceName, -1)
        }
    }

    @Test
    fun testStopCapture() {
        // start capturing
        startCaptureOnHandler(ifaceName)
        // simulate capture status for stop capturing
        verifySetCapture(true, 1)

        // stop capturing
        stopCaptureOnHandler(ifaceName)
        verifySetCapture(false, 1)
        verifyZeroInteractions(tracker)
    }

    @Test
    fun testDuplicatedStartAndStop() {
        // start capture with a long timeout
        startCaptureOnHandler(ifaceName, 10_000)
        verifySetCapture(true, 1)

        // start capturing for multiple times
        for (i in 1..10) {
            assertThrows(RuntimeException::class.java) {
                startCaptureOnHandler(ifaceName)
            }
        }

        // expect no duplicated start capture
        verifySetCapture(true, 0)

        // stop capturing for multiple times
        stopCaptureOnHandler(ifaceName)
        verifySetCapture(false, 1)
        for (i in 1..10) {
            assertThrows(RuntimeException::class.java) {
                stopCaptureOnHandler(ifaceName)
            }
        }

        verifySetCapture(false, 0)
        verifyZeroInteractions(tracker)
    }

    @Test
    fun testMatchedPacketCount() {
        val matchedPkt = "12345"
        val notMatchedPkt = "54321"

        // simulate get matched packet count
        doReturn(1).`when`(tracker).getMatchedPacketCount(matchedPkt)
        // simulate get not matched packet count
        doReturn(0).`when`(tracker).getMatchedPacketCount(notMatchedPkt)

        // start capture
        startCaptureOnHandler(ifaceName)

        assertEquals(1, getMatchedPktCntOnHandler(ifaceName, matchedPkt))
        assertEquals(0, getMatchedPktCntOnHandler(ifaceName, notMatchedPkt))

        // for non-existed interface
        val nonExistedIface = "non-existed-iface"
        assertThrows(RuntimeException::class.java) {
            getMatchedPktCntOnHandler(nonExistedIface, matchedPkt)
            getMatchedPktCntOnHandler(nonExistedIface, notMatchedPkt)
        }

        // stop capture
        stopCaptureOnHandler(ifaceName)

        // expect no matched packet after stop capturing
        assertThrows(RuntimeException::class.java) {
            getMatchedPktCntOnHandler(ifaceName, matchedPkt)
            getMatchedPktCntOnHandler(ifaceName, notMatchedPkt)
        }
    }

    private fun startCaptureOnHandler(
        ifaceName: String, maxCaptureTime: Long = TEST_MAX_CAPTURE_TIME_MS
    ) {
        visibleOnHandlerThread(rawTracker.handler) {
            rawTracker.startCapture(ifaceName, maxCaptureTime)
        }
    }

    private fun stopCaptureOnHandler(ifaceName: String) {
        visibleOnHandlerThread(rawTracker.handler) {
            rawTracker.stopCapture(ifaceName)
        }
    }

    private fun getMatchedPktCntOnHandler(ifaceName: String, packetPattern: String): Int {
        return visibleOnHandlerThread(rawTracker.handler, ThrowingSupplier {
            rawTracker.getMatchedPacketCount(ifaceName, packetPattern)
        })
    }

    private fun verifySetCapture(
        isCapture: Boolean,
        receiveCnt: Int
    ) {
        verify(tracker, timeout(TEST_TIMEOUT_MS).times(receiveCnt)).setCapture(eq(isCapture))
        clearInvocations<Any>(tracker)
    }
}