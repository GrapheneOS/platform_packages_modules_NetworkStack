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
package android.net.ip

import android.net.MacAddress
import android.net.ip.IgmpReportMonitor.Callback
import android.os.Handler
import android.os.HandlerThread
import android.system.Os
import android.system.OsConstants.AF_UNIX
import android.system.OsConstants.SOCK_NONBLOCK
import android.system.OsConstants.SOCK_STREAM
import androidx.test.filters.SmallTest
import com.android.net.module.util.HexDump
import com.android.net.module.util.InterfaceParams
import com.android.testutils.DevSdkIgnoreRunner
import com.android.testutils.visibleOnHandlerThread
import com.android.testutils.waitForIdle
import java.io.FileDescriptor
import libcore.io.IoUtils
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.mockito.Mock
import org.mockito.Mockito
import org.mockito.Mockito.timeout
import org.mockito.Mockito.verify
import org.mockito.MockitoAnnotations

/**
 * Test for IgmpReportMonitor.
 */
@SmallTest
@DevSdkIgnoreRunner.MonitorThreadLeak
class IgmpReportMonitorTest {
    companion object {
        private const val TIMEOUT_MS: Long = 1000
        private const val SLEEP_TIMEOUT_MS: Long = 100
        private val TAG = this::class.simpleName
    }

    private val loInterfaceParams = InterfaceParams.getByName("lo")
    private val ifParams =
        InterfaceParams(
            "lo",
            loInterfaceParams.index,
            MacAddress.fromBytes(byteArrayOf(2, 3, 4, 5, 6, 7)),
            loInterfaceParams.defaultMtu
        )

    private val handlerThread by lazy {
        HandlerThread("$TAG-handler-thread").apply{ start() }
    }
    private val handler by lazy { Handler(handlerThread.looper) }
    private var writeSocket = FileDescriptor()
    private lateinit var igmpReportMonitor: IgmpReportMonitor

    @Mock private lateinit var callback: Callback

    @Before
    fun setUp() {
        MockitoAnnotations.initMocks(this)
        val readSocket = FileDescriptor()
        Os.socketpair(AF_UNIX, SOCK_STREAM or SOCK_NONBLOCK, 0, writeSocket, readSocket)
        igmpReportMonitor = IgmpReportMonitor(handler, ifParams, callback, readSocket)
        visibleOnHandlerThread(handler) {
            igmpReportMonitor.start()
        }
    }

    @After
    fun tearDown() {
        IoUtils.closeQuietly(writeSocket)
        handler.waitForIdle(TIMEOUT_MS)
        Mockito.framework().clearInlineMocks()
        handlerThread.quitSafely()
        handlerThread.join()
    }

    @Test
    fun testIgmpReportMonitorCallback() {
        val matchedPacket = HexDump.hexStringToByteArray("000000")
        val pktCnt = 2
        for (i in 0..<pktCnt) {
            Os.write(writeSocket, matchedPacket, 0, matchedPacket.size)
            Thread.sleep(SLEEP_TIMEOUT_MS)
        }
        verify(callback, timeout(TIMEOUT_MS).times(pktCnt)).notifyMulticastAddrChange()
    }
}
