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
import android.net.ip.ConnectivityPacketTracker.Dependencies
import android.os.Handler
import android.os.HandlerThread
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants.AF_UNIX
import android.system.OsConstants.SOCK_NONBLOCK
import android.system.OsConstants.SOCK_STREAM
import android.util.LocalLog
import androidx.test.filters.SmallTest
import com.android.net.module.util.HexDump
import com.android.net.module.util.InterfaceParams
import com.android.testutils.DevSdkIgnoreRunner
import com.android.testutils.waitForIdle
import java.io.FileDescriptor
import java.io.InterruptedIOException
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import kotlin.test.assertEquals
import libcore.io.IoUtils
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.mockito.ArgumentMatchers.anyInt
import org.mockito.Mock
import org.mockito.Mockito
import org.mockito.Mockito.doReturn
import org.mockito.MockitoAnnotations

/**
 * Test for ConnectivityPacketTracker.
 */
@SmallTest
@DevSdkIgnoreRunner.MonitorThreadLeak
class ConnectivityPacketTrackerTest {
    companion object {
        private const val TIMEOUT_MS: Long = 10000
        private const val SLEEP_TIMEOUT_MS: Long = 500
        private const val TEST_MAX_CAPTURE_PKT_SIZE: Int = 100
        private const val TAG = "ConnectivityPacketTrackerTest"
    }

    private val loInterfaceParams = InterfaceParams.getByName("lo")
    private val ifParams =
        InterfaceParams(
            "lo",
            loInterfaceParams.index,
            MacAddress.fromBytes(byteArrayOf(2, 3, 4, 5, 6, 7)),
            loInterfaceParams.defaultMtu
        )
    private val writeSocket = FileDescriptor()
    private val handlerThread by lazy {
        HandlerThread("$TAG-handler-thread").apply { start() }
    }
    private val handler by lazy { Handler(handlerThread.looper) }
    @Mock private lateinit var mDependencies: Dependencies
    @Mock private lateinit var localLog: LocalLog
    @Before
    fun setUp() {
        MockitoAnnotations.initMocks(this)
        val readSocket = FileDescriptor()
        Os.socketpair(AF_UNIX, SOCK_STREAM or SOCK_NONBLOCK, 0, writeSocket, readSocket)
        doReturn(readSocket).`when`(mDependencies).createPacketReaderSocket(anyInt())
        doReturn(TEST_MAX_CAPTURE_PKT_SIZE).`when`(mDependencies).maxCapturePktSize
    }

    @After
    fun tearDown() {
        IoUtils.closeQuietly(writeSocket)
        handler.waitForIdle(10000)
        Mockito.framework().clearInlineMocks()
        handlerThread.quitSafely()
        handlerThread.join()
    }

    @Test
    fun testCapturePacket() {
        val packetTracker = getConnectivityPacketTracker()
        // Using scapy to generate ARP request packet:
        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
        // arp = ARP()
        // pkt = eth/arp
        val arpPkt = """
            010203040506000102030405080600010800060400015c857e3c74e1c0a8012200000000000000000000
        """.replace("\\s+".toRegex(), "").trim().uppercase()
        val arpPktByteArray = HexDump.hexStringToByteArray(arpPkt)
        assertEquals(0, getCapturePacketTypeCount(packetTracker))
        assertEquals(0, getMatchedPacketCount(packetTracker, arpPkt))

        // start capture packet
        setCapture(packetTracker, true)

        for (i in 1..5) {
            pretendPacketReceive(arpPktByteArray)
            Thread.sleep(SLEEP_TIMEOUT_MS)
        }

        assertEquals(1, getCapturePacketTypeCount(packetTracker))
        assertEquals(5, getMatchedPacketCount(packetTracker, arpPkt))

        // stop capture packet
        setCapture(packetTracker, false)
        assertEquals(0, getCapturePacketTypeCount(packetTracker))
        assertEquals(0, getMatchedPacketCount(packetTracker, arpPkt))
    }

    @Test
    fun testMaxCapturePacketSize() {
        doReturn(3).`when`(mDependencies).maxCapturePktSize
        val packetTracker = getConnectivityPacketTracker(mDependencies)

        // Using scapy to generate ARP request packet:
        // eth = Ether(src="00:01:02:03:04:05", dst="01:02:03:04:05:06")
        // arp = ARP()
        // pkt = eth/arp
        val arpPkt = """
            010203040506000102030405080600010800060400015c857e3c74e1c0a8012200000000000000000000
        """.replace("\\s+".toRegex(), "").trim().uppercase()
        val arpPktByteArray = HexDump.hexStringToByteArray(arpPkt)
        // start capture packet
        setCapture(packetTracker, true)
        val pktCnt = 5
        val pktList = ArrayList<String>()
        for (i in 0..<pktCnt) {
            // modify the original packet's last byte
            val modPkt = arpPktByteArray.copyOf()
            modPkt[modPkt.size - 1] = i.toByte()
            pretendPacketReceive(modPkt)
            pktList.add(HexDump.toHexString(modPkt))
            Thread.sleep(SLEEP_TIMEOUT_MS)
        }

        // The old packets are evicted due to LruCache size
        pktList.take(2).forEach {
            assertEquals(0, getMatchedPacketCount(packetTracker, it))
        }

        pktList.drop(2).forEach {
            assertEquals(1, getMatchedPacketCount(packetTracker, it))
        }

        assertEquals(mDependencies.maxCapturePktSize, getCapturePacketTypeCount(packetTracker))
    }

    @Throws(InterruptedIOException::class, ErrnoException::class)
    private fun pretendPacketReceive(packet: ByteArray) {
        Os.write(writeSocket, packet, 0, packet.size)
    }

    private fun getConnectivityPacketTracker(
        dependencies: Dependencies = mDependencies
    ): ConnectivityPacketTracker {
        val result = CompletableFuture<ConnectivityPacketTracker>()
        handler.post {
            try {
                val tracker = ConnectivityPacketTracker(handler, ifParams, localLog, dependencies)
                tracker.start(TAG)
                result.complete(tracker)
            } catch (e: Exception) {
                result.completeExceptionally(e)
            }
        }

        return result.get(TIMEOUT_MS, TimeUnit.MILLISECONDS)
    }

    private fun setCapture(
        packetTracker: ConnectivityPacketTracker,
        isCapturing: Boolean
    ) {
        val result = CompletableFuture<Unit>()
        handler.post {
            try {
                packetTracker.setCapture(isCapturing)
                result.complete(Unit)
            } catch (e: Exception) {
                result.completeExceptionally(e)
            }
        }

        result.get(TIMEOUT_MS, TimeUnit.MILLISECONDS)
    }

    private fun getMatchedPacketCount(
        packetTracker: ConnectivityPacketTracker,
        packet: String
    ): Int {
        val result = CompletableFuture<Int>()
        handler.post {
            try {
                result.complete(packetTracker.getMatchedPacketCount(packet))
            } catch (e: Exception) {
                result.completeExceptionally(e)
            }
        }

        return result.get(TIMEOUT_MS, TimeUnit.MILLISECONDS)
    }

    private fun getCapturePacketTypeCount(
        packetTracker: ConnectivityPacketTracker
    ): Int {
        val result = CompletableFuture<Int>()
        handler.post {
            try {
                val totalCnt = packetTracker.capturePacketTypeCount
                result.complete(totalCnt)
            } catch (e: Exception) {
                result.completeExceptionally(e)
            }
        }

        return result.get(TIMEOUT_MS, TimeUnit.MILLISECONDS)
    }
}