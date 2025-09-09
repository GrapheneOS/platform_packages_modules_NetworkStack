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

package android.net.dhcp6

import android.app.AlarmManager
import android.content.Context
import android.net.LinkAddress
import android.net.LinkProperties
import android.os.Handler
import android.os.HandlerThread
import androidx.test.filters.SmallTest
import androidx.test.runner.AndroidJUnit4
import com.android.net.module.util.InterfaceParams
import com.android.net.module.util.dhcp6.Dhcp6AddrRegInformPacket
import com.android.net.module.util.dhcp6.Dhcp6AddrRegReplyPacket
import com.android.net.module.util.dhcp6.Dhcp6Packet
import com.android.testutils.postAndWait
import com.android.testutils.waitForIdle
import java.net.Inet6Address
import java.net.InetAddress
import java.nio.ByteBuffer
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import org.junit.After
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.ArgumentCaptor
import org.mockito.Mockito
import org.mockito.Mockito.any
import org.mockito.Mockito.anyByte
import org.mockito.Mockito.anyInt
import org.mockito.Mockito.anyLong
import org.mockito.Mockito.clearInvocations
import org.mockito.Mockito.doReturn
import org.mockito.Mockito.eq
import org.mockito.Mockito.never
import org.mockito.Mockito.times
import org.mockito.Mockito.verify

const val IFNAME = "lo"
const val TIMEOUT_MS = 5_000

@RunWith(AndroidJUnit4::class)
@SmallTest
class Dhcp6AddrRegTrackerTest {
    internal inline fun <reified T> mock() = Mockito.mock(T::class.java)

    private val alarmManager = mock<AlarmManager>()
    private val context = mock<Context>().also {
        doReturn(alarmManager).`when`(it).getSystemService(eq(AlarmManager::class.java))
    }
    private val packetDispatcher = mock<Dhcp6PacketDispatcher>()

    private val handlerThread = HandlerThread("Dhcp6AddrRegDispatcher thread").apply { start() }
    private val handler = Handler(handlerThread.looper)

    private var realtimeMs = 0L
    private val deps = object : Dhcp6AddrRegTracker.Dependencies() {
        override fun elapsedRealtime(): Long {
            return realtimeMs
        }
    }
    private val tracker = Dhcp6AddrRegTracker(context, handler, IFNAME, packetDispatcher, deps)

    @After
    fun tearDown() {
        handlerThread.waitForIdle(TIMEOUT_MS)
        handlerThread.quitSafely()
        handlerThread.join()
    }

    /** Convenience class to hold captured Alarm information */
    private inner class Alarm(
        val scheduledMs: Long,
        val listener: AlarmManager.OnAlarmListener
    ) {
        fun advanceClockAndFire() {
            realtimeMs = scheduledMs
            handler.postAndWait { listener.onAlarm() }
        }
    }

    private fun expectAlarmSet(): Alarm {
        // Note: if addr reg tracker starts setting multiple alarms, the tag can be used to
        // distinguish them.
        val time = ArgumentCaptor.forClass(Long::class.java)
        val cb = ArgumentCaptor.forClass(AlarmManager.OnAlarmListener::class.java)
        verify(alarmManager).setExact(anyInt(), time.capture(), any(), cb.capture(), any())

        // Allow reusing this function for multiple invocations of setExact().
        clearInvocations(alarmManager)
        return Alarm(time.value, cb.value)
    }

    /**
     * Expect an ADDR-REG-INFORM packet. Warning: this helper clears calling invocations on
     * packetDispatcher.
     */
    private fun expectAddrRegInformPacket(addr: InetAddress): Dhcp6AddrRegInformPacket {
        val packetCaptor = ArgumentCaptor.forClass(ByteBuffer::class.java)
        verify(packetDispatcher).transmitPacket(packetCaptor.capture(), eq(addr as Inet6Address))
        clearInvocations(packetDispatcher)

        val bb = packetCaptor.value
        val packet = Dhcp6Packet.decode(bb.array(), bb.limit())
        assertIs<Dhcp6AddrRegInformPacket>(packet)
        return packet
    }

    private fun expectMessageHandler(): Dhcp6PacketDispatcher.MessageHandler {
        val captor = ArgumentCaptor.forClass(Dhcp6PacketDispatcher.MessageHandler::class.java)
        verify(packetDispatcher).registerHandler(captor.capture(), anyByte())
        return captor.value
    }

    private fun buildAddrRegReply(inform: Dhcp6AddrRegInformPacket): Dhcp6AddrRegReplyPacket {
        // "UUID" based DUID for test.
        val serverDuid = byteArrayOf(0, 4, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15)
        return Dhcp6AddrRegReplyPacket(
            inform.transactionId,
            inform.clientDuid,
            serverDuid,
            inform.mIaAddress,
            inform.mPreferred,
            inform.mValid
        )
    }

    @Test
    fun testNoPacketSentBeforeStart() {
        verify(packetDispatcher, never()).transmitPacket(any(), any())
    }

    @Test
    fun testStart_withOneAddress() {
        val ifaceParams = InterfaceParams.getByName(IFNAME)
        val addr = InetAddress.getByName("2001:db8::1")
        val lp = LinkProperties().apply {
            addLinkAddress(LinkAddress(addr, 64))
        }
        handler.postAndWait { tracker.start(ifaceParams, lp) }

        val addrRegInform = expectAddrRegInformPacket(addr)
        assertEquals(addr as Inet6Address, addrRegInform.mIaAddress)
    }

    @Test
    fun testSetLinkProperties() {
        val ifaceParams = InterfaceParams.getByName(IFNAME)
        val lp = LinkProperties()
        handler.postAndWait { tracker.start(ifaceParams, lp) }
        verify(packetDispatcher, never()).transmitPacket(any(), any())

        val addr = InetAddress.getByName("2001:db8:42::42")
        lp.addLinkAddress(LinkAddress(addr, 64))
        handler.postAndWait { tracker.setLinkProperties(lp) }

        val addrRegInform = expectAddrRegInformPacket(addr)
        assertEquals(addr as Inet6Address, addrRegInform.mIaAddress)
        // Note that LinkAddress(addr, prefixLength) sets the lifetimes to unknown (-1). The address
        // registration logic still registers these addresses but with lifetime 0. If the address is
        // refreshed, the registration is renewed immediately. While this is working as intended, in
        // reality, this scenario should not happen in production, because the lifetime is always
        // populated.
        assertEquals(0, addrRegInform.mPreferred)
        assertEquals(0, addrRegInform.mValid)
    }

    @Test
    fun testRetry_noResponse() {
        val ifaceParams = InterfaceParams.getByName(IFNAME)
        val lp = LinkProperties()
        handler.postAndWait { tracker.start(ifaceParams, lp) }

        val addr = InetAddress.getByName("2001:db8:12::34")
        lp.addLinkAddress(LinkAddress(addr, 64))
        handler.postAndWait { tracker.setLinkProperties(lp) }

        val addrRegInform = expectAddrRegInformPacket(addr)
        assertEquals(addr as Inet6Address, addrRegInform.mIaAddress)

        // The code will retry 3 times.
        for (i in 0 until 3) {
            expectAlarmSet().advanceClockAndFire()
            val addrRegInform = expectAddrRegInformPacket(addr)
            assertEquals(addr as Inet6Address, addrRegInform.mIaAddress)
        }

        // Retries take between ~[5.8, 8.2]s
        assertTrue(realtimeMs > 5_000, "Actual value $realtimeMs")
        assertTrue(realtimeMs < 9_000, "Actual value $realtimeMs")

        // Verify that no further alarms are scheduled.
        verify(alarmManager, never()).setExact(anyInt(), anyLong(), any(), any(), any())
    }

    @Test
    fun testRetry_successAfterSecondAttempt() {
        val ifaceParams = InterfaceParams.getByName(IFNAME)
        val lp = LinkProperties()
        handler.postAndWait { tracker.start(ifaceParams, lp) }
        val messageHandler = expectMessageHandler()

        val addr = InetAddress.getByName("2001:db8:12::34")
        lp.addLinkAddress(LinkAddress(addr, 64))
        handler.postAndWait { tracker.setLinkProperties(lp) }

        // Retry once
        expectAddrRegInformPacket(addr)
        expectAlarmSet().advanceClockAndFire()
        val inform = expectAddrRegInformPacket(addr)
        val alarm = expectAlarmSet()

        // Verify that the alarm has not been cancelled yet.
        verify(alarmManager, never()).cancel(eq(alarm.listener))

        // Send back response
        val reply = buildAddrRegReply(inform)
        messageHandler.handleMessage(reply, inform.mIaAddress)
        handler.waitForIdle(TIMEOUT_MS)

        // Verify that the last alarm is cancelled and no further alarms are scheduled.
        verify(alarmManager).cancel(eq(alarm.listener))
        verify(alarmManager, never()).setExact(anyInt(), anyLong(), any(), any(), any())
    }
}
