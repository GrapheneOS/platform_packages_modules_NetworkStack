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
import android.net.dhcp6.Dhcp6AddrRegTracker.AddressRegistrationAlarmListener
import android.net.dhcp6.Dhcp6AddrRegTracker.SupportTimeoutAlarm
import android.os.Handler
import android.os.HandlerThread
import android.system.OsConstants.RT_SCOPE_UNIVERSE
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
import org.mockito.InOrder
import org.mockito.Mockito
import org.mockito.Mockito.any
import org.mockito.Mockito.anyByte
import org.mockito.Mockito.anyInt
import org.mockito.Mockito.anyLong
import org.mockito.Mockito.doReturn
import org.mockito.Mockito.eq
import org.mockito.Mockito.inOrder
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

    private inline fun <reified T : AlarmManager.OnAlarmListener> expectAlarmSet(
        inOrder: InOrder
    ): Alarm {
        val time = ArgumentCaptor.forClass(Long::class.java)
        val cb = ArgumentCaptor.forClass(T::class.java)
        inOrder.verify(alarmManager).setExact(anyInt(), time.capture(), any(), cb.capture(), any())
        return Alarm(time.value, cb.value)
    }

    private inline fun <reified T : AlarmManager.OnAlarmListener> verifyNeverScheduled(
        inOrder: InOrder
    ) {
        inOrder.verify(
            alarmManager,
            never()
        ).setExact(anyInt(), anyLong(), any(), any(T::class.java), any())
    }

    /** Expect an ADDR-REG-INFORM packet. */
    private fun expectAddrRegInformPacket(
        inOrder: InOrder,
        addr: InetAddress
    ): Dhcp6AddrRegInformPacket {
        val captor = ArgumentCaptor.forClass(ByteBuffer::class.java)
        inOrder.verify(packetDispatcher).transmitPacket(captor.capture(), eq(addr as Inet6Address))

        val bb = captor.value
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

    private fun createGua(addr: String, prefix: Int, deprecation: Long, expiry: Long): LinkAddress {
        val inetAddr = InetAddress.getByName(addr)
        return LinkAddress(inetAddr, prefix, 0 /*flags*/, RT_SCOPE_UNIVERSE, deprecation, expiry)
    }

    private fun LinkAddress.copyWithNewLifetime(deprecation: Long, expiry: Long): LinkAddress {
        return LinkAddress(address, prefixLength, flags, scope, deprecation, expiry)
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

        val inOrder = inOrder(packetDispatcher)
        val addrRegInform = expectAddrRegInformPacket(inOrder, addr)
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

        val inOrder = inOrder(packetDispatcher)
        val addrRegInform = expectAddrRegInformPacket(inOrder, addr)
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

        val inOrder = inOrder(alarmManager, packetDispatcher)
        expectAddrRegInformPacket(inOrder, addr)

        // The code will retry 3 times.
        for (i in 0 until 3) {
            expectAlarmSet<AddressRegistrationAlarmListener>(inOrder).advanceClockAndFire()
            expectAddrRegInformPacket(inOrder, addr)
        }

        // Retries take between ~[5.8, 8.2]s
        assertTrue(realtimeMs > 5_000, "Actual value $realtimeMs")
        assertTrue(realtimeMs < 9_000, "Actual value $realtimeMs")

        // Verify that no further alarms are scheduled.
        verifyNeverScheduled<AddressRegistrationAlarmListener>(inOrder)
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
        val inOrder = inOrder(alarmManager, packetDispatcher)
        expectAddrRegInformPacket(inOrder, addr)
        expectAlarmSet<AddressRegistrationAlarmListener>(inOrder).advanceClockAndFire()
        val inform = expectAddrRegInformPacket(inOrder, addr)
        val alarm = expectAlarmSet<AddressRegistrationAlarmListener>(inOrder)

        // Send back response
        val reply = buildAddrRegReply(inform)
        messageHandler.handleMessage(reply, inform.mIaAddress)
        handler.waitForIdle(TIMEOUT_MS)

        // Verify that the last alarm is cancelled and no further alarms are scheduled.
        inOrder.verify(alarmManager).cancel(eq(alarm.listener))
        inOrder.verifyNoMoreInteractions()
    }

    @Test
    fun testUpdateRegisteredAddress() {
        val ifaceParams = InterfaceParams.getByName(IFNAME)
        val la = createGua("2001:db8:1234::42", 64, 100_000 /*deprecationMs*/, 200_000 /*expiryMs*/)
        val lp = LinkProperties().apply {
            addLinkAddress(la)
        }
        handler.postAndWait { tracker.start(ifaceParams, lp) }
        val messageHandler = expectMessageHandler()

        // Confirm address registration
        val inOrder = inOrder(alarmManager, packetDispatcher)
        val inform = expectAddrRegInformPacket(inOrder, la.address)
        val alarm = expectAlarmSet<AddressRegistrationAlarmListener>(inOrder) // retry alarm

        val reply = buildAddrRegReply(inform)
        messageHandler.handleMessage(reply, inform.mIaAddress)
        handler.waitForIdle(TIMEOUT_MS)

        // Alarm was cancelled upon reception of the reply.
        inOrder.verify(alarmManager).cancel(eq(alarm.listener))
        inOrder.verifyNoMoreInteractions()

        // At this point we know that la is meant to be refreshed no later than 80%*200s = 160s
        // ([144, 176] when accounting for the desync multiplier) iff the address is updated. Note
        // that realtimeMs starts at 0.

        // Make some time pass
        realtimeMs += 50_000

        // Refresh the address. This *schedules* the event for min(nowMs + AddrRegRefreshInterval,
        // NextAddrRegRefreshTime). AddrRegRefreshInterval is 80% of the valid lifetime.
        // NextAddrRegRefreshTime is the time originally noted above (160s).
        lp.removeLinkAddress(la)
        lp.addLinkAddress(la.copyWithNewLifetime(150_000 /*deprecationMs*/, 250_000 /*expiryMs*/))
        handler.postAndWait { tracker.setLinkProperties(lp) }
        expectAlarmSet<AddressRegistrationAlarmListener>(inOrder).advanceClockAndFire()
        expectAddrRegInformPacket(inOrder, la.address)
        // Update should happen between [144, 176] (i.e. 160 += 10%).
        assertTrue(realtimeMs >= 144_000, "Actual value $realtimeMs")
        assertTrue(realtimeMs <= 176_000, "Actual value $realtimeMs")

        // Ensure that retry mechanism works here as well.
        expectAlarmSet<AddressRegistrationAlarmListener>(inOrder).advanceClockAndFire()
        expectAddrRegInformPacket(inOrder, la.address)
    }

    @Test
    fun testUpdateRegisteredAddress_withInsignificantChange() {
        val ifaceParams = InterfaceParams.getByName(IFNAME)
        val la = createGua("2001:db8:1234::42", 64, 100_000 /*deprecationMs*/, 200_000 /*expiryMs*/)
        val lp = LinkProperties().apply {
            addLinkAddress(la)
        }
        handler.postAndWait { tracker.start(ifaceParams, lp) }
        val messageHandler = expectMessageHandler()

        // Confirm address registration
        val inOrder = inOrder(alarmManager, packetDispatcher)
        val inform = expectAddrRegInformPacket(inOrder, la.address)
        val alarm = expectAlarmSet<AddressRegistrationAlarmListener>(inOrder)

        val reply = buildAddrRegReply(inform)
        messageHandler.handleMessage(reply, inform.mIaAddress)
        handler.waitForIdle(TIMEOUT_MS)

        inOrder.verify(alarmManager).cancel(eq(alarm.listener))
        inOrder.verifyNoMoreInteractions()

        // Sending the same LinkProperties does not result in any changes.
        handler.postAndWait { tracker.setLinkProperties(lp) }
        inOrder.verifyNoMoreInteractions()

        // Sending a slightly updated address does not result in any changes (+-3s are deemed
        // insignificant).
        lp.removeLinkAddress(la)
        lp.addLinkAddress(la.copyWithNewLifetime(102_000 /*deprecationMs*/, 202_000 /*expiryMs*/))
        handler.postAndWait { tracker.setLinkProperties(lp) }
        inOrder.verifyNoMoreInteractions()
    }

    // TODO: try to deduplicate these tests a bit.
    @Test
    fun testUpdateRegisteredAddress_reduceLifetime() {
        val ifaceParams = InterfaceParams.getByName(IFNAME)
        val la = createGua("2001:db8:1234::42", 64, 100_000 /*deprecationMs*/, 200_000 /*expiryMs*/)
        val lp = LinkProperties().apply {
            addLinkAddress(la)
        }
        handler.postAndWait { tracker.start(ifaceParams, lp) }
        val messageHandler = expectMessageHandler()

        // Confirm address registration
        val inOrder = inOrder(alarmManager, packetDispatcher)
        val inform = expectAddrRegInformPacket(inOrder, la.address)
        val alarm = expectAlarmSet<AddressRegistrationAlarmListener>(inOrder)

        val reply = buildAddrRegReply(inform)
        messageHandler.handleMessage(reply, inform.mIaAddress)
        handler.waitForIdle(TIMEOUT_MS)

        inOrder.verify(alarmManager).cancel(eq(alarm.listener))
        inOrder.verifyNoMoreInteractions()

        lp.removeLinkAddress(la)
        lp.addLinkAddress(la.copyWithNewLifetime(0 /*deprecationMs*/, 10_000 /*expiryMs*/))

        // Significantly reduced lifetime will result in a new alarm set.
        handler.postAndWait { tracker.setLinkProperties(lp) }
        expectAlarmSet<AddressRegistrationAlarmListener>(inOrder).advanceClockAndFire()
        expectAddrRegInformPacket(inOrder, la.address)

        // Reducing the lifetime beyond NextAddrRegRefreshTime causes the packet to be sent sooner.
        // In this case, in 8 (= 10*80%) +-10% seconds. (Note that in this test, realtimeMs was not
        // increased before receiving the shorter lifetime packet.)
        assertTrue(realtimeMs >= 7_200, "Actual value $realtimeMs")
        assertTrue(realtimeMs <= 8_800, "Actual value $realtimeMs")
    }

    @Test
    fun testStop() {
        val ifaceParams = InterfaceParams.getByName(IFNAME)
        val lp = LinkProperties()
        handler.postAndWait { tracker.start(ifaceParams, lp) }
        handler.postAndWait { tracker.stop() }

        val addr = InetAddress.getByName("2001:db8:42::42")
        lp.addLinkAddress(LinkAddress(addr, 64))
        handler.postAndWait { tracker.setLinkProperties(lp) }

        verify(packetDispatcher, never()).transmitPacket(any(), any())
        verify(
            alarmManager,
            never()
        ).setExact(
            anyInt(),
            anyLong(),
            any(),
            any(AddressRegistrationAlarmListener::class.java),
            any()
        )
    }

    @Test
    fun testSupportTimeout_stopsAddrRegTracker() {
        val ifaceParams = InterfaceParams.getByName(IFNAME)
        val addr = InetAddress.getByName("2001:db8::1")
        val lp = LinkProperties().apply {
            addLinkAddress(LinkAddress(addr, 64))
        }
        handler.postAndWait { tracker.start(ifaceParams, lp) }

        val inOrder = inOrder(alarmManager, packetDispatcher)
        expectAlarmSet<SupportTimeoutAlarm>(inOrder).advanceClockAndFire()
        assertEquals(realtimeMs, 15_000)
        expectAddrRegInformPacket(inOrder, addr)

        val addr2 = InetAddress.getByName("2001:db8:42::42")
        lp.addLinkAddress(LinkAddress(addr2, 64))
        handler.postAndWait { tracker.setLinkProperties(lp) }

        // Ensure the tracker is stopped.
        inOrder.verify(packetDispatcher, never()).transmitPacket(any(), any())
    }

    @Test
    fun testSupportTimeout_startsOnFirstPacket() {
        val ifaceParams = InterfaceParams.getByName(IFNAME)
        val lp = LinkProperties()
        handler.postAndWait { tracker.start(ifaceParams, lp) }

        val inOrder = inOrder(alarmManager)
        inOrder.verifyNoMoreInteractions()

        val addr = InetAddress.getByName("2001:db8:42::42")
        lp.addLinkAddress(LinkAddress(addr, 64))
        handler.postAndWait { tracker.setLinkProperties(lp) }

        expectAlarmSet<SupportTimeoutAlarm>(inOrder)
    }

    @Test
    fun testSupportTimeout_cancelledByReply() {
        val ifaceParams = InterfaceParams.getByName(IFNAME)
        val addr = InetAddress.getByName("2001:db8::1")
        val lp = LinkProperties().apply {
            addLinkAddress(LinkAddress(addr, 64))
        }
        handler.postAndWait { tracker.start(ifaceParams, lp) }
        val messageHandler = expectMessageHandler()

        val inOrder = inOrder(alarmManager, packetDispatcher)
        val alarm = expectAlarmSet<SupportTimeoutAlarm>(inOrder)
        val inform = expectAddrRegInformPacket(inOrder, addr)

        // Send a reply which should cancel the SupportTimeoutAlarm.
        val reply = buildAddrRegReply(inform)
        messageHandler.handleMessage(reply, inform.mIaAddress)
        handler.waitForIdle(TIMEOUT_MS)

        inOrder.verify(alarmManager).cancel(eq(alarm.listener))
    }
}
