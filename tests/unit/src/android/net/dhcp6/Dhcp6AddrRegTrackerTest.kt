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
import com.android.net.module.util.dhcp6.Dhcp6Packet
import com.android.testutils.waitForIdle
import java.net.Inet6Address
import java.net.InetAddress
import java.nio.ByteBuffer
import kotlin.test.assertEquals
import kotlin.test.assertIs
import org.junit.After
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.ArgumentCaptor
import org.mockito.Mockito
import org.mockito.Mockito.any
import org.mockito.Mockito.doReturn
import org.mockito.Mockito.eq
import org.mockito.Mockito.never
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
    private val tracker = Dhcp6AddrRegTracker(context, handler, IFNAME, packetDispatcher)

    @After
    fun tearDown() {
        handlerThread.waitForIdle(TIMEOUT_MS)
        handlerThread.quitSafely()
        handlerThread.join()
    }

    private fun expectAddrRegInformPacket(addr: InetAddress): Dhcp6AddrRegInformPacket {
        val packetCaptor = ArgumentCaptor.forClass(ByteBuffer::class.java)
        verify(packetDispatcher).transmitPacket(packetCaptor.capture(), eq(addr as Inet6Address))

        val bb = packetCaptor.value
        val packet = Dhcp6Packet.decode(bb.array(), bb.limit())
        assertIs<Dhcp6AddrRegInformPacket>(packet)
        return packet
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
        tracker.start(ifaceParams, lp)

        val addrRegInform = expectAddrRegInformPacket(addr)
        assertEquals(addr as Inet6Address, addrRegInform.mIaAddress)
    }

    @Test
    fun testSetLinkProperties() {
        val ifaceParams = InterfaceParams.getByName(IFNAME)
        val lp = LinkProperties()
        tracker.start(ifaceParams, lp)
        verify(packetDispatcher, never()).transmitPacket(any(), any())

        val addr = InetAddress.getByName("2001:db8:42::42")
        lp.addLinkAddress(LinkAddress(addr, 64))
        tracker.setLinkProperties(lp)

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
}
