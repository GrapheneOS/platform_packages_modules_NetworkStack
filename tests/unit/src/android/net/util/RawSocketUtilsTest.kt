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

import android.content.Context
import android.net.TetheringManager
import android.system.Os
import com.android.dx.mockito.inline.extended.ExtendedMockito
import com.android.net.module.util.HexDump
import com.android.testutils.DevSdkIgnoreRule
import com.android.testutils.DevSdkIgnoreRunner
import java.io.FileDescriptor
import java.net.NetworkInterface
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import org.junit.After
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.ArgumentCaptor
import org.mockito.ArgumentMatchers.any
import org.mockito.ArgumentMatchers.eq
import org.mockito.Mock
import org.mockito.Mockito.doAnswer
import org.mockito.Mockito.doReturn
import org.mockito.Mockito.framework
import org.mockito.Mockito.`when`
import org.mockito.MockitoSession
import org.mockito.quality.Strictness

@RunWith(DevSdkIgnoreRunner::class)
class RawSocketUtilsTest {
    @get:Rule
    val ignoreRule = DevSdkIgnoreRule()
    companion object {
        private const val TEST_IFINDEX = 123
        private const val TEST_IFACENAME = "wlan0"
        private const val TEST_SRC_MAC = "FFFFFFFFFFFF"
        private const val TEST_DST_MAC = "1234567890AB"
        private const val TEST_INVALID_PACKET_IN_HEX = "DEADBEEF"
        private const val TEST_PACKET_TYPE_IN_HEX = "88A4"
        private const val TEST_VALID_PACKET_IN_HEX =
                TEST_DST_MAC + TEST_SRC_MAC + TEST_PACKET_TYPE_IN_HEX
    }
    @Mock
    private lateinit var mockContext: Context
    @Mock
    private lateinit var mockTetheringManager: TetheringManager
    @Mock
    private lateinit var mockNetworkInterface: NetworkInterface

    // For mocking static methods.
    private lateinit var mockitoSession: MockitoSession

    @Before
    fun setup() {
        mockitoSession = ExtendedMockito.mockitoSession()
                .mockStatic(Os::class.java)
                .mockStatic(NetworkInterface::class.java)
                .mockStatic(SocketUtils::class.java)
                .initMocks(this)
                .strictness(Strictness.LENIENT)
                .startMocking()
        doReturn(mockTetheringManager).`when`(mockContext)
                .getSystemService(eq(TetheringManager::class.java))
        `when`(NetworkInterface.getByName(any())).thenReturn(mockNetworkInterface)
        doReturn(TEST_IFINDEX).`when`(mockNetworkInterface).index
    }

    @After
    fun teardown() {
        mockitoSession.finishMocking()
        // Clear mocks to prevent from stubs holding instances and cause memory leaks.
        framework().clearInlineMocks()
    }

    @Test
    fun sendRawPacketDownStream_invalidTetheredInterface() {
        doAnswer {
            val callback = it.arguments[1] as TetheringManager.TetheringEventCallback
            callback.onTetheredInterfacesChanged(listOf("eth0"))
        }.`when`(mockTetheringManager).registerTetheringEventCallback(any(), any())
        assertFailsWith<SecurityException> {
            RawSocketUtils.sendRawPacketDownStream(
                mockContext,
                TEST_IFACENAME,
                TEST_INVALID_PACKET_IN_HEX
            )
        }
    }

    @Test
    fun sendRawPacketDownStream_invalidPacket() {
        doAnswer {
            val callback = it.arguments[1] as TetheringManager.TetheringEventCallback
            callback.onTetheredInterfacesChanged(listOf(TEST_IFACENAME))
        }.`when`(mockTetheringManager).registerTetheringEventCallback(any(), any())

        assertFailsWith<ArrayIndexOutOfBoundsException> {
            RawSocketUtils.sendRawPacketDownStream(
                    mockContext,
                    TEST_IFACENAME,
                    TEST_INVALID_PACKET_IN_HEX
            )
        }
    }

    @Test
    fun sendRawPacketDownStream_validPacket() {
        doAnswer {
            val callback = it.arguments[1] as TetheringManager.TetheringEventCallback
            callback.onTetheredInterfacesChanged(listOf(TEST_IFACENAME))
        }.`when`(mockTetheringManager).registerTetheringEventCallback(any(), any())

        RawSocketUtils.sendRawPacketDownStream(
            mockContext,
            TEST_IFACENAME,
            TEST_VALID_PACKET_IN_HEX
        )

        // Verify interactions with mocked static methods.
        val fileDescriptorCaptor = ArgumentCaptor.forClass(FileDescriptor::class.java)
        val packetDataCaptor = ArgumentCaptor.forClass(ByteArray::class.java)
        val packetDataLengthCaptor = ArgumentCaptor.forClass(Int::class.java)
        ExtendedMockito.verify {
            Os.sendto(
                fileDescriptorCaptor.capture(),
                packetDataCaptor.capture(),
                eq(0),
                packetDataLengthCaptor.capture(),
                eq(0),
                any()
            )
        }
        assertEquals(TEST_VALID_PACKET_IN_HEX, HexDump.toHexString(packetDataCaptor.value))
        assertEquals(TEST_VALID_PACKET_IN_HEX.length / 2, packetDataLengthCaptor.value)
        // TODO: Verify ifindex and packetType once the members of PacketSocketAddress
        //  can be accessed.
        ExtendedMockito.verify { SocketUtils.closeSocket(eq(fileDescriptorCaptor.value)) }
    }
}
