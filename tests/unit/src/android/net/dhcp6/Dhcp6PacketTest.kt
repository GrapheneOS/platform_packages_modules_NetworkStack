/*
 * Copyright (C) 2023 The Android Open Source Project
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

import androidx.test.filters.SmallTest
import androidx.test.runner.AndroidJUnit4
import com.android.net.module.util.HexDump
import com.android.testutils.assertThrows
import java.nio.ByteBuffer
import kotlin.test.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
@SmallTest
class Dhcp6PacketTest {
    @Test
    fun testDecodeDhcp6SolicitPacket() {
        val solicitHex =
                // Solicit, Transaction ID
                "01000F51" +
                // client identifier option(option_len=12)
                "0001000C0003001B024CCBFFFE5F6EA9" +
                // elapsed time option(option_len=2)
                "000800020000" +
                // IA_PD option(option_len=41, including IA prefix option)
                "00190029DE3570F50000000000000000" +
                // IA prefix option(option_len=25)
                "001A001900000000000000004000000000000000000000000000000000"
        val bytes = HexDump.hexStringToByteArray(solicitHex)
        val packet = Dhcp6Packet.decodePacket(ByteBuffer.wrap(bytes))
        assertTrue(packet is Dhcp6SolicitPacket)
    }

    @Test
    fun testDecodeDhcp6SolicitPacket_incorrectOptionLength() {
        val solicitHex =
                // Solicit, Transaction ID
                "01000F51" +
                // client identifier option(option_len=12)
                "0001000C0003001B024CCBFFFE5F6EA9" +
                // elapsed time option(wrong option_len: 4)
                "000800040000" +
                // IA_PD option(option_len=41, including IA prefix option)
                "00190029DE3570F50000000000000000" +
                // IA prefix option(option_len=25)
                "001A001900000000000000004000000000000000000000000000000000"
        val bytes = HexDump.hexStringToByteArray(solicitHex)
        assertThrows(Dhcp6Packet.ParseException::class.java) {
                Dhcp6Packet.decodePacket(ByteBuffer.wrap(bytes))
        }
    }

    @Test
    fun testDecodeDhcp6SolicitPacket_lastTruncatedOption() {
        val solicitHex =
                // Solicit, Transaction ID
                "01000F51" +
                // client identifier option(option_len=12)
                "0001000C0003001B024CCBFFFE5F6EA9" +
                // elapsed time option(option_len=2)
                "000800020000" +
                // IA_PD option(option_len=41, including IA prefix option)
                "00190029DE3570F50000000000000000" +
                // IA prefix option(option_len=25, missing one byte)
                "001A0019000000000000000040000000000000000000000000000000"
        val bytes = HexDump.hexStringToByteArray(solicitHex)
        assertThrows(Dhcp6Packet.ParseException::class.java) {
                Dhcp6Packet.decodePacket(ByteBuffer.wrap(bytes))
        }
    }

    @Test
    fun testDecodeDhcp6SolicitPacket_middleTruncatedOption() {
        val solicitHex =
                // Solicit, Transaction ID
                "01000F51" +
                // client identifier option(option_len=12, missing one byte)
                "0001000C0003001B024CCBFFFE5F6E" +
                // elapsed time option(option_len=2)
                "000800020000" +
                // IA_PD option(option_len=41, including IA prefix option)
                "00190029DE3570F50000000000000000" +
                // IA prefix option(option_len=25)
                "001A001900000000000000004000000000000000000000000000000000"
        val bytes = HexDump.hexStringToByteArray(solicitHex)
        assertThrows(Dhcp6Packet.ParseException::class.java) {
                Dhcp6Packet.decodePacket(ByteBuffer.wrap(bytes))
        }
    }
}
