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
package android.net.apf

import android.net.apf.ApfCounterTracker.Counter
import android.net.apf.ApfCounterTracker.Counter.CORRUPT_DNS_PACKET
import android.net.apf.ApfCounterTracker.Counter.DROPPED_ETHERTYPE_NOT_ALLOWED
import android.net.apf.ApfCounterTracker.Counter.DROPPED_ETH_BROADCAST
import android.net.apf.ApfCounterTracker.Counter.PASSED_ALLOCATE_FAILURE
import android.net.apf.ApfCounterTracker.Counter.PASSED_ARP
import android.net.apf.ApfCounterTracker.Counter.PASSED_TRANSMIT_FAILURE
import android.net.apf.ApfCounterTracker.Counter.TOTAL_PACKETS
import android.net.apf.ApfTestHelpers.Companion.DROP
import android.net.apf.ApfTestHelpers.Companion.MIN_PKT_SIZE
import android.net.apf.ApfTestHelpers.Companion.PASS
import android.net.apf.ApfTestHelpers.Companion.assertDrop
import android.net.apf.ApfTestHelpers.Companion.assertPass
import android.net.apf.ApfTestHelpers.Companion.assertVerdict
import android.net.apf.ApfTestHelpers.Companion.decodeCountersIntoMap
import android.net.apf.ApfTestHelpers.Companion.verifyProgramRun
import android.net.apf.BaseApfGenerator.APF_VERSION_2
import android.net.apf.BaseApfGenerator.APF_VERSION_3
import android.net.apf.BaseApfGenerator.APF_VERSION_6
import android.net.apf.BaseApfGenerator.DROP_LABEL
import android.net.apf.BaseApfGenerator.IllegalInstructionException
import android.net.apf.BaseApfGenerator.MemorySlot
import android.net.apf.BaseApfGenerator.PASS_LABEL
import android.net.apf.BaseApfGenerator.Register.R0
import android.net.apf.BaseApfGenerator.Register.R1
import androidx.test.filters.SmallTest
import com.android.net.module.util.HexDump
import com.android.net.module.util.Struct
import com.android.net.module.util.structs.EthernetHeader
import com.android.net.module.util.structs.Ipv4Header
import com.android.net.module.util.structs.UdpHeader
import com.android.testutils.DevSdkIgnoreRule
import com.android.testutils.DevSdkIgnoreRunner
import java.nio.ByteBuffer
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.Mockito.times

const val ETH_HLEN = 14
const val IPV4_HLEN = 20
const val IPPROTO_UDP = 17

/**
 * Tests for APF generator instructions.
 */
@RunWith(DevSdkIgnoreRunner::class)
@SmallTest
class ApfGeneratorTest {

    @get:Rule val ignoreRule = DevSdkIgnoreRule()

    private val ramSize = 2048
    private val clampSize = 2048

    private val testPacket = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16)

    @Test
    fun testDataInstructionMustComeFirst() {
        var gen = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
        gen.addAllocateR0()
        assertFailsWith<IllegalInstructionException> { gen.addData(ByteArray(3) { 0x01 }) }
    }

    @Test
    fun testApfInstructionEncodingSizeCheck() {
        var gen = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
        assertFailsWith<IllegalArgumentException> {
            ApfV6Generator(ByteArray(65536) { 0x01 }, APF_VERSION_6, ramSize, clampSize)
        }
        assertFailsWith<IllegalArgumentException> { gen.addAllocate(65536) }
        assertFailsWith<IllegalArgumentException> { gen.addAllocate(-1) }
        assertFailsWith<IllegalArgumentException> { gen.addDataCopy(-1, 1) }
        assertFailsWith<IllegalArgumentException> { gen.addPacketCopy(-1, 1) }
        assertFailsWith<IllegalArgumentException> { gen.addDataCopy(1, 256) }
        assertFailsWith<IllegalArgumentException> { gen.addPacketCopy(1, 256) }
        assertFailsWith<IllegalArgumentException> { gen.addDataCopy(1, -1) }
        assertFailsWith<IllegalArgumentException> { gen.addPacketCopy(1, -1) }
        assertFailsWith<IllegalArgumentException> { gen.addPacketCopyFromR0(256) }
        assertFailsWith<IllegalArgumentException> { gen.addDataCopyFromR0(256) }
        assertFailsWith<IllegalArgumentException> { gen.addPacketCopyFromR0(-1) }
        assertFailsWith<IllegalArgumentException> { gen.addDataCopyFromR0(-1) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0DoesNotContainDnsQ(
                byteArrayOf(1, 'A'.code.toByte(), 0, 0),
                256,
                ApfV4Generator.DROP_LABEL
        ) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0DoesNotContainDnsQ(
                byteArrayOf(1, 'a'.code.toByte(), 0, 0),
                0x0c,
                ApfV4Generator.DROP_LABEL
        ) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0DoesNotContainDnsQ(
                byteArrayOf(1, '.'.code.toByte(), 0, 0),
                0x0c,
                ApfV4Generator.DROP_LABEL
        ) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0DoesNotContainDnsQ(
                byteArrayOf(0, 0),
                0xc0,
                ApfV4Generator.DROP_LABEL
        ) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0DoesNotContainDnsQ(
                byteArrayOf(1, 'A'.code.toByte()),
                0xc0,
                ApfV4Generator.DROP_LABEL
        ) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0DoesNotContainDnsQ(
                byteArrayOf(64) + ByteArray(64) { 'A'.code.toByte() } + byteArrayOf(0, 0),
                0xc0,
                ApfV4Generator.DROP_LABEL
        ) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0DoesNotContainDnsQ(
                byteArrayOf(1, 'A'.code.toByte(), 1, 'B'.code.toByte(), 0),
                0xc0,
                ApfV4Generator.DROP_LABEL
        ) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0DoesNotContainDnsQ(
                byteArrayOf(1, 'A'.code.toByte(), 1, 'B'.code.toByte()),
                0xc0,
                ApfV4Generator.DROP_LABEL
        ) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0ContainDnsQ(
                byteArrayOf(1, 'A'.code.toByte(), 0, 0),
                256,
                ApfV4Generator.DROP_LABEL
        ) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0ContainDnsQ(
                byteArrayOf(1, 'a'.code.toByte(), 0, 0),
                0x0c,
                ApfV4Generator.DROP_LABEL
        ) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0ContainDnsQ(
                byteArrayOf(1, '.'.code.toByte(), 0, 0),
                0x0c,
                ApfV4Generator.DROP_LABEL
        ) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0ContainDnsQ(
                byteArrayOf(0, 0),
                0xc0,
                ApfV4Generator.DROP_LABEL
        ) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0ContainDnsQ(
                byteArrayOf(1, 'A'.code.toByte()),
                0xc0,
                ApfV4Generator.DROP_LABEL
        ) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0ContainDnsQ(
                byteArrayOf(64) + ByteArray(64) { 'A'.code.toByte() } + byteArrayOf(0, 0),
                0xc0,
                ApfV4Generator.DROP_LABEL
        ) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0ContainDnsQ(
                byteArrayOf(1, 'A'.code.toByte(), 1, 'B'.code.toByte(), 0),
                0xc0,
                ApfV4Generator.DROP_LABEL
        ) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0ContainDnsQ(
                byteArrayOf(1, 'A'.code.toByte(), 1, 'B'.code.toByte()),
                0xc0,
                ApfV4Generator.DROP_LABEL
        ) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0DoesNotContainDnsA(
                byteArrayOf(1, 'a'.code.toByte(), 0, 0),
                ApfV4Generator.DROP_LABEL
        ) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0DoesNotContainDnsA(
                byteArrayOf(1, '.'.code.toByte(), 0, 0),
                ApfV4Generator.DROP_LABEL
        ) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0DoesNotContainDnsA(
                byteArrayOf(0, 0),
                ApfV4Generator.DROP_LABEL
        ) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0DoesNotContainDnsA(
                byteArrayOf(1, 'A'.code.toByte()),
                ApfV4Generator.DROP_LABEL
        ) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0DoesNotContainDnsA(
                byteArrayOf(64) + ByteArray(64) { 'A'.code.toByte() } + byteArrayOf(0, 0),
                ApfV4Generator.DROP_LABEL
        ) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0DoesNotContainDnsA(
                byteArrayOf(1, 'A'.code.toByte(), 1, 'B'.code.toByte(), 0),
                ApfV4Generator.DROP_LABEL
        ) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0DoesNotContainDnsA(
                byteArrayOf(1, 'A'.code.toByte(), 1, 'B'.code.toByte()),
                ApfV4Generator.DROP_LABEL
        ) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0ContainDnsA(
                byteArrayOf(1, 'a'.code.toByte(), 0, 0),
                ApfV4Generator.DROP_LABEL
        ) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0ContainDnsA(
                byteArrayOf(1, '.'.code.toByte(), 0, 0),
                ApfV4Generator.DROP_LABEL
        ) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0ContainDnsA(
                byteArrayOf(0, 0),
                ApfV4Generator.DROP_LABEL
        ) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0ContainDnsA(
                byteArrayOf(1, 'A'.code.toByte()),
                ApfV4Generator.DROP_LABEL
        ) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0ContainDnsA(
                byteArrayOf(64) + ByteArray(64) { 'A'.code.toByte() } + byteArrayOf(0, 0),
                ApfV4Generator.DROP_LABEL
        ) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0ContainDnsA(
                byteArrayOf(1, 'A'.code.toByte(), 1, 'B'.code.toByte(), 0),
                ApfV4Generator.DROP_LABEL
        ) }
        assertFailsWith<IllegalArgumentException> { gen.addJumpIfPktAtR0ContainDnsA(
                byteArrayOf(1, 'A'.code.toByte(), 1, 'B'.code.toByte()),
                ApfV4Generator.DROP_LABEL
        ) }
        assertFailsWith<IllegalArgumentException> {
            gen.addJumpIfBytesAtR0Equal(ByteArray(2048) { 1 }, DROP_LABEL)
        }
        assertFailsWith<IllegalArgumentException> {
            gen.addJumpIfBytesAtR0NotEqual(ByteArray(2048) { 1 }, DROP_LABEL)
        }
        assertFailsWith<IllegalArgumentException> { gen.addCountAndDrop(PASSED_ARP) }
        assertFailsWith<IllegalArgumentException> { gen.addCountAndPass(DROPPED_ETH_BROADCAST) }
        assertFailsWith<IllegalArgumentException> {
            gen.addCountAndDropIfR0Equals(3, PASSED_ARP)
        }
        assertFailsWith<IllegalArgumentException> {
            gen.addCountAndPassIfR0Equals(3, DROPPED_ETH_BROADCAST)
        }
        assertFailsWith<IllegalArgumentException> {
            gen.addCountAndDropIfR0NotEquals(3, PASSED_ARP)
        }
        assertFailsWith<IllegalArgumentException> {
            gen.addCountAndPassIfR0NotEquals(3, DROPPED_ETH_BROADCAST)
        }
        assertFailsWith<IllegalArgumentException> {
            gen.addCountAndDropIfR0LessThan(3, PASSED_ARP)
        }
        assertFailsWith<IllegalArgumentException> {
            gen.addCountAndPassIfR0LessThan(3, DROPPED_ETH_BROADCAST)
        }
        assertFailsWith<IllegalArgumentException> {
            gen.addCountAndDropIfR0GreaterThan(3, PASSED_ARP)
        }
        assertFailsWith<IllegalArgumentException> {
            gen.addCountAndPassIfR0GreaterThan(3, DROPPED_ETH_BROADCAST)
        }
        assertFailsWith<IllegalArgumentException> {
            gen.addCountAndDropIfBytesAtR0NotEqual(byteArrayOf(1), PASSED_ARP)
        }
        assertFailsWith<IllegalArgumentException> {
            gen.addCountAndDropIfBytesAtR0Equal(byteArrayOf(1), PASSED_ARP)
        }
        assertFailsWith<IllegalArgumentException> {
            gen.addCountAndPassIfBytesAtR0Equal(byteArrayOf(1), DROPPED_ETH_BROADCAST)
        }
        assertFailsWith<IllegalArgumentException> {
            gen.addCountAndDropIfR0AnyBitsSet(3, PASSED_ARP)
        }
        assertFailsWith<IllegalArgumentException> {
            gen.addCountAndPassIfR0AnyBitsSet(3, DROPPED_ETH_BROADCAST)
        }
        assertFailsWith<IllegalArgumentException> {
            gen.addCountAndDropIfR0IsOneOf(setOf(3), PASSED_ARP)
        }
        assertFailsWith<IllegalArgumentException> {
            gen.addCountAndPassIfR0IsOneOf(setOf(3), DROPPED_ETH_BROADCAST)
        }
        assertFailsWith<IllegalArgumentException> {
            gen.addCountAndDropIfR0IsNoneOf(setOf(3), PASSED_ARP)
        }
        assertFailsWith<IllegalArgumentException> {
            gen.addCountAndPassIfR0IsNoneOf(setOf(3), DROPPED_ETH_BROADCAST)
        }
        assertFailsWith<IllegalArgumentException> {
            gen.addCountAndDropIfBytesAtR0EqualsAnyOf(listOf(byteArrayOf(1)), PASSED_ARP)
        }
        assertFailsWith<IllegalArgumentException> {
            gen.addCountAndPassIfBytesAtR0EqualsAnyOf(listOf(byteArrayOf(1)), DROPPED_ETH_BROADCAST)
        }
        assertFailsWith<IllegalArgumentException> {
            gen.addCountAndDropIfBytesAtR0EqualsNoneOf(listOf(byteArrayOf(1)), PASSED_ARP)
        }
        assertFailsWith<IllegalArgumentException> {
            gen.addCountAndPassIfBytesAtR0EqualsNoneOf(
                    listOf(byteArrayOf(1)),
                    DROPPED_ETH_BROADCAST
            )
        }
        assertFailsWith<IllegalArgumentException> {
            gen.addWrite32(byteArrayOf())
        }
        assertFailsWith<IllegalArgumentException> {
            gen.addJumpIfOneOf(R0, setOf(), PASS_LABEL)
        }
        assertFailsWith<IllegalArgumentException> {
            gen.addJumpIfOneOf(R0, setOf(-1, 1), PASS_LABEL)
        }
        assertFailsWith<IllegalArgumentException> {
            gen.addJumpIfOneOf(R0, setOf(4294967296L, 1), PASS_LABEL)
        }
        assertFailsWith<IllegalArgumentException> {
            gen.addJumpIfOneOf(R0, List(34) { (it + 1).toLong() }.toSet(), PASS_LABEL)
        }
        assertFailsWith<IllegalArgumentException> {
            gen.addJumpIfBytesAtR0EqualsAnyOf(listOf(ByteArray(2048) { 1 }), PASS_LABEL )
        }
        assertFailsWith<IllegalArgumentException> {
            gen.addJumpIfBytesAtR0EqualsAnyOf(
                    listOf(byteArrayOf(1), byteArrayOf(1, 2)),
                    PASS_LABEL
            )
        }

        val v4gen = ApfV4Generator(APF_VERSION_3, ramSize, clampSize)
        assertFailsWith<IllegalArgumentException> { v4gen.addCountAndDrop(PASSED_ARP) }
        assertFailsWith<IllegalArgumentException> { v4gen.addCountAndPass(DROPPED_ETH_BROADCAST) }
        assertFailsWith<IllegalArgumentException> {
            v4gen.addCountAndDropIfR0Equals(3, PASSED_ARP)
        }
        assertFailsWith<IllegalArgumentException> {
            v4gen.addCountAndPassIfR0Equals(3, DROPPED_ETH_BROADCAST)
        }
        assertFailsWith<IllegalArgumentException> {
            v4gen.addCountAndDropIfR0NotEquals(3, PASSED_ARP)
        }
        assertFailsWith<IllegalArgumentException> {
            v4gen.addCountAndPassIfR0NotEquals(3, DROPPED_ETH_BROADCAST)
        }
        assertFailsWith<IllegalArgumentException> {
            v4gen.addCountAndDropIfBytesAtR0Equal(byteArrayOf(1), PASSED_ARP)
        }
        assertFailsWith<IllegalArgumentException> {
            v4gen.addCountAndPassIfBytesAtR0Equal(byteArrayOf(1), DROPPED_ETH_BROADCAST)
        }
        assertFailsWith<IllegalArgumentException> {
            v4gen.addCountAndDropIfR0LessThan(3, PASSED_ARP)
        }
        assertFailsWith<IllegalArgumentException> {
            v4gen.addCountAndPassIfR0LessThan(3, DROPPED_ETH_BROADCAST)
        }
        assertFailsWith<IllegalArgumentException> {
            v4gen.addCountAndDropIfR0GreaterThan(3, PASSED_ARP)
        }
        assertFailsWith<IllegalArgumentException> {
            v4gen.addCountAndPassIfR0GreaterThan(3, DROPPED_ETH_BROADCAST)
        }
        assertFailsWith<IllegalArgumentException> {
            v4gen.addCountAndDropIfBytesAtR0NotEqual(byteArrayOf(1), PASSED_ARP)
        }
        assertFailsWith<IllegalArgumentException> {
            v4gen.addCountAndDropIfR0AnyBitsSet(3, PASSED_ARP)
        }
        assertFailsWith<IllegalArgumentException> {
            v4gen.addCountAndPassIfR0AnyBitsSet(3, DROPPED_ETH_BROADCAST)
        }
        assertFailsWith<IllegalArgumentException> {
            v4gen.addCountAndDropIfR0IsOneOf(setOf(3), PASSED_ARP)
        }
        assertFailsWith<IllegalArgumentException> {
            v4gen.addCountAndPassIfR0IsOneOf(setOf(3), DROPPED_ETH_BROADCAST)
        }
        assertFailsWith<IllegalArgumentException> {
            v4gen.addCountAndDropIfR0IsNoneOf(setOf(3), PASSED_ARP)
        }
        assertFailsWith<IllegalArgumentException> {
            v4gen.addCountAndPassIfR0IsNoneOf(setOf(3), DROPPED_ETH_BROADCAST)
        }
        assertFailsWith<IllegalArgumentException> {
            v4gen.addCountAndDropIfBytesAtR0EqualsAnyOf(listOf(byteArrayOf(1)), PASSED_ARP)
        }
        assertFailsWith<IllegalArgumentException> {
            v4gen.addCountAndPassIfBytesAtR0EqualsAnyOf(
                    listOf(byteArrayOf(1)),
                    DROPPED_ETH_BROADCAST
            )
        }
        assertFailsWith<IllegalArgumentException> {
            v4gen.addCountAndDropIfBytesAtR0EqualsNoneOf(listOf(byteArrayOf(1)), PASSED_ARP)
        }
        assertFailsWith<IllegalArgumentException> {
            v4gen.addCountAndPassIfBytesAtR0EqualsNoneOf(
                    listOf(byteArrayOf(1)),
                    DROPPED_ETH_BROADCAST
            )
        }
    }

    @Test
    fun testValidateDnsNames() {
        // '%' is a valid label character in mDNS subtype
        // byte == 0xff means it is a '*' wildcard, which is a valid encoding.
        val program = ApfV6Generator(ramSize, ramSize, clampSize).addJumpIfPktAtR0ContainDnsQ(
                byteArrayOf(1, '%'.code.toByte(), 0, 0),
                1,
                DROP_LABEL
        ).addJumpIfPktAtR0ContainDnsA(
                byteArrayOf(0xff.toByte(), 1, 'B'.code.toByte(), 0, 0),
                DROP_LABEL
        ).generate()
    }

    @Test
    fun testApfInstructionsEncoding() {
        val v4gen = ApfV4Generator(APF_VERSION_2, ramSize, clampSize)
        v4gen.addPass()
        var program = v4gen.generate()
        // encoding PASS opcode: opcode=0, imm_len=0, R=0
        assertContentEquals(
                byteArrayOf(encodeInstruction(opcode = 0, immLength = 0, register = 0)),
                program
        )
        assertContentEquals(
                listOf("0: pass"),
                ApfJniUtils.disassembleApf(program).map { it.trim() }
        )

        var gen = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
        gen.addDrop()
        program = gen.generate().skipDataAndDebug()
        // encoding DROP opcode: opcode=0, imm_len=0, R=1
        assertContentEquals(
                byteArrayOf(encodeInstruction(opcode = 0, immLength = 0, register = 1)),
                program
        )
        assertContentEquals(
                listOf("0: drop"),
                ApfJniUtils.disassembleApf(program).map { it.trim() }
        )

        gen = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
        gen.addCountAndPass(129)
        program = gen.generate().skipDataAndDebug()
        // encoding COUNT(PASS) opcode: opcode=0, imm_len=size_of(imm), R=0, imm=counterNumber
        assertContentEquals(
                byteArrayOf(
                        encodeInstruction(opcode = 0, immLength = 1, register = 0),
                        0x81.toByte()
                ),
                program
        )
        assertContentEquals(
                listOf("0: pass        counter=129"),
                ApfJniUtils.disassembleApf(program).map { it.trim() }
        )

        gen = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
        gen.addCountAndDrop(1000)
        program = gen.generate().skipDataAndDebug()
        // encoding COUNT(DROP) opcode: opcode=0, imm_len=size_of(imm), R=1, imm=counterNumber
        assertContentEquals(
                byteArrayOf(
                        encodeInstruction(opcode = 0, immLength = 2, register = 1),
                        0x03,
                        0xe8.toByte()
                ),
                program
        )
        assertContentEquals(
                listOf("0: drop        counter=1000"),
                ApfJniUtils.disassembleApf(program).map { it.trim() }
        )

        gen = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
        gen.addCountAndPass(PASSED_ARP)
        program = gen.generate().skipDataAndDebug()
        // encoding COUNT(PASS) opcode: opcode=0, imm_len=size_of(imm), R=0, imm=counterNumber
        assertContentEquals(
                byteArrayOf(
                        encodeInstruction(opcode = 0, immLength = 1, register = 0),
                        PASSED_ARP.value().toByte()
                ),
                program
        )
        assertContentEquals(
                listOf("0: pass        counter=10"),
                ApfJniUtils.disassembleApf(program).map { it.trim() }
        )

        gen = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
        gen.addCountAndDrop(DROPPED_ETHERTYPE_NOT_ALLOWED)
        program = gen.generate().skipDataAndDebug()
        // encoding COUNT(DROP) opcode: opcode=0, imm_len=size_of(imm), R=1, imm=counterNumber
        assertContentEquals(
                byteArrayOf(
                        encodeInstruction(opcode = 0, immLength = 1, register = 1),
                        DROPPED_ETHERTYPE_NOT_ALLOWED.value().toByte()
                ),
                program
        )
        assertContentEquals(
                listOf("0: drop        counter=47"),
                ApfJniUtils.disassembleApf(program).map { it.trim() }
        )

        gen = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
        gen.addAllocateR0()
        gen.addAllocate(1500)
        program = gen.generate().skipDataAndDebug()
        // encoding ALLOC opcode: opcode=21(EXT opcode number), imm=36(TRANS opcode number).
        // R=0 means length stored in R0. R=1 means the length stored in imm1.
        assertContentEquals(
                byteArrayOf(
                        encodeInstruction(opcode = 21, immLength = 1, register = 0),
                        36,
                        encodeInstruction(opcode = 21, immLength = 1, register = 1),
                        36,
                        0x05,
                        0xDC.toByte()
                ),
                program
        )
        assertContentEquals(listOf(
                "0: allocate    r0",
                "2: allocate    1500"
        ), ApfJniUtils.disassembleApf(program).map { it.trim() })

        gen = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
        gen.addTransmitWithoutChecksum()
        gen.addTransmitL4(30, 40, 50, 256, true)
        program = gen.generate().skipDataAndDebug()
        // encoding TRANSMIT opcode: opcode=21(EXT opcode number),
        // imm=37(TRANSMIT opcode number),
        assertContentEquals(byteArrayOf(
                encodeInstruction(opcode = 21, immLength = 1, register = 0),
                37, 255.toByte(), 255.toByte(),
                encodeInstruction(opcode = 21, immLength = 1, register = 1), 37, 30, 40, 50, 1, 0
        ), program)
        assertContentEquals(listOf(
                "0: transmit    ip_ofs=255",
                "4: transmitudp ip_ofs=30, csum_ofs=40, csum_start=50, partial_csum=0x0100",
        ), ApfJniUtils.disassembleApf(program).map { it.trim() })

        val largeByteArray = ByteArray(256) { 0x01 }
        gen = ApfV6Generator(largeByteArray, APF_VERSION_6, ramSize, clampSize)
        program = gen.generate()
        assertContentEquals(
                byteArrayOf(
                        encodeInstruction(opcode = 14, immLength = 2, register = 1), 1, 0
                ) + largeByteArray + byteArrayOf(
                        encodeInstruction(opcode = 21, immLength = 1, register = 0), 48, 6, 9
                ),
                program
        )
        assertContentEquals(
                listOf(
                        "0: data        256, " + "01".repeat(256),
                        "259: debugbuf    size=1545"
                ),
                ApfJniUtils.disassembleApf(program).map { it.trim() }
        )

        gen = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
        gen.addWriteU8(0x01)
        gen.addWriteU16(0x0102)
        gen.addWriteU32(0x01020304)
        gen.addWriteU8(0x00)
        gen.addWriteU8(0x80)
        gen.addWriteU16(0x0000)
        gen.addWriteU16(0x8000)
        gen.addWriteU32(0x00000000)
        gen.addWriteU32(0x80000000)
        gen.addWrite32(-2)
        gen.addWrite32(byteArrayOf(0xff.toByte(), 0xfe.toByte(), 0xfd.toByte(), 0xfc.toByte()))
        program = gen.generate().skipDataAndDebug()
        assertContentEquals(byteArrayOf(
                encodeInstruction(24, 1, 0), 0x01,
                encodeInstruction(24, 2, 0), 0x01, 0x02,
                encodeInstruction(24, 4, 0), 0x01, 0x02, 0x03, 0x04,
                encodeInstruction(24, 1, 0), 0x00,
                encodeInstruction(24, 1, 0), 0x80.toByte(),
                encodeInstruction(24, 2, 0), 0x00, 0x00,
                encodeInstruction(24, 2, 0), 0x80.toByte(), 0x00,
                encodeInstruction(24, 4, 0), 0x00, 0x00, 0x00, 0x00,
                encodeInstruction(24, 4, 0), 0x80.toByte(), 0x00, 0x00, 0x00,
                encodeInstruction(24, 4, 0), 0xff.toByte(), 0xff.toByte(),
                0xff.toByte(), 0xfe.toByte(),
                encodeInstruction(24, 4, 0), 0xff.toByte(), 0xfe.toByte(),
                0xfd.toByte(), 0xfc.toByte()), program)
        assertContentEquals(listOf(
                "0: write       0x01",
                "2: write       0x0102",
                "5: write       0x01020304",
                "10: write       0x00",
                "12: write       0x80",
                "14: write       0x0000",
                "17: write       0x8000",
                "20: write       0x00000000",
                "25: write       0x80000000",
                "30: write       0xfffffffe",
                "35: write       0xfffefdfc"
        ), ApfJniUtils.disassembleApf(program).map { it.trim() })

        gen = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
        gen.addWriteU8(R0)
        gen.addWriteU16(R0)
        gen.addWriteU32(R0)
        gen.addWriteU8(R1)
        gen.addWriteU16(R1)
        gen.addWriteU32(R1)
        program = gen.generate().skipDataAndDebug()
        assertContentEquals(byteArrayOf(
                encodeInstruction(21, 1, 0), 38,
                encodeInstruction(21, 1, 0), 39,
                encodeInstruction(21, 1, 0), 40,
                encodeInstruction(21, 1, 1), 38,
                encodeInstruction(21, 1, 1), 39,
                encodeInstruction(21, 1, 1), 40
        ), program)
        assertContentEquals(listOf(
                "0: ewrite1     r0",
                "2: ewrite2     r0",
                "4: ewrite4     r0",
                "6: ewrite1     r1",
                "8: ewrite2     r1",
                "10: ewrite4     r1"
        ), ApfJniUtils.disassembleApf(program).map { it.trim() })

        gen = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
        gen.addDataCopy(0, 10)
        gen.addDataCopy(1, 5)
        gen.addPacketCopy(1000, 255)
        program = gen.generate().skipDataAndDebug()
        assertContentEquals(byteArrayOf(
                encodeInstruction(25, 0, 1), 10,
                encodeInstruction(25, 1, 1), 1, 5,
                encodeInstruction(25, 2, 0),
                0x03.toByte(), 0xe8.toByte(), 0xff.toByte(),
        ), program)
        assertContentEquals(listOf(
                "0: datacopy    src=0, len=10",
                "2: datacopy    src=1, len=5",
                "5: pktcopy     src=1000, len=255"
        ), ApfJniUtils.disassembleApf(program).map { it.trim() })

        gen = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
        gen.addDataCopyFromR0(5)
        gen.addPacketCopyFromR0(5)
        gen.addDataCopyFromR0LenR1()
        gen.addPacketCopyFromR0LenR1()
        program = gen.generate().skipDataAndDebug()
        assertContentEquals(byteArrayOf(
                encodeInstruction(21, 1, 1), 41, 5,
                encodeInstruction(21, 1, 0), 41, 5,
                encodeInstruction(21, 1, 1), 42,
                encodeInstruction(21, 1, 0), 42,
        ), program)
        assertContentEquals(listOf(
                "0: edatacopy    src=r0, len=5",
                "3: epktcopy     src=r0, len=5",
                "6: edatacopy    src=r0, len=r1",
                "8: epktcopy     src=r0, len=r1"
        ), ApfJniUtils.disassembleApf(program).map{ it.trim() })

        gen = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
        gen.addJumpIfBytesAtR0Equal(byteArrayOf('a'.code.toByte()), ApfV4Generator.DROP_LABEL)
        program = gen.generate().skipDataAndDebug()
        assertContentEquals(byteArrayOf(
                encodeInstruction(opcode = 20, immLength = 1, register = 1),
                1,
                1,
                'a'.code.toByte()
        ), program)
        assertContentEquals(listOf(
                "0: jbseq       r0, 0x1, DROP, 61"
        ), ApfJniUtils.disassembleApf(program).map{ it.trim() })

        val qnames = byteArrayOf(1, 'A'.code.toByte(), 1, 'B'.code.toByte(), 0, 0)
        gen = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
        gen.addJumpIfPktAtR0DoesNotContainDnsQ(qnames, 0x0c, ApfV4Generator.DROP_LABEL)
        gen.addJumpIfPktAtR0ContainDnsQ(qnames, 0x0c, ApfV4Generator.DROP_LABEL)
        program = gen.generate().skipDataAndDebug()
        assertContentEquals(byteArrayOf(
                encodeInstruction(21, 1, 0), 43, 11, 0x0c.toByte(),
        ) + qnames + byteArrayOf(
                encodeInstruction(21, 1, 1), 43, 1, 0x0c.toByte(),
        ) + qnames, program)
        assertContentEquals(listOf(
                "0: jdnsqne     r0, DROP, 12, (1)A(1)B(0)(0)",
                "10: jdnsqeq     r0, DROP, 12, (1)A(1)B(0)(0)"
        ), ApfJniUtils.disassembleApf(program).map{ it.trim() })

        gen = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
        gen.addJumpIfPktAtR0DoesNotContainDnsQSafe(qnames, 0x0c, ApfV4Generator.DROP_LABEL)
        gen.addJumpIfPktAtR0ContainDnsQSafe(qnames, 0x0c, ApfV4Generator.DROP_LABEL)
        program = gen.generate().skipDataAndDebug()
        assertContentEquals(byteArrayOf(
                encodeInstruction(21, 1, 0), 45, 11, 0x0c.toByte(),
        ) + qnames + byteArrayOf(
                encodeInstruction(21, 1, 1), 45, 1, 0x0c.toByte(),
        ) + qnames, program)
        assertContentEquals(listOf(
                "0: jdnsqnesafe r0, DROP, 12, (1)A(1)B(0)(0)",
                "10: jdnsqeqsafe r0, DROP, 12, (1)A(1)B(0)(0)"
        ), ApfJniUtils.disassembleApf(program).map{ it.trim() })

        gen = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
        gen.addJumpIfPktAtR0DoesNotContainDnsA(qnames, ApfV4Generator.DROP_LABEL)
        gen.addJumpIfPktAtR0ContainDnsA(qnames, ApfV4Generator.DROP_LABEL)
        program = gen.generate().skipDataAndDebug()
        assertContentEquals(byteArrayOf(
                encodeInstruction(21, 1, 0), 44, 10,
        ) + qnames + byteArrayOf(
                encodeInstruction(21, 1, 1), 44, 1,
        ) + qnames, program)
        assertContentEquals(listOf(
                "0: jdnsane     r0, DROP, (1)A(1)B(0)(0)",
                "9: jdnsaeq     r0, DROP, (1)A(1)B(0)(0)"
        ), ApfJniUtils.disassembleApf(program).map{ it.trim() })

        gen = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
        gen.addJumpIfPktAtR0DoesNotContainDnsASafe(qnames, ApfV4Generator.DROP_LABEL)
        gen.addJumpIfPktAtR0ContainDnsASafe(qnames, ApfV4Generator.DROP_LABEL)
        program = gen.generate().skipDataAndDebug()
        assertContentEquals(byteArrayOf(
                encodeInstruction(21, 1, 0), 46, 10,
        ) + qnames + byteArrayOf(
                encodeInstruction(21, 1, 1), 46, 1,
        ) + qnames, program)
        assertContentEquals(listOf(
                "0: jdnsanesafe r0, DROP, (1)A(1)B(0)(0)",
                "9: jdnsaeqsafe r0, DROP, (1)A(1)B(0)(0)"
        ), ApfJniUtils.disassembleApf(program).map{ it.trim() })

        gen = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
        gen.addJumpIfOneOf(R1, List(32) { (it + 1).toLong() }.toSet(), DROP_LABEL)
        gen.addJumpIfOneOf(R0, setOf(0, 257, 65536), DROP_LABEL)
        gen.addJumpIfNoneOf(R0, setOf(1, 2, 3), DROP_LABEL)
        program = gen.generate().skipDataAndDebug()
        assertContentEquals(byteArrayOf(
                encodeInstruction(21, 1, 1), 47, 24, -16, 1, 2, 3, 4, 5, 6,
                7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
                29, 30, 31, 32,
                encodeInstruction(21, 1, 0), 47, 8, 14, 0, 0, 0, 0, 0, 0,
                1, 1, 0, 1, 0, 0,
                encodeInstruction(21, 1, 0), 47, 1, 9, 1, 2, 3
        ), program)

        gen = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
        gen.addJumpIfOneOf(R0, setOf(0, 128, 256, 65536), DROP_LABEL)
        gen.addJumpIfNoneOf(R1, setOf(0, 128, 256, 65536), DROP_LABEL)
        program = gen.generate().skipDataAndDebug()
        assertContentEquals(listOf(
                "0: joneof      r0, DROP, { 0, 128, 256, 65536 }",
                "20: jnoneof     r1, DROP, { 0, 128, 256, 65536 }"
        ), ApfJniUtils.disassembleApf(program).map{ it.trim() })

        gen = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
        gen.addJumpIfBytesAtR0EqualsAnyOf(listOf(byteArrayOf(1, 2), byteArrayOf(3, 4)), DROP_LABEL)
        gen.addJumpIfBytesAtR0EqualNoneOf(listOf(byteArrayOf(1, 2), byteArrayOf(3, 4)), DROP_LABEL)
        gen.addJumpIfBytesAtR0EqualNoneOf(listOf(byteArrayOf(1, 1), byteArrayOf(1, 1)), DROP_LABEL)
        program = gen.generate().skipDataAndDebug()
        assertContentEquals(byteArrayOf(
                encodeInstruction(opcode = 20, immLength = 2, register = 1),
                0, 15, 8, 2, 1, 2, 3, 4,
                encodeInstruction(opcode = 20, immLength = 2, register = 0),
                0, 6, 8, 2, 1, 2, 3, 4,
                encodeInstruction(opcode = 20, immLength = 1, register = 0),
                1, 2, 1, 1
        ), program)
        assertContentEquals(listOf(
                "0: jbseq       r0, 0x2, DROP, { 0102, 0304 }",
                "9: jbsne       r0, 0x2, DROP, { 0102, 0304 }",
                "18: jbsne       r0, 0x2, DROP, 0101"
        ), ApfJniUtils.disassembleApf(program).map{ it.trim() })
    }

    @Test
    fun testWriteToTxBuffer() {
        var program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                .addAllocate(14)
                .addWriteU8(0x01)
                .addWriteU16(0x0203)
                .addWriteU32(0x04050607)
                .addWrite32(-2)
                .addWrite32(byteArrayOf(0xff.toByte(), 0xfe.toByte(), 0xfd.toByte(), 0xfc.toByte()))
                .addLoadImmediate(R0, 1)
                .addWriteU8(R0)
                .addLoadImmediate(R0, 0x0203)
                .addWriteU16(R0)
                .addLoadImmediate(R1, 0x04050607)
                .addWriteU32(R1)
                .addTransmitWithoutChecksum()
                .generate()
        assertPass(APF_VERSION_6, program, ByteArray(MIN_PKT_SIZE))
        assertContentEquals(
                byteArrayOf(
                        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xff.toByte(),
                        0xff.toByte(), 0xff.toByte(), 0xfe.toByte(), 0xff.toByte(), 0xfe.toByte(),
                        0xfd.toByte(), 0xfc.toByte(), 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07),
                ApfJniUtils.getTransmittedPacket()
        )
    }

    @Test
    fun testCopyToTxBuffer() {
        var program = ApfV6Generator(byteArrayOf(33, 34, 35), APF_VERSION_6, ramSize, clampSize)
                .addAllocate(14)
                .addDataCopy(3, 2) // arg1=src, arg2=len
                .addDataCopy(5, 1) // arg1=src, arg2=len
                .addPacketCopy(0, 1) // arg1=src, arg2=len
                .addPacketCopy(1, 3) // arg1=src, arg2=len
                .addLoadImmediate(R0, 3) // data copy offset
                .addDataCopyFromR0(2) // len
                .addLoadImmediate(R0, 5) // data copy offset
                .addLoadImmediate(R1, 1) // len
                .addDataCopyFromR0LenR1()
                .addLoadImmediate(R0, 0) // packet copy offset
                .addPacketCopyFromR0(1) // len
                .addLoadImmediate(R0, 1) // packet copy offset
                .addLoadImmediate(R1, 3) // len
                .addPacketCopyFromR0LenR1()
                .addTransmitWithoutChecksum()
                .generate()
        assertPass(APF_VERSION_6, program, testPacket)
        assertContentEquals(
                byteArrayOf(33, 34, 35, 1, 2, 3, 4, 33, 34, 35, 1, 2, 3, 4),
                ApfJniUtils.getTransmittedPacket()
        )
    }

    @Test
    fun testCopyContentToTxBuffer() {
        val program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                .addAllocate(18)
                .addDataCopy(HexDump.hexStringToByteArray("112233445566"))
                .addDataCopy(HexDump.hexStringToByteArray("223344"))
                .addDataCopy(HexDump.hexStringToByteArray("778899"))
                .addDataCopy(HexDump.hexStringToByteArray("112233445566"))
                .addTransmitWithoutChecksum()
                .generate()
        assertContentEquals(listOf(
                "0: data        9, 112233445566778899",
                "12: debugbuf    size=1772",
                "16: allocate    18",
                "20: datacopy    src=3, len=6",
                "23: datacopy    src=4, len=3",
                "26: datacopy    src=9, len=3",
                "29: datacopy    src=3, len=6",
                "32: transmit    ip_ofs=255"
        ), ApfJniUtils.disassembleApf(program).map{ it.trim() })
        assertPass(APF_VERSION_6, program, testPacket)
        val transmitPkt = HexDump.toHexString(ApfJniUtils.getTransmittedPacket())
        assertEquals("112233445566223344778899112233445566", transmitPkt)
    }

    @Test
    fun testPassDrop() {
        var program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                .addDrop()
                .addPass()
                .generate()
        assertDrop(APF_VERSION_6, program, testPacket)

        program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                .addCountAndDrop(Counter.DROPPED_ETH_BROADCAST)
                .generate()
        verifyProgramRun(APF_VERSION_6, program, testPacket, DROPPED_ETH_BROADCAST)

        program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                .addCountAndPass(Counter.PASSED_ARP)
                .generate()
        verifyProgramRun(APF_VERSION_6, program, testPacket, PASSED_ARP)
    }

    @Test
    fun testLoadStoreCounter() {
        doTestLoadStoreCounter (
                { mutableMapOf() },
                { ApfV4Generator(APF_VERSION_3, ramSize, clampSize) }
        )
        doTestLoadStoreCounter (
                { mutableMapOf(TOTAL_PACKETS to 1) },
                { ApfV6Generator(APF_VERSION_6, ramSize, clampSize) }
        )
    }

    private fun doTestLoadStoreCounter(
            getInitialMap: () -> MutableMap<Counter, Long>,
            getGenerator: () -> ApfV4GeneratorBase<*>
    ) {
        val program = getGenerator()
                .addIncrementCounter(PASSED_ARP, 2)
                .addPass()
                .generate()
        var dataRegion = ByteArray(Counter.totalSize()) { 0 }
        assertVerdict(APF_VERSION_6, PASS, program, testPacket, dataRegion)
        var counterMap = decodeCountersIntoMap(dataRegion)
        var expectedMap = getInitialMap()
        expectedMap[PASSED_ARP] = 2
        assertEquals(expectedMap, counterMap)
    }

    @Test
    fun testV4CountAndPassDropCompareR0() {
        doTestCountAndPassDropCompareR0(
                getGenerator = { ApfV4Generator(APF_VERSION_3, ramSize, clampSize) },
                incTotal = false
        )
    }

    @Test
    fun testV6CountAndPassDropCompareR0() {
        doTestCountAndPassDropCompareR0(
                getGenerator = { ApfV6Generator(APF_VERSION_6, ramSize, clampSize) },
                incTotal = true
        )
    }

    private fun doTestCountAndPassDropCompareR0(
            getGenerator: () -> ApfV4GeneratorBase<*>,
            incTotal: Boolean
    ) {
        var program = getGenerator()
                .addLoadImmediate(R0, 123)
                .addCountAndDropIfR0Equals(123, Counter.DROPPED_ETH_BROADCAST)
                .addPass()
                .addCountTrampoline()
                .generate()
        verifyProgramRun(
                APF_VERSION_6,
                program,
                testPacket,
                DROPPED_ETH_BROADCAST,
                incTotal = incTotal
        )

        program = getGenerator()
                .addLoadImmediate(R0, 123)
                .addCountAndPassIfR0Equals(123, Counter.PASSED_ARP)
                .addPass()
                .addCountTrampoline()
                .generate()
        verifyProgramRun(APF_VERSION_6, program, testPacket, PASSED_ARP, incTotal = incTotal)

        program = getGenerator()
                .addLoadImmediate(R0, 123)
                .addCountAndDropIfR0NotEquals(124, Counter.DROPPED_ETH_BROADCAST)
                .addPass()
                .addCountTrampoline()
                .generate()
        verifyProgramRun(
                APF_VERSION_6,
                program,
                testPacket,
                DROPPED_ETH_BROADCAST,
                incTotal = incTotal
        )

        program = getGenerator()
                .addLoadImmediate(R0, 123)
                .addCountAndPassIfR0NotEquals(124, Counter.PASSED_ARP)
                .addPass()
                .addCountTrampoline()
                .generate()
        verifyProgramRun(APF_VERSION_6, program, testPacket, PASSED_ARP, incTotal = incTotal)

        program = getGenerator()
                .addLoadImmediate(R0, 123)
                .addCountAndDropIfR0LessThan(124, Counter.DROPPED_ETH_BROADCAST)
                .addPass()
                .addCountTrampoline()
                .generate()
        verifyProgramRun(
                APF_VERSION_6,
                program,
                testPacket,
                DROPPED_ETH_BROADCAST,
                incTotal = incTotal
        )

        program = getGenerator()
                .addLoadImmediate(R0, 123)
                .addCountAndPassIfR0LessThan(124, Counter.PASSED_ARP)
                .addPass()
                .addCountTrampoline()
                .generate()
        verifyProgramRun(APF_VERSION_6, program, testPacket, PASSED_ARP, incTotal = incTotal)

        program = getGenerator()
                .addLoadImmediate(R0, 123)
                .addCountAndDropIfR0GreaterThan(122, Counter.DROPPED_ETH_BROADCAST)
                .addPass()
                .addCountTrampoline()
                .generate()
        verifyProgramRun(
                APF_VERSION_6,
                program,
                testPacket,
                DROPPED_ETH_BROADCAST,
                incTotal = incTotal
        )

        program = getGenerator()
                .addLoadImmediate(R0, 123)
                .addCountAndPassIfR0GreaterThan(122, Counter.PASSED_ARP)
                .addPass()
                .addCountTrampoline()
                .generate()
        verifyProgramRun(APF_VERSION_6, program, testPacket, PASSED_ARP, incTotal = incTotal)

        program = getGenerator()
                .addLoadImmediate(R0, 1)
                .addCountAndDropIfBytesAtR0NotEqual(
                        byteArrayOf(5, 5), DROPPED_ETH_BROADCAST)
                .addPass()
                .addCountTrampoline()
                .generate()
        verifyProgramRun(
                APF_VERSION_6,
                program,
                testPacket,
                DROPPED_ETH_BROADCAST,
                incTotal = incTotal
        )

        program = getGenerator()
                .addLoadImmediate(R0, 1)
                .addCountAndPassIfBytesAtR0NotEqual(
                        byteArrayOf(5, 5), PASSED_ARP)
                .addPass()
                .addCountTrampoline()
                .generate()
        verifyProgramRun(APF_VERSION_6, program, testPacket, PASSED_ARP, incTotal = incTotal)

        program = getGenerator()
                .addLoadImmediate(R0, 1)
                .addCountAndDropIfR0AnyBitsSet(0xffff, DROPPED_ETH_BROADCAST)
                .addPass()
                .addCountTrampoline()
                .generate()
        verifyProgramRun(
                APF_VERSION_6,
                program,
                testPacket,
                DROPPED_ETH_BROADCAST,
                incTotal = incTotal
        )

        program = getGenerator()
                .addLoadImmediate(R0, 1)
                .addCountAndPassIfR0AnyBitsSet(0xffff, PASSED_ARP)
                .addPass()
                .addCountTrampoline()
                .generate()
        verifyProgramRun(APF_VERSION_6, program, testPacket, PASSED_ARP, incTotal = incTotal)

        program = getGenerator()
                .addLoadImmediate(R0, 123)
                .addCountAndDropIfR0IsOneOf(setOf(123), DROPPED_ETH_BROADCAST)
                .addPass()
                .addCountTrampoline()
                .generate()
        verifyProgramRun(
                APF_VERSION_6,
                program,
                testPacket,
                DROPPED_ETH_BROADCAST,
                incTotal = incTotal
        )

        program = getGenerator()
                .addLoadImmediate(R0, 123)
                .addCountAndPassIfR0IsOneOf(setOf(123), PASSED_ARP)
                .addPass()
                .addCountTrampoline()
                .generate()
        verifyProgramRun(APF_VERSION_6, program, testPacket, PASSED_ARP, incTotal = incTotal)

        program = getGenerator()
                .addLoadImmediate(R0, 123)
                .addCountAndDropIfR0IsNoneOf(setOf(124), DROPPED_ETH_BROADCAST)
                .addPass()
                .addCountTrampoline()
                .generate()
        verifyProgramRun(
                APF_VERSION_6,
                program,
                testPacket,
                DROPPED_ETH_BROADCAST,
                incTotal = incTotal
        )

        program = getGenerator()
                .addLoadImmediate(R0, 123)
                .addCountAndPassIfR0IsNoneOf(setOf(124), PASSED_ARP)
                .addPass()
                .addCountTrampoline()
                .generate()
        verifyProgramRun(APF_VERSION_6, program, testPacket, PASSED_ARP, incTotal = incTotal)

        program = getGenerator()
                .addLoadImmediate(R0, 123)
                .addCountAndDropIfR0IsOneOf(setOf(123, 124), DROPPED_ETH_BROADCAST)
                .addPass()
                .addCountTrampoline()
                .generate()
        verifyProgramRun(
                APF_VERSION_6,
                program,
                testPacket,
                DROPPED_ETH_BROADCAST,
                incTotal = incTotal
        )

        program = getGenerator()
                .addLoadImmediate(R0, 123)
                .addCountAndPassIfR0IsOneOf(setOf(123, 124), PASSED_ARP)
                .addPass()
                .addCountTrampoline()
                .generate()
        verifyProgramRun(APF_VERSION_6, program, testPacket, PASSED_ARP, incTotal = incTotal)

        program = getGenerator()
                .addLoadImmediate(R0, 123)
                .addCountAndDropIfR0IsNoneOf(setOf(122, 124), DROPPED_ETH_BROADCAST)
                .addPass()
                .addCountTrampoline()
                .generate()
        verifyProgramRun(
                APF_VERSION_6,
                program,
                testPacket,
                DROPPED_ETH_BROADCAST,
                incTotal = incTotal
        )

        program = getGenerator()
                .addLoadImmediate(R0, 123)
                .addCountAndPassIfR0IsNoneOf(setOf(122, 124), PASSED_ARP)
                .addPass()
                .addCountTrampoline()
                .generate()
        verifyProgramRun(APF_VERSION_6, program, testPacket, PASSED_ARP, incTotal = incTotal)

        program = getGenerator()
                .addLoadImmediate(R0, 0)
                .addCountAndDropIfBytesAtR0EqualsAnyOf(
                        listOf(byteArrayOf(1, 2), byteArrayOf(3, 4)),
                        DROPPED_ETH_BROADCAST
                )
                .addPass()
                .addCountTrampoline()
                .generate()
        verifyProgramRun(
                APF_VERSION_6,
                program,
                testPacket,
                DROPPED_ETH_BROADCAST,
                incTotal = incTotal
        )

        program = getGenerator()
                .addLoadImmediate(R0, 0)
                .addCountAndPassIfBytesAtR0EqualsAnyOf(
                        listOf(byteArrayOf(1, 2), byteArrayOf(3, 4)),
                        PASSED_ARP
                )
                .addPass()
                .addCountTrampoline()
                .generate()
        verifyProgramRun(APF_VERSION_6, program, testPacket, PASSED_ARP, incTotal = incTotal)

        program = getGenerator()
                .addLoadImmediate(R0, 0)
                .addCountAndDropIfBytesAtR0EqualsNoneOf(
                        listOf(byteArrayOf(1, 3), byteArrayOf(3, 4)),
                        DROPPED_ETH_BROADCAST
                )
                .addPass()
                .addCountTrampoline()
                .generate()
        verifyProgramRun(
                APF_VERSION_6,
                program,
                testPacket,
                DROPPED_ETH_BROADCAST,
                incTotal = incTotal
        )

        program = getGenerator()
                .addLoadImmediate(R0, 0)
                .addCountAndPassIfBytesAtR0EqualsNoneOf(
                        listOf(byteArrayOf(1, 3), byteArrayOf(3, 4)),
                        PASSED_ARP
                )
                .addPass()
                .addCountTrampoline()
                .generate()
        verifyProgramRun(APF_VERSION_6, program, testPacket, PASSED_ARP, incTotal = incTotal)

        program = getGenerator()
                .addLoadImmediate(R0, 1)
                .addCountAndDropIfBytesAtR0Equal(
                        byteArrayOf(2, 3), DROPPED_ETH_BROADCAST)
                .addPass()
                .addCountTrampoline()
                .generate()
        verifyProgramRun(
                APF_VERSION_6,
                program,
                testPacket,
                DROPPED_ETH_BROADCAST,
                incTotal = incTotal
        )

        program = getGenerator()
                .addLoadImmediate(R0, 1)
                .addCountAndPassIfBytesAtR0Equal(
                        byteArrayOf(2, 3), PASSED_ARP)
                .addPass()
                .addCountTrampoline()
                .generate()
        verifyProgramRun(APF_VERSION_6, program, testPacket, PASSED_ARP, incTotal = incTotal)
    }

    @Test
    fun testV4CountAndPassDrop() {
        var program = ApfV4Generator(APF_VERSION_3, ramSize, clampSize)
                .addCountAndDrop(Counter.DROPPED_ETH_BROADCAST)
                .addCountTrampoline()
                .generate()
        verifyProgramRun(
                APF_VERSION_6,
                program,
                testPacket,
                DROPPED_ETH_BROADCAST,
                incTotal = false
        )

        program = ApfV4Generator(APF_VERSION_3, ramSize, clampSize)
                .addCountAndPass(Counter.PASSED_ARP)
                .addCountTrampoline()
                .generate()
        verifyProgramRun(APF_VERSION_6, program, testPacket, PASSED_ARP, incTotal = false)
    }

    @Test
    fun testV2CountAndPassDrop() {
        var program = ApfV4Generator(APF_VERSION_2, ramSize, clampSize)
                .addCountAndDrop(Counter.DROPPED_ETH_BROADCAST)
                .addCountTrampoline()
                .generate()
        var dataRegion = ByteArray(Counter.totalSize()) { 0 }
        assertVerdict(APF_VERSION_6, DROP, program, testPacket, dataRegion)
        assertContentEquals(ByteArray(Counter.totalSize()) { 0 }, dataRegion)

        program = ApfV4Generator(APF_VERSION_2, ramSize, clampSize)
                .addCountAndPass(PASSED_ARP)
                .addCountTrampoline()
                .generate()
        dataRegion = ByteArray(Counter.totalSize()) { 0 }
        assertVerdict(APF_VERSION_6, PASS, program, testPacket, dataRegion)
        assertContentEquals(ByteArray(Counter.totalSize()) { 0 }, dataRegion)
    }

    @Test
    fun testAllocateFailure() {
        val program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                // allocate size: 65535 > sizeof(apf_test_buffer): 1514, trigger allocate failure.
                .addAllocate(65535)
                .addDrop()
                .generate()
        verifyProgramRun(APF_VERSION_6, program, testPacket, PASSED_ALLOCATE_FAILURE)
    }

    @Test
    fun testTransmitFailure() {
        val program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                .addAllocate(14)
                // len: 13 is less than ETH_HLEN, trigger transmit failure.
                .addLoadImmediate(R0, 13)
                .addStoreToMemory(MemorySlot.TX_BUFFER_OUTPUT_POINTER, R0)
                .addTransmitWithoutChecksum()
                .addDrop()
                .generate()
        verifyProgramRun(APF_VERSION_6, program, testPacket, PASSED_TRANSMIT_FAILURE)
    }

    @Test
    fun testTransmitL4() {
        val etherIpv4UdpPacket = intArrayOf(
                0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb,
                0x38, 0xca, 0x84, 0xb7, 0x7f, 0x16,
                0x08, 0x00, // end of ethernet header
                0x45,
                0x04,
                0x00, 0x3f,
                0x43, 0xcd,
                0x40, 0x00,
                0xff,
                0x11,
                0x00, 0x00, // ipv4 checksum set to 0
                0xc0, 0xa8, 0x01, 0x03,
                0xe0, 0x00, 0x00, 0xfb, // end of ipv4 header
                0x14, 0xe9,
                0x14, 0xe9,
                0x00, 0x2b,
                0x00, 0x2b, // end of udp header. udp checksum set to udp (header + payload) size
                0x00, 0x00, 0x84, 0x00, 0x00, 0x00,
                0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x62, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c,
                0x00, 0x00, 0x01, 0x80, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x04, 0xc0, 0xa8, 0x01,
                0x09,
        ).map { it.toByte() }.toByteArray()
        val program = ApfV6Generator(etherIpv4UdpPacket, APF_VERSION_6, ramSize, clampSize)
                .addAllocate(etherIpv4UdpPacket.size)
                .addDataCopy(3, etherIpv4UdpPacket.size) // arg1=src, arg2=len
                .addTransmitL4(
                        ETH_HLEN, // ipOfs,
                        ETH_HLEN + IPV4_HLEN + 6, // csumOfs
                        ETH_HLEN + IPV4_HLEN - 8, // csumStart
                        IPPROTO_UDP, // partialCsum
                        true // isUdp
                )
                .generate()
        assertPass(APF_VERSION_6, program, testPacket)
        val txBuf = ByteBuffer.wrap(ApfJniUtils.getTransmittedPacket())
        Struct.parse(EthernetHeader::class.java, txBuf)
        val ipv4Hdr = Struct.parse(Ipv4Header::class.java, txBuf)
        val udpHdr = Struct.parse(UdpHeader::class.java, txBuf)
        assertEquals(0x9535.toShort(), ipv4Hdr.checksum)
        assertEquals(0xa73d.toShort(), udpHdr.checksum)
    }

    @Test
    fun testDnsQuestionMatch() {
        // needles = { A, B.LOCAL }
        val needlesMatch = intArrayOf(
                0x01, 'A'.code,
                0x00,
                0x01, 'B'.code,
                0x05, 'L'.code, 'O'.code, 'C'.code, 'A'.code, 'L'.code,
                0x00,
                0x00
        ).map { it.toByte() }.toByteArray()
        val udpPayload = intArrayOf(
                0x00, 0x00, 0x00, 0x00, // tid = 0x00, flags = 0x00,
                0x00, 0x02, // qdcount = 2
                0x00, 0x00, // ancount = 0
                0x00, 0x00, // nscount = 0
                0x00, 0x00, // arcount = 0
                0x01, 'a'.code,
                0x01, 'b'.code,
                0x05, 'l'.code, 'o'.code, 'c'.code, 'a'.code, 'l'.code,
                0x00, // qname1 = a.b.local
                0x00, 0x01, 0x00, 0x01, // type = A, class = 0x0001
                0xc0, 0x0e, // qname2 = b.local (name compression)
                0x00, 0x01, 0x00, 0x01 // type = A, class = 0x0001
        ).map { it.toByte() }.toByteArray()

        var program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                .addLoadImmediate(R0, 0)
                .addJumpIfPktAtR0ContainDnsQ(needlesMatch, 0x01, DROP_LABEL) // arg2=qtype
                .addPass()
                .generate()
        assertDrop(APF_VERSION_6, program, udpPayload)

        program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                .addLoadImmediate(R0, 0)
                .addJumpIfPktAtR0ContainDnsQSafe(needlesMatch, 0x01, DROP_LABEL)
                .addPass()
                .generate()
        assertDrop(APF_VERSION_6, program, udpPayload)

        program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                .addLoadImmediate(R0, 0)
                .addJumpIfPktAtR0DoesNotContainDnsQ(needlesMatch, 0x01, DROP_LABEL) // arg2=qtype
                .addPass()
                .generate()
        assertPass(APF_VERSION_6, program, udpPayload)

        program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                .addLoadImmediate(R0, 0)
                .addJumpIfPktAtR0DoesNotContainDnsQSafe(needlesMatch, 0x01, DROP_LABEL) // arg2=qtype
                .addPass()
                .generate()
        assertPass(APF_VERSION_6, program, udpPayload)

        val badUdpPayload = intArrayOf(
                0x00, 0x00, 0x00, 0x00, // tid = 0x00, flags = 0x00,
                0x00, 0x02, // qdcount = 2
                0x00, 0x00, // ancount = 0
                0x00, 0x00, // nscount = 0
                0x00, 0x00, // arcount = 0
                0x01, 'a'.code,
                0x01, 'b'.code,
                0x05, 'l'.code, 'o'.code, 'c'.code, 'a'.code, 'l'.code,
                0x00, // qname1 = a.b.local
                0x00, 0x01, 0x00, 0x01, // type = A, class = 0x0001
                0xc0, 0x1b, // corrupted pointer cause infinite loop
                0x00, 0x01, 0x00, 0x01 // type = A, class = 0x0001
        ).map { it.toByte() }.toByteArray()

        program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                .addLoadImmediate(R0, 0)
                .addJumpIfPktAtR0ContainDnsQ(needlesMatch, 0x01, DROP_LABEL) // arg2=qtype
                .addPass()
                .generate()
        verifyProgramRun(APF_VERSION_6, program, badUdpPayload, CORRUPT_DNS_PACKET, result = DROP)

        program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                .addLoadImmediate(R0, 0)
                .addJumpIfPktAtR0ContainDnsQSafe(needlesMatch, 0x01, DROP_LABEL) // arg2=qtype
                .addPass()
                .generate()
        verifyProgramRun(APF_VERSION_6, program, badUdpPayload, CORRUPT_DNS_PACKET, result = PASS)
    }

    @Test
    fun testDnsAnswerMatch() {
        // needles = { A, B.LOCAL }
        val needlesMatch = intArrayOf(
                0x01, 'A'.code,
                0x00,
                0x01, 'B'.code,
                0x05, 'L'.code, 'O'.code, 'C'.code, 'A'.code, 'L'.code,
                0x00,
                0x00
        ).map { it.toByte() }.toByteArray()

        val udpPayload = intArrayOf(
                0x00, 0x00, 0x84, 0x00, // tid = 0x00, flags = 0x8400,
                0x00, 0x00, // qdcount = 0
                0x00, 0x02, // ancount = 2
                0x00, 0x00, // nscount = 0
                0x00, 0x00, // arcount = 0
                0x01, 'a'.code,
                0x01, 'b'.code,
                0x05, 'l'.code, 'o'.code, 'c'.code, 'a'.code, 'l'.code,
                0x00, // name1 = a.b.local
                0x00, 0x01, 0x80, 0x01, // type = A, class = 0x8001
                0x00, 0x00, 0x00, 0x78, // ttl = 120
                0x00, 0x04, 0xc0, 0xa8, 0x01, 0x09, // rdlengh = 4, rdata = 192.168.1.9
                0xc0, 0x0e, // name2 = b.local (name compression)
                0x00, 0x01, 0x80, 0x01, // type = A, class = 0x8001
                0x00, 0x00, 0x00, 0x78, // ttl = 120
                0x00, 0x04, 0xc0, 0xa8, 0x01, 0x09 // rdlengh = 4, rdata = 192.168.1.9
        ).map { it.toByte() }.toByteArray()

        var program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                .addLoadImmediate(R0, 0)
                .addJumpIfPktAtR0ContainDnsA(needlesMatch, DROP_LABEL)
                .addPass()
                .generate()
        assertDrop(APF_VERSION_6, program, udpPayload)

        program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                .addLoadImmediate(R0, 0)
                .addJumpIfPktAtR0ContainDnsASafe(needlesMatch, DROP_LABEL)
                .addPass()
                .generate()
        assertDrop(APF_VERSION_6, program, udpPayload)

        program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                .addLoadImmediate(R0, 0)
                .addJumpIfPktAtR0DoesNotContainDnsA(needlesMatch, DROP_LABEL)
                .addPass()
                .generate()
        assertPass(APF_VERSION_6, program, udpPayload)

        program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                .addLoadImmediate(R0, 0)
                .addJumpIfPktAtR0DoesNotContainDnsASafe(needlesMatch, DROP_LABEL)
                .addPass()
                .generate()
        assertPass(APF_VERSION_6, program, udpPayload)

        val badUdpPayload = intArrayOf(
                0x00, 0x00, 0x84, 0x00, // tid = 0x00, flags = 0x8400,
                0x00, 0x00, // qdcount = 0
                0x00, 0x02, // ancount = 2
                0x00, 0x00, // nscount = 0
                0x00, 0x00, // arcount = 0
                0x01, 'a'.code,
                0x01, 'b'.code,
                0x05, 'l'.code, 'o'.code, 'c'.code, 'a'.code, 'l'.code,
                0x00, // name1 = a.b.local
                0x00, 0x01, 0x80, 0x01, // type = A, class = 0x8001
                0x00, 0x00, 0x00, 0x78, // ttl = 120
                0x00, 0x04, 0xc0, 0xa8, 0x01, 0x09, // rdlengh = 4, rdata = 192.168.1.9
                0xc0, 0x25, // corrupted pointer cause infinite loop
                0x00, 0x01, 0x80, 0x01, // type = A, class = 0x8001
                0x00, 0x00, 0x00, 0x78, // ttl = 120
                0x00, 0x04, 0xc0, 0xa8, 0x01, 0x09 // rdlengh = 4, rdata = 192.168.1.9
        ).map { it.toByte() }.toByteArray()

        program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                .addLoadImmediate(R0, 0)
                .addJumpIfPktAtR0ContainDnsA(needlesMatch, DROP_LABEL)
                .addPass()
                .generate()
        verifyProgramRun(APF_VERSION_6, program, badUdpPayload, CORRUPT_DNS_PACKET, result = DROP)

        program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                .addLoadImmediate(R0, 0)
                .addJumpIfPktAtR0ContainDnsASafe(needlesMatch, DROP_LABEL)
                .addPass()
                .generate()
        verifyProgramRun(APF_VERSION_6, program, badUdpPayload, CORRUPT_DNS_PACKET, result = PASS)
    }

    @Test
    fun testGetCounterValue() {
        val counterBytes = intArrayOf(0xff, 0, 0, 0, 0x78, 0x56, 0x34, 0x12)
                .map { it.toByte() }.toByteArray()
        assertEquals(0xff, ApfCounterTracker.getCounterValue(counterBytes, Counter.TOTAL_PACKETS))
    }

    @Test
    fun testJumpMultipleByteSequencesMatch() {
        var program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                .addLoadImmediate(R0, 0)
                .addJumpIfBytesAtR0EqualsAnyOf(
                        listOf(byteArrayOf(1, 2, 3), byteArrayOf(6, 5, 4)),
                        DROP_LABEL
                )
                .addPass()
                .generate()
        assertDrop(APF_VERSION_6, program, testPacket)

        program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                .addLoadImmediate(R0, 2)
                .addJumpIfBytesAtR0EqualsAnyOf(
                        listOf(byteArrayOf(1, 2, 3), byteArrayOf(6, 5, 4)),
                        DROP_LABEL
                )
                .addPass()
                .generate()
        assertPass(APF_VERSION_6, program, testPacket)

        program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                .addLoadImmediate(R0, 1)
                .addJumpIfBytesAtR0EqualNoneOf(
                        listOf(byteArrayOf(1, 2, 3), byteArrayOf(6, 5, 4)),
                        DROP_LABEL
                )
                .addPass()
                .generate()
        assertDrop(APF_VERSION_6, program, testPacket)

        program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                .addLoadImmediate(R0, 0)
                .addJumpIfBytesAtR0EqualNoneOf(
                        listOf(byteArrayOf(1, 2, 3), byteArrayOf(6, 5, 4)),
                        DROP_LABEL
                )
                .addPass()
                .generate()
        assertPass(APF_VERSION_6, program, testPacket)
    }

    @Test
    fun testJumpOneOf() {
        var program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                .addLoadImmediate(R0, 255)
                .addJumpIfOneOf(R0, setOf(1, 2, 3, 128, 255), DROP_LABEL)
                .addPass()
                .generate()
        assertDrop(APF_VERSION_6, program, testPacket)

        program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                .addLoadImmediate(R0, 254)
                .addJumpIfOneOf(R0, setOf(1, 2, 3, 128, 255), DROP_LABEL)
                .addPass()
                .generate()
        assertPass(APF_VERSION_6, program, testPacket)

        program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                .addLoadImmediate(R0, 254)
                .addJumpIfNoneOf(R0, setOf(1, 2, 3, 128, 255), DROP_LABEL)
                .addPass()
                .generate()
        assertDrop(APF_VERSION_6, program, testPacket)

        program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                .addLoadImmediate(R0, 255)
                .addJumpIfNoneOf(R0, setOf(1, 2, 3, 128, 255), DROP_LABEL)
                .addPass()
                .generate()
        assertPass(APF_VERSION_6, program, testPacket)
    }

    @Test
    fun testDebugBuffer() {
        val program = ApfV6Generator(APF_VERSION_6, ramSize, clampSize)
                .addLoad8(R0, 255)
                .generate()
        val dataRegion = ByteArray(ramSize - program.size) { 0 }

        assertVerdict(APF_VERSION_6, PASS, program, testPacket, dataRegion)
        // offset 3 in the data region should contain if the interpreter is APFv6 mode or not
        assertEquals(1, dataRegion[3])
    }

    private fun encodeInstruction(opcode: Int, immLength: Int, register: Int): Byte {
        val immLengthEncoding = if (immLength == 4) 3 else immLength
        return opcode.shl(3).or(immLengthEncoding.shl(1)).or(register).toByte()
    }

    private fun ByteArray.skipDataAndDebug(): ByteArray {
        assertEquals(
                listOf(
                        encodeInstruction(14, 2, 1),
                        0,
                        0,
                        encodeInstruction(21, 1, 0),
                        48
                        // the actual exception buffer size is not checked here.
                ),
                this.take(5)
        )
        return this.drop(7).toByteArray()
    }
}
