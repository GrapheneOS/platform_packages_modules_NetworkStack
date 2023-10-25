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

import androidx.test.filters.SmallTest
import androidx.test.runner.AndroidJUnit4
import kotlin.test.assertContentEquals
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Tests for APFv6 specific instructions.
 */
@RunWith(AndroidJUnit4::class)
@SmallTest
class ApfV5Test {

    @Test
    fun testApfInstructionsEncoding() {
        var gen = ApfGenerator(MIN_APF_VERSION)
        gen.addAlloc(ApfGenerator.Register.R0)
        var program = gen.generate()
        assertContentEquals(byteArrayOf(encodeInstruction(21, 1, 0), 36), program)
        assertContentEquals(arrayOf("       0: alloc r0"), ApfJniUtils.disassembleApf(program))

        gen = ApfGenerator(MIN_APF_VERSION)
        gen.addTrans(ApfGenerator.Register.R1)
        program = gen.generate()
        assertContentEquals(byteArrayOf(encodeInstruction(21, 1, 1), 37), program)
        assertContentEquals(arrayOf("       0: trans r1"), ApfJniUtils.disassembleApf(program))

        gen = ApfGenerator(MIN_APF_VERSION)
        gen.addWrite(0x01, 1)
        gen.addWrite(0x0102, 2)
        gen.addWrite(0x01020304, 4)
        program = gen.generate()
        assertContentEquals(byteArrayOf(
                encodeInstruction(24, 1, 0), 0x01,
                encodeInstruction(24, 2, 0), 0x01, 0x02,
                encodeInstruction(24, 4, 0), 0x01, 0x02, 0x03, 0x04
        ), program)
        assertContentEquals(arrayOf(
                "       0: write 0x01",
                "       2: write 0x0102",
                "       5: write 0x01020304"), ApfJniUtils.disassembleApf(program))

        gen = ApfGenerator(MIN_APF_VERSION)
        gen.addWrite(ApfGenerator.Register.R0, 1)
        gen.addWrite(ApfGenerator.Register.R0, 2)
        gen.addWrite(ApfGenerator.Register.R0, 4)
        program = gen.generate()
        assertContentEquals(byteArrayOf(
                encodeInstruction(21, 1, 0), 38,
                encodeInstruction(21, 1, 0), 39,
                encodeInstruction(21, 1, 0), 40
        ), program)
        assertContentEquals(arrayOf(
                "       0: write r0, 1",
                "       2: write r0, 2",
                "       4: write r0, 4"), ApfJniUtils.disassembleApf(program))
    }

    private fun encodeInstruction(opcode: Int, immLength: Int, register: Int): Byte {
        val immLengthEncoding = if (immLength == 4) 3 else immLength
        return opcode.shl(3).or(immLengthEncoding.shl(1)).or(register).toByte()
    }

    companion object {
        private const val MIN_APF_VERSION = 5
    }
}
