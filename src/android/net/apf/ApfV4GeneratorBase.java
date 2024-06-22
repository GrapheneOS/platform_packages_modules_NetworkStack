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

package android.net.apf;

import static android.net.apf.BaseApfGenerator.Rbit.Rbit0;
import static android.net.apf.BaseApfGenerator.Register.R0;
import static android.net.apf.BaseApfGenerator.Register.R1;


import android.annotation.NonNull;

import com.android.internal.annotations.VisibleForTesting;

import java.util.List;
import java.util.Set;

/**
 * APF assembler/generator.  A tool for generating an APF program.
 *
 * Call add*() functions to add instructions to the program, then call
 * {@link BaseApfGenerator#generate} to get the APF bytecode for the program.
 * <p>
 * Choose between these approaches for your instruction helper methods: If the functionality must
 * be identical across APF versions, make it a final method within the base class. If it needs
 * version-specific adjustments, use an abstract method in the base class with final
 * implementations in generator instances.
 *
 * @param <Type> the generator class
 *
 * @hide
 */
public abstract class ApfV4GeneratorBase<Type extends ApfV4GeneratorBase<Type>> extends
        BaseApfGenerator {

    /**
     * Creates an ApfV4GeneratorBase instance which is able to emit instructions for the specified
     * {@code version} of the APF interpreter. Throws {@code IllegalInstructionException} if
     * the requested version is unsupported.
     */
    @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public ApfV4GeneratorBase(int version, int ramSize, int clampSize,
            boolean disableCounterRangeCheck) throws IllegalInstructionException {
        super(version, ramSize, clampSize, disableCounterRangeCheck);
        requireApfVersion(APF_VERSION_2);
    }

    final Type self() {
        return (Type) this;
    }

    final Type append(Instruction instruction) {
        if (mGenerated) {
            throw new IllegalStateException("Program already generated");
        }
        mInstructions.add(instruction);
        return self();
    }

    /**
     * Define a label at the current end of the program. Jumps can jump to this label. Labels are
     * their own separate instructions, though with size 0. This facilitates having labels with
     * no corresponding code to execute, for example a label at the end of a program. For example
     * an {@link ApfV4GeneratorBase} might be passed to a function that adds a filter like so:
     * <pre>
     *   load from packet
     *   compare loaded data, jump if not equal to "next_filter"
     *   load from packet
     *   compare loaded data, jump if not equal to "next_filter"
     *   jump to drop label
     *   define "next_filter" here
     * </pre>
     * In this case "next_filter" may not have any generated code associated with it.
     */
    public final Type defineLabel(String name) throws IllegalInstructionException {
        return append(new Instruction(Opcodes.LABEL).setLabel(name));
    }

    /**
     * Add an unconditional jump instruction to the end of the program.
     */
    public final Type addJump(String target) {
        return append(new Instruction(Opcodes.JMP).setTargetLabel(target));
    }

    /**
     * Add an unconditional jump instruction to the next instruction - ie. a no-op.
     */
    public final Type addNop() {
        return append(new Instruction(Opcodes.JMP).addUnsigned(0));
    }

    /**
     * Add an instruction to the end of the program to load the byte at offset {@code offset}
     * bytes from the beginning of the packet into {@code register}.
     */
    public final Type addLoad8(Register r, int ofs) {
        return append(new Instruction(Opcodes.LDB, r).addPacketOffset(ofs));
    }

    /**
     * Add an instruction to the end of the program to load 16-bits at offset {@code offset}
     * bytes from the beginning of the packet into {@code register}.
     */
    public final Type addLoad16(Register r, int ofs) {
        return append(new Instruction(Opcodes.LDH, r).addPacketOffset(ofs));
    }

    /**
     * Add an instruction to the end of the program to load 32-bits at offset {@code offset}
     * bytes from the beginning of the packet into {@code register}.
     */
    public final Type addLoad32(Register r, int ofs) {
        return append(new Instruction(Opcodes.LDW, r).addPacketOffset(ofs));
    }

    /**
     * Add an instruction to the end of the program to load a byte from the packet into
     * {@code register}. The offset of the loaded byte from the beginning of the packet is
     * the sum of {@code offset} and the value in register R1.
     */
    public final Type addLoad8Indexed(Register r, int ofs) {
        return append(new Instruction(Opcodes.LDBX, r).addTwosCompUnsigned(ofs));
    }

    /**
     * Add an instruction to the end of the program to load 16-bits from the packet into
     * {@code register}. The offset of the loaded 16-bits from the beginning of the packet is
     * the sum of {@code offset} and the value in register R1.
     */
    public final Type addLoad16Indexed(Register r, int ofs) {
        return append(new Instruction(Opcodes.LDHX, r).addTwosCompUnsigned(ofs));
    }

    /**
     * Add an instruction to the end of the program to load 32-bits from the packet into
     * {@code register}. The offset of the loaded 32-bits from the beginning of the packet is
     * the sum of {@code offset} and the value in register R1.
     */
    public final Type addLoad32Indexed(Register r, int ofs) {
        return append(new Instruction(Opcodes.LDWX, r).addTwosCompUnsigned(ofs));
    }

    /**
     * Add an instruction to the end of the program to add {@code value} to register R0.
     */
    public final Type addAdd(long val) {
        if (val == 0) return self();  // nop, as APFv6 would '+= R1'
        return append(new Instruction(Opcodes.ADD).addTwosCompUnsigned(val));
    }

    /**
     * Add an instruction to the end of the program to subtract {@code value} from register R0.
     */
    public final Type addSub(long val) {
        return addAdd(-val);  // note: addSub(4 billion) isn't valid, as addAdd(-4 billion) isn't
    }

    /**
     * Add an instruction to the end of the program to multiply register R0 by {@code value}.
     */
    public final Type addMul(long val) {
        if (val == 0) return addLoadImmediate(R0, 0);  // equivalent, as APFv6 would '*= R1'
        return append(new Instruction(Opcodes.MUL).addUnsigned(val));
    }

    /**
     * Add an instruction to the end of the program to divide register R0 by {@code value}.
     */
    public final Type addDiv(long val) {
        if (val == 0) return addPass();  // equivalent, as APFv6 would '/= R1'
        return append(new Instruction(Opcodes.DIV).addUnsigned(val));
    }

    /**
     * Add an instruction to the end of the program to logically and register R0 with {@code value}.
     */
    public final Type addAnd(long val) {
        if (val == 0) return addLoadImmediate(R0, 0);  // equivalent, as APFv6 would '+= R1'
        return append(new Instruction(Opcodes.AND).addTwosCompUnsigned(val));
    }

    /**
     * Add an instruction to the end of the program to logically or register R0 with {@code value}.
     */
    public final Type addOr(long val) {
        if (val == 0) return self();  // nop, as APFv6 would '|= R1'
        return append(new Instruction(Opcodes.OR).addTwosCompUnsigned(val));
    }

    /**
     * Add an instruction to the end of the program to shift left register R0 by {@code value} bits.
     */
    // TODO: consider whether should change the argument type to byte
    public final Type addLeftShift(int val) {
        if (val == 0) return self();  // nop, as APFv6 would '<<= R1'
        return append(new Instruction(Opcodes.SH).addSigned(val));
    }

    /**
     * Add an instruction to the end of the program to shift right register R0 by {@code value}
     * bits.
     */
    // TODO: consider whether should change the argument type to byte
    public final Type addRightShift(int val) {
        return addLeftShift(-val);
    }

    // R0 op= R1, where op should be one of Opcodes.{ADD,MUL,DIV,AND,OR,SH}
    abstract void addR0ArithR1(Opcodes opcode);

    /**
     * Add an instruction to the end of the program to add register R1 to register R0.
     */
    public final Type addAddR1ToR0() {
        addR0ArithR1(Opcodes.ADD);  // R0 += R1
        return self();
    }

    /**
     * Add an instruction to the end of the program to multiply register R0 by register R1.
     */
    public final Type addMulR0ByR1() {
        addR0ArithR1(Opcodes.MUL);  // R0 *= R1
        return self();
    }

    /**
     * Add an instruction to the end of the program to divide register R0 by register R1.
     */
    public final Type addDivR0ByR1() {
        addR0ArithR1(Opcodes.DIV);  // R0 /= R1
        return self();
    }

    /**
     * Add an instruction to the end of the program to logically and register R0 with register R1
     * and store the result back into register R0.
     */
    public final Type addAndR0WithR1() {
        addR0ArithR1(Opcodes.AND);  // R0 &= R1
        return self();
    }

    /**
     * Add an instruction to the end of the program to logically or register R0 with register R1
     * and store the result back into register R0.
     */
    public final Type addOrR0WithR1() {
        addR0ArithR1(Opcodes.OR);  // R0 |= R1
        return self();
    }

    /**
     * Add an instruction to the end of the program to shift register R0 left by the value in
     * register R1.
     */
    public final Type addLeftShiftR0ByR1() {
        addR0ArithR1(Opcodes.SH);  // R0 <<= R1
        return self();
    }

    /**
     * Add an instruction to the end of the program to move {@code value} into {@code register}.
     */
    public final Type addLoadImmediate(Register register, int value) {
        return append(new Instruction(Opcodes.LI, register).addSigned(value));
    }

    /**
     * Add an instruction to the end of the program to jump to {@code target} if register R0's
     * value equals {@code value}.
     */
    public final Type addJumpIfR0Equals(long val, String tgt) {
        return append(new Instruction(Opcodes.JEQ).addTwosCompUnsigned(val).setTargetLabel(tgt));
    }

    /**
     * Add instructions to the end of the program to increase counter and drop packet if R0 equals
     * {@code val}
     * WARNING: may modify R1
     */
    public abstract Type addCountAndDropIfR0Equals(long val, ApfCounterTracker.Counter cnt)
            throws IllegalInstructionException;

    /**
     * Add instructions to the end of the program to increase counter and pass packet if R0 equals
     * {@code val}
     * WARNING: may modify R1
     */
    public abstract Type addCountAndPassIfR0Equals(long val, ApfCounterTracker.Counter cnt)
            throws IllegalInstructionException;

    /**
     * Add an instruction to the end of the program to jump to {@code target} if register R0's
     * value does not equal {@code value}.
     */
    public final Type addJumpIfR0NotEquals(long val, String tgt) {
        return append(new Instruction(Opcodes.JNE).addTwosCompUnsigned(val).setTargetLabel(tgt));
    }

    /**
     * Add instructions to the end of the program to increase counter and drop packet if R0 not
     * equals {@code val}
     * WARNING: may modify R1
     */
    public abstract Type addCountAndDropIfR0NotEquals(long val, ApfCounterTracker.Counter cnt)
            throws IllegalInstructionException;

    /**
     * Add instructions to the end of the program to increase counter and pass packet if R0 not
     * equals {@code val}
     * WARNING: may modify R1
     */
    public abstract Type addCountAndPassIfR0NotEquals(long val, ApfCounterTracker.Counter cnt)
            throws IllegalInstructionException;

    /**
     * Add an instruction to the end of the program to jump to {@code target} if register R0's
     * value is greater than {@code value}.
     */
    public final Type addJumpIfR0GreaterThan(long val, String tgt) {
        return append(new Instruction(Opcodes.JGT).addUnsigned(val).setTargetLabel(tgt));
    }

    /**
     * Add instructions to the end of the program to increase counter and drop packet if R0 greater
     * than {@code val}
     * WARNING: may modify R1
     */
    public abstract Type addCountAndDropIfR0GreaterThan(long val, ApfCounterTracker.Counter cnt)
            throws IllegalInstructionException;

    /**
     * Add instructions to the end of the program to increase counter and pass packet if R0 greater
     * than {@code val}
     * WARNING: may modify R1
     */
    public abstract Type addCountAndPassIfR0GreaterThan(long val, ApfCounterTracker.Counter cnt)
            throws IllegalInstructionException;

    /**
     * Add an instruction to the end of the program to jump to {@code target} if register R0's
     * value is less than {@code value}.
     */
    public final Type addJumpIfR0LessThan(long val, String tgt) {
        return append(new Instruction(Opcodes.JLT).addUnsigned(val).setTargetLabel(tgt));
    }

    /**
     * Add instructions to the end of the program to increase counter and drop packet if R0 less
     * than {@code val}
     * WARNING: may modify R1
     */
    public abstract Type addCountAndDropIfR0LessThan(long val, ApfCounterTracker.Counter cnt)
            throws IllegalInstructionException;

    /**
     * Add instructions to the end of the program to increase counter and pass packet if R0 less
     * than {@code val}
     * WARNING: may modify R1
     */
    public abstract Type addCountAndPassIfR0LessThan(long val, ApfCounterTracker.Counter cnt)
            throws IllegalInstructionException;

    /**
     * Add an instruction to the end of the program to jump to {@code target} if register R0's
     * value has any bits set that are also set in {@code value}.
     */
    public final Type addJumpIfR0AnyBitsSet(long val, String tgt) {
        return append(new Instruction(Opcodes.JSET).addTwosCompUnsigned(val).setTargetLabel(tgt));
    }

    /**
     * Add an instruction to the end of the program to count and drop packet if register R0's
     * value has any bits set that are also set in {@code value}.
     * WARNING: may modify R1
     */
    public abstract Type addCountAndDropIfR0AnyBitsSet(long val, ApfCounterTracker.Counter cnt)
            throws IllegalInstructionException;

    /**
     * Add an instruction to the end of the program to count and pass packet if register R0's
     * value has any bits set that are also set in {@code value}.
     * WARNING: may modify R1
     */
    public abstract Type addCountAndPassIfR0AnyBitsSet(long val, ApfCounterTracker.Counter cnt)
            throws IllegalInstructionException;

    /**
     * Add an instruction to the end of the program to count and drop if the bytes of the
     * packet at an offset specified by register R0 match any of the elements in {@code bytesList}.
     * WARNING: may modify R1
     */
    public abstract Type addCountAndDropIfBytesAtR0EqualsAnyOf(@NonNull List<byte[]> bytesList,
            ApfCounterTracker.Counter cnt) throws IllegalInstructionException;

    /**
     * Add an instruction to the end of the program to count and pass if the bytes of the
     * packet at an offset specified by register R0 match any of the elements in {@code bytesList}.
     * WARNING: may modify R1
     */
    public abstract Type addCountAndPassIfBytesAtR0EqualsAnyOf(@NonNull List<byte[]> bytesList,
            ApfCounterTracker.Counter cnt) throws IllegalInstructionException;

    /**
     * Add an instruction to the end of the program to count and drop if the bytes of the
     * packet at an offset specified by register R0 match none the elements in {@code bytesList}.
     * WARNING: may modify R1
     */
    public abstract Type addCountAndDropIfBytesAtR0EqualsNoneOf(@NonNull List<byte[]> bytesList,
            ApfCounterTracker.Counter cnt) throws IllegalInstructionException;

    /**
     * Add an instruction to the end of the program to count and pass if the bytes of the
     * packet at an offset specified by register R0 match none of the elements in {@code bytesList}.
     * WARNING: may modify R1
     */
    public abstract Type addCountAndPassIfBytesAtR0EqualsNoneOf(@NonNull List<byte[]> bytesList,
            ApfCounterTracker.Counter cnt) throws IllegalInstructionException;

    /**
     * Add an instruction to the end of the program to jump to {@code target} if register R0's
     * value equals register R1's value.
     */
    public final Type addJumpIfR0EqualsR1(String tgt) {
        return append(new Instruction(Opcodes.JEQ, R1).setTargetLabel(tgt));
    }

    /**
     * Add an instruction to the end of the program to jump to {@code target} if register R0's
     * value does not equal register R1's value.
     */
    public final Type addJumpIfR0NotEqualsR1(String tgt) {
        return append(new Instruction(Opcodes.JNE, R1).setTargetLabel(tgt));
    }

    /**
     * Add an instruction to the end of the program to jump to {@code target} if register R0's
     * value is greater than register R1's value.
     */
    public final Type addJumpIfR0GreaterThanR1(String tgt) {
        return append(new Instruction(Opcodes.JGT, R1).setTargetLabel(tgt));
    }

    /**
     * Add an instruction to the end of the program to jump to {@code target} if register R0's
     * value is less than register R1's value.
     */
    public final Type addJumpIfR0LessThanR1(String target) {
        return append(new Instruction(Opcodes.JLT, R1).setTargetLabel(target));
    }

    /**
     * Add an instruction to the end of the program to jump to {@code target} if register R0's
     * value has any bits set that are also set in R1's value.
     */
    public final Type addJumpIfR0AnyBitsSetR1(String tgt) {
        return append(new Instruction(Opcodes.JSET, R1).setTargetLabel(tgt));
    }

    /**
     * Add an instruction to the end of the program to jump to {@code tgt} if the bytes of the
     * packet at an offset specified by register0 don't match {@code bytes}.
     * R=0 means check for not equal.
     */
    public final Type addJumpIfBytesAtR0NotEqual(@NonNull byte[] bytes, String tgt) {
        validateBytes(bytes);
        return append(new Instruction(Opcodes.JBSMATCH).addUnsigned(
                bytes.length).setTargetLabel(tgt).setBytesImm(bytes));
    }

    /**
     * Add instructions to the end of the program to increase counter and drop packet if the
     * bytes of the packet at an offset specified by register0 don't match {@code bytes}.
     * WARNING: may modify R1
     */
    public abstract Type addCountAndDropIfBytesAtR0NotEqual(byte[] bytes,
            ApfCounterTracker.Counter cnt) throws IllegalInstructionException;

    /**
     * Add instructions to the end of the program to increase counter and pass packet if the
     * bytes of the packet at an offset specified by register0 don't match {@code bytes}.
     * WARNING: may modify R1
     */
    public abstract Type addCountAndPassIfBytesAtR0NotEqual(byte[] bytes,
            ApfCounterTracker.Counter cnt) throws IllegalInstructionException;

    /**
     * Add instructions to the end of the program to increase counter and drop packet if the
     * bytes of the packet at an offset specified by register0 match {@code bytes}.
     * WARNING: may modify R1
     */
    public final Type addCountAndDropIfBytesAtR0Equal(byte[] bytes,
            ApfCounterTracker.Counter cnt) throws IllegalInstructionException {
        final String tgt = getUniqueLabel();
        return addJumpIfBytesAtR0NotEqual(bytes, tgt).addCountAndDrop(cnt).defineLabel(tgt);
    }


    /**
     * Add instructions to the end of the program to increase counter and pass packet if the
     * bytes of the packet at an offset specified by register0 match {@code bytes}.
     * WARNING: may modify R1
     */
    public final Type addCountAndPassIfBytesAtR0Equal(byte[] bytes,
            ApfCounterTracker.Counter cnt) throws IllegalInstructionException {
        final String tgt = getUniqueLabel();
        return addJumpIfBytesAtR0NotEqual(bytes, tgt).addCountAndPass(cnt).defineLabel(tgt);
    }

    /**
     * Add instructions to the end of the program to increase counter and pass packet if the
     * value in register0 is one of {@code values}.
     * WARNING: may modify R1
     */
    public abstract Type addCountAndPassIfR0IsOneOf(@NonNull Set<Long> values,
            ApfCounterTracker.Counter cnt) throws IllegalInstructionException;

    /**
     * Add instructions to the end of the program to increase counter and drop packet if the
     * value in register0 is one of {@code values}.
     * WARNING: may modify R1
     */
    public abstract Type addCountAndDropIfR0IsOneOf(@NonNull Set<Long> values,
            ApfCounterTracker.Counter cnt) throws IllegalInstructionException;

    /**
     * Add instructions to the end of the program to increase counter and pass packet if the
     * value in register0 is none of {@code values}.
     * WARNING: may modify R1
     */
    public abstract Type addCountAndPassIfR0IsNoneOf(@NonNull Set<Long> values,
            ApfCounterTracker.Counter cnt) throws IllegalInstructionException;

    /**
     * Add instructions to the end of the program to increase counter and drop packet if the
     * value in register0 is none of {@code values}.
     * WARNING: may modify R1
     */
    public abstract Type addCountAndDropIfR0IsNoneOf(@NonNull Set<Long> values,
            ApfCounterTracker.Counter cnt) throws IllegalInstructionException;

    /**
     * Add an instruction to the end of the program to load memory slot {@code slot} into
     * {@code register}.
     */
    public final Type addLoadFromMemory(Register r, MemorySlot slot)
            throws IllegalInstructionException {
        return append(new BaseApfGenerator.Instruction(ExtendedOpcodes.LDM, slot.value, r));
    }

    /**
     * Add an instruction to the end of the program to store {@code register} into memory slot
     * {@code slot}.
     */
    public final Type addStoreToMemory(MemorySlot slot, Register r)
            throws IllegalInstructionException {
        return append(new Instruction(ExtendedOpcodes.STM, slot.value, r));
    }

    /**
     * Add an instruction to the end of the program to logically not {@code register}.
     */
    public final Type addNot(Register r) {
        return append(new Instruction(ExtendedOpcodes.NOT, r));
    }

    /**
     * Add an instruction to the end of the program to negate {@code register}.
     */
    public final Type addNeg(Register r) {
        return append(new Instruction(ExtendedOpcodes.NEG, r));
    }

    /**
     * Add an instruction to swap the values in register R0 and register R1.
     */
    public final Type addSwap() {
        return append(new Instruction(ExtendedOpcodes.SWAP));
    }

    /**
     * Add an instruction to the end of the program to move the value into
     * {@code register} from the other register.
     */
    public final Type addMove(Register r) {
        return append(new Instruction(ExtendedOpcodes.MOVE, r));
    }

    /**
     * Add an instruction to the end of the program to let the program immediately return PASS.
     */
    public final Type addPass() {
        // PASS requires using Rbit0 because it shares opcode with DROP
        return append(new Instruction(Opcodes.PASSDROP, Rbit0));
    }

    /**
     * Abstract method for adding instructions to increment the counter and return PASS.
     */
    public abstract Type addCountAndPass(ApfCounterTracker.Counter counter);

    /**
     * Abstract method for adding instructions to increment the counter and return DROP.
     */
    public abstract Type addCountAndDrop(ApfCounterTracker.Counter counter);

    /**
     * Add an instruction to the end of the program to load 32 bits from the data memory into
     * {@code register}.
     * In APFv2, it is a noop.
     * WARNING: clobbers the *other* register.
     */
    public abstract Type addLoadCounter(Register register, ApfCounterTracker.Counter counter)
            throws IllegalInstructionException;

    /**
     * Add an instruction to the end of the program to store 32 bits from {@code register} into the
     * data memory.
     * In APFv2, it is a noop.
     * WARNING: clobbers the *other* register.
     */
    public abstract Type addStoreCounter(ApfCounterTracker.Counter counter, Register register)
            throws IllegalInstructionException;

    /**
     * Add an instruction to the end of the program to increment counter value by {@code val).
     * In APFv2, it is a noop.
     * WARNING: clobbers both registers.
     */
    public final Type addIncrementCounter(ApfCounterTracker.Counter counter, int val)
            throws IllegalInstructionException {
        if (mVersion <= 2) return self();
        return addLoadCounter(R0, counter).addAdd(val).addStoreCounter(counter, R0);
    }

    /**
     * Add an instruction to the end of the program to increment counter value by one.
     * In APFv2, it is a noop.
     * WARNING: clobbers both registers.
     */
    public final Type addIncrementCounter(ApfCounterTracker.Counter counter)
            throws IllegalInstructionException {
        return addIncrementCounter(counter, 1);
    }

    /**
     * The abstract method to generate count trampoline instructions.
     * @return
     * @throws IllegalInstructionException
     */
    public abstract Type addCountTrampoline() throws IllegalInstructionException;
}

