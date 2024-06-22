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

import static android.net.apf.BaseApfGenerator.Rbit.Rbit1;
import static android.net.apf.BaseApfGenerator.Register.R0;
import static android.net.apf.BaseApfGenerator.Register.R1;

import android.annotation.NonNull;

import com.android.internal.annotations.VisibleForTesting;

import java.util.List;
import java.util.Set;

/**
 * APFv4 assembler/generator. A tool for generating an APFv4 program.
 *
 * @hide
 */
public final class ApfV4Generator extends ApfV4GeneratorBase<ApfV4Generator> {

    /**
     * Jump to this label to terminate the program, increment the counter and indicate the packet
     * should be passed to the AP.
     */
    private static final String COUNT_AND_PASS_LABEL = "__COUNT_AND_PASS__";

    /**
     * Jump to this label to terminate the program, increment counter, and indicate the packet
     * should be dropped.
     */
    private static final String COUNT_AND_DROP_LABEL = "__COUNT_AND_DROP__";

    public final String mCountAndDropLabel;
    public final String mCountAndPassLabel;

    /**
     * Returns true if we support the specified {@code version}, otherwise false.
     */
    public static boolean supportsVersion(int version) {
        return version >= APF_VERSION_2;
    }

    /**
     * Creates an ApfV4Generator instance which is able to emit instructions for the specified
     * {@code version} of the APF interpreter. Throws {@code IllegalInstructionException} if
     * the requested version is unsupported.
     */
    @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public ApfV4Generator(int version, int ramSize, int clampSize, boolean disableCounterRangeCheck)
            throws IllegalInstructionException {
        // make sure mVersion is not greater than 4 when using this class
        super(version > 4 ? 4 : version, ramSize, clampSize, disableCounterRangeCheck);
        mCountAndDropLabel = version > 2 ? COUNT_AND_DROP_LABEL : DROP_LABEL;
        mCountAndPassLabel = version > 2 ? COUNT_AND_PASS_LABEL : PASS_LABEL;
    }

    /**
     * Creates an ApfV4Generator instance which is able to emit instructions for the specified
     * {@code version} of the APF interpreter. Throws {@code IllegalInstructionException} if
     * the requested version is unsupported.
     */
    public ApfV4Generator(int version, int ramSize, int clampSize)
            throws IllegalInstructionException {
        this(version, ramSize, clampSize, false);
    }

    @Override
    void addR0ArithR1(Opcodes opcode) {
        append(new Instruction(opcode, Rbit1));  // APFv2/4: R0 op= R1
    }

    /**
     * Generates instructions to prepare to increment the specified counter and jump to the
     * "__COUNT_AND_PASS__" label.
     * In APFv2, it will directly return PASS.
     *
     * @param counter The ApfCounterTracker.Counter to increment
     * @return Type the generator object
     */
    @Override
    public ApfV4Generator addCountAndPass(ApfCounterTracker.Counter counter) {
        checkPassCounterRange(counter);
        return maybeAddLoadCounterOffset(R1, counter).addJump(mCountAndPassLabel);
    }

    /**
     * Generates instructions to prepare to increment the specified counter and jump to the
     * "__COUNT_AND_DROP__" label.
     * In APFv2, it will directly return DROP.
     *
     * @param counter The ApfCounterTracker.Counter to increment
     * @return Type the generator object
     */
    @Override
    public ApfV4Generator addCountAndDrop(ApfCounterTracker.Counter counter) {
        checkDropCounterRange(counter);
        return maybeAddLoadCounterOffset(R1, counter).addJump(mCountAndDropLabel);
    }

    @Override
    public ApfV4Generator addCountAndDropIfR0Equals(long val, ApfCounterTracker.Counter cnt) {
        checkDropCounterRange(cnt);
        return maybeAddLoadCounterOffset(R1, cnt).addJumpIfR0Equals(val, mCountAndDropLabel);
    }

    @Override
    public ApfV4Generator addCountAndPassIfR0Equals(long val, ApfCounterTracker.Counter cnt) {
        checkPassCounterRange(cnt);
        return maybeAddLoadCounterOffset(R1, cnt).addJumpIfR0Equals(val, mCountAndPassLabel);
    }

    @Override
    public ApfV4Generator addCountAndDropIfR0NotEquals(long val, ApfCounterTracker.Counter cnt) {
        checkDropCounterRange(cnt);
        return maybeAddLoadCounterOffset(R1, cnt).addJumpIfR0NotEquals(val, mCountAndDropLabel);
    }

    @Override
    public ApfV4Generator addCountAndPassIfR0NotEquals(long val, ApfCounterTracker.Counter cnt) {
        checkPassCounterRange(cnt);
        return maybeAddLoadCounterOffset(R1, cnt).addJumpIfR0NotEquals(val, mCountAndPassLabel);
    }

    @Override
    public ApfV4Generator addCountAndDropIfR0AnyBitsSet(long val, ApfCounterTracker.Counter cnt) {
        checkDropCounterRange(cnt);
        return maybeAddLoadCounterOffset(R1, cnt).addJumpIfR0AnyBitsSet(val, mCountAndDropLabel);
    }

    @Override
    public ApfV4Generator addCountAndPassIfR0AnyBitsSet(long val, ApfCounterTracker.Counter cnt) {
        checkPassCounterRange(cnt);
        return maybeAddLoadCounterOffset(R1, cnt).addJumpIfR0AnyBitsSet(val, mCountAndPassLabel);
    }

    @Override
    public ApfV4Generator addCountAndDropIfR0LessThan(long val, ApfCounterTracker.Counter cnt) {
        checkDropCounterRange(cnt);
        if (val <= 0) {
            throw new IllegalArgumentException("val must > 0, current val: " + val);
        }
        return maybeAddLoadCounterOffset(R1, cnt).addJumpIfR0LessThan(val, mCountAndDropLabel);
    }

    @Override
    public ApfV4Generator addCountAndPassIfR0LessThan(long val, ApfCounterTracker.Counter cnt) {
        checkPassCounterRange(cnt);
        if (val <= 0) {
            throw new IllegalArgumentException("val must > 0, current val: " + val);
        }
        return maybeAddLoadCounterOffset(R1, cnt).addJumpIfR0LessThan(val, mCountAndPassLabel);
    }

    @Override
    public ApfV4Generator addCountAndDropIfR0GreaterThan(long val, ApfCounterTracker.Counter cnt)
            throws IllegalInstructionException {
        checkDropCounterRange(cnt);
        if (val < 0 || val >= 4294967295L) {
            throw new IllegalArgumentException("val must >= 0 and < 2^32-1, current val: " + val);
        }
        return maybeAddLoadCounterOffset(R1, cnt).addJumpIfR0GreaterThan(val, mCountAndDropLabel);
    }

    @Override
    public ApfV4Generator addCountAndPassIfR0GreaterThan(long val, ApfCounterTracker.Counter cnt)
            throws IllegalInstructionException {
        checkPassCounterRange(cnt);
        if (val < 0 || val >= 4294967295L) {
            throw new IllegalArgumentException("val must >= 0 and < 2^32-1, current val: " + val);
        }
        return maybeAddLoadCounterOffset(R1, cnt).addJumpIfR0GreaterThan(val, mCountAndPassLabel);
    }

    @Override
    public ApfV4Generator addCountAndDropIfBytesAtR0NotEqual(byte[] bytes,
            ApfCounterTracker.Counter cnt) throws IllegalInstructionException {
        checkDropCounterRange(cnt);
        return maybeAddLoadCounterOffset(R1, cnt).addJumpIfBytesAtR0NotEqual(bytes,
                mCountAndDropLabel);
    }

    @Override
    public ApfV4Generator addCountAndPassIfBytesAtR0NotEqual(byte[] bytes,
            ApfCounterTracker.Counter cnt) throws IllegalInstructionException {
        checkPassCounterRange(cnt);
        return maybeAddLoadCounterOffset(R1, cnt).addJumpIfBytesAtR0NotEqual(bytes,
                mCountAndPassLabel);
    }

    @Override
    public ApfV4Generator addCountAndPassIfR0IsOneOf(@NonNull Set<Long> values,
            ApfCounterTracker.Counter cnt) throws IllegalInstructionException {
        if (values.isEmpty()) {
            throw new IllegalArgumentException("values cannot be empty");
        }
        checkPassCounterRange(cnt);
        maybeAddLoadCounterOffset(R1, cnt);
        for (Long v : values) {
            addJumpIfR0Equals(v, mCountAndPassLabel);
        }
        return this;
    }

    @Override
    public ApfV4Generator addCountAndDropIfR0IsOneOf(@NonNull Set<Long> values,
            ApfCounterTracker.Counter cnt) throws IllegalInstructionException {
        if (values.isEmpty()) {
            throw new IllegalArgumentException("values cannot be empty");
        }
        checkDropCounterRange(cnt);
        maybeAddLoadCounterOffset(R1, cnt);
        for (Long v : values) {
            addJumpIfR0Equals(v, mCountAndDropLabel);
        }
        return this;
    }

    @Override
    public ApfV4Generator addCountAndPassIfR0IsNoneOf(@NonNull Set<Long> values,
            ApfCounterTracker.Counter cnt) throws IllegalInstructionException {
        if (values.isEmpty()) {
            throw new IllegalArgumentException("values cannot be empty");
        }
        String tgt = getUniqueLabel();
        for (Long v : values) {
            addJumpIfR0Equals(v, tgt);
        }
        addCountAndPass(cnt);
        defineLabel(tgt);
        return this;
    }

    @Override
    public ApfV4Generator addCountAndDropIfR0IsNoneOf(@NonNull Set<Long> values,
            ApfCounterTracker.Counter cnt) throws IllegalInstructionException {
        if (values.isEmpty()) {
            throw new IllegalArgumentException("values cannot be empty");
        }
        String tgt = getUniqueLabel();
        for (Long v : values) {
            addJumpIfR0Equals(v, tgt);
        }
        addCountAndDrop(cnt);
        defineLabel(tgt);
        return this;
    }

    private ApfV4Generator addCountAndDropOrPassByMatchingBytesAtR0(@NonNull List<byte[]> bytesList,
            ApfCounterTracker.Counter cnt, boolean matchAny, boolean drop)
            throws IllegalInstructionException {
        final List<byte[]> deduplicatedList = validateDeduplicateBytesList(bytesList);
        maybeAddLoadCounterOffset(R1, cnt);
        String matchLabel = getUniqueLabel();
        String allNoMatchLabel = getUniqueLabel();
        for (byte[] v : deduplicatedList) {
            String notMatchLabel = getUniqueLabel();
            addJumpIfBytesAtR0NotEqual(v, notMatchLabel);
            addJump(matchLabel);
            defineLabel(notMatchLabel);
        }
        if (matchAny) {
            addJump(allNoMatchLabel);
            defineLabel(matchLabel);
        }
        if (drop) {
            addCountAndDrop(cnt);
        } else {
            addCountAndPass(cnt);
        }
        if (matchAny) {
            defineLabel(allNoMatchLabel);
        } else {
            defineLabel(matchLabel);
        }
        return this;
    }

    @Override
    public ApfV4Generator addCountAndDropIfBytesAtR0EqualsAnyOf(@NonNull List<byte[]> bytesList,
            ApfCounterTracker.Counter cnt) throws IllegalInstructionException {
        return addCountAndDropOrPassByMatchingBytesAtR0(bytesList, cnt, true /* matchAny */,
                true /* drop */);
    }

    @Override
    public ApfV4Generator addCountAndPassIfBytesAtR0EqualsAnyOf(@NonNull List<byte[]> bytesList,
            ApfCounterTracker.Counter cnt) throws IllegalInstructionException {
        return addCountAndDropOrPassByMatchingBytesAtR0(bytesList, cnt, true /* matchAny */,
                false /* drop */);
    }

    @Override
    public ApfV4Generator addCountAndDropIfBytesAtR0EqualsNoneOf(@NonNull List<byte[]> bytesList,
            ApfCounterTracker.Counter cnt) throws IllegalInstructionException {
        return addCountAndDropOrPassByMatchingBytesAtR0(bytesList, cnt, false /* matchAny */,
                true /* drop */);
    }

    @Override
    public ApfV4Generator addCountAndPassIfBytesAtR0EqualsNoneOf(@NonNull List<byte[]> bytesList,
            ApfCounterTracker.Counter cnt) throws IllegalInstructionException {
        return addCountAndDropOrPassByMatchingBytesAtR0(bytesList, cnt, false /* matchAny */,
                false /* drop */);
    }

    /**
     * Add an instruction to the end of the program to load 32 bits from the data memory into
     * {@code register}. The source address is computed by adding the signed immediate
     * {@code offset} to the other register.
     * Requires APF v4 or greater.
     */
    public final ApfV4Generator addLoadData(Register dst, int ofs)
            throws IllegalInstructionException {
        requireApfVersion(3);
        return append(new Instruction(Opcodes.LDDW, dst).addSigned(ofs));
    }

    /**
     * Add an instruction to the end of the program to store 32 bits from {@code register} into the
     * data memory. The destination address is computed by adding the signed immediate
     * {@code offset} to the other register.
     * Requires APF v4 or greater.
     */
    public final ApfV4Generator addStoreData(Register src, int ofs)
            throws IllegalInstructionException {
        requireApfVersion(3);
        return append(new Instruction(Opcodes.STDW, src).addSigned(ofs));
    }

    @Override
    public ApfV4Generator addLoadCounter(Register register, ApfCounterTracker.Counter counter)
            throws IllegalInstructionException {
        if (mVersion <= 2) return self();
        return maybeAddLoadCounterOffset(register.other(), counter).addLoadData(register, 0);
    }

    @Override
    public ApfV4Generator addStoreCounter(ApfCounterTracker.Counter counter, Register register)
            throws IllegalInstructionException {
        if (mVersion <= 2) return self();
        return maybeAddLoadCounterOffset(register.other(), counter).addStoreData(register, 0);
    }

    /**
     * Append the count & (pass|drop) trampoline, which increments the counter at the data address
     * pointed to by R1, then jumps to the (pass|drop) label. This saves a few bytes over inserting
     * the entire sequence inline for every counter.
     * This instruction is necessary to be called at the end of any APFv4 program in order to make
     * counter incrementing logic work.
     * In APFv2, it is a noop.
     */
    @Override
    public ApfV4Generator addCountTrampoline() throws IllegalInstructionException {
        if (mVersion <= 2) return self();
        return defineLabel(COUNT_AND_PASS_LABEL)
                .addLoadData(R0, 0)  // R0 = *(R1 + 0)
                .addAdd(1)           // R0++
                .addStoreData(R0, 0) // *(R1 + 0) = R0
                .addJump(PASS_LABEL)
                .defineLabel(COUNT_AND_DROP_LABEL)
                .addLoadData(R0, 0)  // R0 = *(R1 + 0)
                .addAdd(1)           // R0++
                .addStoreData(R0, 0) // *(R1 + 0) = R0
                .addJump(DROP_LABEL);
    }

    /**
     * This function is no-op in APFv4
     */
    @Override
    void updateExceptionBufferSize(int programSize) { }

    private ApfV4Generator maybeAddLoadCounterOffset(Register reg, ApfCounterTracker.Counter cnt) {
        if (mVersion <= 2) return self();
        return addLoadImmediate(reg, cnt.offset());
    }
}
