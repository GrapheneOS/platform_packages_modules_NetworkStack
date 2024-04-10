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

import static android.net.apf.BaseApfGenerator.Register.R0;
import static android.net.apf.BaseApfGenerator.Register.R1;

import com.android.internal.annotations.VisibleForTesting;

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

    private final String mCountAndDropLabel;
    private final String mCountAndPassLabel;

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
    public ApfV4Generator(int version) throws IllegalInstructionException {
        // make sure mVersion is not greater than 4 when using this class
        super(version >= 4 ? 4 : version);
        mCountAndDropLabel = version >= 4 ? COUNT_AND_DROP_LABEL : DROP_LABEL;
        mCountAndPassLabel = version >= 4 ? COUNT_AND_PASS_LABEL : PASS_LABEL;
    }

    @Override
    void addArithR1(Opcodes opcode) {
        append(new Instruction(opcode, R1));
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
        return maybeAddLoadR1CounterOffset(counter).addJump(mCountAndPassLabel);
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
        return maybeAddLoadR1CounterOffset(counter).addJump(mCountAndDropLabel);
    }

    @Override
    public ApfV4Generator addCountAndDropIfR0Equals(long val, ApfCounterTracker.Counter cnt) {
        checkDropCounterRange(cnt);
        return maybeAddLoadR1CounterOffset(cnt).addJumpIfR0Equals(val, mCountAndDropLabel);
    }

    @Override
    public ApfV4Generator addCountAndPassIfR0Equals(long val, ApfCounterTracker.Counter cnt) {
        checkPassCounterRange(cnt);
        return maybeAddLoadR1CounterOffset(cnt).addJumpIfR0Equals(val, mCountAndPassLabel);
    }

    @Override
    public ApfV4Generator addCountAndDropIfR0NotEquals(long val, ApfCounterTracker.Counter cnt) {
        checkDropCounterRange(cnt);
        return maybeAddLoadR1CounterOffset(cnt).addJumpIfR0NotEquals(val, mCountAndDropLabel);
    }

    @Override
    public ApfV4Generator addCountAndPassIfR0NotEquals(long val, ApfCounterTracker.Counter cnt) {
        checkPassCounterRange(cnt);
        return maybeAddLoadR1CounterOffset(cnt).addJumpIfR0NotEquals(val, mCountAndPassLabel);
    }

    @Override
    public ApfV4Generator addCountAndDropIfR0LessThan(long val, ApfCounterTracker.Counter cnt) {
        checkDropCounterRange(cnt);
        if (val <= 0) {
            throw new IllegalArgumentException("val must > 0, current val: " + val);
        }
        return maybeAddLoadR1CounterOffset(cnt).addJumpIfR0LessThan(val, mCountAndDropLabel);
    }

    @Override
    public ApfV4Generator addCountAndPassIfR0LessThan(long val, ApfCounterTracker.Counter cnt) {
        checkPassCounterRange(cnt);
        if (val <= 0) {
            throw new IllegalArgumentException("val must > 0, current val: " + val);
        }
        return maybeAddLoadR1CounterOffset(cnt).addJumpIfR0LessThan(val, mCountAndPassLabel);
    }

    @Override
    public ApfV4Generator addCountAndDropIfBytesAtR0NotEqual(byte[] bytes,
            ApfCounterTracker.Counter cnt) throws IllegalInstructionException {
        checkDropCounterRange(cnt);
        return maybeAddLoadR1CounterOffset(cnt).addJumpIfBytesAtR0NotEqual(bytes,
                mCountAndDropLabel);
    }

    @Override
    public ApfV4Generator addCountAndPassIfBytesAtR0NotEqual(byte[] bytes,
            ApfCounterTracker.Counter cnt) throws IllegalInstructionException {
        checkPassCounterRange(cnt);
        return maybeAddLoadR1CounterOffset(cnt).addJumpIfBytesAtR0NotEqual(bytes,
                mCountAndPassLabel);
    }

    /**
     * Add an instruction to the end of the program to load 32 bits from the data memory into
     * {@code register}. The source address is computed by adding the signed immediate
     * {@code offset} to the other register.
     * Requires APF v4 or greater.
     */
    public final ApfV4Generator addLoadData(Register dst, int ofs)
            throws IllegalInstructionException {
        requireApfVersion(APF_VERSION_4);
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
        requireApfVersion(APF_VERSION_4);
        return append(new Instruction(Opcodes.STDW, src).addSigned(ofs));
    }

    @Override
    public ApfV4Generator addLoadCounter(Register register, ApfCounterTracker.Counter counter)
            throws IllegalInstructionException {
        if (mVersion < 4) return self();
        return maybeAddLoadCounterOffset(register.other(), counter).addLoadData(register, 0);
    }

    @Override
    public ApfV4Generator addStoreCounter(ApfCounterTracker.Counter counter, Register register)
            throws IllegalInstructionException {
        if (mVersion < 4) return self();
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
        if (mVersion < 4) return self();
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

    private ApfV4Generator maybeAddLoadCounterOffset(Register reg, ApfCounterTracker.Counter cnt) {
        if (mVersion < 4) return self();
        return addLoadImmediate(reg, cnt.offset());
    }

    private ApfV4Generator maybeAddLoadR1CounterOffset(ApfCounterTracker.Counter counter) {
        return maybeAddLoadCounterOffset(R1, counter);
    }
}
