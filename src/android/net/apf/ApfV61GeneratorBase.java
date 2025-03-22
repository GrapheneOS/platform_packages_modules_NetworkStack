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
package android.net.apf;

import static android.net.apf.BaseApfGenerator.Rbit.Rbit0;
import static android.net.apf.BaseApfGenerator.Rbit.Rbit1;
import static android.net.apf.BaseApfGenerator.Register.R0;

import androidx.annotation.NonNull;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * The abstract class for APFv6.1 assembler/generator.
 *
 * @param <Type> the generator class
 *
 * @hide
 */
public abstract class ApfV61GeneratorBase<Type extends ApfV61GeneratorBase<Type>> extends
            ApfV6GeneratorBase<Type> {

    /**
     * Creates an ApfV61GeneratorBase instance.
     */
    public ApfV61GeneratorBase(byte[] bytes, int version, int ramSize, int clampSize)
            throws IllegalInstructionException {
        super(bytes, version, ramSize, clampSize);
    }

    @Override
    public final Type addCountAndDropIfR0Equals(long val, ApfCounterTracker.Counter cnt) {
        return addJumpIfR0Equals(val, cnt.getJumpDropLabel());
    }

    @Override
    public final Type addCountAndPassIfR0Equals(long val, ApfCounterTracker.Counter cnt) {
        return addJumpIfR0Equals(val, cnt.getJumpPassLabel());
    }

    @Override
    public final Type addCountAndDropIfR0NotEquals(long val, ApfCounterTracker.Counter cnt) {
        return addJumpIfR0NotEquals(val, cnt.getJumpDropLabel());
    }

    @Override
    public final Type addCountAndPassIfR0NotEquals(long val, ApfCounterTracker.Counter cnt) {
        return addJumpIfR0NotEquals(val, cnt.getJumpPassLabel());
    }

    @Override
    public Type addCountAndDropIfR0AnyBitsSet(long val, ApfCounterTracker.Counter cnt) {
        return addJumpIfR0AnyBitsSet(val, cnt.getJumpDropLabel());
    }

    @Override
    public Type addCountAndPassIfR0AnyBitsSet(long val, ApfCounterTracker.Counter cnt) {
        return addJumpIfR0AnyBitsSet(val, cnt.getJumpPassLabel());
    }

    @Override
    public final Type addCountAndDropIfR0LessThan(long val, ApfCounterTracker.Counter cnt) {
        if (val <= 0) {
            throw new IllegalArgumentException("val must > 0, current val: " + val);
        }
        return addJumpIfR0LessThan(val, cnt.getJumpDropLabel());
    }

    @Override
    public final Type addCountAndPassIfR0LessThan(long val, ApfCounterTracker.Counter cnt) {
        if (val <= 0) {
            throw new IllegalArgumentException("val must > 0, current val: " + val);
        }
        return addJumpIfR0LessThan(val, cnt.getJumpPassLabel());
    }

    @Override
    public Type addCountAndDropIfR0GreaterThan(long val, ApfCounterTracker.Counter cnt) {
        if (val < 0 || val >= 4294967295L) {
            throw new IllegalArgumentException("val must >= 0 and < 2^32-1, current val: " + val);
        }
        return addJumpIfR0GreaterThan(val, cnt.getJumpDropLabel());
    }

    @Override
    public Type addCountAndPassIfR0GreaterThan(long val, ApfCounterTracker.Counter cnt) {
        if (val < 0 || val >= 4294967295L) {
            throw new IllegalArgumentException("val must >= 0 and < 2^32-1, current val: " + val);
        }
        return addJumpIfR0GreaterThan(val, cnt.getJumpPassLabel());
    }

    @Override
    public final Type addCountAndDropIfBytesAtR0NotEqual(byte[] bytes,
            ApfCounterTracker.Counter cnt) {
        return addJumpIfBytesAtR0NotEqual(bytes, cnt.getJumpDropLabel());
    }

    @Override
    public final Type addCountAndPassIfBytesAtR0NotEqual(byte[] bytes,
            ApfCounterTracker.Counter cnt) {
        return addJumpIfBytesAtR0NotEqual(bytes, cnt.getJumpPassLabel());
    }

    @Override
    public Type addCountAndPassIfR0IsOneOf(@NonNull Set<Long> values,
            ApfCounterTracker.Counter cnt) {
        if (values.isEmpty()) {
            throw new IllegalArgumentException("values cannot be empty");
        }
        if (values.size() == 1) {
            return addCountAndPassIfR0Equals(values.iterator().next(), cnt);
        }
        return addJumpIfOneOf(R0, values, cnt.getJumpPassLabel());
    }

    @Override
    public Type addCountAndDropIfR0IsOneOf(@NonNull Set<Long> values,
            ApfCounterTracker.Counter cnt) {
        if (values.isEmpty()) {
            throw new IllegalArgumentException("values cannot be empty");
        }
        if (values.size() == 1) {
            return addCountAndDropIfR0Equals(values.iterator().next(), cnt);
        }
        return addJumpIfOneOf(R0, values, cnt.getJumpDropLabel());
    }

    @Override
    public Type addCountAndPassIfR0IsNoneOf(@NonNull Set<Long> values,
            ApfCounterTracker.Counter cnt) {
        if (values.isEmpty()) {
            throw new IllegalArgumentException("values cannot be empty");
        }
        if (values.size() == 1) {
            return addCountAndPassIfR0NotEquals(values.iterator().next(), cnt);
        }
        return addJumpIfNoneOf(R0, values, cnt.getJumpPassLabel());
    }

    @Override
    public Type addCountAndDropIfBytesAtR0EqualsAnyOf(@NonNull List<byte[]> bytesList,
            ApfCounterTracker.Counter cnt) {
        return addJumpIfBytesAtR0EqualsAnyOf(bytesList, cnt.getJumpDropLabel());
    }

    @Override
    public Type addCountAndPassIfBytesAtR0EqualsAnyOf(@NonNull List<byte[]> bytesList,
            ApfCounterTracker.Counter cnt) {
        return addJumpIfBytesAtR0EqualsAnyOf(bytesList, cnt.getJumpPassLabel());
    }

    @Override
    public Type addCountAndDropIfBytesAtR0EqualsNoneOf(@NonNull List<byte[]> bytesList,
            ApfCounterTracker.Counter cnt) {
        return addJumpIfBytesAtR0EqualsNoneOf(bytesList, cnt.getJumpDropLabel());
    }

    @Override
    public Type addCountAndPassIfBytesAtR0EqualsNoneOf(@NonNull List<byte[]> bytesList,
            ApfCounterTracker.Counter cnt) {
        return addJumpIfBytesAtR0EqualsNoneOf(bytesList, cnt.getJumpPassLabel());
    }

    @Override
    public Type addCountAndDropIfR0IsNoneOf(@NonNull Set<Long> values,
            ApfCounterTracker.Counter cnt) {
        if (values.isEmpty()) {
            throw new IllegalArgumentException("values cannot be empty");
        }
        if (values.size() == 1) {
            return addCountAndDropIfR0NotEquals(values.iterator().next(), cnt);
        }
        return addJumpIfNoneOf(R0, values, cnt.getJumpDropLabel());
    }

    @Override
    public final Type addJumpIfPktAtR0ContainDnsQ(byte[] qnames, int[] qtypes, short tgt) {
        for (int i = 0; i < qtypes.length; i += 2) {
            if (i == qtypes.length - 1) {
                addJumpIfPktAtR0ContainDnsQ(qnames, qtypes[i], tgt);
            } else {
                addJumpIfPktAtR0ContainDnsQ2(qnames, qtypes[i], qtypes[i + 1], tgt);
            }
        }
        return self();
    }

    @Override
    public Type addAllocate(int size) {
        final int imm = (size > 266) ? (size - 266 + 7) / 8 : 0;
        return append(new Instruction(Opcodes.ALLOC_XMIT, Rbit1).addUnsigned(imm));
    }

    @Override
    public Type addTransmitWithoutChecksum() {
        return append(new Instruction(Opcodes.ALLOC_XMIT, Rbit0));
    }

    @Override
    protected boolean handleOptimizedTransmit(int ipOfs, int csumOfs, int csumStart,
                                              int partialCsum, boolean isUdp) {
        if (ipOfs != 14) return false;
        int v = -1;
        if ( isUdp && csumStart == 26 && csumOfs == 40) v = 0;  // ether/ipv4/udp
        if (!isUdp && csumStart == 26 && csumOfs == 44) v = 1;  // ether/ipv4/tcp
        if (!isUdp && csumStart == 34 && csumOfs == 36) v = 2;  // ether/ipv4/icmp
        if (!isUdp && csumStart == 38 && csumOfs == 40) v = 3;  // ether/ipv4/routeralert/icmp
        if ( isUdp && csumStart == 22 && csumOfs == 60) v = 4;  // ether/ipv6/udp
        if (!isUdp && csumStart == 22 && csumOfs == 64) v = 5;  // ether/ipv6/tcp
        if (!isUdp && csumStart == 22 && csumOfs == 56) v = 6;  // ether/ipv6/icmp
        if (!isUdp && csumStart == 22 && csumOfs == 64) v = 7;  // ether/ipv6/routeralert/icmp
        if (v < 0) return false;
        v |= partialCsum << 3;
        append(new Instruction(Opcodes.ALLOC_XMIT, Rbit0).addUnsigned(v));
        return true;
    }

    private List<byte[]> addJumpIfBytesAtOffsetEqualsHelper(int offset,
            @NonNull List<byte[]> bytesList, short tgt, boolean jumpOnMatch)
            throws IllegalInstructionException {
        final List<byte[]> deduplicatedList =
                bytesList.size() == 1 ? bytesList : validateDeduplicateBytesList(bytesList);
        if (offset < 0 || offset > 255) {
            return deduplicatedList;
        }
        final int count = deduplicatedList.size();
        final int compareLength = deduplicatedList.get(0).length;
        if (compareLength > 16) {
            return deduplicatedList;
        }
        final List<byte[]> failbackList = new ArrayList<>();
        final List<Integer> ptrs = new ArrayList<>();
        for (int i = 0; i < count; ++i) {
            final byte[] bytes = deduplicatedList.get(i);
            int relativeOffset = mInstructions.get(0).findMatchInDataBytes(bytes, 0, bytes.length);
            if (relativeOffset < 0 || relativeOffset % 2 == 1 || relativeOffset > 510) {
                failbackList.add(bytes);
                continue;
            }
            ptrs.add(relativeOffset / 2);
        }
        final Rbit rbit = jumpOnMatch ? Rbit1 : Rbit0;
        int totalPtrs = ptrs.size();
        for (int i = 0; i < totalPtrs; i += 16) {
            final int currentCount = Math.min(totalPtrs - i, 16);
            final Instruction instruction = new Instruction(Opcodes.JBSPTRMATCH, rbit)
                    .addU8(offset)
                    .addU8((currentCount - 1) * 16 + (compareLength - 1))
                    .setTargetLabel(tgt);
            for (int j = 0; j < currentCount; j++) {
                instruction.addU8(ptrs.get(i + j));
            }
            append(instruction);
        }
        return failbackList;
    }

    /**
     * Add an instruction to the end of the program to jump to {@code tgt} if the bytes of the
     * packet at an offset specified by {@code offset} match any of the elements in
     * {@code bytesList}.
     */
    public Type addJumpIfBytesAtOffsetEqualsAnyOf(int offset, @NonNull List<byte[]> bytesList,
            short tgt) throws IllegalInstructionException {
        final List<byte[]> failbackList = addJumpIfBytesAtOffsetEqualsHelper(offset, bytesList, tgt,
                true /* jumpOnMatch */);
        if (failbackList.isEmpty()) {
            return self();
        }
        return addLoadImmediate(R0, offset).addJumpIfBytesAtR0EqualsAnyOf(failbackList, tgt);
    }

    /**
     * Add an instruction to the end of the program to jump to {@code tgt} if the bytes of the
     * packet at an offset specified by {@code offset} match none of the elements in
     * {@code bytesList}.
     */
    public Type addJumpIfBytesAtOffsetEqualsNoneOf(int offset, @NonNull List<byte[]> bytesList,
            short tgt) throws IllegalInstructionException {
        final List<byte[]> failbackList = addJumpIfBytesAtOffsetEqualsHelper(offset, bytesList, tgt,
                false /* jumpOnMatch */);
        if (failbackList.isEmpty()) {
            return self();
        }
        return addLoadImmediate(R0, offset).addJumpIfBytesAtR0EqualsNoneOf(failbackList, tgt);
    }

    @Override
    public Type addCountAndDropIfBytesAtOffsetEqualsAnyOf(int offset, List<byte[]> bytesList,
            ApfCounterTracker.Counter cnt) throws IllegalInstructionException {
        return addJumpIfBytesAtOffsetEqualsAnyOf(offset, bytesList, cnt.getJumpDropLabel());
    }

    @Override
    public Type addCountAndPassIfBytesAtOffsetEqualsAnyOf(int offset, List<byte[]> bytesList,
            ApfCounterTracker.Counter cnt) throws IllegalInstructionException {
        return addJumpIfBytesAtOffsetEqualsAnyOf(offset, bytesList, cnt.getJumpPassLabel());
    }

    @Override
    public Type addCountAndDropIfBytesAtOffsetEqualsNoneOf(int offset, List<byte[]> bytesList,
            ApfCounterTracker.Counter cnt) throws IllegalInstructionException {
        return addJumpIfBytesAtOffsetEqualsNoneOf(offset, bytesList, cnt.getJumpDropLabel());
    }

    @Override
    public Type addCountAndPassIfBytesAtOffsetEqualsNoneOf(int offset, List<byte[]> bytesList,
            ApfCounterTracker.Counter cnt) throws IllegalInstructionException {
        return addJumpIfBytesAtOffsetEqualsNoneOf(offset, bytesList, cnt.getJumpPassLabel());
    }

    @Override
    public Type addCountAndPassIfBytesAtOffsetNotEqual(int offset, byte[] bytes,
            ApfCounterTracker.Counter cnt) throws IllegalInstructionException {
        return addJumpIfBytesAtOffsetEqualsNoneOf(offset, List.of(bytes), cnt.getJumpPassLabel());
    }

    @Override
    public Type addCountAndDropIfBytesAtOffsetNotEqual(int offset, byte[] bytes,
            ApfCounterTracker.Counter cnt) throws IllegalInstructionException {
        return addJumpIfBytesAtOffsetEqualsNoneOf(offset, List.of(bytes), cnt.getJumpDropLabel());
    }

    @Override
    public Type addCountAndPassIfBytesAtOffsetEqual(int offset, byte[] bytes,
            ApfCounterTracker.Counter cnt) throws IllegalInstructionException {
        return addJumpIfBytesAtOffsetEqualsAnyOf(offset, List.of(bytes), cnt.getJumpPassLabel());
    }

    @Override
    public Type addCountAndDropIfBytesAtOffsetEqual(int offset, byte[] bytes,
            ApfCounterTracker.Counter cnt) throws IllegalInstructionException {
        return addJumpIfBytesAtOffsetEqualsAnyOf(offset, List.of(bytes), cnt.getJumpDropLabel());
    }

    @Override
    public Type addJumpIfBytesAtOffsetNotEqual(int offset, @NonNull byte[] bytes, short tgt)
            throws IllegalInstructionException {
        return addJumpIfBytesAtOffsetEqualsNoneOf(offset, List.of(bytes), tgt);
    }

    /**
     * Appends a conditional jump instruction to the program: Jumps to {@code tgt} if the UDP
     * payload's DNS questions contain the QNAMEs specified in {@code qnames} and qtype
     * equals {@code qtype1} or {@code qtype2}. Examines the payload starting at the offset in R0.
     * Drops packets if packets are corrupted.
     */
    public final Type addJumpIfPktAtR0ContainDnsQ2(@android.annotation.NonNull byte[] qnames,
            int qtype1, int qtype2, short tgt) {
        validateNames(qnames);
        return append(new Instruction(ExtendedOpcodes.JDNSQMATCH2, Rbit1).setTargetLabel(tgt)
                .addU8(qtype1).addU8(qtype2).setBytesImm(qnames));
    }

    /**
     * Preload the content of the data region.
     */
    public Type addPreloadData(@NonNull byte[] data) throws IllegalInstructionException {
        mInstructions.get(0).maybeUpdateBytesImm(data, 0, data.length);
        return self();
    }
}
