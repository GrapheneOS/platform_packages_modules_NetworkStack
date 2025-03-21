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

import static android.net.apf.BaseApfGenerator.Rbit.Rbit1;
import static android.net.apf.BaseApfGenerator.Register.R0;

import androidx.annotation.NonNull;

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
}
