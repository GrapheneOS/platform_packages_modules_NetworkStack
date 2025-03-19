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

import android.annotation.NonNull;

import com.android.internal.annotations.VisibleForTesting;

import java.util.List;
import java.util.Set;

/**
 * APFv6 assembler/generator. A tool for generating an APFv6 program.
 *
 * @hide
 */
public final class ApfV6Generator extends ApfV6GeneratorBase<ApfV6Generator> {
    /**
     * Returns true if we support the specified {@code version}, otherwise false.
     */
    public static boolean supportsVersion(int version) {
        return version >= APF_VERSION_6;
    }

    /**
     * Creates an ApfV6Generator instance which emits instructions for APFv6.
     */
    public ApfV6Generator(int version, int ramSize, int clampSize)
            throws IllegalInstructionException {
        this(new byte[0], version, ramSize, clampSize);
    }

    /**
     * Creates an ApfV6Generator instance which emits instructions APFv6.
     * Initializes the data region with {@code bytes}.
     */
    @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public ApfV6Generator(byte[] bytes, int version, int ramSize, int clampSize)
            throws IllegalInstructionException {
        super(bytes, version, ramSize, clampSize);
    }

    @Override
    public ApfV6Generator addCountAndDropIfR0Equals(long val, ApfCounterTracker.Counter cnt)
            throws IllegalInstructionException {
        final short tgt = getUniqueLabel();
        return addJumpIfR0NotEquals(val, tgt).addCountAndDrop(cnt).defineLabel(tgt);
    }

    @Override
    public ApfV6Generator addCountAndPassIfR0Equals(long val, ApfCounterTracker.Counter cnt)
            throws IllegalInstructionException {
        final short tgt = getUniqueLabel();
        return addJumpIfR0NotEquals(val, tgt).addCountAndPass(cnt).defineLabel(tgt);
    }

    @Override
    public ApfV6Generator addCountAndDropIfR0NotEquals(long val, ApfCounterTracker.Counter cnt)
            throws IllegalInstructionException {
        final short tgt = getUniqueLabel();
        return addJumpIfR0Equals(val, tgt).addCountAndDrop(cnt).defineLabel(tgt);
    }

    @Override
    public ApfV6Generator addCountAndPassIfR0NotEquals(long val, ApfCounterTracker.Counter cnt)
            throws IllegalInstructionException {
        final short tgt = getUniqueLabel();
        return addJumpIfR0Equals(val, tgt).addCountAndPass(cnt).defineLabel(tgt);
    }

    @Override
    public ApfV6Generator addCountAndDropIfR0AnyBitsSet(long val, ApfCounterTracker.Counter cnt)
            throws IllegalInstructionException {
        final short countAndDropLabel = getUniqueLabel();
        final short skipLabel = getUniqueLabel();
        return addJumpIfR0AnyBitsSet(val, countAndDropLabel)
                .addJump(skipLabel)
                .defineLabel(countAndDropLabel)
                .addCountAndDrop(cnt)
                .defineLabel(skipLabel);
    }

    @Override
    public ApfV6Generator addCountAndPassIfR0AnyBitsSet(long val, ApfCounterTracker.Counter cnt)
            throws IllegalInstructionException {
        final short countAndPassLabel = getUniqueLabel();
        final short skipLabel = getUniqueLabel();
        return addJumpIfR0AnyBitsSet(val, countAndPassLabel)
                .addJump(skipLabel)
                .defineLabel(countAndPassLabel)
                .addCountAndPass(cnt)
                .defineLabel(skipLabel);
    }

    @Override
    public ApfV6Generator addCountAndDropIfR0LessThan(long val, ApfCounterTracker.Counter cnt)
            throws IllegalInstructionException {
        if (val <= 0) {
            throw new IllegalArgumentException("val must > 0, current val: " + val);
        }
        final short tgt = getUniqueLabel();
        return addJumpIfR0GreaterThan(val - 1, tgt).addCountAndDrop(cnt).defineLabel(tgt);
    }

    @Override
    public ApfV6Generator addCountAndPassIfR0LessThan(long val, ApfCounterTracker.Counter cnt)
            throws IllegalInstructionException {
        if (val <= 0) {
            throw new IllegalArgumentException("val must > 0, current val: " + val);
        }
        final short tgt = getUniqueLabel();
        return addJumpIfR0GreaterThan(val - 1, tgt).addCountAndPass(cnt).defineLabel(tgt);
    }

    @Override
    public ApfV6Generator addCountAndDropIfR0GreaterThan(long val, ApfCounterTracker.Counter cnt)
            throws IllegalInstructionException {
        if (val < 0 || val >= 4294967295L) {
            throw new IllegalArgumentException("val must >= 0 and < 2^32-1, current val: " + val);
        }
        final short tgt = getUniqueLabel();
        return addJumpIfR0LessThan(val + 1, tgt).addCountAndDrop(cnt).defineLabel(tgt);
    }

    @Override
    public ApfV6Generator addCountAndPassIfR0GreaterThan(long val, ApfCounterTracker.Counter cnt)
            throws IllegalInstructionException {
        if (val < 0 || val >= 4294967295L) {
            throw new IllegalArgumentException("val must >= 0 and < 2^32-1, current val: " + val);
        }
        final short tgt = getUniqueLabel();
        return addJumpIfR0LessThan(val + 1, tgt).addCountAndPass(cnt).defineLabel(tgt);
    }

    @Override
    public ApfV6Generator addCountAndDropIfBytesAtR0NotEqual(byte[] bytes,
            ApfCounterTracker.Counter cnt) throws IllegalInstructionException {
        final short tgt = getUniqueLabel();
        return addJumpIfBytesAtR0Equal(bytes, tgt).addCountAndDrop(cnt).defineLabel(tgt);
    }

    @Override
    public ApfV6Generator addCountAndPassIfBytesAtR0NotEqual(byte[] bytes,
            ApfCounterTracker.Counter cnt) throws IllegalInstructionException {
        final short tgt = getUniqueLabel();
        return addJumpIfBytesAtR0Equal(bytes, tgt).addCountAndPass(cnt).defineLabel(tgt);
    }

    @Override
    public ApfV6Generator addCountAndPassIfR0IsOneOf(@NonNull Set<Long> values,
            ApfCounterTracker.Counter cnt) throws IllegalInstructionException {
        if (values.isEmpty()) {
            throw new IllegalArgumentException("values cannot be empty");
        }
        if (values.size() == 1) {
            return addCountAndPassIfR0Equals(values.iterator().next(), cnt);
        }
        final short tgt = getUniqueLabel();
        return addJumpIfNoneOf(R0, values, tgt).addCountAndPass(cnt).defineLabel(tgt);
    }

    @Override
    public ApfV6Generator addCountAndDropIfR0IsOneOf(@NonNull Set<Long> values,
            ApfCounterTracker.Counter cnt) throws IllegalInstructionException {
        if (values.isEmpty()) {
            throw new IllegalArgumentException("values cannot be empty");
        }
        if (values.size() == 1) {
            return addCountAndDropIfR0Equals(values.iterator().next(), cnt);
        }
        final short tgt = getUniqueLabel();
        return addJumpIfNoneOf(R0, values, tgt).addCountAndDrop(cnt).defineLabel(tgt);
    }

    @Override
    public ApfV6Generator addCountAndPassIfR0IsNoneOf(@NonNull Set<Long> values,
            ApfCounterTracker.Counter cnt) throws IllegalInstructionException {
        if (values.isEmpty()) {
            throw new IllegalArgumentException("values cannot be empty");
        }
        if (values.size() == 1) {
            return addCountAndPassIfR0NotEquals(values.iterator().next(), cnt);
        }
        final short tgt = getUniqueLabel();
        return addJumpIfOneOf(R0, values, tgt).addCountAndPass(cnt).defineLabel(tgt);
    }

    @Override
    public ApfV6Generator addCountAndDropIfBytesAtR0EqualsAnyOf(@NonNull List<byte[]> bytesList,
            ApfCounterTracker.Counter cnt)
            throws IllegalInstructionException {
        final short tgt = getUniqueLabel();
        return addJumpIfBytesAtR0EqualsNoneOf(bytesList, tgt).addCountAndDrop(cnt).defineLabel(tgt);
    }

    @Override
    public ApfV6Generator addCountAndPassIfBytesAtR0EqualsAnyOf(@NonNull List<byte[]> bytesList,
            ApfCounterTracker.Counter cnt)
            throws IllegalInstructionException {
        final short tgt = getUniqueLabel();
        return addJumpIfBytesAtR0EqualsNoneOf(bytesList, tgt).addCountAndPass(cnt).defineLabel(tgt);
    }

    @Override
    public ApfV6Generator addCountAndDropIfBytesAtR0EqualsNoneOf(@NonNull List<byte[]> bytesList,
            ApfCounterTracker.Counter cnt)
            throws IllegalInstructionException {
        final short tgt = getUniqueLabel();
        return addJumpIfBytesAtR0EqualsAnyOf(bytesList, tgt).addCountAndDrop(cnt).defineLabel(tgt);
    }

    @Override
    public ApfV6Generator addCountAndPassIfBytesAtR0EqualsNoneOf(@NonNull List<byte[]> bytesList,
            ApfCounterTracker.Counter cnt)
            throws IllegalInstructionException {
        final short tgt = getUniqueLabel();
        return addJumpIfBytesAtR0EqualsAnyOf(bytesList, tgt).addCountAndPass(cnt).defineLabel(tgt);
    }

    @Override
    public ApfV6Generator addCountAndDropIfR0IsNoneOf(@NonNull Set<Long> values,
            ApfCounterTracker.Counter cnt) throws IllegalInstructionException {
        if (values.isEmpty()) {
            throw new IllegalArgumentException("values cannot be empty");
        }
        if (values.size() == 1) {
            return addCountAndDropIfR0NotEquals(values.iterator().next(), cnt);
        }
        final short tgt = getUniqueLabel();
        return addJumpIfOneOf(R0, values, tgt).addCountAndDrop(cnt).defineLabel(tgt);
    }

    @Override
    public ApfV6Generator addJumpIfPktAtR0ContainDnsQ(byte[] qnames, int[] qtypes, short tgt) {
        for (int qtype : qtypes) {
            addJumpIfPktAtR0ContainDnsQ(qnames, qtype, tgt);
        }
        return self();
    }
}
