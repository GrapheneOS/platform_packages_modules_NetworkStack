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
    public final Type addCountAndDropIfR0Equals(long val, ApfCounterTracker.Counter cnt)
            throws IllegalInstructionException {
        final short tgt = getUniqueLabel();
        return addJumpIfR0NotEquals(val, tgt).addCountAndDrop(cnt).defineLabel(tgt);
    }

    @Override
    public final Type addCountAndPassIfR0Equals(long val, ApfCounterTracker.Counter cnt)
            throws IllegalInstructionException {
        final short tgt = getUniqueLabel();
        return addJumpIfR0NotEquals(val, tgt).addCountAndPass(cnt).defineLabel(tgt);
    }

    @Override
    public final Type addCountAndDropIfR0NotEquals(long val, ApfCounterTracker.Counter cnt)
            throws IllegalInstructionException {
        final short tgt = getUniqueLabel();
        return addJumpIfR0Equals(val, tgt).addCountAndDrop(cnt).defineLabel(tgt);
    }

    @Override
    public final Type addCountAndPassIfR0NotEquals(long val, ApfCounterTracker.Counter cnt)
            throws IllegalInstructionException {
        final short tgt = getUniqueLabel();
        return addJumpIfR0Equals(val, tgt).addCountAndPass(cnt).defineLabel(tgt);
    }

    @Override
    public Type addCountAndDropIfR0AnyBitsSet(long val, ApfCounterTracker.Counter cnt)
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
    public Type addCountAndPassIfR0AnyBitsSet(long val, ApfCounterTracker.Counter cnt)
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
    public final Type addCountAndDropIfR0LessThan(long val, ApfCounterTracker.Counter cnt)
            throws IllegalInstructionException {
        if (val <= 0) {
            throw new IllegalArgumentException("val must > 0, current val: " + val);
        }
        final short tgt = getUniqueLabel();
        return addJumpIfR0GreaterThan(val - 1, tgt).addCountAndDrop(cnt).defineLabel(tgt);
    }

    @Override
    public final Type addCountAndPassIfR0LessThan(long val, ApfCounterTracker.Counter cnt)
            throws IllegalInstructionException {
        if (val <= 0) {
            throw new IllegalArgumentException("val must > 0, current val: " + val);
        }
        final short tgt = getUniqueLabel();
        return addJumpIfR0GreaterThan(val - 1, tgt).addCountAndPass(cnt).defineLabel(tgt);
    }

    @Override
    public Type addCountAndDropIfR0GreaterThan(long val, ApfCounterTracker.Counter cnt)
            throws IllegalInstructionException {
        if (val < 0 || val >= 4294967295L) {
            throw new IllegalArgumentException("val must >= 0 and < 2^32-1, current val: " + val);
        }
        final short tgt = getUniqueLabel();
        return addJumpIfR0LessThan(val + 1, tgt).addCountAndDrop(cnt).defineLabel(tgt);
    }

    @Override
    public Type addCountAndPassIfR0GreaterThan(long val, ApfCounterTracker.Counter cnt)
            throws IllegalInstructionException {
        if (val < 0 || val >= 4294967295L) {
            throw new IllegalArgumentException("val must >= 0 and < 2^32-1, current val: " + val);
        }
        final short tgt = getUniqueLabel();
        return addJumpIfR0LessThan(val + 1, tgt).addCountAndPass(cnt).defineLabel(tgt);
    }

    @Override
    public final Type addCountAndDropIfBytesAtR0NotEqual(byte[] bytes,
            ApfCounterTracker.Counter cnt) throws IllegalInstructionException {
        final short tgt = getUniqueLabel();
        return addJumpIfBytesAtR0Equal(bytes, tgt).addCountAndDrop(cnt).defineLabel(tgt);
    }

    @Override
    public final Type addCountAndPassIfBytesAtR0NotEqual(byte[] bytes,
            ApfCounterTracker.Counter cnt) throws IllegalInstructionException {
        final short tgt = getUniqueLabel();
        return addJumpIfBytesAtR0Equal(bytes, tgt).addCountAndPass(cnt).defineLabel(tgt);
    }

    @Override
    public Type addCountAndPassIfR0IsOneOf(@NonNull Set<Long> values,
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
    public Type addCountAndDropIfR0IsOneOf(@NonNull Set<Long> values,
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
    public Type addCountAndPassIfR0IsNoneOf(@NonNull Set<Long> values,
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
    public Type addCountAndDropIfBytesAtR0EqualsAnyOf(@NonNull List<byte[]> bytesList,
            ApfCounterTracker.Counter cnt)
            throws IllegalInstructionException {
        final short tgt = getUniqueLabel();
        return addJumpIfBytesAtR0EqualNoneOf(bytesList, tgt).addCountAndDrop(cnt).defineLabel(tgt);
    }

    @Override
    public Type addCountAndPassIfBytesAtR0EqualsAnyOf(@NonNull List<byte[]> bytesList,
            ApfCounterTracker.Counter cnt)
            throws IllegalInstructionException {
        final short tgt = getUniqueLabel();
        return addJumpIfBytesAtR0EqualNoneOf(bytesList, tgt).addCountAndPass(cnt).defineLabel(tgt);
    }

    @Override
    public Type addCountAndDropIfBytesAtR0EqualsNoneOf(@NonNull List<byte[]> bytesList,
            ApfCounterTracker.Counter cnt)
            throws IllegalInstructionException {
        final short tgt = getUniqueLabel();
        return addJumpIfBytesAtR0EqualsAnyOf(bytesList, tgt).addCountAndDrop(cnt).defineLabel(tgt);
    }

    @Override
    public Type addCountAndPassIfBytesAtR0EqualsNoneOf(@NonNull List<byte[]> bytesList,
            ApfCounterTracker.Counter cnt)
            throws IllegalInstructionException {
        final short tgt = getUniqueLabel();
        return addJumpIfBytesAtR0EqualsAnyOf(bytesList, tgt).addCountAndPass(cnt).defineLabel(tgt);
    }

    @Override
    public Type addCountAndDropIfR0IsNoneOf(@NonNull Set<Long> values,
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
}
