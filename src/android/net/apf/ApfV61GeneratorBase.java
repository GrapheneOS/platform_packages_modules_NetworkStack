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
}
