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

import static android.net.apf.BaseApfGenerator.Register.R1;

import com.android.internal.annotations.VisibleForTesting;

import java.util.Objects;

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
     * Creates an ApfV6Generator instance which is able to emit instructions for the specified
     * {@code version} of the APF interpreter. Throws {@code IllegalInstructionException} if
     * the requested version is unsupported.
     */
    @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public ApfV6Generator() throws IllegalInstructionException {
        super();
        addData(new byte[0]);
    }

    /**
     * Creates an ApfV6Generator instance which is able to emit instructions for the specified
     * {@code version} of the APF interpreter. Throws {@code IllegalInstructionException} if
     * the requested version is unsupported.
     * Initializes the data region with {@code bytes}.
     */
    @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public ApfV6Generator(byte[] bytes) throws IllegalInstructionException {
        super();
        Objects.requireNonNull(bytes);
        addData(bytes);
    }
}
