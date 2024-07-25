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

import android.annotation.NonNull;
import android.annotation.Nullable;

import com.android.net.module.util.HexDump;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Represents a rule for offloading mDNS service.
 *
 * @hide
 */
public class MdnsOffloadRule {

    /**
     * The payload data to be sent in the mDNS offload reply.
     * If the payload is empty, the APF must let the query through so that host can respond.
     */
    @Nullable
    public final byte[] mOffloadPayload;

    @NonNull
    public final List<Matcher> mMatchers;

    /**
     * Construct an mDNS offload rule.
     */
    public MdnsOffloadRule(@NonNull List<Matcher> matchers, @Nullable byte[] offloadPayload) {
        mMatchers = matchers;
        mOffloadPayload = offloadPayload;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof MdnsOffloadRule that)) return false;
        return Arrays.equals(mOffloadPayload, that.mOffloadPayload)
                && Objects.equals(mMatchers, that.mMatchers);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(mMatchers);
        result = 31 * result + Arrays.hashCode(mOffloadPayload);
        return result;
    }

    @Override
    public String toString() {
        return "MdnsOffloadRule{" + "mOffloadPayload="
                + ((mOffloadPayload == null) ? "(null)" : HexDump.toHexString(mOffloadPayload))
                + ", mMatchers=" + mMatchers + '}';
    }

    /**
     * The matcher class.
     * <p>
     * A matcher encapsulates the following information:
     *   mQnames: The QNAME(s) (query names) to match in the mDNS query.
     *   mQtype: The QTYPE (query type) to match in the mDNS query.
     */
    public static class Matcher {
        /**
         * The QNAME(s) from the mDNS query that this rule matches.
         */
        public final byte[] mQnames;
        /**
         * The QTYPE from the mDNS query that this rule matches.
         */
        public final int mQtype;

        /**
         * Creates a new Matcher.
         */
        public Matcher(byte[] qnames, int qtype) {
            mQnames = qnames;
            mQtype = qtype;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof Matcher that)) return false;
            return mQtype == that.mQtype && Arrays.equals(mQnames, that.mQnames);
        }

        @Override
        public int hashCode() {
            int result = Objects.hash(mQtype);
            result = 31 * result + Arrays.hashCode(mQnames);
            return result;
        }

        @Override
        public String toString() {
            return "Matcher{" + "mQnames=" + HexDump.toHexString(mQnames) + ", mQtype="
                    + mQtype + '}';
        }
    }

}
