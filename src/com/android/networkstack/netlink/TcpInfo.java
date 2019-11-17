/*
 * Copyright (C) 2019 The Android Open Source Project
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
package com.android.networkstack.netlink;

import android.util.Log;
import android.util.Range;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.android.internal.annotations.VisibleForTesting;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Objects;

/**
 * Class for tcp_info.
 *
 * Corresponds to {@code struct tcp_info} from bionic/libc/kernel/uapi/linux/tcp.h
 */
public class TcpInfo {
    public enum Field {
        STATE(Byte.BYTES),
        CASTATE(Byte.BYTES),
        RETRANSMITS(Byte.BYTES),
        PROBES(Byte.BYTES),
        BACKOFF(Byte.BYTES),
        OPTIONS(Byte.BYTES),
        WSCALE(Byte.BYTES),
        DELIVERY_RATE_APP_LIMITED(Byte.BYTES),
        RTO(Integer.BYTES),
        ATO(Integer.BYTES),
        SND_MSS(Integer.BYTES),
        RCV_MSS(Integer.BYTES),
        UNACKED(Integer.BYTES),
        SACKED(Integer.BYTES),
        LOST(Integer.BYTES),
        RETRANS(Integer.BYTES),
        FACKETS(Integer.BYTES),
        LAST_DATA_SENT(Integer.BYTES),
        LAST_ACK_SENT(Integer.BYTES),
        LAST_DATA_RECV(Integer.BYTES),
        LAST_ACK_RECV(Integer.BYTES),
        PMTU(Integer.BYTES),
        RCV_SSTHRESH(Integer.BYTES),
        RTT(Integer.BYTES),
        RTTVAR(Integer.BYTES),
        SND_SSTHRESH(Integer.BYTES),
        SND_CWND(Integer.BYTES),
        ADVMSS(Integer.BYTES),
        REORDERING(Integer.BYTES),
        RCV_RTT(Integer.BYTES),
        RCV_SPACE(Integer.BYTES),
        TOTAL_RETRANS(Integer.BYTES),
        PACING_RATE(Long.BYTES),
        MAX_PACING_RATE(Long.BYTES),
        BYTES_ACKED(Long.BYTES),
        BYTES_RECEIVED(Long.BYTES),
        SEGS_OUT(Integer.BYTES),
        SEGS_IN(Integer.BYTES),
        NOTSENT_BYTES(Integer.BYTES),
        MIN_RTT(Integer.BYTES),
        DATA_SEGS_IN(Integer.BYTES),
        DATA_SEGS_OUT(Integer.BYTES),
        DELIVERY_RATE(Long.BYTES),
        BUSY_TIME(Long.BYTES),
        RWND_LIMITED(Long.BYTES),
        SNDBUF_LIMITED(Long.BYTES);

        public final int size;

        Field(int s) {
            size = s;
        }
    }

    private static final String TAG = "TcpInfo";
    private final LinkedHashMap<Field, Number> mFieldsValues = new LinkedHashMap<Field, Number>();

    private TcpInfo(@NonNull ByteBuffer bytes, int infolen) {
        final int start = bytes.position();
        for (final Field field : Field.values()) {
            switch (field.size) {
                case Byte.BYTES:
                    mFieldsValues.put(field, getByte(bytes, start, infolen));
                    break;
                case Integer.BYTES:
                    mFieldsValues.put(field, getInt(bytes, start, infolen));
                    break;
                case Long.BYTES:
                    mFieldsValues.put(field, getLong(bytes, start, infolen));
                    break;
                default:
                    Log.e(TAG, "Unexpected size:" + field.size);
            }
        }

    }

    @VisibleForTesting
    TcpInfo(@NonNull HashMap<Field, Number> info) {
        for (final Field field : Field.values()) {
            mFieldsValues.put(field, info.get(field));
        }
    }

    /** Parse a TcpInfo from a giving ByteBuffer with a specific length. */
    @Nullable
    public static TcpInfo parse(@NonNull ByteBuffer bytes, int infolen) {
        try {
            TcpInfo info = new TcpInfo(bytes, infolen);
            return info;
        } catch (BufferUnderflowException e) {
            Log.e(TAG, "parsing error.", e);
            return null;
        }
    }

    /**
     * Helper function for handling different struct tcp_info versions in the kernel.
     */
    private static boolean isValidOffset(int start, int len, int pos, int targetBytes) {
        final Range a = new Range(start, start + len);
        final Range b = new Range(pos, pos + targetBytes);
        return a.contains(b);
    }

    /** Get value for specific key. */
    @Nullable
    public Number getValue(@NonNull Field key) {
        return mFieldsValues.get(key);
    }

    @Nullable
    private static Byte getByte(@NonNull ByteBuffer buffer, int start, int len) {
        if (!isValidOffset(start, len, buffer.position(), Byte.BYTES)) return null;

        return buffer.get();
    }

    @Nullable
    private static Integer getInt(@NonNull ByteBuffer buffer, int start, int len) {
        if (!isValidOffset(start, len, buffer.position(), Integer.BYTES)) return null;

        return buffer.getInt();
    }

    @Nullable
    private static Long getLong(@NonNull ByteBuffer buffer, int start, int len) {
        if (!isValidOffset(start, len, buffer.position(), Long.BYTES)) return null;

        return buffer.getLong();
    }

    private static String decodeWscale(byte num) {
        return String.valueOf((num >> 4) & 0x0f)  + ":" + String.valueOf(num & 0x0f);
    }

    /**
     *  Returns a string representing a given tcp state.
     *  Map to enum in bionic/libc/include/netinet/tcp.h
     */
    @VisibleForTesting
    static String getTcpStateName(int state) {
        switch (state) {
            case 1: return "TCP_ESTABLISHED";
            case 2: return "TCP_SYN_SENT";
            case 3: return "TCP_SYN_RECV";
            case 4: return "TCP_FIN_WAIT1";
            case 5: return "TCP_FIN_WAIT2";
            case 6: return "TCP_TIME_WAIT";
            case 7: return "TCP_CLOSE";
            case 8: return "TCP_CLOSE_WAIT";
            case 9: return "TCP_LAST_ACK";
            case 10: return "TCP_LISTEN";
            case 11: return "TCP_CLOSING";
            default: return "UNKNOWN:" + Integer.toString(state);
        }
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof TcpInfo)) return false;
        TcpInfo other = (TcpInfo) obj;

        for (final Field key : mFieldsValues.keySet()) {
            if (!Objects.equals(mFieldsValues.get(key), other.mFieldsValues.get(key))) {
                return false;
            }
        }
        return true;
    }

    @Override
    public int hashCode() {
        return Objects.hash(mFieldsValues.values().toArray());
    }

    @Override
    public String toString() {
        String str = "TcpInfo{ ";
        for (final Field key : mFieldsValues.keySet()) {
            str += key.name().toLowerCase() + "=";
            if (key == Field.STATE) {
                str += getTcpStateName(mFieldsValues.get(key).intValue()) + " ";
            } else if (key == Field.WSCALE) {
                str += decodeWscale(mFieldsValues.get(key).byteValue()) + " ";
            } else {
                str += mFieldsValues.get(key) + " ";
            }
        }
        str += "}";
        return str;
    }
}
