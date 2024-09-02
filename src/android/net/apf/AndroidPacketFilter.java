/*
 * Copyright (C) 2023 The Android Open Source Project
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

import android.annotation.Nullable;
import android.net.LinkProperties;
import android.net.NattKeepalivePacketDataParcelable;
import android.net.TcpKeepalivePacketDataParcelable;

import com.android.internal.util.IndentingPrintWriter;

/**
 * The interface for AndroidPacketFilter
 */
public interface AndroidPacketFilter {
    /**
     * Update the LinkProperties that will be used by APF.
     */
    void setLinkProperties(LinkProperties lp);

    /**
     * Shutdown the APF.
     */
    void shutdown();

    /**
     * Switch for the multicast filter.
     * @param isEnabled if  the multicast filter should be enabled or not.
     */
    void setMulticastFilter(boolean isEnabled);

    /**
     * Set the APF data snapshot and return the latest counter snapshot as a String.
     */
    String setDataSnapshot(byte[] data);

    /**
     * Add TCP keepalive ack packet filter.
     * This will add a filter to drop acks to the keepalive packet passed as an argument.
     *
     * @param slot The index used to access the filter.
     * @param sentKeepalivePacket The attributes of the sent keepalive packet.
     */
    void addTcpKeepalivePacketFilter(int slot,
            TcpKeepalivePacketDataParcelable sentKeepalivePacket);

    /**
     * Add NAT-T keepalive packet filter.
     * This will add a filter to drop NAT-T keepalive packet which is passed as an argument.
     *
     * @param slot The index used to access the filter.
     * @param sentKeepalivePacket The attributes of the sent keepalive packet.
     */
    void addNattKeepalivePacketFilter(int slot,
            NattKeepalivePacketDataParcelable sentKeepalivePacket);

    /**
     * Remove keepalive packet filter.
     *
     * @param slot The index used to access the filter.
     */
    void removeKeepalivePacketFilter(int slot);

    /**
     * Dump the status of APF.
     */
    void dump(IndentingPrintWriter pw);

    /**
     * Indicates whether the ApfFilter is currently running / paused for test and debugging
     * purposes.
     */
    boolean isRunning();

    /**
     * Indicates whether the clat interface is added or removed.
     */
    default void updateClatInterfaceState(boolean add) {}

    /** Pause ApfFilter updates for testing purposes. */
    void pause();

    /** Resume ApfFilter updates for testing purposes. */
    void resume();

    /** Return hex string of current APF snapshot for testing purposes. */
    @Nullable String getDataSnapshotHexString();

    /**
     * Determines whether the APF interpreter advertises support for the data buffer access
     * opcodes LDDW (LoaD Data Word) and STDW (STore Data Word).
     */
    default boolean hasDataAccess(int apfVersionSupported) {
        return apfVersionSupported > 2;
    }

    /**
     * Whether the ApfFilter supports generating ND offload code.
     */
    default boolean supportNdOffload() {
        return false;
    }

    /**
     * Return if the ApfFilter should enable mDNS offload.
     */
    default boolean shouldEnableMdnsOffload() {
        return false;
    }
}
