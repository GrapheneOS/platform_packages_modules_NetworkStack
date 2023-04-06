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

package android.net.dhcp6;

import static com.android.net.module.util.NetworkStackConstants.DHCP_MAX_OPTION_LEN;

import androidx.annotation.NonNull;

import java.nio.ByteBuffer;

/**
 * Defines basic data and operations needed to build and use packets for the
 * DHCPv6 protocol. Subclasses create the specific packets used at each
 * stage of the negotiation.
 *
 * @hide
 */
public class Dhcp6Packet {

    /**
     * DHCPv6 Message Type.
     */
    public static final byte DHCP6_MESSAGE_TYPE_SOLICIT = 1;
    public static final byte DHCP6_MESSAGE_TYPE_ADVERTISE = 2;
    public static final byte DHCP6_MESSAGE_TYPE_REQUEST = 3;
    public static final byte DHCP6_MESSAGE_TYPE_CONFIRM = 4;
    public static final byte DHCP6_MESSAGE_TYPE_RENEW = 5;
    public static final byte DHCP6_MESSAGE_TYPE_REBIND = 6;
    public static final byte DHCP6_MESSAGE_TYPE_REPLY = 7;
    public static final byte DHCP6_MESSAGE_TYPE_RELEASE = 8;
    public static final byte DHCP6_MESSAGE_TYPE_DECLINE = 9;
    public static final byte DHCP6_MESSAGE_TYPE_RECONFIGURE = 10;
    public static final byte DHCP6_MESSAGE_TYPE_INFORMATION_REQUEST = 11;
    public static final byte DHCP6_MESSAGE_TYPE_RELAY_FORW = 12;
    public static final byte DHCP6_MESSAGE_TYPE_RELAY_REPL = 13;

    /**
     * DHCPv6 Optional Type: Client Identifier.
     * DHCPv6 message from client must have this option.
     */
    public static final byte DHCP6_CLIENT_IDENTIFIER = 1;
    @NonNull
    protected final byte[] mClientDuid;

    /**
     * DHCPv6 Optional Type: Server Identifier.
     */
    public static final byte DHCP6_SERVER_IDENTIFIER = 2;
    protected final byte[] mServerDuid;

    /**
     * DHCPv6 Optional Type: Elapsed time.
     */
    public static final byte DHCP6_ELAPSED_TIME = 8;
    protected final short mSecs;

    /**
     * DHCPv6 Optional Type: Status Code.
     */
    public static final byte DHCP6_STATUS_CODE = 13;
    protected short mStatusCode;
    protected String mStatusMsg;

    public static final short STATUS_SUCCESS           = 0;
    public static final short STATUS_UNSPEC_FAIL       = 1;
    public static final short STATUS_NO_ADDR_AVAI      = 2;
    public static final short STATUS_NO_BINDING        = 3;
    public static final short STATUS_PREFIX_NOT_ONLINK = 4;
    public static final short STATUS_USE_MULTICAST     = 5;
    public static final short STATUS_NO_PREFIX_AVAI    = 6;

    /**
     * DHCPv6 Optional Type: IA_PD.
     */
    public static final byte DHCP6_IA_PD = 25;
    @NonNull
    protected final byte[] mIaPd;

    /**
     * The transaction identifier used in this particular DHCPv6 negotiation
     */
    protected final int mTransId;

    /**
     * The unique identifier for IA_NA, IA_TA, IA_PD used in this particular DHCPv6 negotiation
     */
    protected int mIaId;

    Dhcp6Packet(int transId, short secs, @NonNull final byte[] clientDuid, final byte[] serverDuid,
            @NonNull final byte[] iapd) {
        mTransId = transId;
        mSecs = secs;
        mClientDuid = clientDuid;
        mServerDuid = serverDuid;
        mIaPd = iapd;
    }

    /**
     * Returns the transaction ID.
     */
    public int getTransactionId() {
        return mTransId;
    }

    /**
     * Returns IA_ID associated to IA_PD.
     */
    public int getIaId() {
        return mIaId;
    }

    /**
     * Returns the client's DUID.
     */
    @NonNull
    public byte[] getClientDuid() {
        return mClientDuid;
    }

    /**
     * Returns the server's DUID.
     */
    public byte[] getServerDuid() {
        return mServerDuid;
    }

    /**
     * Adds an optional parameter containing an array of bytes.
     */
    protected static void addTlv(ByteBuffer buf, short type, @NonNull byte[] payload) {
        if (payload.length > DHCP_MAX_OPTION_LEN) {
            throw new IllegalArgumentException("DHCP option too long: "
                    + payload.length + " vs. " + DHCP_MAX_OPTION_LEN);
        }
        buf.putShort(type);
        buf.putShort((short) payload.length);
        buf.put(payload);
    }

    /**
     * Adds an optional parameter containing a short integer.
     */
    protected static void addTlv(ByteBuffer buf, short type, short value) {
        buf.putShort(type);
        buf.putShort((short) 2);
        buf.putShort(value);
    }

    /**
     * Builds a DHCPv6 SOLICIT packet from the required specified parameters.
     */
    public static ByteBuffer buildSolicitPacket(int transId, short secs, final byte[] iapd,
            final byte[] duid) {
        final Dhcp6SolicitPacket pkt = new Dhcp6SolicitPacket(transId, secs, duid, iapd);
        return pkt.buildPacket();
    }
}
