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

import android.net.MacAddress;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.VisibleForTesting;

import com.android.internal.util.HexDump;
import com.android.net.module.util.Struct;
import com.android.net.module.util.structs.IaPdOption;
import com.android.net.module.util.structs.IaPrefixOption;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.OptionalInt;

/**
 * Defines basic data and operations needed to build and use packets for the
 * DHCPv6 protocol. Subclasses create the specific packets used at each
 * stage of the negotiation.
 *
 * @hide
 */
public class Dhcp6Packet {
    private static final String TAG = Dhcp6Packet.class.getSimpleName();
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
     * DHCPv6 Optional Type: Option Request Option.
     */
    public static final byte DHCP6_OPTION_REQUEST_OPTION = 6;

    /**
     * DHCPv6 Optional Type: Elapsed time.
     * This time is expressed in hundredths of a second.
     */
    public static final byte DHCP6_ELAPSED_TIME = 8;
    protected final int mElapsedTime;

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
     * DHCPv6 zero-length Optional Type: Rapid Commit. Per RFC4039, both DHCPDISCOVER and DHCPACK
     * packet may include this option.
     */
    public static final byte DHCP6_RAPID_COMMIT = 14;
    public boolean mRapidCommit;

    /**
     * DHCPv6 Optional Type: IA_PD.
     */
    public static final byte DHCP6_IA_PD = 25;
    @NonNull
    protected final byte[] mIaPd;
    @NonNull
    protected PrefixDelegation mPrefixDelegation;

    /**
     * DHCPv6 Optional Type: SOL_MAX_RT.
     */
    public static final byte DHCP6_SOL_MAX_RT = 82;
    private OptionalInt mSolMaxRt;

    /**
     * The transaction identifier used in this particular DHCPv6 negotiation
     */
    protected final int mTransId;

    /**
     * The unique identifier for IA_NA, IA_TA, IA_PD used in this particular DHCPv6 negotiation
     */
    protected int mIaId;

    Dhcp6Packet(int transId, int elapsedTime, @NonNull final byte[] clientDuid,
            final byte[] serverDuid, @NonNull final byte[] iapd) {
        mTransId = transId;
        mElapsedTime = elapsedTime;
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
     * Returns the SOL_MAX_RT option value.
     */
    public OptionalInt getSolMaxRtValue() {
        return mSolMaxRt;
    }

    /**
     * A class to take DHCPv6 IA_PD option allocated from server.
     * https://www.rfc-editor.org/rfc/rfc8415.html#section-21.21
     */
    public static class PrefixDelegation {
        public int iaid;
        public int t1;
        public int t2;
        public final IaPrefixOption ipo;

        PrefixDelegation(int iaid, int t1, int t2, final IaPrefixOption ipo) {
            this.iaid = iaid;
            this.t1 = t1;
            this.t2 = t2;
            this.ipo = ipo;
        }

        @Override
        public String toString() {
            return "Prefix Delegation: iaid " + iaid + ", t1 " + t1 + ", t2 " + t2
                    + ", prefix " + ipo;
        }
    }

    /**
     * DHCPv6 packet parsing exception.
     */
    public static class ParseException extends Exception {
        ParseException(String msg) {
            super(msg);
        }
    }

    private static void skipOption(@NonNull final ByteBuffer packet, int optionLen)
            throws BufferUnderflowException {
        for (int i = 0; i < optionLen; i++) {
            packet.get();
        }
    }

    /**
     * Reads a string of specified length from the buffer.
     *
     * TODO: move to a common place which can be shared with DhcpClient.
     */
    private static String readAsciiString(@NonNull final ByteBuffer buf, int byteCount,
            boolean isNullOk) {
        final byte[] bytes = new byte[byteCount];
        buf.get(bytes);
        return readAsciiString(bytes, isNullOk);
    }

    private static String readAsciiString(@NonNull final byte[] payload, boolean isNullOk) {
        final byte[] bytes = payload;
        int length = bytes.length;
        if (!isNullOk) {
            // Stop at the first null byte. This is because some DHCP options (e.g., the domain
            // name) are passed to netd via FrameworkListener, which refuses arguments containing
            // null bytes. We don't do this by default because vendorInfo is an opaque string which
            // could in theory contain null bytes.
            for (length = 0; length < bytes.length; length++) {
                if (bytes[length] == 0) {
                    break;
                }
            }
        }
        return new String(bytes, 0, length, StandardCharsets.US_ASCII);
    }

    /**
     * Creates a concrete Dhcp6Packet from the supplied ByteBuffer.
     *
     * The buffer only starts with a UDP encapsulation (i.e. DHCPv6 message). A subset of the
     * optional parameters are parsed and are stored in object fields. Client/Server message
     * format:
     *
     *  0                   1                   2                   3
     *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |    msg-type   |               transaction-id                  |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                                                               |
     * .                            options                            .
     * .                 (variable number and length)                  .
     * |                                                               |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */
    @VisibleForTesting
    static Dhcp6Packet decode(@NonNull final ByteBuffer packet) throws ParseException {
        int elapsedTime = 0;
        byte[] iapd = null;
        byte[] serverDuid = null;
        byte[] clientDuid = null;
        short statusCode = STATUS_SUCCESS;
        String statusMsg = null;
        boolean rapidCommit = false;
        int solMaxRt = 0;

        packet.order(ByteOrder.BIG_ENDIAN);

        // DHCPv6 message contents.
        final int msgTypeAndTransId = packet.getInt();
        final byte messageType = (byte) (msgTypeAndTransId >> 24);
        final int transId = msgTypeAndTransId & 0xffffff;

        /**
         * Parse DHCPv6 options, option format:
         *
         * 0                   1                   2                   3
         * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * |          option-code          |           option-len          |
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * |                          option-data                          |
         * |                      (option-len octets)                      |
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         */
        while (packet.hasRemaining()) {
            try {
                final short optionType = packet.getShort();
                final int optionLen = packet.getShort() & 0xFFFF;
                int expectedLen = 0;

                switch(optionType) {
                    case DHCP6_SERVER_IDENTIFIER:
                        expectedLen = optionLen;
                        final byte[] sduid = new byte[expectedLen];
                        packet.get(sduid, 0 /* offset */, expectedLen);
                        serverDuid = sduid;
                        break;
                    case DHCP6_CLIENT_IDENTIFIER:
                        expectedLen = optionLen;
                        final byte[] cduid = new byte[expectedLen];
                        packet.get(cduid, 0 /* offset */, expectedLen);
                        clientDuid = cduid;
                        break;
                    case DHCP6_IA_PD:
                        expectedLen = optionLen;
                        final byte[] bytes = new byte[expectedLen];
                        packet.get(bytes, 0 /* offset */, expectedLen);
                        iapd = bytes;
                        break;
                    case DHCP6_RAPID_COMMIT:
                        expectedLen = 0;
                        rapidCommit = true;
                        break;
                    case DHCP6_ELAPSED_TIME:
                        expectedLen = 2;
                        elapsedTime = (int) (packet.getShort() & 0xFFFF);
                        break;
                    case DHCP6_STATUS_CODE:
                        expectedLen = optionLen;
                        statusCode = packet.getShort();
                        statusMsg = readAsciiString(packet, expectedLen - 2, false /* isNullOk */);
                        break;
                    case DHCP6_SOL_MAX_RT:
                        expectedLen = 4;
                        solMaxRt = packet.getInt();
                        break;
                    default:
                        expectedLen = optionLen;
                        // BufferUnderflowException will be thrown if option is truncated.
                        skipOption(packet, optionLen);
                        break;
                }
                if (expectedLen != optionLen) {
                    throw new ParseException(
                            "Invalid length " + optionLen + " for option " + optionType
                                    + ", expected " + expectedLen);
                }
            } catch (BufferUnderflowException e) {
                throw new ParseException(e.getMessage());
            }
        }

        Dhcp6Packet newPacket;

        switch(messageType) {
            case DHCP6_MESSAGE_TYPE_SOLICIT:
                newPacket = new Dhcp6SolicitPacket(transId, elapsedTime, clientDuid, iapd,
                        rapidCommit);
                break;
            case DHCP6_MESSAGE_TYPE_ADVERTISE:
                newPacket = new Dhcp6AdvertisePacket(transId, clientDuid, serverDuid, iapd);
                break;
            case DHCP6_MESSAGE_TYPE_REQUEST:
                newPacket = new Dhcp6RequestPacket(transId, elapsedTime, clientDuid, serverDuid,
                        iapd);
                break;
            case DHCP6_MESSAGE_TYPE_REPLY:
                newPacket = new Dhcp6ReplyPacket(transId, clientDuid, serverDuid, iapd,
                        rapidCommit);
                break;
            case DHCP6_MESSAGE_TYPE_RENEW:
                newPacket = new Dhcp6RenewPacket(transId, elapsedTime, clientDuid, serverDuid,
                        iapd);
                break;
            case DHCP6_MESSAGE_TYPE_REBIND:
                newPacket = new Dhcp6RebindPacket(transId, elapsedTime, clientDuid, iapd);
                break;
            default:
                throw new ParseException("Unimplemented DHCP6 message type %d" + messageType);
        }

        if (iapd != null) {
            final ByteBuffer buffer = ByteBuffer.wrap(iapd);
            final int iaid = buffer.getInt();
            final int t1 = buffer.getInt();
            final int t2 = buffer.getInt();
            final IaPrefixOption ipo = Struct.parse(IaPrefixOption.class, buffer);
            newPacket.mPrefixDelegation = new PrefixDelegation(iaid, t1, t2, ipo);
            newPacket.mIaId = iaid;
        }
        newPacket.mStatusCode = statusCode;
        newPacket.mStatusMsg = statusMsg;
        newPacket.mRapidCommit = rapidCommit;
        newPacket.mSolMaxRt =
                (solMaxRt >= 60 && solMaxRt <= 86400)
                        ? OptionalInt.of(solMaxRt)
                        : OptionalInt.empty();

        return newPacket;
    }

    /**
     * Parse a packet from an array of bytes, stopping at the given length.
     */
    public static Dhcp6Packet decode(@NonNull final byte[] packet, int length)
            throws ParseException {
        final ByteBuffer buffer = ByteBuffer.wrap(packet, 0, length).order(ByteOrder.BIG_ENDIAN);
        return decode(buffer);
    }

    /**
     * Follow RFC8415 section 18.2.9 and 18.2.10 to check if the received DHCPv6 message is valid.
     */
    public boolean isValid(int transId, @NonNull final byte[] clientDuid) {
        if (mClientDuid == null) {
            Log.e(TAG, "DHCPv6 message without Client DUID option");
            return false;
        }
        if (!Arrays.equals(mClientDuid, clientDuid)) {
            Log.e(TAG, "Unexpected client DUID " + HexDump.toHexString(mClientDuid)
                    + ", expected " + HexDump.toHexString(clientDuid));
            return false;
        }
        if (mTransId != transId) {
            Log.e(TAG, "Unexpected transaction ID " + mTransId + ", expected " + transId);
            return false;
        }
        return true;
    }

    /**
     * Check whether or not the delegated prefix in DHCPv6 packet is valid.
     *
     * TODO: ensure that the prefix has a reasonable lifetime, and the timers aren't too short.
     */
    public static boolean hasValidPrefixDelegation(@NonNull final PrefixDelegation pd) {
        if (pd == null) {
            Log.e(TAG, "DHCPv6 packet without IA_PD option, ignoring");
            return false;
        }
        if (pd.ipo.prefixLen > 64) {
            Log.e(TAG, "IA_PD option with prefix length " + pd.ipo.prefixLen + " longer than 64");
            return false;
        }
        final long t1 = pd.t1;
        final long t2 = pd.t2;
        if (t1 < 0 || t2 < 0) {
            Log.e(TAG, "IA_PD option with invalid T1 " + t1 + " or T2 " + t2);
            return false;
        }

        // Generally, t1 must be smaller or equal to t2 (except when t2 is 0).
        if (t2 != 0 && t1 > t2) {
            Log.e(TAG, "IA_PD option with T1 " + t1 + " greater than T2 " + t2);
            return false;
        }
        final long preferred = pd.ipo.preferred;
        final long valid = pd.ipo.valid;
        if (preferred < 0 || valid < 0) {
            Log.e(TAG, "IA_PD option with invalid lifetime, preferred lifetime " + preferred
                    + ", valid lifetime " + valid);
            return false;
        }
        if (preferred > valid) {
            Log.e(TAG, "IA_PD option with preferred lifetime " + preferred
                    + " greater than valid lifetime " + valid);
            return false;
        }

        // If t2 is 0, ignore it.
        if (t2 != 0 && preferred < t2) {
            Log.e(TAG, "preferred lifetime " + preferred + " is smaller than T2 " + t2);
            return false;
        }
        return true;
    }

    /**
     * Returns the client DUID, follows RFC 8415 and creates a client DUID
     * based on the link-layer address(DUID-LL).
     *
     * TODO: use Struct to build and parse DUID.
     *
     * 0                   1                   2                   3
     * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |         DUID-Type (3)         |    hardware type (16 bits)    |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * .                                                               .
     * .             link-layer address (variable length)              .
     * .                                                               .
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */
    public static byte[] createClientDuid(@NonNull final MacAddress macAddress) {
        final byte[] duid = new byte[10];
        // type: Link-layer address(3)
        duid[0] = (byte) 0x00;
        duid[1] = (byte) 0x03;
        // hardware type: Ethernet(1)
        duid[2] = (byte) 0x00;
        duid[3] = (byte) 0x01;
        System.arraycopy(macAddress.toByteArray() /* src */, 0 /* srcPos */, duid /* dest */,
                4 /* destPos */, 6 /* length */);
        return duid;
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
     * Adds an optional parameter containing zero-length value.
     */
    protected static void addTlv(ByteBuffer buf, short type) {
        buf.putShort(type);
        buf.putShort((short) 0);
    }

    /**
     * Build an IA_PD option from given specific parameters, including IA_PREFIX option.
     */
    public static ByteBuffer buildIaPdOption(int iaid, int t1, int t2, long preferred, long valid,
            final byte[] prefix, byte prefixLen) {
        final ByteBuffer iapd = ByteBuffer.allocate(IaPdOption.LENGTH
                + Struct.getSize(IaPrefixOption.class));
        iapd.putInt(iaid);
        iapd.putInt(t1);
        iapd.putInt(t2);
        final ByteBuffer prefixOption = IaPrefixOption.build((short) IaPrefixOption.LENGTH,
                preferred, valid, prefixLen, prefix);
        iapd.put(prefixOption);
        iapd.flip();
        return iapd;
    }

    /**
     * Builds a DHCPv6 SOLICIT packet from the required specified parameters.
     */
    public static ByteBuffer buildSolicitPacket(int transId, long millisecs,
            @NonNull final byte[] iapd, @NonNull final byte[] clientDuid, boolean rapidCommit) {
        final Dhcp6SolicitPacket pkt =
                new Dhcp6SolicitPacket(transId, (int) (millisecs / 10) /* elapsed time */,
                        clientDuid, iapd, rapidCommit);
        return pkt.buildPacket();
    }

    /**
     * Builds a DHCPv6 ADVERTISE packet from the required specified parameters.
     */
    public static ByteBuffer buildAdvertisePacket(int transId, @NonNull final byte[] iapd,
            @NonNull final byte[] clientDuid, @NonNull final byte[] serverDuid) {
        final Dhcp6AdvertisePacket pkt =
                new Dhcp6AdvertisePacket(transId, clientDuid, serverDuid, iapd);
        return pkt.buildPacket();
    }

    /**
     * Builds a DHCPv6 REPLY packet from the required specified parameters.
     */
    public static ByteBuffer buildReplyPacket(int transId, @NonNull final byte[] iapd,
            @NonNull final byte[] clientDuid, @NonNull final byte[] serverDuid,
            boolean rapidCommit) {
        final Dhcp6ReplyPacket pkt =
                new Dhcp6ReplyPacket(transId, clientDuid, serverDuid, iapd, rapidCommit);
        return pkt.buildPacket();
    }

    /**
     * Builds a DHCPv6 REQUEST packet from the required specified parameters.
     */
    public static ByteBuffer buildRequestPacket(int transId, long millisecs,
            @NonNull final byte[] iapd, @NonNull final byte[] clientDuid,
            @NonNull final byte[] serverDuid) {
        final Dhcp6RequestPacket pkt =
                new Dhcp6RequestPacket(transId, (int) (millisecs / 10) /* elapsed time */,
                        clientDuid, serverDuid, iapd);
        return pkt.buildPacket();
    }

    /**
     * Builds a DHCPv6 RENEW packet from the required specified parameters.
     */
    public static ByteBuffer buildRenewPacket(int transId, long millisecs,
            @NonNull final byte[] iapd, @NonNull final byte[] clientDuid,
            @NonNull final byte[] serverDuid) {
        final Dhcp6RenewPacket pkt =
                new Dhcp6RenewPacket(transId, (int) (millisecs / 10) /* elapsed time */, clientDuid,
                        serverDuid, iapd);
        return pkt.buildPacket();
    }

    /**
     * Builds a DHCPv6 REBIND packet from the required specified parameters.
     */
    public static ByteBuffer buildRebindPacket(int transId, long millisecs,
            @NonNull final byte[] iapd, @NonNull final byte[] clientDuid) {
        final Dhcp6RebindPacket pkt = new Dhcp6RebindPacket(transId,
                (int) (millisecs / 10) /* elapsed time */, clientDuid, iapd);
        return pkt.buildPacket();
    }
}
