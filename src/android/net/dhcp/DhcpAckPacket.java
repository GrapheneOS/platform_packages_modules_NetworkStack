/*
 * Copyright (C) 2010 The Android Open Source Project
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

package android.net.dhcp;

import java.net.Inet4Address;
import java.nio.ByteBuffer;

/**
 * This class implements the DHCP-ACK packet.
 */
public class DhcpAckPacket extends DhcpPacket {

    /**
     * The address of the server which sent this packet.
     */
    private final Inet4Address mSrcIp;

    DhcpAckPacket(int transId, short secs, boolean broadcast, Inet4Address serverAddress,
            Inet4Address relayIp, Inet4Address clientIp, Inet4Address yourIp, byte[] clientMac,
            boolean rapidCommit) {
        super(transId, secs, clientIp, yourIp, serverAddress, relayIp, clientMac, broadcast);
        mBroadcast = broadcast;
        mSrcIp = serverAddress;
        mRapidCommit = rapidCommit;
    }

    public String toString() {
        String s = super.toString();
        String dnsServers = " DNS servers: ";

        for (Inet4Address dnsServer: mDnsServers) {
            dnsServers += dnsServer.toString() + " ";
        }

        return s + " ACK: your new IP " + mYourIp
                + ", netmask " + mSubnetMask
                + ", gateways " + mGateways + dnsServers
                + ", lease time " + mLeaseTime
                + ", domain " + mDomainName
                + (mIpv6OnlyWaitTime != null ? ", V6ONLY_WAIT " + mIpv6OnlyWaitTime : "");
    }

    /**
     * Fills in a packet with the requested ACK parameters.
     */
    public ByteBuffer buildPacket(int encap, short destUdp, short srcUdp) {
        ByteBuffer result = ByteBuffer.allocate(MAX_LENGTH);
        Inet4Address destIp = mBroadcast ? INADDR_BROADCAST : mYourIp;
        Inet4Address srcIp = mBroadcast ? INADDR_ANY : mSrcIp;

        fillInPacket(encap, destIp, srcIp, destUdp, srcUdp, result,
            DHCP_BOOTREPLY, mBroadcast);
        result.flip();
        return result;
    }

    /**
     * Adds the optional parameters to the client-generated ACK packet.
     */
    void finishPacket(ByteBuffer buffer) {
        addTlv(buffer, DHCP_MESSAGE_TYPE, DHCP_MESSAGE_TYPE_ACK);
        addTlv(buffer, DHCP_SERVER_IDENTIFIER, mServerIdentifier);
        addCommonServerTlvs(buffer);
        if (mRapidCommit) {
            addTlv(buffer, DHCP_RAPID_COMMIT);
        }
        addTlvEnd(buffer);
    }

    /**
     * Un-boxes an Integer, returning 0 if a null reference is supplied.
     */
    private static final int getInt(Integer v) {
        if (v == null) {
            return 0;
        } else {
            return v.intValue();
        }
    }
}
