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

import static android.system.OsConstants.IPPROTO_ICMPV6;

import static com.android.net.module.util.NetworkStackConstants.ETHER_HEADER_LEN;
import static com.android.net.module.util.NetworkStackConstants.IPV4_HEADER_MIN_LEN;
import static com.android.net.module.util.NetworkStackConstants.IPV4_IGMP_TYPE_V1_REPORT;
import static com.android.net.module.util.NetworkStackConstants.IPV4_IGMP_TYPE_V2_JOIN_REPORT;
import static com.android.net.module.util.NetworkStackConstants.IPV4_IGMP_TYPE_V2_LEAVE_REPORT;
import static com.android.net.module.util.NetworkStackConstants.IPV4_IGMP_TYPE_V3_REPORT;
import static com.android.net.module.util.NetworkStackConstants.IPV4_OPTION_LEN_ROUTER_ALERT;
import static com.android.net.module.util.NetworkStackConstants.IPV4_OPTION_TYPE_ROUTER_ALERT;

import android.net.InetAddresses;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Set;

/**
 * The class which declares constants used in ApfFilter and unit tests.
 */
public final class ApfConstants {

    private ApfConstants() {}
    public static final int ETH_HEADER_LEN = 14;
    public static final int ETH_DEST_ADDR_OFFSET = 0;
    public static final int ETH_ETHERTYPE_OFFSET = 12;
    public static final int ETH_TYPE_MIN = 0x0600;
    public static final int ETH_TYPE_MAX = 0xFFFF;
    // TODO: Make these offsets relative to end of link-layer header; don't include ETH_HEADER_LEN.
    public static final int IPV4_TOTAL_LENGTH_OFFSET = ETH_HEADER_LEN + 2;
    public static final int IPV4_FRAGMENT_OFFSET_OFFSET = ETH_HEADER_LEN + 6;
    // Endianness is not an issue for this constant because the APF interpreter always operates in
    // network byte order.
    public static final int IPV4_FRAGMENT_OFFSET_MASK = 0x1fff;
    public static final int IPV4_FRAGMENT_MORE_FRAGS_MASK = 0x2000;
    public static final int IPV4_PROTOCOL_OFFSET = ETH_HEADER_LEN + 9;
    public static final int IPV4_SRC_ADDR_OFFSET = ETH_HEADER_LEN + 12;
    public static final int IPV4_DEST_ADDR_OFFSET = ETH_HEADER_LEN + 16;
    public static final int IPV4_ANY_HOST_ADDRESS = 0;
    public static final int IPV4_BROADCAST_ADDRESS = -1; // 255.255.255.255
    // The IPv4 all hosts destination 224.0.0.1
    public static final byte[] IPV4_ALL_HOSTS_ADDRESS =
            InetAddresses.parseNumericAddress("224.0.0.1").getAddress();
    // The IPv4 all multicast routers destination 224.0.0.22
    public static final byte[] IPV4_ALL_IGMPV3_MULTICAST_ROUTERS_ADDRESS =
            InetAddresses.parseNumericAddress("224.0.0.22").getAddress();
    public static long IPV4_ALL_HOSTS_ADDRESS_IN_LONG = 0xe0000001L; // 224.0.0.1
    public static final int IPV4_IGMP_TYPE_QUERY = 0x11;
    public static final Set<Long> IGMP_TYPE_REPORTS = Set.of(
            (long) IPV4_IGMP_TYPE_V1_REPORT,
            (long) IPV4_IGMP_TYPE_V2_JOIN_REPORT,
            (long) IPV4_IGMP_TYPE_V2_LEAVE_REPORT,
            (long) IPV4_IGMP_TYPE_V3_REPORT);
    public static final byte[] IPV4_ROUTER_ALERT_OPTION = {
            (byte) IPV4_OPTION_TYPE_ROUTER_ALERT,   // option type
            (byte) IPV4_OPTION_LEN_ROUTER_ALERT,    // option length
            0,  0   // option value
    };
    public static final int IPV4_ROUTER_ALERT_OPTION_LEN = 4;
    public static final int IGMP_CHECKSUM_WITH_ROUTER_ALERT_OFFSET =
            ETHER_HEADER_LEN + IPV4_HEADER_MIN_LEN + IPV4_ROUTER_ALERT_OPTION_LEN + 2;
    public static final byte[] IGMPV2_REPORT_FROM_IPV4_OPTION_TO_IGMP_CHECKSUM = {
            // option type
            (byte) IPV4_OPTION_TYPE_ROUTER_ALERT,
            // option length
            (byte) IPV4_OPTION_LEN_ROUTER_ALERT,
            // option value
            0,  0,
            // IGMP type
            // Indicating an IGMPv2 Membership Report (Join Group)
            (byte) IPV4_IGMP_TYPE_V2_JOIN_REPORT,
            // max response time
            // Typically used in IGMP queries,but is not significant in IGMPv2 reports.
            0,
            // checksum, calculate later
            0, 0
    };

    // IGMPv3 group record types
    // From include/uapi/linux/igmp.h
    public static final int IGMPV3_MODE_IS_EXCLUDE = 2;

    // MLDv2 group record types
    // From include/uapi/linux/icmpv6.h
    public static final int MLD2_MODE_IS_EXCLUDE = 2;

    // Traffic class and Flow label are not byte aligned. Luckily we
    // don't care about either value so we'll consider bytes 1-3 of the
    // IPv6 header as don't care.
    public static final int IPV6_FLOW_LABEL_OFFSET = ETH_HEADER_LEN + 1;
    public static final int IPV6_FLOW_LABEL_LEN = 3;
    public static final int IPV6_PAYLOAD_LEN_OFFSET = ETH_HEADER_LEN + 4;
    public static final int IPV6_NEXT_HEADER_OFFSET = ETH_HEADER_LEN + 6;
    public static final int IPV6_HOP_LIMIT_OFFSET = ETH_HEADER_LEN + 7;
    public static final int IPV6_SRC_ADDR_OFFSET = ETH_HEADER_LEN + 8;
    public static final int IPV6_DEST_ADDR_OFFSET = ETH_HEADER_LEN + 24;
    public static final int IPV6_HEADER_LEN = 40;
    // The IPv6 all nodes address ff02::1
    public static final byte[] IPV6_ALL_NODES_ADDRESS =
            { (byte) 0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    // The IPv6 unspecified address ::
    public static final byte[] IPV6_UNSPECIFIED_ADDRESS =
            {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    // The IPv6 solicited nodes multicast address prefix ff02::1:ffXX:X/104
    public static final byte[] IPV6_SOLICITED_NODES_PREFIX =
            { (byte) 0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, (byte) 0xff};
    public static final byte[] IPV6_MLD_V2_ALL_ROUTERS_MULTICAST_ADDRESS =
            { (byte) 0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 0x16 };

    /**
     * IPv6 Router Alert Option constants.
     *
     * See also:
     *     - https://tools.ietf.org/html/rfc2711
     */
    public static final int IPV6_ROUTER_ALERT_OPTION_TYPE = 5;
    public static final int IPV6_ROUTER_ALERT_OPTION_LEN = 2;

    /**
     * IPv6 MLD constants.
     *
     * See also:
     *     - https://tools.ietf.org/html/rfc2710
     *     - https://tools.ietf.org/html/rfc3810
     */
    public static final int IPV6_MLD_MESSAGE_MIN_SIZE = 8;
    public static final int IPV6_MLD_MIN_SIZE = 24;
    public static final int IPV6_MLD_TYPE_QUERY = 130;
    public static final int IPV6_MLD_TYPE_V1_REPORT = 131;
    public static final int IPV6_MLD_TYPE_V1_DONE = 132;
    public static final int IPV6_MLD_TYPE_V2_REPORT = 143;
    public static final int IPV6_MLD_V2_MULTICAST_ADDRESS_RECORD_SIZE = 20;
    // kernel reference: net/ipv6/mcast.c#igmp6_send()
    public static final byte[] IPV6_MLD_HOPOPTS = {
            (byte) IPPROTO_ICMPV6,   // next header type
            0,  // next header length
            (byte) IPV6_ROUTER_ALERT_OPTION_TYPE, // Router Alert option type
            (byte) IPV6_ROUTER_ALERT_OPTION_LEN,  // Router Alert option length
            0,  0,  // Router Alert option value
            (byte) 0x01, (byte) 0x00  // PadN type and length
    };

    public static final Set<Long> IPV6_MLD_TYPE_REPORTS = Set.of(
            (long) IPV6_MLD_TYPE_V1_REPORT,
            (long) IPV6_MLD_TYPE_V1_DONE,
            (long) IPV6_MLD_TYPE_V2_REPORT
    );
    public static final int IPV6_EXT_HEADER_OFFSET = ETH_HEADER_LEN + IPV6_HEADER_LEN;
    public static final int IPV6_MLD_CHECKSUM_OFFSET =
            ETHER_HEADER_LEN + IPV6_HEADER_LEN + IPV6_MLD_HOPOPTS.length + 2;
    public static final int IPV6_MLD_TYPE_OFFSET =
            IPV6_EXT_HEADER_OFFSET + IPV6_MLD_HOPOPTS.length;
    public static final int IPV6_MLD_MULTICAST_ADDR_OFFSET =
            IPV6_EXT_HEADER_OFFSET + IPV6_MLD_HOPOPTS.length + 8;

    public static final int ICMP4_TYPE_NO_OPTIONS_OFFSET = ETH_HEADER_LEN + IPV4_HEADER_MIN_LEN;
    public static final int ICMP4_CHECKSUM_NO_OPTIONS_OFFSET =
            ETH_HEADER_LEN + IPV4_HEADER_MIN_LEN + 2;
    public static final int ICMP4_CONTENT_NO_OPTIONS_OFFSET =
            ETH_HEADER_LEN + IPV4_HEADER_MIN_LEN + 4;

    public static final int ICMP6_ECHO_REQUEST_HEADER_LEN = 8;
    public static final int ICMP6_TYPE_OFFSET = ETH_HEADER_LEN + IPV6_HEADER_LEN;
    public static final int ICMP6_CODE_OFFSET = ETH_HEADER_LEN + IPV6_HEADER_LEN + 1;
    public static final int ICMP6_CHECKSUM_OFFSET = ETH_HEADER_LEN + IPV6_HEADER_LEN + 2;
    public static final int ICMP6_CONTENT_OFFSET = ETH_HEADER_LEN + IPV6_HEADER_LEN + 4;
    public static final int ICMP6_NS_TARGET_IP_OFFSET = ICMP6_TYPE_OFFSET + 8;
    public static final int ICMP6_NS_OPTION_TYPE_OFFSET = ICMP6_NS_TARGET_IP_OFFSET + 16;
    // From RFC4861:
    public static final int ICMP6_RA_HEADER_LEN = 16;
    public static final int ICMP6_RA_CHECKSUM_OFFSET =
            ETH_HEADER_LEN + IPV6_HEADER_LEN + 2;
    public static final int ICMP6_RA_CHECKSUM_LEN = 2;
    public static final int ICMP6_RA_OPTION_OFFSET =
            ETH_HEADER_LEN + IPV6_HEADER_LEN + ICMP6_RA_HEADER_LEN;
    public static final int ICMP6_RA_ROUTER_LIFETIME_OFFSET =
            ETH_HEADER_LEN + IPV6_HEADER_LEN + 6;
    public static final int ICMP6_RA_ROUTER_LIFETIME_LEN = 2;
    // Prefix information option.
    public static final int ICMP6_PREFIX_OPTION_TYPE = 3;
    public static final int ICMP6_PREFIX_OPTION_VALID_LIFETIME_OFFSET = 4;
    public static final int ICMP6_PREFIX_OPTION_VALID_LIFETIME_LEN = 4;
    public static final int ICMP6_PREFIX_OPTION_PREFERRED_LIFETIME_LEN = 4;

    // From RFC4861: source link-layer address
    public static final int ICMP6_SOURCE_LL_ADDRESS_OPTION_TYPE = 1;
    // From RFC4861: mtu size option
    public static final int ICMP6_MTU_OPTION_TYPE = 5;
    // From RFC6106: Recursive DNS Server option
    public static final int ICMP6_RDNSS_OPTION_TYPE = 25;
    // From RFC5175: RA Flags Extension option
    public static final int ICMP6_RA_FLAGS_EXTENSION_OPTION_TYPE = 26;
    // From RFC6106: DNS Search List option
    public static final int ICMP6_DNSSL_OPTION_TYPE = 31;
    // From RFC8910: Captive-Portal option
    public static final int ICMP6_CAPTIVE_PORTAL_OPTION_TYPE = 37;
    // From RFC8781: PREF64 option
    public static final int ICMP6_PREF64_OPTION_TYPE = 38;

    // From RFC4191: Route Information option
    public static final int ICMP6_ROUTE_INFO_OPTION_TYPE = 24;
    // Above three options all have the same format:
    public static final int ICMP6_4_BYTE_LIFETIME_OFFSET = 4;
    public static final int ICMP6_4_BYTE_LIFETIME_LEN = 4;
    public static final int IPPROTO_HOPOPTS = 0;

    // NOTE: this must be added to the IPv4 header length in MemorySlot.IPV4_HEADER_SIZE
    public static final int TCP_UDP_SOURCE_PORT_OFFSET = ETH_HEADER_LEN;
    public static final int TCP_UDP_DESTINATION_PORT_OFFSET = ETH_HEADER_LEN + 2;
    public static final int IGMP_MAX_RESP_TIME_OFFSET = ETHER_HEADER_LEN + 1;
    public static final int IGMP_MULTICAST_ADDRESS_OFFSET = ETH_HEADER_LEN + 4;
    public static final int UDP_HEADER_LEN = 8;

    public static final int TCP_HEADER_SIZE_OFFSET = 12;

    public static final int DHCP_SERVER_PORT = 67;
    public static final int DHCP_CLIENT_PORT = 68;

    public static final int DNS_HEADER_LEN = 12;
    public static final int IPV4_UDP_DESTINATION_PORT_NO_OPTIONS_OFFSET =
            ETH_HEADER_LEN + IPV4_HEADER_MIN_LEN + 2;
    public static final int IPV4_UDP_DESTINATION_CHECKSUM_NO_OPTIONS_OFFSET =
            ETH_HEADER_LEN + IPV4_HEADER_MIN_LEN + 6;
    public static final int IPV4_UDP_PAYLOAD_NO_OPTIONS_OFFSET =
            ETH_HEADER_LEN + IPV4_HEADER_MIN_LEN + UDP_HEADER_LEN;
    public static final int IPV4_DNS_QDCOUNT_NO_OPTIONS_OFFSET =
            ETH_HEADER_LEN + IPV4_HEADER_MIN_LEN + UDP_HEADER_LEN + 4;
    public static final int IPV6_UDP_DESTINATION_PORT_OFFSET =
            ETH_HEADER_LEN + IPV6_HEADER_LEN + 2;
    public static final int IPV6_UDP_DESTINATION_CHECKSUM_OFFSET =
            ETH_HEADER_LEN + IPV6_HEADER_LEN + 6;
    public static final int IPv6_UDP_PAYLOAD_OFFSET =
            ETH_HEADER_LEN + IPV6_HEADER_LEN + UDP_HEADER_LEN;
    public static final int IPV6_DNS_QDCOUNT_OFFSET =
            ETH_HEADER_LEN + IPV6_HEADER_LEN + UDP_HEADER_LEN + 4;

    public static final int ARP_HEADER_OFFSET = ETH_HEADER_LEN;
    public static final byte[] ARP_IPV4_HEADER = {
            0, 1, // Hardware type: Ethernet (1)
            8, 0, // Protocol type: IP (0x0800)
            6,    // Hardware size: 6
            4,    // Protocol size: 4
    };
    public static final int ARP_OPCODE_OFFSET = ARP_HEADER_OFFSET + 6;
    // Opcode: ARP request (0x0001), ARP reply (0x0002)
    public static final short ARP_OPCODE_REQUEST = 1;
    public static final short ARP_OPCODE_REPLY = 2;
    public static final int ARP_SOURCE_IP_ADDRESS_OFFSET = ARP_HEADER_OFFSET + 14;
    public static final int ARP_TARGET_IP_ADDRESS_OFFSET = ARP_HEADER_OFFSET + 24;
    // Limit on the Black List size to cap on program usage for this
    // TODO: Select a proper max length
    public static final int APF_MAX_ETH_TYPE_BLACK_LIST_LEN = 20;

    // The ethernet solicited nodes multicast address prefix 33:33:FF:xx:xx:xx
    public static final byte[] ETH_SOLICITED_NODES_PREFIX =
            {(byte) 0x33, (byte) 0x33, (byte) 0xff};
    public static final byte[] ETH_MULTICAST_IPV6_ALL_NODES_MAC_ADDRESS =
            { (byte) 0x33, (byte) 0x33, 0, 0, 0, 1};
    public static final byte[] ETH_MULTICAST_MDNS_V4_MAC_ADDRESS =
            {(byte) 0x01, (byte) 0x00, (byte) 0x5e, (byte) 0x00, (byte) 0x00, (byte) 0xfb};
    public static final byte[] ETH_MULTICAST_MDNS_V6_MAC_ADDRESS =
            {(byte) 0x33, (byte) 0x33, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xfb};
    public static final byte[] ETH_MULTICAST_IGMP_V3_ALL_MULTICAST_ROUTERS_ADDRESS =
            { (byte) 0x01, 0, (byte) 0x5e, 0, 0, (byte) 0x16};
    public static final byte[] ETH_MULTICAST_MLD_V2_ALL_MULTICAST_ROUTERS_ADDRESS =
            { (byte) 0x33, (byte) 0x33, 0, 0, 0, (byte) 0x16};
    public static final int MDNS_PORT = 5353;
    public static final byte[] MDNS_PORT_IN_BYTES = ByteBuffer.allocate(2).order(
            ByteOrder.BIG_ENDIAN).putShort((short) MDNS_PORT).array();

    public static final long MDNS_IPV4_ADDR_IN_LONG = 0xE00000FBL; // 224.0.0.251
    public static final byte[] MDNS_IPV4_ADDR = InetAddresses.parseNumericAddress(
            "224.0.0.251").getAddress();
    public static final byte[] MDNS_IPV6_ADDR = InetAddresses.parseNumericAddress(
            "FF02::FB").getAddress();
    public static final int ECHO_PORT = 7;
    // NOTE: this must be added to the IPv4 header length in MemorySlot.IPV4_HEADER_SIZE, or the
    // IPv6 header length.
    public static final int DHCP_CLIENT_MAC_OFFSET = ETH_HEADER_LEN + UDP_HEADER_LEN + 28;

    /**
     * Fixed byte sequence representing the following part of the ARP reply header:
     * EtherType + HTYPE + PTYPE + HLEN + PLEN + ops reply (0x0002)
     */
    public static final byte[] FIXED_ARP_REPLY_HEADER =
            new byte[]{0x08, 0x06, 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02};
}
