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

import static android.net.util.DataStallUtils.CONFIG_TCP_PACKETS_FAIL_RATE;
import static android.net.util.DataStallUtils.DEFAULT_TCP_PACKETS_FAIL_PERCENTAGE;
import static android.provider.DeviceConfig.NAMESPACE_CONNECTIVITY;
import static android.system.OsConstants.AF_INET;

import static com.android.networkstack.netlink.TcpSocketTracker.SOCKDIAG_MSG_HEADER_SIZE;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertFalse;
import static junit.framework.Assert.assertTrue;

import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.when;

import android.net.netlink.StructNlMsgHdr;

import androidx.test.filters.SmallTest;
import androidx.test.runner.AndroidJUnit4;

import libcore.util.HexEncoding;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.io.FileDescriptor;
import java.nio.ByteBuffer;
import java.util.HashMap;

// TODO: Add more tests for missing coverage.
@RunWith(AndroidJUnit4.class)
@SmallTest
public class TcpSocketTrackerTest {
    private static final int TEST_BUFFER_SIZE = 1024;
    private static final String DIAG_MSG_HEX =
            // struct nlmsghdr.
            "00000058" +      // length = 88
            "0020" +         // type = SOCK_DIAG_BY_FAMILY
            "0103" +         // flags = NLM_F_REQUEST | NLM_F_DUMP
            "00000000" +     // seqno
            "00000000" +     // pid (0 == kernel)
            // struct inet_diag_req_v2
            "02" +           // family = AF_INET
            "06" +           // state
            "00" +           // timer
            "00" +           // retrans
            // inet_diag_sockid
            "A5DE" +         // idiag_sport = 42462
            "B971" +         // idiag_dport = 47473
            "0a006402000000000000000000000000" + // idiag_src = 10.0.100.2
            "08080808000000000000000000000000" + // idiag_dst = 8.8.8.8
            "00000000" +    // idiag_if
            "000027760000ED34" + // idiag_cookie = 43387759684916
            "00000000" +    // idiag_expires
            "00000000" +    // idiag_rqueue
            "00000000" +    // idiag_wqueue
            "00000000" +    // idiag_uid
            "00000000";    // idiag_inode
    private static final byte[] SOCK_DIAG_MSG_BYTES =
            HexEncoding.decode(DIAG_MSG_HEX.toCharArray(), false);
    // Hexadecimal representation of a SOCK_DIAG response with tcp info.
    private static final String SOCK_DIAG_TCP_INET_HEX =
            // struct nlmsghdr.
            "00000114" +        // length = 276
            "0020" +            // type = SOCK_DIAG_BY_FAMILY
            "0103" +            // flags = NLM_F_REQUEST | NLM_F_DUMP
            "00000000" +        // seqno
            "00000000" +        // pid (0 == kernel)
            // struct inet_diag_req_v2
            "02" +              // family = AF_INET
            "06" +              // state
            "00" +              // timer
            "00" +              // retrans
            // inet_diag_sockid
            "A5DE" +            // idiag_sport = 42462
            "B971" +            // idiag_dport = 47473
            "0a006402000000000000000000000000" + // idiag_src = 10.0.100.2
            "08080808000000000000000000000000" + // idiag_dst = 8.8.8.8
            "00000000" +            // idiag_if
            "000027760000ED34" +    // idiag_cookie = 43387759684916
            "00000000" +            // idiag_expires
            "00000000" +            // idiag_rqueue
            "00000000" +            // idiag_wqueue
            "00000000" +            // idiag_uid
            "00000000" +            // idiag_inode
            // rtattr
            "0005" +            // len = 5
            "0008" +            // type = 8
            "00000000" +        // data
            "0008" +            // len = 8
            "000F" +            // type = 15(INET_DIAG_MARK)
            "000C0064" +        // data, socket mark=786532
            "00AC" +            // len = 172
            "0002" +            // type = 2(INET_DIAG_INFO)
            // tcp_info
            "01" +              // state = TCP_ESTABLISHED
            "00" +              // ca_state = TCP_CA_OPEN
            "05" +              // retransmits = 5
            "00" +              // probes = 0
            "00" +              // backoff = 0
            "07" +              // option = TCPI_OPT_WSCALE|TCPI_OPT_SACK|TCPI_OPT_TIMESTAMPS
            "88" +              // wscale = 8
            "00" +              // delivery_rate_app_limited = 0
            "001B914A" +        // rto = 1806666
            "00000000" +        // ato = 0
            "0000052E" +        // sndMss = 1326
            "00000218" +        // rcvMss = 536
            "00000000" +        // unsacked = 0
            "00000000" +        // acked = 0
            "00000005" +        // lost = 5
            "00000000" +        // retrans = 0
            "00000000" +        // fackets = 0
            "000000BB" +        // lastDataSent = 187
            "00000000" +        // lastAckSent = 0
            "000000BB" +        // lastDataRecv = 187
            "000000BB" +        // lastDataAckRecv = 187
            "000005DC" +        // pmtu = 1500
            "00015630" +        // rcvSsthresh = 87600
            "00092C3E" +        // rttt = 601150
            "0004961F" +        // rttvar = 300575
            "00000578" +        // sndSsthresh = 1400
            "0000000A" +        // sndCwnd = 10
            "000005A8" +        // advmss = 1448
            "00000003" +        // reordering = 3
            "00000000" +        // rcvrtt = 0
            "00015630" +        // rcvspace = 87600
            "00000000" +        // totalRetrans = 0
            "000000000000AC53" +    // pacingRate = 44115
            "FFFFFFFFFFFFFFFF" +    // maxPacingRate = 18446744073709551615
            "0000000000000001" +    // bytesAcked = 1
            "0000000000000000" +    // bytesReceived = 0
            "0000000A" +        // SegsOut = 10
            "00000000" +        // SegsIn = 0
            "00000000" +        // NotSentBytes = 0
            "00092C3E" +        // minRtt = 601150
            "00000000" +        // DataSegsIn = 0
            "00000000" +        // DataSegsOut = 0
            "0000000000000000"; // deliverRate = 0
    private static final byte[] SOCK_DIAG_TCP_INET_BYTES =
            HexEncoding.decode(SOCK_DIAG_TCP_INET_HEX.toCharArray(), false);

    private static final String TEST_RESPONSE_HEX = SOCK_DIAG_TCP_INET_HEX
            // struct nlmsghdr
            + "00000014"     // length = 20
            + "0003"         // type = NLMSG_DONE
            + "0103"         // flags = NLM_F_REQUEST | NLM_F_DUMP
            + "00000000"     // seqno
            + "00000000"     // pid (0 == kernel)
            // struct inet_diag_req_v2
            + "02"           // family = AF_INET
            + "06"           // state
            + "00"           // timer
            + "00";          // retrans
    private static final byte[] TEST_RESPONSE_BYTES =
            HexEncoding.decode(TEST_RESPONSE_HEX.toCharArray(), false);
    @Mock private TcpSocketTracker.Dependencies mDependencies;
    @Mock private FileDescriptor mMockFd;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        when(mDependencies.isTcpInfoParsingSupported()).thenReturn(true);
        when(mDependencies.connectToKernel()).thenReturn(mMockFd);
        when(mDependencies.getDeviceConfigPropertyInt(
                eq(NAMESPACE_CONNECTIVITY),
                eq(CONFIG_TCP_PACKETS_FAIL_RATE),
                anyInt())).thenReturn(DEFAULT_TCP_PACKETS_FAIL_PERCENTAGE);
    }

    @Test
    public void testParseSockInfo() {
        final ByteBuffer buffer = ByteBuffer.wrap(SOCK_DIAG_TCP_INET_BYTES);
        final TcpSocketTracker tst = new TcpSocketTracker(mDependencies);
        buffer.position(SOCKDIAG_MSG_HEADER_SIZE);
        final TcpSocketTracker.SocketInfo parsed =
                tst.parseSockInfo(buffer, AF_INET, 276, 100L);
        final HashMap<TcpInfo.Field, Number> expected = new HashMap<>();
        expected.put(TcpInfo.Field.STATE, (byte) 0x01);
        expected.put(TcpInfo.Field.CASTATE, (byte) 0x00);
        expected.put(TcpInfo.Field.RETRANSMITS, (byte) 0x05);
        expected.put(TcpInfo.Field.PROBES, (byte) 0x00);
        expected.put(TcpInfo.Field.BACKOFF, (byte) 0x00);
        expected.put(TcpInfo.Field.OPTIONS, (byte) 0x07);
        expected.put(TcpInfo.Field.WSCALE, (byte) 0x88);
        expected.put(TcpInfo.Field.DELIVERY_RATE_APP_LIMITED, (byte) 0x00);
        expected.put(TcpInfo.Field.RTO, 1806666);
        expected.put(TcpInfo.Field.ATO, 0);
        expected.put(TcpInfo.Field.SND_MSS, 1326);
        expected.put(TcpInfo.Field.RCV_MSS, 536);
        expected.put(TcpInfo.Field.UNACKED, 0);
        expected.put(TcpInfo.Field.SACKED, 0);
        expected.put(TcpInfo.Field.LOST, 5);
        expected.put(TcpInfo.Field.RETRANS, 0);
        expected.put(TcpInfo.Field.FACKETS, 0);
        expected.put(TcpInfo.Field.LAST_DATA_SENT, 187);
        expected.put(TcpInfo.Field.LAST_ACK_SENT, 0);
        expected.put(TcpInfo.Field.LAST_DATA_RECV, 187);
        expected.put(TcpInfo.Field.LAST_ACK_RECV, 187);
        expected.put(TcpInfo.Field.PMTU, 1500);
        expected.put(TcpInfo.Field.RCV_SSTHRESH, 87600);
        expected.put(TcpInfo.Field.RTT, 601150);
        expected.put(TcpInfo.Field.RTTVAR, 300575);
        expected.put(TcpInfo.Field.SND_SSTHRESH, 1400);
        expected.put(TcpInfo.Field.SND_CWND, 10);
        expected.put(TcpInfo.Field.ADVMSS, 1448);
        expected.put(TcpInfo.Field.REORDERING, 3);
        expected.put(TcpInfo.Field.RCV_RTT, 0);
        expected.put(TcpInfo.Field.RCV_SPACE, 87600);
        expected.put(TcpInfo.Field.TOTAL_RETRANS, 0);
        expected.put(TcpInfo.Field.PACING_RATE, 44115L);
        expected.put(TcpInfo.Field.MAX_PACING_RATE, -1L);
        expected.put(TcpInfo.Field.BYTES_ACKED, 1L);
        expected.put(TcpInfo.Field.BYTES_RECEIVED, 0L);
        expected.put(TcpInfo.Field.SEGS_OUT, 10);
        expected.put(TcpInfo.Field.SEGS_IN, 0);
        expected.put(TcpInfo.Field.NOTSENT_BYTES, 0);
        expected.put(TcpInfo.Field.MIN_RTT, 601150);
        expected.put(TcpInfo.Field.DATA_SEGS_IN, 0);
        expected.put(TcpInfo.Field.DATA_SEGS_OUT, 0);
        expected.put(TcpInfo.Field.DELIVERY_RATE, 0L);

        assertEquals(parsed.tcpInfo, new TcpInfo(expected));
        assertEquals(parsed.fwmark, 786532);
        assertEquals(parsed.updateTime, 100);
        assertEquals(parsed.ipFamily, AF_INET);
    }

    @Test
    public void testEnoughBytesRemainForValidNlMsg() {
        final ByteBuffer buffer = ByteBuffer.allocate(TEST_BUFFER_SIZE);

        buffer.position(TEST_BUFFER_SIZE - StructNlMsgHdr.STRUCT_SIZE);
        assertTrue(TcpSocketTracker.enoughBytesRemainForValidNlMsg(buffer));
        // Remaining buffer size is less than a valid StructNlMsgHdr size.
        buffer.position(TEST_BUFFER_SIZE - StructNlMsgHdr.STRUCT_SIZE + 1);
        assertFalse(TcpSocketTracker.enoughBytesRemainForValidNlMsg(buffer));

        buffer.position(TEST_BUFFER_SIZE);
        assertFalse(TcpSocketTracker.enoughBytesRemainForValidNlMsg(buffer));
    }

    @Test
    public void testIsDataStallSuspected() {
        when(mDependencies.isTcpInfoParsingSupported()).thenReturn(false);
        final TcpSocketTracker tst = new TcpSocketTracker(mDependencies);
        assertFalse(tst.isDataStallSuspected());
        when(mDependencies.isTcpInfoParsingSupported()).thenReturn(true);
        assertFalse(tst.isDataStallSuspected());
        when(mDependencies.getDeviceConfigPropertyInt(any(), eq(CONFIG_TCP_PACKETS_FAIL_RATE),
                anyInt())).thenReturn(0);
        assertTrue(tst.isDataStallSuspected());
    }

    @Test
    public void testPollSocketsInfo() throws Exception {
        when(mDependencies.isTcpInfoParsingSupported()).thenReturn(false);
        final TcpSocketTracker tst = new TcpSocketTracker(mDependencies);
        assertFalse(tst.pollSocketsInfo());

        when(mDependencies.isTcpInfoParsingSupported()).thenReturn(true);
        // No enough bytes remain for a valid NlMsg.
        final ByteBuffer invalidBuffer = ByteBuffer.allocate(1);
        when(mDependencies.recvMesssage(any())).thenReturn(invalidBuffer);
        assertTrue(tst.pollSocketsInfo());
        assertEquals(0, tst.getLatestPacketFailRate());
        assertEquals(0, tst.getSentSinceLastRecv());

        // Header only.
        final ByteBuffer headerBuffer = ByteBuffer.wrap(SOCK_DIAG_MSG_BYTES);
        when(mDependencies.recvMesssage(any())).thenReturn(headerBuffer);
        assertTrue(tst.pollSocketsInfo());
        assertEquals(0, tst.getSentSinceLastRecv());
        assertEquals(0, tst.getLatestPacketFailRate());

        final ByteBuffer tcpBuffer = ByteBuffer.wrap(TEST_RESPONSE_BYTES);
        when(mDependencies.recvMesssage(any())).thenReturn(tcpBuffer);
        assertTrue(tst.pollSocketsInfo());
        assertEquals(10, tst.getSentSinceLastRecv());
        assertEquals(100, tst.getLatestPacketFailRate());
    }
}
