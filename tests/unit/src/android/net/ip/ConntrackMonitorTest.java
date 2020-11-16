/*
 * Copyright (C) 2020 The Android Open Source Project
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
package android.net.ip;

import static android.system.OsConstants.AF_UNIX;
import static android.system.OsConstants.SOCK_DGRAM;

import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;

import android.net.netlink.NetlinkSocket;
import android.net.util.SharedLog;
import android.os.ConditionVariable;
import android.os.Handler;
import android.os.HandlerThread;
import android.system.ErrnoException;
import android.system.Os;

import androidx.annotation.NonNull;
import androidx.test.filters.SmallTest;
import androidx.test.runner.AndroidJUnit4;

import libcore.util.HexEncoding;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.io.FileDescriptor;
import java.io.InterruptedIOException;


/**
 * Tests for ConntrackMonitor.
 */
@RunWith(AndroidJUnit4.class)
@SmallTest
public class ConntrackMonitorTest {
    private static final long TIMEOUT_MS = 10_000L;

    @Mock private SharedLog mLog;
    @Mock private ConntrackMonitor.ConntrackEventConsumer mConsumer;

    private final HandlerThread mHandlerThread = new HandlerThread(
            ConntrackMonitorTest.class.getSimpleName());

    // Late init since the handler thread has been started.
    private Handler mHandler;
    private TestConntrackMonitor mConntrackMonitor;

    // A version of [ConntrackMonitor] that reads packets from the socket pair, and instead
    // allows the test to write test packets to the socket pair via [sendMessage].
    private class TestConntrackMonitor extends ConntrackMonitor {
        TestConntrackMonitor(@NonNull Handler h, @NonNull SharedLog log,
                @NonNull ConntrackEventConsumer cb) {
            super(h, log, cb);

            mReadFd = new FileDescriptor();
            mWriteFd = new FileDescriptor();
            try {
                Os.socketpair(AF_UNIX, SOCK_DGRAM, 0, mWriteFd, mReadFd);
            } catch (ErrnoException e) {
                fail("Could not create socket pair: " + e);
            }
        }

        @Override
        protected FileDescriptor createFd() {
            return mReadFd;
        }

        private void sendMessage(byte[] msg) {
            mHandler.post(() -> {
                try {
                    NetlinkSocket.sendMessage(mWriteFd, msg, 0 /* offset */, msg.length,
                                              TIMEOUT_MS);
                } catch (ErrnoException | InterruptedIOException e) {
                    fail("Unable to send netfilter message: " + e);
                }
            });
        }

        private final FileDescriptor mReadFd;
        private final FileDescriptor mWriteFd;
    }

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);

        mHandlerThread.start();
        mHandler = new Handler(mHandlerThread.getLooper());

        // ConntrackMonitor needs to be started from the handler thread.
        final ConditionVariable initDone = new ConditionVariable();
        mHandler.post(() -> {
            TestConntrackMonitor m = new TestConntrackMonitor(mHandler, mLog, mConsumer);
            m.start();
            mConntrackMonitor = m;

            initDone.open();
        });
        if (!initDone.block(TIMEOUT_MS)) {
            fail("... init monitor timed-out after " + TIMEOUT_MS + "ms");
        }
    }

    @After
    public void tearDown() throws Exception {
        mHandlerThread.quitSafely();
    }

    // TODO: Add conntrack message attributes to have further verification.
    public static final String CT_V4NEW_HEX =
            // CHECKSTYLE:OFF IndentationCheck
            // struct nlmsghdr
            "14000000" +      // length = 20
            "0001" +          // type = NFNL_SUBSYS_CTNETLINK (1) << 8 | IPCTNL_MSG_CT_NEW (0)
            "0006" +          // flags = NLM_F_CREATE | NLM_F_EXCL
            "00000000" +      // seqno = 0
            "00000000" +      // pid = 0
            // struct nfgenmsg
            "02" +            // nfgen_family = AF_INET
            "00" +            // version = NFNETLINK_V0
            "0000";           // res_id
            // CHECKSTYLE:ON IndentationCheck
    public static final byte[] CT_V4NEW_BYTES =
            HexEncoding.decode(CT_V4NEW_HEX.replaceAll(" ", "").toCharArray(), false);

    @Test
    public void testConntrackEvent_New() throws Exception {
        mConntrackMonitor.sendMessage(CT_V4NEW_BYTES);
        verify(mConsumer, timeout(TIMEOUT_MS)).accept(any() /* TODO: check the content */);
    }
}
