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

import android.net.netlink.ConntrackMessage;
import android.net.netlink.NetlinkMessage;
import android.net.util.SharedLog;
import android.os.Handler;
import android.system.OsConstants;

import androidx.annotation.NonNull;

/**
 * ConntrackMonitor.
 *
 * Monitors the netfilter conntrack notifications and presents to callers
 * ConntrackEvents describing each event.
 *
 * @hide
 */
public class ConntrackMonitor extends NetlinkMonitor {
    private static final String TAG = ConntrackMonitor.class.getSimpleName();
    private static final boolean DBG = false;
    private static final boolean VDBG = false;

    // Reference kernel/uapi/linux/netfilter/nfnetlink_compat.h
    public static final int NF_NETLINK_CONNTRACK_NEW = 1;
    public static final int NF_NETLINK_CONNTRACK_UPDATE = 2;
    public static final int NF_NETLINK_CONNTRACK_DESTROY = 4;

    /**
     * A class for describing parsed netfilter conntrack events.
     */
    public static class ConntrackEvent { /*TODO*/ }

    /**
     * A callback to caller for conntrack event.
     */
    public interface ConntrackEventConsumer {
        /**
         * Every conntrack event received on the netlink socket is passed in
         * here.
         */
        void accept(@NonNull ConntrackEvent event);
    }

    private final ConntrackEventConsumer mConsumer;

    public ConntrackMonitor(@NonNull Handler h, @NonNull SharedLog log,
            @NonNull ConntrackEventConsumer cb) {
        super(h, log, TAG, OsConstants.NETLINK_NETFILTER, NF_NETLINK_CONNTRACK_NEW
                | NF_NETLINK_CONNTRACK_UPDATE | NF_NETLINK_CONNTRACK_DESTROY);
        mConsumer = cb;
    }

    @Override
    public void processNetlinkMessage(NetlinkMessage nlMsg, final long whenMs) {
        if (!(nlMsg instanceof ConntrackMessage)) {
            mLog.e("non-conntrack msg: " + nlMsg);
            return;
        }

        mConsumer.accept(new ConntrackEvent() /* TODO */);
    }
}
