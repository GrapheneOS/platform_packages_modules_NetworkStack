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

package android.net.shared;

import static android.net.RouteInfo.RTN_UNICAST;

import android.net.INetd;
import android.net.IpPrefix;
import android.net.RouteInfo;
import android.net.TetherConfigParcel;
import android.os.RemoteException;
import android.os.ServiceSpecificException;

import java.util.ArrayList;
import java.util.List;

/**
 * Implements common operations on INetd
 * @hide
 */
public class NetdUtils {
    /** Start tethering. */
    public static void tetherStart(final INetd netd, final boolean usingLegacyDnsProxy,
            final String[] dhcpRange) throws RemoteException, ServiceSpecificException {
        final TetherConfigParcel config = new TetherConfigParcel();
        config.usingLegacyDnsProxy = usingLegacyDnsProxy;
        config.dhcpRanges = dhcpRange;
        netd.tetherStartWithConfiguration(config);
    }

    /** Setup interface for tethering. */
    public static void tetherInterface(final INetd netd, final String iface, final IpPrefix dest)
            throws RemoteException, ServiceSpecificException {
        netd.tetherInterfaceAdd(iface);

        netd.networkAddInterface(INetd.LOCAL_NET_ID, iface);
        List<RouteInfo> routes = new ArrayList<>();
        routes.add(new RouteInfo(dest, null, iface, RTN_UNICAST));
        RouteUtils.addRoutesToLocalNetwork(netd, iface, routes);
    }

    /** Reset interface for tethering. */
    public static void untetherInterface(final INetd netd, String iface)
            throws RemoteException, ServiceSpecificException {
        try {
            netd.tetherInterfaceRemove(iface);
        } finally {
            netd.networkRemoveInterface(INetd.LOCAL_NET_ID, iface);
        }
    }
}
