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

import static android.net.apf.ApfConstants.APF_MAX_ETH_TYPE_BLACK_LIST_LEN;
import static android.net.apf.ApfConstants.ARP_HEADER_OFFSET;
import static android.net.apf.ApfConstants.ARP_IPV4_HEADER;
import static android.net.apf.ApfConstants.ARP_OPCODE_OFFSET;
import static android.net.apf.ApfConstants.ARP_OPCODE_REPLY;
import static android.net.apf.ApfConstants.ARP_OPCODE_REQUEST;
import static android.net.apf.ApfConstants.ARP_SOURCE_IP_ADDRESS_OFFSET;
import static android.net.apf.ApfConstants.ARP_TARGET_IP_ADDRESS_OFFSET;
import static android.net.apf.ApfConstants.DHCP_CLIENT_MAC_OFFSET;
import static android.net.apf.ApfConstants.DHCP_CLIENT_PORT;
import static android.net.apf.ApfConstants.DHCP_SERVER_PORT;
import static android.net.apf.ApfConstants.ECHO_PORT;
import static android.net.apf.ApfConstants.ETH_DEST_ADDR_OFFSET;
import static android.net.apf.ApfConstants.ETH_ETHERTYPE_OFFSET;
import static android.net.apf.ApfConstants.ETH_HEADER_LEN;
import static android.net.apf.ApfConstants.ETH_MULTICAST_MDNS_V4_MAC_ADDRESS;
import static android.net.apf.ApfConstants.ETH_MULTICAST_MDNS_V6_MAC_ADDRESS;
import static android.net.apf.ApfConstants.ETH_TYPE_MAX;
import static android.net.apf.ApfConstants.ETH_TYPE_MIN;
import static android.net.apf.ApfConstants.FIXED_ARP_REPLY_HEADER;
import static android.net.apf.ApfConstants.ICMP6_4_BYTE_LIFETIME_LEN;
import static android.net.apf.ApfConstants.ICMP6_4_BYTE_LIFETIME_OFFSET;
import static android.net.apf.ApfConstants.ICMP6_CAPTIVE_PORTAL_OPTION_TYPE;
import static android.net.apf.ApfConstants.ICMP6_CHECKSUM_OFFSET;
import static android.net.apf.ApfConstants.ICMP6_CODE_OFFSET;
import static android.net.apf.ApfConstants.ICMP6_DNSSL_OPTION_TYPE;
import static android.net.apf.ApfConstants.ICMP6_MTU_OPTION_TYPE;
import static android.net.apf.ApfConstants.ICMP6_NS_OPTION_TYPE_OFFSET;
import static android.net.apf.ApfConstants.ICMP6_NS_TARGET_IP_OFFSET;
import static android.net.apf.ApfConstants.ICMP6_PREF64_OPTION_TYPE;
import static android.net.apf.ApfConstants.ICMP6_PREFIX_OPTION_PREFERRED_LIFETIME_LEN;
import static android.net.apf.ApfConstants.ICMP6_PREFIX_OPTION_TYPE;
import static android.net.apf.ApfConstants.ICMP6_PREFIX_OPTION_VALID_LIFETIME_LEN;
import static android.net.apf.ApfConstants.ICMP6_PREFIX_OPTION_VALID_LIFETIME_OFFSET;
import static android.net.apf.ApfConstants.ICMP6_RA_CHECKSUM_LEN;
import static android.net.apf.ApfConstants.ICMP6_RA_CHECKSUM_OFFSET;
import static android.net.apf.ApfConstants.ICMP6_RA_OPTION_OFFSET;
import static android.net.apf.ApfConstants.ICMP6_RA_ROUTER_LIFETIME_LEN;
import static android.net.apf.ApfConstants.ICMP6_RA_ROUTER_LIFETIME_OFFSET;
import static android.net.apf.ApfConstants.ICMP6_RDNSS_OPTION_TYPE;
import static android.net.apf.ApfConstants.ICMP6_ROUTE_INFO_OPTION_TYPE;
import static android.net.apf.ApfConstants.ICMP6_SOURCE_LL_ADDRESS_OPTION_TYPE;
import static android.net.apf.ApfConstants.ICMP6_TYPE_OFFSET;
import static android.net.apf.ApfConstants.IPPROTO_HOPOPTS;
import static android.net.apf.ApfConstants.IPV4_ANY_HOST_ADDRESS;
import static android.net.apf.ApfConstants.IPV4_BROADCAST_ADDRESS;
import static android.net.apf.ApfConstants.IPV4_DEST_ADDR_OFFSET;
import static android.net.apf.ApfConstants.IPV4_FRAGMENT_MORE_FRAGS_MASK;
import static android.net.apf.ApfConstants.IPV4_FRAGMENT_OFFSET_MASK;
import static android.net.apf.ApfConstants.IPV4_FRAGMENT_OFFSET_OFFSET;
import static android.net.apf.ApfConstants.IPV4_PROTOCOL_OFFSET;
import static android.net.apf.ApfConstants.IPV4_TOTAL_LENGTH_OFFSET;
import static android.net.apf.ApfConstants.IPV6_ALL_NODES_ADDRESS;
import static android.net.apf.ApfConstants.IPV6_DEST_ADDR_OFFSET;
import static android.net.apf.ApfConstants.IPV6_FLOW_LABEL_LEN;
import static android.net.apf.ApfConstants.IPV6_FLOW_LABEL_OFFSET;
import static android.net.apf.ApfConstants.IPV6_HEADER_LEN;
import static android.net.apf.ApfConstants.IPV6_HOP_LIMIT_OFFSET;
import static android.net.apf.ApfConstants.IPV6_NEXT_HEADER_OFFSET;
import static android.net.apf.ApfConstants.IPV6_PAYLOAD_LEN_OFFSET;
import static android.net.apf.ApfConstants.IPV6_SOLICITED_NODES_PREFIX;
import static android.net.apf.ApfConstants.IPV6_SRC_ADDR_OFFSET;
import static android.net.apf.ApfConstants.IPV6_UNSPECIFIED_ADDRESS;
import static android.net.apf.ApfConstants.MDNS_PORT;
import static android.net.apf.ApfConstants.TCP_HEADER_SIZE_OFFSET;
import static android.net.apf.ApfConstants.TCP_UDP_DESTINATION_PORT_OFFSET;
import static android.net.apf.ApfConstants.TCP_UDP_SOURCE_PORT_OFFSET;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_NS_INVALID;
import static android.net.apf.ApfCounterTracker.Counter.DROPPED_IPV6_NS_OTHER_HOST;
import static android.net.apf.ApfCounterTracker.Counter.FILTER_AGE_16384THS;
import static android.net.apf.ApfCounterTracker.Counter.FILTER_AGE_SECONDS;
import static android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_NS_DAD;
import static android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_NS_NO_SLLA_OPTION;
import static android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_NS_TENTATIVE;
import static android.net.apf.ApfCounterTracker.Counter.PASSED_IPV6_NS_NO_ADDRESS;
import static android.net.apf.BaseApfGenerator.MemorySlot;
import static android.net.apf.BaseApfGenerator.Register.R0;
import static android.net.apf.BaseApfGenerator.Register.R1;
import static android.net.util.SocketUtils.makePacketSocketAddress;
import static android.os.PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED;
import static android.os.PowerManager.ACTION_DEVICE_LIGHT_IDLE_MODE_CHANGED;
import static android.system.OsConstants.AF_PACKET;
import static android.system.OsConstants.ETH_P_ARP;
import static android.system.OsConstants.ETH_P_IP;
import static android.system.OsConstants.ETH_P_IPV6;
import static android.system.OsConstants.IFA_F_TENTATIVE;
import static android.system.OsConstants.IPPROTO_ICMPV6;
import static android.system.OsConstants.IPPROTO_TCP;
import static android.system.OsConstants.IPPROTO_UDP;
import static android.system.OsConstants.SOCK_CLOEXEC;
import static android.system.OsConstants.SOCK_RAW;

import static com.android.net.module.util.NetworkStackConstants.ETHER_ADDR_LEN;
import static com.android.net.module.util.NetworkStackConstants.ETHER_BROADCAST;
import static com.android.net.module.util.NetworkStackConstants.ETHER_HEADER_LEN;
import static com.android.net.module.util.NetworkStackConstants.ETHER_SRC_ADDR_OFFSET;
import static com.android.net.module.util.NetworkStackConstants.ICMPV6_ECHO_REQUEST_TYPE;
import static com.android.net.module.util.NetworkStackConstants.ICMPV6_NA_HEADER_LEN;
import static com.android.net.module.util.NetworkStackConstants.ICMPV6_ND_OPTION_SLLA;
import static com.android.net.module.util.NetworkStackConstants.ICMPV6_ND_OPTION_TLLA;
import static com.android.net.module.util.NetworkStackConstants.ICMPV6_ND_OPTION_TLLA_LEN;
import static com.android.net.module.util.NetworkStackConstants.ICMPV6_NEIGHBOR_ADVERTISEMENT;
import static com.android.net.module.util.NetworkStackConstants.ICMPV6_NEIGHBOR_SOLICITATION;
import static com.android.net.module.util.NetworkStackConstants.ICMPV6_ROUTER_ADVERTISEMENT;
import static com.android.net.module.util.NetworkStackConstants.ICMPV6_ROUTER_SOLICITATION;
import static com.android.net.module.util.NetworkStackConstants.IPV4_ADDR_LEN;
import static com.android.net.module.util.NetworkStackConstants.IPV6_ADDR_LEN;

import android.annotation.NonNull;
import android.annotation.Nullable;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.MacAddress;
import android.net.NattKeepalivePacketDataParcelable;
import android.net.TcpKeepalivePacketDataParcelable;
import android.net.apf.ApfCounterTracker.Counter;
import android.net.apf.BaseApfGenerator.IllegalInstructionException;
import android.net.ip.IpClient.IpClientCallbacksWrapper;
import android.os.PowerManager;
import android.os.SystemClock;
import android.stats.connectivity.NetworkQuirkEvent;
import android.system.ErrnoException;
import android.system.Os;
import android.text.format.DateUtils;
import android.util.ArraySet;
import android.util.Log;
import android.util.Pair;
import android.util.SparseArray;

import com.android.internal.annotations.GuardedBy;
import com.android.internal.annotations.VisibleForTesting;
import com.android.internal.util.HexDump;
import com.android.internal.util.IndentingPrintWriter;
import com.android.internal.util.TokenBucket;
import com.android.modules.utils.build.SdkLevel;
import com.android.net.module.util.CollectionUtils;
import com.android.net.module.util.ConnectivityUtils;
import com.android.net.module.util.InterfaceParams;
import com.android.net.module.util.SocketUtils;
import com.android.networkstack.metrics.ApfSessionInfoMetrics;
import com.android.networkstack.metrics.IpClientRaInfoMetrics;
import com.android.networkstack.metrics.NetworkQuirkMetrics;
import com.android.networkstack.util.NetworkStackUtils;

import java.io.FileDescriptor;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * For networks that support packet filtering via APF programs, {@code ApfFilter}
 * listens for IPv6 ICMPv6 router advertisements (RAs) and generates APF programs to
 * filter out redundant duplicate ones.
 * <p>
 * Threading model:
 * A collection of RAs we've received is kept in mRas. Generating APF programs uses mRas to
 * know what RAs to filter for, thus generating APF programs is dependent on mRas.
 * mRas can be accessed by multiple threads:
 * - ReceiveThread, which listens for RAs and adds them to mRas, and generates APF programs.
 * - callers of:
 *    - setMulticastFilter(), which can cause an APF program to be generated.
 *    - dump(), which dumps mRas among other things.
 *    - shutdown(), which clears mRas.
 * So access to mRas is synchronized.
 *
 * @hide
 */
public class ApfFilter implements AndroidPacketFilter {

    // Helper class for specifying functional filter parameters.
    public static class ApfConfiguration {
        public int apfVersionSupported;
        public int apfRamSize;
        public int installableProgramSizeClamp = Integer.MAX_VALUE;
        public boolean multicastFilter;
        public boolean ieee802_3Filter;
        public int[] ethTypeBlackList;
        public int minRdnssLifetimeSec;
        public int acceptRaMinLft;
        public long minMetricsSessionDurationMs;
        public boolean hasClatInterface;
        public boolean shouldHandleArpOffload;
        public boolean shouldHandleNdOffload;
    }

    /** A wrapper class of {@link SystemClock} to be mocked in unit tests. */
    public static class Clock {
        /**
         * @see SystemClock#elapsedRealtime
         */
        public long elapsedRealtime() {
            return SystemClock.elapsedRealtime();
        }
    }

    // Thread to listen for RAs.
    @VisibleForTesting
    public class ReceiveThread extends Thread {
        private final byte[] mPacket = new byte[1514];
        private final FileDescriptor mSocket;

        private volatile boolean mStopped;

        public ReceiveThread(FileDescriptor socket) {
            mSocket = socket;
        }

        public void halt() {
            mStopped = true;
            // Interrupts the read() call the thread is blocked in.
            SocketUtils.closeSocketQuietly(mSocket);
        }

        @Override
        public void run() {
            log("begin monitoring");
            while (!mStopped) {
                try {
                    int length = Os.read(mSocket, mPacket, 0, mPacket.length);
                    processRa(mPacket, length);
                } catch (IOException|ErrnoException e) {
                    if (!mStopped) {
                        Log.e(TAG, "Read error", e);
                    }
                }
            }
        }
    }

    private static final String TAG = "ApfFilter";
    private static final boolean DBG = true;
    private static final boolean VDBG = false;

    private final int mApfRamSize;
    private final int mMaximumApfProgramSize;
    private final int mInstallableProgramSizeClamp;
    private final IpClientCallbacksWrapper mIpClientCallback;
    private final InterfaceParams mInterfaceParams;
    private final TokenBucket mTokenBucket;

    @VisibleForTesting
    public final int mApfVersionSupported;
    @VisibleForTesting
    @NonNull
    public final byte[] mHardwareAddress;
    @VisibleForTesting
    public ReceiveThread mReceiveThread;
    @GuardedBy("this")
    private long mUniqueCounter;
    @GuardedBy("this")
    private boolean mMulticastFilter;
    @GuardedBy("this")
    private boolean mInDozeMode;
    private final boolean mDrop802_3Frames;
    private final int[] mEthTypeBlackList;

    private final Clock mClock;
    private final ApfCounterTracker mApfCounterTracker = new ApfCounterTracker();
    @GuardedBy("this")
    private final long mSessionStartMs;
    @GuardedBy("this")
    private int mNumParseErrorRas = 0;
    @GuardedBy("this")
    private int mNumZeroLifetimeRas = 0;
    @GuardedBy("this")
    private int mLowestRouterLifetimeSeconds = Integer.MAX_VALUE;
    @GuardedBy("this")
    private long mLowestPioValidLifetimeSeconds = Long.MAX_VALUE;
    @GuardedBy("this")
    private long mLowestRioRouteLifetimeSeconds = Long.MAX_VALUE;
    @GuardedBy("this")
    private long mLowestRdnssLifetimeSeconds = Long.MAX_VALUE;

    // Ignore non-zero RDNSS lifetimes below this value.
    private final int mMinRdnssLifetimeSec;

    // Minimum session time for metrics, duration less than this time will not be logged.
    private final long mMinMetricsSessionDurationMs;

    // Tracks the value of /proc/sys/ipv6/conf/$iface/accept_ra_min_lft which affects router, RIO,
    // and PIO valid lifetimes.
    private final int mAcceptRaMinLft;
    private final boolean mShouldHandleArpOffload;
    private final boolean mShouldHandleNdOffload;

    private final NetworkQuirkMetrics mNetworkQuirkMetrics;
    private final IpClientRaInfoMetrics mIpClientRaInfoMetrics;
    private final ApfSessionInfoMetrics mApfSessionInfoMetrics;

    private static boolean isDeviceIdleModeChangedAction(Intent intent) {
        return ACTION_DEVICE_IDLE_MODE_CHANGED.equals(intent.getAction());
    }

    private boolean isDeviceLightIdleModeChangedAction(Intent intent) {
        // The ACTION_DEVICE_LIGHT_IDLE_MODE_CHANGED only exist since T. For lower platform version,
        // the check should return false. The explicit SDK check is needed to make linter happy
        // about accessing ACTION_DEVICE_LIGHT_IDLE_MODE_CHANGED in this function.
        if (!SdkLevel.isAtLeastT()) {
            return false;
        }
        return ACTION_DEVICE_LIGHT_IDLE_MODE_CHANGED.equals(intent.getAction());
    }

    private boolean isDeviceLightIdleMode(@NonNull PowerManager powerManager) {
        // The powerManager.isDeviceLightIdleMode() only exist since T. For lower platform version,
        // the check should return false. The explicit SDK check is needed to make linter happy
        // about accessing powerManager.isDeviceLightIdleMode() in this function.
        if (!SdkLevel.isAtLeastT()) {
            return false;
        }

        return powerManager.isDeviceLightIdleMode();
    }

    // Detects doze mode state transitions.
    private final BroadcastReceiver mDeviceIdleReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            final PowerManager powerManager = context.getSystemService(PowerManager.class);
            if (isDeviceIdleModeChangedAction(intent)
                    || isDeviceLightIdleModeChangedAction(intent)) {
                final boolean deviceIdle = powerManager.isDeviceIdleMode()
                        || isDeviceLightIdleMode(powerManager);
                setDozeMode(deviceIdle);
            }
        }
    };

    // Our IPv4 address, if we have just one, otherwise null.
    @GuardedBy("this")
    private byte[] mIPv4Address;
    // The subnet prefix length of our IPv4 network. Only valid if mIPv4Address is not null.
    @GuardedBy("this")
    private int mIPv4PrefixLength;

    // Our IPv6 non-tentative addresses
    @GuardedBy("this")
    private Set<Inet6Address> mIPv6NonTentativeAddresses = new ArraySet<>();

    // Our tentative IPv6 addresses
    @GuardedBy("this")
    private Set<Inet6Address> mIPv6TentativeAddresses = new ArraySet<>();

    // Whether CLAT is enabled.
    @GuardedBy("this")
    private boolean mHasClat;

    // mIsRunning is reflects the state of the ApfFilter during integration tests. ApfFilter can be
    // paused using "adb shell cmd apf <iface> <cmd>" commands. A paused ApfFilter will not install
    // any new programs, but otherwise operates normally.
    private volatile boolean mIsRunning = true;

    private final Dependencies mDependencies;

    public ApfFilter(Context context, ApfConfiguration config, InterfaceParams ifParams,
            IpClientCallbacksWrapper ipClientCallback, NetworkQuirkMetrics networkQuirkMetrics) {
        this(context, config, ifParams, ipClientCallback, networkQuirkMetrics,
                new Dependencies(context), new Clock());
    }

    @VisibleForTesting
    public ApfFilter(Context context, ApfConfiguration config, InterfaceParams ifParams,
            IpClientCallbacksWrapper ipClientCallback, NetworkQuirkMetrics networkQuirkMetrics,
            Dependencies dependencies) {
        this(context, config, ifParams, ipClientCallback, networkQuirkMetrics, dependencies,
                new Clock());
    }

    @VisibleForTesting
    public ApfFilter(Context context, ApfConfiguration config, InterfaceParams ifParams,
            IpClientCallbacksWrapper ipClientCallback, NetworkQuirkMetrics networkQuirkMetrics,
            Dependencies dependencies, Clock clock) {
        mApfVersionSupported = config.apfVersionSupported;
        mApfRamSize = config.apfRamSize;
        mInstallableProgramSizeClamp = config.installableProgramSizeClamp;
        int maximumApfProgramSize = mApfRamSize;
        if (hasDataAccess(mApfVersionSupported)) {
            // Reserve space for the counters.
            maximumApfProgramSize -= Counter.totalSize();
        }
        // Prevent generating (and thus installing) larger programs
        if (maximumApfProgramSize > mInstallableProgramSizeClamp) {
            maximumApfProgramSize = mInstallableProgramSizeClamp;
        }
        mMaximumApfProgramSize = maximumApfProgramSize;
        mIpClientCallback = ipClientCallback;
        mInterfaceParams = ifParams;
        mMulticastFilter = config.multicastFilter;
        mDrop802_3Frames = config.ieee802_3Filter;
        mMinRdnssLifetimeSec = config.minRdnssLifetimeSec;
        mAcceptRaMinLft = config.acceptRaMinLft;
        mShouldHandleArpOffload = config.shouldHandleArpOffload;
        mShouldHandleNdOffload = config.shouldHandleNdOffload;
        mDependencies = dependencies;
        mNetworkQuirkMetrics = networkQuirkMetrics;
        mIpClientRaInfoMetrics = dependencies.getIpClientRaInfoMetrics();
        mApfSessionInfoMetrics = dependencies.getApfSessionInfoMetrics();
        mClock = clock;
        mSessionStartMs = mClock.elapsedRealtime();
        mMinMetricsSessionDurationMs = config.minMetricsSessionDurationMs;
        mHasClat = config.hasClatInterface;

        // Now fill the black list from the passed array
        mEthTypeBlackList = filterEthTypeBlackList(config.ethTypeBlackList);

        // TokenBucket for rate limiting filter installation. APF filtering relies on the filter
        // always being up-to-date and APF bytecode being in sync with userspace. The TokenBucket
        // merely prevents illconfigured / abusive networks from impacting the system, so it does
        // not need to be very restrictive.
        // The TokenBucket starts with its full capacity of 20 tokens (= 20 filter updates). A new
        // token is generated every 3 seconds limiting the filter update rate to at most once every
        // 3 seconds.
        mTokenBucket = new TokenBucket(3_000 /* deltaMs */, 20 /* capacity */, 20 /* tokens */);

        mHardwareAddress = mInterfaceParams.macAddr.toByteArray();
        // TODO: ApfFilter should not generate programs until IpClient sends provisioning success.
        startFilter();

        // Listen for doze-mode transition changes to enable/disable the IPv6 multicast filter.
        mDependencies.addDeviceIdleReceiver(mDeviceIdleReceiver);

        mDependencies.onApfFilterCreated(this);
        // mReceiveThread is created in startFilter() and halted in shutdown().
        mDependencies.onThreadCreated(mReceiveThread);
    }

    /**
     * Dependencies class for testing.
     */
    @VisibleForTesting
    public static class Dependencies {
        private final Context mContext;
        public Dependencies(final Context context) {
            mContext = context;
        }

        /** Add receiver for detecting doze mode change */
        public void addDeviceIdleReceiver(@NonNull final BroadcastReceiver receiver) {
            final IntentFilter intentFilter = new IntentFilter(ACTION_DEVICE_IDLE_MODE_CHANGED);
            if (SdkLevel.isAtLeastT()) {
                intentFilter.addAction(ACTION_DEVICE_LIGHT_IDLE_MODE_CHANGED);
            }
            mContext.registerReceiver(receiver, intentFilter);
        }

        /** Remove broadcast receiver. */
        public void removeBroadcastReceiver(@NonNull final BroadcastReceiver receiver) {
            mContext.unregisterReceiver(receiver);
        }

        /**
         * Get a ApfSessionInfoMetrics instance.
         */
        public ApfSessionInfoMetrics getApfSessionInfoMetrics() {
            return new ApfSessionInfoMetrics();
        }

        /**
         * Get a IpClientRaInfoMetrics instance.
         */
        public IpClientRaInfoMetrics getIpClientRaInfoMetrics() {
            return new IpClientRaInfoMetrics();
        }

        /**
         * Callback to be called when an ApfFilter instance is created.
         *
         * This method is designed to be overridden in test classes to collect created ApfFilter
         * instances.
         */
        public void onApfFilterCreated(@NonNull AndroidPacketFilter apfFilter) {
        }

        /**
         * Callback to be called when a ReceiveThread instance is created.
         *
         * This method is designed for overriding in test classes to collect created threads and
         * waits for the termination.
         */
        public void onThreadCreated(@NonNull Thread thread) {
        }

        /**
         * Loads the existing IPv6 anycast addresses from the file `/proc/net/anycast6`.
         */
        public List<byte[]> getAnycast6Addresses(@NonNull String ifname) {
            final List<Inet6Address> anycast6Addresses =
                    ProcfsParsingUtils.getAnycast6Addresses(ifname);
            final List<byte[]> addresses = new ArrayList<>();
            for (Inet6Address addr : anycast6Addresses) {
                addresses.add(addr.getAddress());
            }

            return addresses;
        }

        /**
         * Loads the existing Ethernet multicast addresses from the file
         * `/proc/net/dev_mcast`.
         */
        public List<byte[]> getEtherMulticastAddresses(@NonNull String ifname) {
            final List<MacAddress> etherAddresses =
                    ProcfsParsingUtils.getEtherMulticastAddresses(ifname);
            final List<byte[]> addresses = new ArrayList<>();
            for (MacAddress addr : etherAddresses) {
                addresses.add(addr.toByteArray());
            }

            return addresses;
        }

        /**
         * Loads the existing ND traffic class for the specific interface from the file
         * /proc/sys/net/ipv6/conf/{ifname}/ndisc_tclass.
         *
         * If the file does not exist or the interface is not found,
         * the function returns 0..255, 0 as default ND traffic class.
         */
        public int getNdTrafficClass(@NonNull String ifname) {
            return ProcfsParsingUtils.getNdTrafficClass(ifname);
        }
    }

    @Override
    public synchronized String setDataSnapshot(byte[] data) {
        mDataSnapshot = data;
        if (mIsRunning) {
            mApfCounterTracker.updateCountersFromData(data);
        }
        return mApfCounterTracker.getCounters().toString();
    }

    private void log(String s) {
        Log.d(TAG, "(" + mInterfaceParams.name + "): " + s);
    }

    @GuardedBy("this")
    private long getUniqueNumberLocked() {
        return mUniqueCounter++;
    }

    private static int[] filterEthTypeBlackList(int[] ethTypeBlackList) {
        ArrayList<Integer> bl = new ArrayList<>();

        for (int p : ethTypeBlackList) {
            // Check if the protocol is a valid ether type
            if ((p < ETH_TYPE_MIN) || (p > ETH_TYPE_MAX)) {
                continue;
            }

            // Check if the protocol is not repeated in the passed array
            if (bl.contains(p)) {
                continue;
            }

            // Check if list reach its max size
            if (bl.size() == APF_MAX_ETH_TYPE_BLACK_LIST_LEN) {
                Log.w(TAG, "Passed EthType Black List size too large (" + bl.size() +
                        ") using top " + APF_MAX_ETH_TYPE_BLACK_LIST_LEN + " protocols");
                break;
            }

            // Now add the protocol to the list
            bl.add(p);
        }

        return bl.stream().mapToInt(Integer::intValue).toArray();
    }

    /**
     * Attempt to start listening for RAs and, if RAs are received, generating and installing
     * filters to ignore useless RAs.
     */
    @VisibleForTesting
    public void startFilter() {
        synchronized (this) {
            // Clear the APF memory to reset all counters upon connecting to the first AP
            // in an SSID. This is limited to APFv3 devices because this large write triggers
            // a crash on some older devices (b/78905546).
            if (hasDataAccess(mApfVersionSupported)) {
                byte[] zeroes = new byte[mApfRamSize];
                if (!mIpClientCallback.installPacketFilter(zeroes)) {
                    sendNetworkQuirkMetrics(NetworkQuirkEvent.QE_APF_INSTALL_FAILURE);
                }
            }

            // Install basic filters
            installNewProgramLocked();
        }
        FileDescriptor socket;
        try {
            socket = Os.socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, 0);
            NetworkStackUtils.attachRaFilter(socket);
            SocketAddress addr = makePacketSocketAddress(ETH_P_IPV6, mInterfaceParams.index);
            Os.bind(socket, addr);
        } catch(SocketException|ErrnoException e) {
            Log.wtf(TAG, "Error starting filter", e);
            return;
        }
        mReceiveThread = new ReceiveThread(socket);
        mReceiveThread.start();
    }

    // Returns seconds since device boot.
    @VisibleForTesting
    protected int secondsSinceBoot() {
        return (int) (mClock.elapsedRealtime() / DateUtils.SECOND_IN_MILLIS);
    }

    public static class InvalidRaException extends Exception {
        public InvalidRaException(String m) {
            super(m);
        }
    }

    /**
     *  Class to keep track of a section in a packet.
     */
    private static class PacketSection {
        public enum Type {
            MATCH,     // A field that should be matched (e.g., the router IP address).
            LIFETIME,  // A lifetime. Not matched, and counts toward minimum RA lifetime if >= min.
        }

        /** The type of section. */
        public final Type type;
        /** Offset into the packet at which this section begins. */
        public final int start;
        /** Length of this section in bytes. */
        public final int length;
        /** If this is a lifetime, the lifetime value. */
        public final long lifetime;
        /** If this is a lifetime, the value below which the lifetime is ignored */
        public final int min;

        PacketSection(int start, int length, Type type, long lifetime, int min) {
            this.start = start;

            if (type == Type.LIFETIME && length != 2 && length != 4) {
                throw new IllegalArgumentException("LIFETIME section length must be 2 or 4 bytes");
            }
            this.length = length;
            this.type = type;

            if (type == Type.MATCH && (lifetime != 0 || min != 0)) {
                throw new IllegalArgumentException("lifetime, min must be 0 for MATCH sections");
            }
            this.lifetime = lifetime;

            // It has already been asserted that min is 0 for MATCH sections.
            if (min < 0) {
                throw new IllegalArgumentException("min must be >= 0 for LIFETIME sections");
            }
            this.min = min;
        }

        public String toString() {
            if (type == Type.LIFETIME) {
                return String.format("%s: (%d, %d) %d %d", type, start, length, lifetime, min);
            } else {
                return String.format("%s: (%d, %d)", type, start, length);
            }
        }
    }

    // A class to hold information about an RA.
    @VisibleForTesting
    public class Ra {
        // Note: mPacket's position() cannot be assumed to be reset.
        private final ByteBuffer mPacket;

        // List of sections in the packet.
        private final ArrayList<PacketSection> mPacketSections = new ArrayList<>();

        // Router lifetime in packet
        private final int mRouterLifetime;
        // Minimum valid lifetime of PIOs in packet, Long.MAX_VALUE means not seen.
        private long mMinPioValidLifetime = Long.MAX_VALUE;
        // Minimum route lifetime of RIOs in packet, Long.MAX_VALUE means not seen.
        private long mMinRioRouteLifetime = Long.MAX_VALUE;
        // Minimum lifetime of RDNSSs in packet, Long.MAX_VALUE means not seen.
        private long mMinRdnssLifetime = Long.MAX_VALUE;
        // The time in seconds in which some of the information contained in this RA expires.
        private final int mExpirationTime;
        // When the packet was last captured, in seconds since Unix Epoch
        private final int mLastSeen;

        // For debugging only. Offsets into the packet where PIOs are.
        private final ArrayList<Integer> mPrefixOptionOffsets = new ArrayList<>();

        // For debugging only. Offsets into the packet where RDNSS options are.
        private final ArrayList<Integer> mRdnssOptionOffsets = new ArrayList<>();

        // For debugging only. Offsets into the packet where RIO options are.
        private final ArrayList<Integer> mRioOptionOffsets = new ArrayList<>();

        // For debugging only. Returns the hex representation of the last matching packet.
        String getLastMatchingPacket() {
            return HexDump.toHexString(mPacket.array(), 0, mPacket.capacity(),
                    false /* lowercase */);
        }

        // For debugging only. Returns the string representation of the IPv6 address starting at
        // position pos in the packet.
        private String IPv6AddresstoString(int pos) {
            try {
                byte[] array = mPacket.array();
                // Can't just call copyOfRange() and see if it throws, because if it reads past the
                // end it pads with zeros instead of throwing.
                if (pos < 0 || pos + 16 > array.length || pos + 16 < pos) {
                    return "???";
                }
                byte[] addressBytes = Arrays.copyOfRange(array, pos, pos + 16);
                InetAddress address = InetAddress.getByAddress(addressBytes);
                return address.getHostAddress();
            } catch (UnsupportedOperationException e) {
                // array() failed. Cannot happen, mPacket is array-backed and read-write.
                return "???";
            } catch (ClassCastException|UnknownHostException e) {
                // Cannot happen.
                return "???";
            }
        }

        // Can't be static because it's in a non-static inner class.
        // TODO: Make this static once RA is its own class.
        private void prefixOptionToString(StringBuffer sb, int offset) {
            String prefix = IPv6AddresstoString(offset + 16);
            int length = getUint8(mPacket, offset + 2);
            long valid = getUint32(mPacket, offset + 4);
            long preferred = getUint32(mPacket, offset + 8);
            sb.append(String.format("%s/%d %ds/%ds ", prefix, length, valid, preferred));
        }

        private void rdnssOptionToString(StringBuffer sb, int offset) {
            int optLen = getUint8(mPacket, offset + 1) * 8;
            if (optLen < 24) return;  // Malformed or empty.
            long lifetime = getUint32(mPacket, offset + 4);
            int numServers = (optLen - 8) / 16;
            sb.append("DNS ").append(lifetime).append("s");
            for (int server = 0; server < numServers; server++) {
                sb.append(" ").append(IPv6AddresstoString(offset + 8 + 16 * server));
            }
            sb.append(" ");
        }

        private void rioOptionToString(StringBuffer sb, int offset) {
            int optLen = getUint8(mPacket, offset + 1) * 8;
            if (optLen < 8 || optLen > 24) return;  // Malformed or empty.
            int prefixLen = getUint8(mPacket, offset + 2);
            long lifetime = getUint32(mPacket, offset + 4);

            // This read is variable length because the prefix can be 0, 8 or 16 bytes long.
            // We can't use any of the ByteBuffer#get methods here because they all start reading
            // from the buffer's current position.
            byte[] prefix = new byte[IPV6_ADDR_LEN];
            System.arraycopy(mPacket.array(), offset + 8, prefix, 0, optLen - 8);
            sb.append("RIO ").append(lifetime).append("s ");
            try {
                InetAddress address = InetAddress.getByAddress(prefix);
                sb.append(address.getHostAddress());
            } catch (UnknownHostException impossible) {
                sb.append("???");
            }
            sb.append("/").append(prefixLen).append(" ");
        }

        public String toString() {
            try {
                StringBuffer sb = new StringBuffer();
                sb.append(String.format("RA %s -> %s %ds ",
                        IPv6AddresstoString(IPV6_SRC_ADDR_OFFSET),
                        IPv6AddresstoString(IPV6_DEST_ADDR_OFFSET),
                        getUint16(mPacket, ICMP6_RA_ROUTER_LIFETIME_OFFSET)));
                for (int i: mPrefixOptionOffsets) {
                    prefixOptionToString(sb, i);
                }
                for (int i: mRdnssOptionOffsets) {
                    rdnssOptionToString(sb, i);
                }
                for (int i: mRioOptionOffsets) {
                    rioOptionToString(sb, i);
                }
                return sb.toString();
            } catch (BufferUnderflowException|IndexOutOfBoundsException e) {
                return "<Malformed RA>";
            }
        }

        /**
         * Add a packet section that should be matched, starting from the current position.
         * @param length the length of the section
         */
        private void addMatchSection(int length) {
            // Don't generate JNEBS instruction for 0 bytes as they will fail the
            // ASSERT_FORWARD_IN_PROGRAM(pc + cmp_imm - 1) check (where cmp_imm is
            // the number of bytes to compare) and immediately pass the packet.
            // The code does not attempt to generate such matches, but add a safety
            // check to prevent doing so in the presence of bugs or malformed or
            // truncated packets.
            if (length == 0) return;

            // we need to add a MATCH section 'from, length, MATCH, 0, 0'
            int from = mPacket.position();

            // if possible try to increase the length of the previous match section
            int lastIdx = mPacketSections.size() - 1;
            if (lastIdx >= 0) {  // there had to be a previous section
                PacketSection prev = mPacketSections.get(lastIdx);
                if (prev.type == PacketSection.Type.MATCH) {  // of type match
                    if (prev.start + prev.length == from) {  // ending where we start
                        from -= prev.length;
                        length += prev.length;
                        mPacketSections.remove(lastIdx);
                    }
                }
            }

            mPacketSections.add(new PacketSection(from, length, PacketSection.Type.MATCH, 0, 0));
            mPacket.position(from + length);
        }

        /**
         * Add a packet section that should be matched, starting from the current position.
         * @param end the offset in the packet before which the section ends
         */
        private void addMatchUntil(int end) {
            addMatchSection(end - mPacket.position());
        }

        /**
         * Add a packet section that should be ignored, starting from the current position.
         * @param length the length of the section in bytes
         */
        private void addIgnoreSection(int length) {
            mPacket.position(mPacket.position() + length);
        }

        /**
         * Add a packet section that represents a lifetime, starting from the current position.
         * @param length the length of the section in bytes
         * @param lifetime the lifetime
         * @param min the minimum acceptable lifetime
         */
        private void addLifetimeSection(int length, long lifetime, int min) {
            mPacketSections.add(
                    new PacketSection(mPacket.position(), length, PacketSection.Type.LIFETIME,
                            lifetime, min));
            mPacket.position(mPacket.position() + length);
        }

        /**
         * Adds packet sections for an RA option with a 4-byte lifetime 4 bytes into the option
         * @param optionLength the length of the option in bytes
         * @param min the minimum acceptable lifetime
         */
        private long add4ByteLifetimeOption(int optionLength, int min) {
            addMatchSection(ICMP6_4_BYTE_LIFETIME_OFFSET);
            final long lifetime = getUint32(mPacket, mPacket.position());
            addLifetimeSection(ICMP6_4_BYTE_LIFETIME_LEN, lifetime, min);
            addMatchSection(optionLength - ICMP6_4_BYTE_LIFETIME_OFFSET
                    - ICMP6_4_BYTE_LIFETIME_LEN);
            return lifetime;
        }

        /**
         * Return the router lifetime of the RA
         */
        public int routerLifetime() {
            return mRouterLifetime;
        }

        /**
         * Return the minimum valid lifetime in PIOs
         */
        public long minPioValidLifetime() {
            return mMinPioValidLifetime;
        }

        /**
         * Return the minimum route lifetime in RIOs
         */
        public long minRioRouteLifetime() {
            return mMinRioRouteLifetime;
        }

        /**
         * Return the minimum lifetime in RDNSSs
         */
        public long minRdnssLifetime() {
            return mMinRdnssLifetime;
        }

        // Note that this parses RA and may throw InvalidRaException (from
        // Buffer.position(int) or due to an invalid-length option) or IndexOutOfBoundsException
        // (from ByteBuffer.get(int) ) if parsing encounters something non-compliant with
        // specifications.
        @VisibleForTesting
        public Ra(byte[] packet, int length) throws InvalidRaException {
            if (length < ICMP6_RA_OPTION_OFFSET) {
                throw new InvalidRaException("Not an ICMP6 router advertisement: too short");
            }

            mPacket = ByteBuffer.wrap(Arrays.copyOf(packet, length));
            mLastSeen = secondsSinceBoot();

            // Check packet in case a packet arrives before we attach RA filter
            // to our packet socket. b/29586253
            if (getUint16(mPacket, ETH_ETHERTYPE_OFFSET) != ETH_P_IPV6 ||
                    getUint8(mPacket, IPV6_NEXT_HEADER_OFFSET) != IPPROTO_ICMPV6 ||
                    getUint8(mPacket, ICMP6_TYPE_OFFSET) != ICMPV6_ROUTER_ADVERTISEMENT) {
                throw new InvalidRaException("Not an ICMP6 router advertisement");
            }

            // Ignore destination MAC address.
            addIgnoreSection(6 /* Size of MAC address */);

            // Ignore the flow label and low 4 bits of traffic class.
            addMatchUntil(IPV6_FLOW_LABEL_OFFSET);
            addIgnoreSection(IPV6_FLOW_LABEL_LEN);

            // Ignore IPv6 destination address.
            addMatchUntil(IPV6_DEST_ADDR_OFFSET);
            addIgnoreSection(IPV6_ADDR_LEN);

            // Ignore checksum.
            addMatchUntil(ICMP6_RA_CHECKSUM_OFFSET);
            addIgnoreSection(ICMP6_RA_CHECKSUM_LEN);

            // Parse router lifetime
            addMatchUntil(ICMP6_RA_ROUTER_LIFETIME_OFFSET);
            mRouterLifetime = getUint16(mPacket, ICMP6_RA_ROUTER_LIFETIME_OFFSET);
            addLifetimeSection(ICMP6_RA_ROUTER_LIFETIME_LEN, mRouterLifetime, mAcceptRaMinLft);
            if (mRouterLifetime == 0) mNumZeroLifetimeRas++;

            // Add remaining fields (reachable time and retransmission timer) to match section.
            addMatchUntil(ICMP6_RA_OPTION_OFFSET);

            while (mPacket.hasRemaining()) {
                final int position = mPacket.position();
                final int optionType = getUint8(mPacket, position);
                final int optionLength = getUint8(mPacket, position + 1) * 8;
                if (optionLength <= 0) {
                    throw new InvalidRaException(String.format(
                        "Invalid option length opt=%d len=%d", optionType, optionLength));
                }

                long lifetime;
                switch (optionType) {
                    case ICMP6_PREFIX_OPTION_TYPE:
                        mPrefixOptionOffsets.add(position);

                        // Parse valid lifetime
                        addMatchSection(ICMP6_PREFIX_OPTION_VALID_LIFETIME_OFFSET);
                        lifetime = getUint32(mPacket, mPacket.position());
                        addLifetimeSection(ICMP6_PREFIX_OPTION_VALID_LIFETIME_LEN,
                                lifetime, mAcceptRaMinLft);
                        mMinPioValidLifetime = getMinForPositiveValue(
                                mMinPioValidLifetime, lifetime);
                        if (lifetime == 0) mNumZeroLifetimeRas++;

                        // Parse preferred lifetime
                        lifetime = getUint32(mPacket, mPacket.position());
                        // The PIO preferred lifetime is not affected by accept_ra_min_lft and
                        // therefore does not have a minimum.
                        addLifetimeSection(ICMP6_PREFIX_OPTION_PREFERRED_LIFETIME_LEN,
                                lifetime, 0 /* min lifetime */);

                        addMatchSection(4);       // Reserved bytes
                        addMatchSection(IPV6_ADDR_LEN);  // The prefix itself
                        break;
                    // These three options have the same lifetime offset and size, and
                    // are processed with the same specialized add4ByteLifetimeOption:
                    case ICMP6_RDNSS_OPTION_TYPE:
                        mRdnssOptionOffsets.add(position);
                        lifetime = add4ByteLifetimeOption(optionLength, mMinRdnssLifetimeSec);
                        mMinRdnssLifetime = getMinForPositiveValue(mMinRdnssLifetime, lifetime);
                        if (lifetime == 0) mNumZeroLifetimeRas++;
                        break;
                    case ICMP6_ROUTE_INFO_OPTION_TYPE:
                        mRioOptionOffsets.add(position);
                        lifetime = add4ByteLifetimeOption(optionLength, mAcceptRaMinLft);
                        mMinRioRouteLifetime = getMinForPositiveValue(
                                mMinRioRouteLifetime, lifetime);
                        if (lifetime == 0) mNumZeroLifetimeRas++;
                        break;
                    case ICMP6_SOURCE_LL_ADDRESS_OPTION_TYPE:
                    case ICMP6_MTU_OPTION_TYPE:
                    case ICMP6_PREF64_OPTION_TYPE:
                        addMatchSection(optionLength);
                        break;
                    case ICMP6_CAPTIVE_PORTAL_OPTION_TYPE: // unlikely to ever change.
                    case ICMP6_DNSSL_OPTION_TYPE: // currently unsupported in userspace.
                    default:
                        // RFC4861 section 4.2 dictates we ignore unknown options for forwards
                        // compatibility.
                        // However, make sure the option's type and length match.
                        addMatchSection(2); // option type & length
                        // optionLength is guaranteed to be >= 8.
                        addIgnoreSection(optionLength - 2);
                        break;
                }
            }
            mExpirationTime = getExpirationTime();
        }

        public enum MatchType {
            NO_MATCH, // the RAs do not match
            MATCH_PASS, // the RAS match, and the APF program would pass.
            MATCH_DROP, // the RAs match, but the APF program would drop.
        }

        // Considering only the MATCH sections, does {@code packet} match this RA?
        MatchType matches(Ra newRa) {
            // Does their size match?
            if (newRa.mPacket.capacity() != mPacket.capacity()) return MatchType.NO_MATCH;

            // If the filter has expired, it cannot match the new RA.
            if (getRemainingFilterLft(secondsSinceBoot()) <= 0) return MatchType.NO_MATCH;

            // Check if all MATCH sections are byte-identical.
            final byte[] newPacket = newRa.mPacket.array();
            final byte[] oldPacket = mPacket.array();
            for (PacketSection section : mPacketSections) {
                if (section.type != PacketSection.Type.MATCH) continue;
                for (int i = section.start; i < (section.start + section.length); i++) {
                    if (newPacket[i] != oldPacket[i]) return MatchType.NO_MATCH;
                }
            }

            // Apply APF lifetime matching to LIFETIME sections and decide whether a packet should
            // be processed (MATCH_PASS) or ignored (MATCH_DROP). This logic is needed to
            // consistently process / ignore packets no matter the current state of the APF program.
            // Note that userspace has no control (or knowledge) over when the APF program is
            // running.
            for (PacketSection section : mPacketSections) {
                if (section.type != PacketSection.Type.LIFETIME) continue;

                // the lifetime of the new RA.
                long lft = 0;
                switch (section.length) {
                    // section.length is guaranteed to be 2 or 4.
                    case 2: lft = getUint16(newRa.mPacket, section.start); break;
                    case 4: lft = getUint32(newRa.mPacket, section.start); break;
                }

                // WARNING: keep this in sync with Ra#generateFilterLocked()!
                if (section.lifetime == 0) {
                    // Case 1) old lft == 0
                    if (section.min > 0) {
                        // a) in the presence of a min value.
                        // if lft >= min -> PASS
                        // gen.addJumpIfR0GreaterThan(section.min - 1, nextFilterLabel);
                        if (lft >= section.min) return MatchType.MATCH_PASS;
                    } else {
                        // b) if min is 0 / there is no min value.
                        // if lft > 0 -> PASS
                        // gen.addJumpIfR0GreaterThan(0, nextFilterLabel);
                        if (lft > 0) return MatchType.MATCH_PASS;
                    }
                } else if (section.min == 0) {
                    // Case 2b) section is not affected by any minimum.
                    //
                    // if lft < (oldLft + 2) // 3 -> PASS
                    // if lft > oldLft            -> PASS
                    // gen.addJumpIfR0LessThan(((section.lifetime + 2) / 3),
                    //        nextFilterLabel);
                    if (lft < (section.lifetime + 2) / 3) return MatchType.MATCH_PASS;
                    // gen.addJumpIfR0GreaterThan(section.lifetime, nextFilterLabel);
                    if (lft > section.lifetime) return MatchType.MATCH_PASS;
                } else if (section.lifetime < section.min) {
                    // Case 2a) 0 < old lft < min
                    //
                    // if lft == 0   -> PASS
                    // if lft >= min -> PASS
                    // gen.addJumpIfR0Equals(0, nextFilterLabel);
                    if (lft == 0) return MatchType.MATCH_PASS;
                    // gen.addJumpIfR0GreaterThan(section.min - 1, nextFilterLabel);
                    if (lft >= section.min) return MatchType.MATCH_PASS;
                } else if (section.lifetime <= 3 * (long) section.min) {
                    // Case 3a) min <= old lft <= 3 * min
                    // Note that:
                    // "(old lft + 2) / 3 <= min" is equivalent to "old lft <= 3 * min"
                    //
                    // Essentially, in this range there is no "renumbering support", as the
                    // renumbering constant of 1/3 * old lft is smaller than the minimum
                    // lifetime accepted by the kernel / userspace.
                    //
                    // if lft == 0     -> PASS
                    // if lft > oldLft -> PASS
                    // gen.addJumpIfR0Equals(0, nextFilterLabel);
                    if (lft == 0) return MatchType.MATCH_PASS;
                    // gen.addJumpIfR0GreaterThan(section.lifetime, nextFilterLabel);
                    if (lft > section.lifetime) return MatchType.MATCH_PASS;
                } else {
                    // Case 4a) otherwise
                    //
                    // if lft == 0                  -> PASS
                    // if lft < min                 -> CONTINUE
                    // if lft < (oldLft + 2) // 3   -> PASS
                    // if lft > oldLft              -> PASS
                    // gen.addJumpIfR0Equals(0, nextFilterLabel);
                    if (lft == 0) return MatchType.MATCH_PASS;
                    // gen.addJumpIfR0LessThan(section.min, continueLabel);
                    if (lft < section.min) continue;
                    // gen.addJumpIfR0LessThan(((section.lifetime + 2) / 3),
                    //         nextFilterLabel);
                    if (lft < (section.lifetime + 2) / 3) return MatchType.MATCH_PASS;
                    // gen.addJumpIfR0GreaterThan(section.lifetime, nextFilterLabel);
                    if (lft > section.lifetime) return MatchType.MATCH_PASS;
                }
            }

            return MatchType.MATCH_DROP;
        }

        // Get the number of seconds in which some of the information contained in this RA expires.
        private int getExpirationTime() {
            // While technically most lifetimes in the RA are u32s, as far as the RA filter is
            // concerned, INT_MAX is still a *much* longer lifetime than any filter would ever
            // reasonably be active for.
            // Clamp expirationTime at INT_MAX.
            int expirationTime = Integer.MAX_VALUE;
            for (PacketSection section : mPacketSections) {
                if (section.type != PacketSection.Type.LIFETIME) {
                    continue;
                }
                // Ignore lifetimes below section.min and always ignore 0 lifetimes.
                if (section.lifetime < Math.max(section.min, 1)) {
                    continue;
                }

                expirationTime = (int) Math.min(expirationTime, section.lifetime);
            }
            return expirationTime;
        }

        // Filter for a fraction of the expiration time and adjust for the age of the RA.
        int getRemainingFilterLft(int currentTimeSeconds) {
            int filterLifetime = ((mExpirationTime / FRACTION_OF_LIFETIME_TO_FILTER)
                    - (currentTimeSeconds - mLastSeen));
            filterLifetime = Math.max(0, filterLifetime);
            // Clamp filterLifetime to <= 65535, so it fits in 2 bytes.
            return Math.min(65535, filterLifetime);
        }

        // Append a filter for this RA to {@code gen}. Jump to DROP_LABEL if it should be dropped.
        // Jump to the next filter if packet doesn't match this RA.
        @GuardedBy("ApfFilter.this")
        void generateFilterLocked(ApfV4GeneratorBase<?> gen, int timeSeconds)
                throws IllegalInstructionException {
            String nextFilterLabel = gen.getUniqueLabel();
            // Skip if packet is not the right size
            gen.addLoadFromMemory(R0, MemorySlot.PACKET_SIZE);
            gen.addJumpIfR0NotEquals(mPacket.capacity(), nextFilterLabel);
            // Skip filter if expired
            gen.addLoadFromMemory(R0, MemorySlot.FILTER_AGE_SECONDS);
            gen.addJumpIfR0GreaterThan(getRemainingFilterLft(timeSeconds), nextFilterLabel);
            for (PacketSection section : mPacketSections) {
                // Generate code to match the packet bytes.
                if (section.type == PacketSection.Type.MATCH) {
                    gen.addLoadImmediate(R0, section.start);
                    gen.addJumpIfBytesAtR0NotEqual(
                            Arrays.copyOfRange(mPacket.array(), section.start,
                                    section.start + section.length),
                            nextFilterLabel);
                } else {
                    switch (section.length) {
                        // length asserted to be either 2 or 4 on PacketSection construction
                        case 2: gen.addLoad16(R0, section.start); break;
                        case 4: gen.addLoad32(R0, section.start); break;
                    }

                    // WARNING: keep this in sync with matches()!
                    // For more information on lifetime comparisons in the APF bytecode, see
                    // go/apf-ra-filter.
                    if (section.lifetime == 0) {
                        // Case 1) old lft == 0
                        if (section.min > 0) {
                            // a) in the presence of a min value.
                            // if lft >= min -> PASS
                            gen.addJumpIfR0GreaterThan(section.min - 1, nextFilterLabel);
                        } else {
                            // b) if min is 0 / there is no min value.
                            // if lft > 0 -> PASS
                            gen.addJumpIfR0GreaterThan(0, nextFilterLabel);
                        }
                    } else if (section.min == 0) {
                        // Case 2b) section is not affected by any minimum.
                        //
                        // if lft < (oldLft + 2) // 3 -> PASS
                        // if lft > oldLft            -> PASS
                        gen.addJumpIfR0LessThan(((section.lifetime + 2) / 3),
                                nextFilterLabel);
                        gen.addJumpIfR0GreaterThan(section.lifetime, nextFilterLabel);
                    } else if (section.lifetime < section.min) {
                        // Case 2a) 0 < old lft < min
                        //
                        // if lft == 0   -> PASS
                        // if lft >= min -> PASS
                        gen.addJumpIfR0Equals(0, nextFilterLabel);
                        gen.addJumpIfR0GreaterThan(section.min - 1, nextFilterLabel);
                    } else if (section.lifetime <= 3 * (long) section.min) {
                        // Case 3a) min <= old lft <= 3 * min
                        // Note that:
                        // "(old lft + 2) / 3 <= min" is equivalent to "old lft <= 3 * min"
                        //
                        // Essentially, in this range there is no "renumbering support", as the
                        // renumbering constant of 1/3 * old lft is smaller than the minimum
                        // lifetime accepted by the kernel / userspace.
                        //
                        // if lft == 0     -> PASS
                        // if lft > oldLft -> PASS
                        gen.addJumpIfR0Equals(0, nextFilterLabel);
                        gen.addJumpIfR0GreaterThan(section.lifetime, nextFilterLabel);
                    } else {
                        final String continueLabel = gen.getUniqueLabel();
                        // Case 4a) otherwise
                        //
                        // if lft == 0                  -> PASS
                        // if lft < min                 -> CONTINUE
                        // if lft < (oldLft + 2) // 3   -> PASS
                        // if lft > oldLft              -> PASS
                        gen.addJumpIfR0Equals(0, nextFilterLabel);
                        gen.addJumpIfR0LessThan(section.min, continueLabel);
                        gen.addJumpIfR0LessThan(((section.lifetime + 2) / 3),
                                nextFilterLabel);
                        gen.addJumpIfR0GreaterThan(section.lifetime, nextFilterLabel);

                        // CONTINUE
                        gen.defineLabel(continueLabel);
                    }
                }
            }
            gen.addCountAndDrop(Counter.DROPPED_RA);
            gen.defineLabel(nextFilterLabel);
        }
    }

    // TODO: Refactor these subclasses to avoid so much repetition.
    private abstract static class KeepalivePacket {
        // Note that the offset starts from IP header.
        // These must be added ether header length when generating program.
        static final int IP_HEADER_OFFSET = 0;
        static final int IPV4_SRC_ADDR_OFFSET = IP_HEADER_OFFSET + 12;

        // Append a filter for this keepalive ack to {@code gen}.
        // Jump to drop if it matches the keepalive ack.
        // Jump to the next filter if packet doesn't match the keepalive ack.
        abstract void generateFilterLocked(ApfV4GeneratorBase<?> gen)
                throws IllegalInstructionException;
    }

    // A class to hold NAT-T keepalive ack information.
    private class NattKeepaliveResponse extends KeepalivePacket {
        static final int UDP_HEADER_LEN = 8;

        protected class NattKeepaliveResponseData {
            public final byte[] srcAddress;
            public final int srcPort;
            public final byte[] dstAddress;
            public final int dstPort;

            NattKeepaliveResponseData(final NattKeepalivePacketDataParcelable sentKeepalivePacket) {
                srcAddress = sentKeepalivePacket.dstAddress;
                srcPort = sentKeepalivePacket.dstPort;
                dstAddress = sentKeepalivePacket.srcAddress;
                dstPort = sentKeepalivePacket.srcPort;
            }
        }

        protected final NattKeepaliveResponseData mPacket;
        protected final byte[] mSrcDstAddr;
        protected final byte[] mPortFingerprint;
        // NAT-T keepalive packet
        protected final byte[] mPayload = {(byte) 0xff};

        NattKeepaliveResponse(final NattKeepalivePacketDataParcelable sentKeepalivePacket) {
            mPacket = new NattKeepaliveResponseData(sentKeepalivePacket);
            mSrcDstAddr = concatArrays(mPacket.srcAddress, mPacket.dstAddress);
            mPortFingerprint = generatePortFingerprint(mPacket.srcPort, mPacket.dstPort);
        }

        byte[] generatePortFingerprint(int srcPort, int dstPort) {
            final ByteBuffer fp = ByteBuffer.allocate(4);
            fp.order(ByteOrder.BIG_ENDIAN);
            fp.putShort((short) srcPort);
            fp.putShort((short) dstPort);
            return fp.array();
        }

        @Override
        @GuardedBy("ApfFilter.this")
        void generateFilterLocked(ApfV4GeneratorBase<?> gen) throws IllegalInstructionException {
            final String nextFilterLabel = gen.getUniqueLabel();

            gen.addLoadImmediate(R0, ETH_HEADER_LEN + IPV4_SRC_ADDR_OFFSET);
            gen.addJumpIfBytesAtR0NotEqual(mSrcDstAddr, nextFilterLabel);

            // A NAT-T keepalive packet contains 1 byte payload with the value 0xff
            // Check payload length is 1
            gen.addLoadFromMemory(R0, MemorySlot.IPV4_HEADER_SIZE);
            gen.addAdd(UDP_HEADER_LEN);
            gen.addSwap();
            gen.addLoad16(R0, IPV4_TOTAL_LENGTH_OFFSET);
            gen.addNeg(R1);
            gen.addAddR1ToR0();
            gen.addJumpIfR0NotEquals(1, nextFilterLabel);

            // Check that the ports match
            gen.addLoadFromMemory(R0, MemorySlot.IPV4_HEADER_SIZE);
            gen.addAdd(ETH_HEADER_LEN);
            gen.addJumpIfBytesAtR0NotEqual(mPortFingerprint, nextFilterLabel);

            // Payload offset = R0 + UDP header length
            gen.addAdd(UDP_HEADER_LEN);
            gen.addJumpIfBytesAtR0NotEqual(mPayload, nextFilterLabel);

            gen.addCountAndDrop(Counter.DROPPED_IPV4_NATT_KEEPALIVE);
            gen.defineLabel(nextFilterLabel);
        }

        public String toString() {
            try {
                return String.format("%s -> %s",
                        ConnectivityUtils.addressAndPortToString(
                                InetAddress.getByAddress(mPacket.srcAddress), mPacket.srcPort),
                        ConnectivityUtils.addressAndPortToString(
                                InetAddress.getByAddress(mPacket.dstAddress), mPacket.dstPort));
            } catch (UnknownHostException e) {
                return "Unknown host";
            }
        }
    }

    // A class to hold TCP keepalive ack information.
    private abstract static class TcpKeepaliveAck extends KeepalivePacket {
        protected static class TcpKeepaliveAckData {
            public final byte[] srcAddress;
            public final int srcPort;
            public final byte[] dstAddress;
            public final int dstPort;
            public final int seq;
            public final int ack;

            // Create the characteristics of the ack packet from the sent keepalive packet.
            TcpKeepaliveAckData(final TcpKeepalivePacketDataParcelable sentKeepalivePacket) {
                srcAddress = sentKeepalivePacket.dstAddress;
                srcPort = sentKeepalivePacket.dstPort;
                dstAddress = sentKeepalivePacket.srcAddress;
                dstPort = sentKeepalivePacket.srcPort;
                seq = sentKeepalivePacket.ack;
                ack = sentKeepalivePacket.seq + 1;
            }
        }

        protected final TcpKeepaliveAckData mPacket;
        protected final byte[] mSrcDstAddr;
        protected final byte[] mPortSeqAckFingerprint;

        TcpKeepaliveAck(final TcpKeepaliveAckData packet, final byte[] srcDstAddr) {
            mPacket = packet;
            mSrcDstAddr = srcDstAddr;
            mPortSeqAckFingerprint = generatePortSeqAckFingerprint(mPacket.srcPort,
                    mPacket.dstPort, mPacket.seq, mPacket.ack);
        }

        static byte[] generatePortSeqAckFingerprint(int srcPort, int dstPort, int seq, int ack) {
            final ByteBuffer fp = ByteBuffer.allocate(12);
            fp.order(ByteOrder.BIG_ENDIAN);
            fp.putShort((short) srcPort);
            fp.putShort((short) dstPort);
            fp.putInt(seq);
            fp.putInt(ack);
            return fp.array();
        }

        public String toString() {
            try {
                return String.format("%s -> %s , seq=%d, ack=%d",
                        ConnectivityUtils.addressAndPortToString(
                                InetAddress.getByAddress(mPacket.srcAddress), mPacket.srcPort),
                        ConnectivityUtils.addressAndPortToString(
                                InetAddress.getByAddress(mPacket.dstAddress), mPacket.dstPort),
                        Integer.toUnsignedLong(mPacket.seq),
                        Integer.toUnsignedLong(mPacket.ack));
            } catch (UnknownHostException e) {
                return "Unknown host";
            }
        }

        // Append a filter for this keepalive ack to {@code gen}.
        // Jump to drop if it matches the keepalive ack.
        // Jump to the next filter if packet doesn't match the keepalive ack.
        abstract void generateFilterLocked(ApfV4GeneratorBase<?> gen)
                throws IllegalInstructionException;
    }

    private class TcpKeepaliveAckV4 extends TcpKeepaliveAck {

        TcpKeepaliveAckV4(final TcpKeepalivePacketDataParcelable sentKeepalivePacket) {
            this(new TcpKeepaliveAckData(sentKeepalivePacket));
        }
        TcpKeepaliveAckV4(final TcpKeepaliveAckData packet) {
            super(packet, concatArrays(packet.srcAddress, packet.dstAddress) /* srcDstAddr */);
        }

        @Override
        @GuardedBy("ApfFilter.this")
        void generateFilterLocked(ApfV4GeneratorBase<?> gen) throws IllegalInstructionException {
            final String nextFilterLabel = gen.getUniqueLabel();

            gen.addLoadImmediate(R0, ETH_HEADER_LEN + IPV4_SRC_ADDR_OFFSET);
            gen.addJumpIfBytesAtR0NotEqual(mSrcDstAddr, nextFilterLabel);

            // Skip to the next filter if it's not zero-sized :
            // TCP_HEADER_SIZE + IPV4_HEADER_SIZE - ipv4_total_length == 0
            // Load the IP header size into R1
            gen.addLoadFromMemory(R1, MemorySlot.IPV4_HEADER_SIZE);
            // Load the TCP header size into R0 (it's indexed by R1)
            gen.addLoad8Indexed(R0, ETH_HEADER_LEN + TCP_HEADER_SIZE_OFFSET);
            // Size offset is in the top nibble, but it must be multiplied by 4, and the two
            // top bits of the low nibble are guaranteed to be zeroes. Right-shift R0 by 2.
            gen.addRightShift(2);
            // R0 += R1 -> R0 contains TCP + IP headers length
            gen.addAddR1ToR0();
            // Load IPv4 total length
            gen.addLoad16(R1, IPV4_TOTAL_LENGTH_OFFSET);
            gen.addNeg(R0);
            gen.addAddR1ToR0();
            gen.addJumpIfR0NotEquals(0, nextFilterLabel);
            // Add IPv4 header length
            gen.addLoadFromMemory(R1, MemorySlot.IPV4_HEADER_SIZE);
            gen.addLoadImmediate(R0, ETH_HEADER_LEN);
            gen.addAddR1ToR0();
            gen.addJumpIfBytesAtR0NotEqual(mPortSeqAckFingerprint, nextFilterLabel);

            gen.addCountAndDrop(Counter.DROPPED_IPV4_KEEPALIVE_ACK);
            gen.defineLabel(nextFilterLabel);
        }
    }

    private static class TcpKeepaliveAckV6 extends TcpKeepaliveAck {
        TcpKeepaliveAckV6(final TcpKeepalivePacketDataParcelable sentKeepalivePacket) {
            this(new TcpKeepaliveAckData(sentKeepalivePacket));
        }
        TcpKeepaliveAckV6(final TcpKeepaliveAckData packet) {
            super(packet, concatArrays(packet.srcAddress, packet.dstAddress) /* srcDstAddr */);
        }

        @Override
        void generateFilterLocked(ApfV4GeneratorBase<?> gen) {
            throw new UnsupportedOperationException("IPv6 TCP Keepalive is not supported yet");
        }
    }

    // Maximum number of RAs to filter for.
    private static final int MAX_RAS = 10;

    @GuardedBy("this")
    private final ArrayList<Ra> mRas = new ArrayList<>();
    @GuardedBy("this")
    private final SparseArray<KeepalivePacket> mKeepalivePackets = new SparseArray<>();
    @GuardedBy("this")
    // TODO: change the mMdnsAllowList to proper type for APFv6 based mDNS offload
    private final List<String[]> mMdnsAllowList = new ArrayList<>();

    // We don't want to filter an RA for it's whole lifetime as it'll be expired by the time we ever
    // see a refresh.  Using half the lifetime might be a good idea except for the fact that
    // packets may be dropped, so let's use 6.
    private static final int FRACTION_OF_LIFETIME_TO_FILTER = 6;

    // When did we last install a filter program? In seconds since Unix Epoch.
    @GuardedBy("this")
    private int mLastTimeInstalledProgram;
    // How long should the last installed filter program live for? In seconds.
    @GuardedBy("this")
    private int mLastInstalledProgramMinLifetime;

    // For debugging only. The last program installed.
    @GuardedBy("this")
    private byte[] mLastInstalledProgram;

    /**
     * For debugging only. Contains the latest APF buffer snapshot captured from the firmware.
     * <p>
     * A typical size for this buffer is 4KB. It is present only if the WiFi HAL supports
     * IWifiStaIface#readApfPacketFilterData(), and the APF interpreter advertised support for
     * the opcodes to access the data buffer (LDDW and STDW).
     */
    @GuardedBy("this") @Nullable
    private byte[] mDataSnapshot;

    // How many times the program was updated since we started.
    @GuardedBy("this")
    private int mNumProgramUpdates = 0;
    // The maximum program size that updated since we started.
    @GuardedBy("this")
    private int mMaxProgramSize = 0;
    // The maximum number of distinct RAs
    @GuardedBy("this")
    private int mMaxDistinctRas = 0;

    private ApfV6Generator tryToConvertToApfV6Generator(ApfV4GeneratorBase<?> gen) {
        if (gen instanceof ApfV6Generator) {
            return (ApfV6Generator) gen;
        }
        return null;
    }

    /**
     * Generate filter code to process ARP packets. Execution of this code ends in either the
     * DROP_LABEL or PASS_LABEL and does not fall off the end.
     * Preconditions:
     *  - Packet being filtered is ARP
     */
    @GuardedBy("this")
    private void generateArpFilterLocked(ApfV4GeneratorBase<?> gen)
            throws IllegalInstructionException {
        // Here's a basic summary of what the ARP filter program does:
        //
        // if clat is enabled (and we're thus IPv6-only)
        //   drop
        // if not ARP IPv4
        //   drop
        // if unknown ARP opcode (ie. not reply or request)
        //   drop
        //
        // if ARP reply:
        //   if source ip is 0.0.0.0
        //     drop
        //   if unicast (or multicast)
        //     pass
        //   if interface has no IPv4 address
        //     if target ip is 0.0.0.0
        //       drop
        //   else
        //     if target ip is not the interface ip
        //       drop
        //   pass
        //
        // if ARP request:
        //   if interface has IPv4 address
        //     if target ip is not the interface ip
        //       drop
        //   pass

        // For IPv6 only network, drop all ARP packet.
        if (mHasClat) {
            gen.addCountAndDrop(Counter.DROPPED_ARP_V6_ONLY);
            return;
        }

        // Drop if not ARP IPv4.
        gen.addLoadImmediate(R0, ARP_HEADER_OFFSET);
        gen.addCountAndDropIfBytesAtR0NotEqual(ARP_IPV4_HEADER, Counter.DROPPED_ARP_NON_IPV4);

        final String checkArpRequest = gen.getUniqueLabel();

        gen.addLoad16(R0, ARP_OPCODE_OFFSET);
        gen.addJumpIfR0Equals(ARP_OPCODE_REQUEST, checkArpRequest); // Skip to arp request check.
        // Drop if unknown ARP opcode.
        gen.addCountAndDropIfR0NotEquals(ARP_OPCODE_REPLY, Counter.DROPPED_ARP_UNKNOWN);

        /*----------  Handle ARP Replies. ----------*/

        // Drop if ARP reply source IP is 0.0.0.0
        gen.addLoad32(R0, ARP_SOURCE_IP_ADDRESS_OFFSET);
        gen.addCountAndDropIfR0Equals(IPV4_ANY_HOST_ADDRESS, Counter.DROPPED_ARP_REPLY_SPA_NO_HOST);

        // Pass if non-broadcast reply.
        // This also accepts multicast arp, but we assume those don't exist.
        gen.addLoadImmediate(R0, ETH_DEST_ADDR_OFFSET);
        gen.addCountAndPassIfBytesAtR0NotEqual(ETHER_BROADCAST, Counter.PASSED_ARP_UNICAST_REPLY);

        // It is a broadcast reply.
        if (mIPv4Address == null) {
            // When there is no IPv4 address, drop GARP replies (b/29404209).
            gen.addLoad32(R0, ARP_TARGET_IP_ADDRESS_OFFSET);
            gen.addCountAndDropIfR0Equals(IPV4_ANY_HOST_ADDRESS, Counter.DROPPED_GARP_REPLY);
        } else {
            // When there is an IPv4 address, drop broadcast replies with a different target IPv4
            // address.
            gen.addLoad32(R0, ARP_TARGET_IP_ADDRESS_OFFSET);
            gen.addCountAndDropIfR0NotEquals(bytesToBEInt(mIPv4Address),
                    Counter.DROPPED_ARP_OTHER_HOST);
        }
        gen.addCountAndPass(Counter.PASSED_ARP_BROADCAST_REPLY);

        /*----------  Handle ARP Requests. ----------*/

        gen.defineLabel(checkArpRequest);
        if (mIPv4Address != null) {
            // When there is an IPv4 address, drop unicast/broadcast requests with a different
            // target IPv4 address.
            gen.addLoad32(R0, ARP_TARGET_IP_ADDRESS_OFFSET);
            gen.addCountAndDropIfR0NotEquals(bytesToBEInt(mIPv4Address),
                    Counter.DROPPED_ARP_OTHER_HOST);

            ApfV6Generator v6Gen = tryToConvertToApfV6Generator(gen);
            if (v6Gen != null && mShouldHandleArpOffload) {
                // Ethernet requires that all packets be at least 60 bytes long
                v6Gen.addAllocate(60)
                        .addPacketCopy(ETHER_SRC_ADDR_OFFSET, ETHER_ADDR_LEN)
                        .addDataCopy(mHardwareAddress)
                        .addDataCopy(FIXED_ARP_REPLY_HEADER)
                        .addDataCopy(mHardwareAddress)
                        .addWrite32(mIPv4Address)
                        .addPacketCopy(ETHER_SRC_ADDR_OFFSET, ETHER_ADDR_LEN)
                        .addPacketCopy(ARP_SOURCE_IP_ADDRESS_OFFSET, IPV4_ADDR_LEN)
                        .addLoadFromMemory(R0, MemorySlot.TX_BUFFER_OUTPUT_POINTER)
                        .addAdd(18)
                        .addStoreToMemory(MemorySlot.TX_BUFFER_OUTPUT_POINTER, R0)
                        .addTransmitWithoutChecksum()
                        .addCountAndDrop(Counter.DROPPED_ARP_REQUEST_REPLIED);
            }
        }
        // If we're not clat, and we don't have an ipv4 address, allow all ARP request to avoid
        // racing against DHCP.
        gen.addCountAndPass(Counter.PASSED_ARP_REQUEST);
    }

    /**
     * Generate filter code to process IPv4 packets. Execution of this code ends in either the
     * DROP_LABEL or PASS_LABEL and does not fall off the end.
     * Preconditions:
     *  - Packet being filtered is IPv4
     */
    @GuardedBy("this")
    private void generateIPv4FilterLocked(ApfV4GeneratorBase<?> gen)
            throws IllegalInstructionException {
        // Here's a basic summary of what the IPv4 filter program does:
        //
        // if the network is IPv6 only network:
        //   if the packet is fragmented:
        //     drop
        //   if the packet is a dhcp packet comes from server:
        //     pass
        //   else
        //     drop
        // if filtering multicast (i.e. multicast lock not held):
        //   if it's DHCP destined to our MAC:
        //     pass
        //   if it's L2 broadcast:
        //     drop
        //   if it's IPv4 multicast:
        //     drop
        //   if it's IPv4 broadcast:
        //     drop
        // if keepalive ack
        //   drop
        // pass

        if (mHasClat) {
            // Check 1) it's not a fragment. 2) it's UDP.
            // Load 16 bit frag flags/offset field, 8 bit ttl, 8 bit protocol
            gen.addLoad32(R0, IPV4_FRAGMENT_OFFSET_OFFSET);
            gen.addOr(0xFF00);
            gen.addCountAndDropIfR0NotEquals(0xFF11, Counter.DROPPED_IPV4_NON_DHCP4);
            // Check it's addressed to DHCP client port.
            gen.addLoadFromMemory(R1, MemorySlot.IPV4_HEADER_SIZE);
            gen.addLoad32Indexed(R0, TCP_UDP_SOURCE_PORT_OFFSET);
            gen.addCountAndDropIfR0NotEquals(DHCP_SERVER_PORT << 16 | DHCP_CLIENT_PORT,
                    Counter.DROPPED_IPV4_NON_DHCP4);
            gen.addCountAndPass(Counter.PASSED_IPV4_FROM_DHCPV4_SERVER);
            return;
        }

        if (mMulticastFilter) {
            final String skipDhcpv4Filter = gen.getUniqueLabel();

            // Pass DHCP addressed to us.
            // Check 1) it's not a fragment. 2) it's UDP.
            // Load 16 bit frag flags/offset field, 8 bit ttl, 8 bit protocol
            gen.addLoad32(R0, IPV4_FRAGMENT_OFFSET_OFFSET);
            gen.addOr(0xFF00);
            gen.addJumpIfR0NotEquals(0xFF11, skipDhcpv4Filter);
            // Check it's addressed to DHCP client port.
            gen.addLoadFromMemory(R1, MemorySlot.IPV4_HEADER_SIZE);
            gen.addLoad16Indexed(R0, TCP_UDP_DESTINATION_PORT_OFFSET);
            gen.addJumpIfR0NotEquals(DHCP_CLIENT_PORT, skipDhcpv4Filter);
            // Check it's DHCP to our MAC address.
            gen.addLoadImmediate(R0, DHCP_CLIENT_MAC_OFFSET);
            // NOTE: Relies on R1 containing IPv4 header offset.
            gen.addAddR1ToR0();
            gen.addJumpIfBytesAtR0NotEqual(mHardwareAddress, skipDhcpv4Filter);
            gen.addCountAndPass(Counter.PASSED_DHCP);

            // Drop all multicasts/broadcasts.
            gen.defineLabel(skipDhcpv4Filter);

            // If IPv4 destination address is in multicast range, drop.
            gen.addLoad8(R0, IPV4_DEST_ADDR_OFFSET);
            gen.addAnd(0xf0);
            gen.addCountAndDropIfR0Equals(0xe0, Counter.DROPPED_IPV4_MULTICAST);

            // If IPv4 broadcast packet, drop regardless of L2 (b/30231088).
            gen.addLoad32(R0, IPV4_DEST_ADDR_OFFSET);
            gen.addCountAndDropIfR0Equals(IPV4_BROADCAST_ADDRESS,
                    Counter.DROPPED_IPV4_BROADCAST_ADDR);
            if (mIPv4Address != null && mIPv4PrefixLength < 31) {
                int broadcastAddr = ipv4BroadcastAddress(mIPv4Address, mIPv4PrefixLength);
                gen.addCountAndDropIfR0Equals(broadcastAddr, Counter.DROPPED_IPV4_BROADCAST_NET);
            }
        }

        // If any TCP keepalive filter matches, drop
        generateV4KeepaliveFilters(gen);

        // If any NAT-T keepalive filter matches, drop
        generateV4NattKeepaliveFilters(gen);

        // If TCP unicast on port 7, drop
        generateV4TcpPort7FilterLocked(gen);

        if (mMulticastFilter) {
            // Otherwise, this is an IPv4 unicast, pass
            // If L2 broadcast packet, drop.
            // TODO: can we invert this condition to fall through to the common pass case below?
            gen.addLoadImmediate(R0, ETH_DEST_ADDR_OFFSET);
            gen.addCountAndPassIfBytesAtR0NotEqual(ETHER_BROADCAST, Counter.PASSED_IPV4_UNICAST);
            gen.addCountAndDrop(Counter.DROPPED_IPV4_L2_BROADCAST);
        }

        // Otherwise, pass
        gen.addCountAndPass(Counter.PASSED_IPV4);
    }

    @GuardedBy("this")
    private void generateKeepaliveFilters(ApfV4GeneratorBase<?> gen, Class<?> filterType, int proto,
            int offset, String label) throws IllegalInstructionException {
        final boolean haveKeepaliveResponses = CollectionUtils.any(mKeepalivePackets,
                filterType::isInstance);

        // If no keepalive packets of this type
        if (!haveKeepaliveResponses) return;

        // If not the right proto, skip keepalive filters
        gen.addLoad8(R0, offset);
        gen.addJumpIfR0NotEquals(proto, label);

        // Drop Keepalive responses
        for (int i = 0; i < mKeepalivePackets.size(); ++i) {
            final KeepalivePacket response = mKeepalivePackets.valueAt(i);
            if (filterType.isInstance(response)) response.generateFilterLocked(gen);
        }

        gen.defineLabel(label);
    }

    @GuardedBy("this")
    private void generateV4KeepaliveFilters(ApfV4GeneratorBase<?> gen)
            throws IllegalInstructionException {
        generateKeepaliveFilters(gen, TcpKeepaliveAckV4.class, IPPROTO_TCP, IPV4_PROTOCOL_OFFSET,
                gen.getUniqueLabel());
    }

    @GuardedBy("this")
    private void generateV4NattKeepaliveFilters(ApfV4GeneratorBase<?> gen)
            throws IllegalInstructionException {
        generateKeepaliveFilters(gen, NattKeepaliveResponse.class,
                IPPROTO_UDP, IPV4_PROTOCOL_OFFSET, gen.getUniqueLabel());
    }

    private List<byte[]> getSolicitedNodeMcastAddressSuffix(
            @NonNull List<byte[]> ipv6Addresses) {
        final List<byte[]> suffixes = new ArrayList<>();
        for (byte[] addr: ipv6Addresses) {
            suffixes.add(Arrays.copyOfRange(addr, 13,  16));
        }
        return suffixes;
    }

    @GuardedBy("this")
    private List<byte[]> getIpv6Addresses(
            boolean includeNonTentative, boolean includeTentative, boolean includeAnycast) {
        final List<byte[]> addresses = new ArrayList<>();
        if (includeNonTentative) {
            for (Inet6Address addr : mIPv6NonTentativeAddresses) {
                addresses.add(addr.getAddress());
            }
        }

        if (includeTentative) {
            for (Inet6Address addr : mIPv6TentativeAddresses) {
                addresses.add(addr.getAddress());
            }
        }

        if (includeAnycast) {
            addresses.addAll(mDependencies.getAnycast6Addresses(mInterfaceParams.name));
        }
        return addresses;
    }

    @GuardedBy("this")
    private List<byte[]> getKnownMacAddresses() {
        final List<byte[]> addresses = new ArrayList<>();
        addresses.addAll(mDependencies.getEtherMulticastAddresses(mInterfaceParams.name));
        addresses.add(mHardwareAddress);
        addresses.add(ETHER_BROADCAST);
        return addresses;
    }

    /**
     * Generate allocate and transmit code to send ICMPv6 non-DAD NA packets.
     */
    @GuardedBy("this")
    private void generateNonDadNaTransmitLocked(ApfV6GeneratorBase<?> gen)
            throws IllegalInstructionException {
        final int ipv6PayloadLen = ICMPV6_NA_HEADER_LEN + ICMPV6_ND_OPTION_TLLA_LEN;
        final int pktLen = ETH_HEADER_LEN + IPV6_HEADER_LEN + ipv6PayloadLen;

        gen.addAllocate(pktLen);

        // Ethernet Header
        gen.addPacketCopy(ICMP6_NS_OPTION_TYPE_OFFSET + 2, ETHER_ADDR_LEN)  // dst MAC address
                .addDataCopy(mHardwareAddress)  // src MAC address
                .addWriteU16(ETH_P_IPV6);  // IPv6 type

        int tclass = mDependencies.getNdTrafficClass(mInterfaceParams.name);
        int vtf = (0x60000000 | (tclass << 20));
        // IPv6 header
        gen.addWrite32(vtf)  // IPv6 Header: version, traffic class, flowlabel
                // payload length (2 bytes) | next header: ICMPv6 (1 byte) | hop limit (1 byte)
                .addWrite32((ipv6PayloadLen << 16) | ((IPPROTO_ICMPV6 << 8) | 255))
                // target ip is guaranteed to be non-tentative as we already check before
                // we call transmit, but the link local ip can potentially be tentative.
                .addPacketCopy(ICMP6_NS_TARGET_IP_OFFSET, IPV6_ADDR_LEN)  // src ip
                .addPacketCopy(IPV6_SRC_ADDR_OFFSET, IPV6_ADDR_LEN);  // dst ip

        // ICMPv6 header and payload
        // ICMPv6 type: NA (1 byte) | code: 0 (1 byte) | checksum: set to payload size (2 bytes)
        gen.addWrite32((ICMPV6_NEIGHBOR_ADVERTISEMENT << 24) | ipv6PayloadLen)
                // Always set Router flag to prevent host deleting routes point at the router
                // Always set Override flag to update neighbor's cache
                // Solicited flag set to 1 if non DAD, refer to RFC4861#7.2.4
                .addWrite32(0xe0000000) // flags: R=1, S=1, O=1
                .addPacketCopy(ICMP6_NS_TARGET_IP_OFFSET, IPV6_ADDR_LEN) // target address
                // lla option: type (1 byte) | lla option: length (1 byte)
                .addWriteU16((ICMPV6_ND_OPTION_TLLA << 8) | 1)
                .addDataCopy(mHardwareAddress);  // lla option: link layer address

        gen.addTransmitL4(
                ETHER_HEADER_LEN,   // ip_ofs
                ICMP6_CHECKSUM_OFFSET,  // csum_ofs
                IPV6_SRC_ADDR_OFFSET,   // csum_start
                IPPROTO_ICMPV6, // partial_sum
                false   // udp
        );
    }

    @GuardedBy("this")
    private void generateNsFilterLocked(ApfV6Generator v6Gen)
            throws IllegalInstructionException {
        final List<byte[]> allIPv6Addrs = getIpv6Addresses(
                true /* includeNonTentative */,
                true /* includeTentative */,
                true /* includeAnycast */);
        if (allIPv6Addrs.isEmpty()) {
            // If there is no IPv6 link local address, allow all NS packets to avoid racing
            // against RS.
            v6Gen.addCountAndPass(PASSED_IPV6_NS_NO_ADDRESS);
            return;
        }

        // Warning: APF program may temporarily filter NS packets targeted for anycast addresses
        // used by processes other than clatd. This is because APF cannot reliably detect signal
        // on when IPV6_{JOIN,LEAVE}_ANYCAST is triggered.
        final List<byte[]> allMACs = getKnownMacAddresses();
        v6Gen.addLoadImmediate(R0, ETH_DEST_ADDR_OFFSET)
                .addCountAndDropIfBytesAtR0EqualsNoneOf(allMACs, DROPPED_IPV6_NS_OTHER_HOST);

        // Dst IPv6 address check:
        final List<byte[]> allSuffixes = getSolicitedNodeMcastAddressSuffix(allIPv6Addrs);
        final String notIpV6SolicitedNodeMcast = v6Gen.getUniqueLabel();
        final String endOfIpV6DstCheck = v6Gen.getUniqueLabel();
        v6Gen.addLoadImmediate(R0, IPV6_DEST_ADDR_OFFSET)
                .addJumpIfBytesAtR0NotEqual(IPV6_SOLICITED_NODES_PREFIX, notIpV6SolicitedNodeMcast)
                .addAdd(13)
                .addCountAndDropIfBytesAtR0EqualsNoneOf(allSuffixes, DROPPED_IPV6_NS_OTHER_HOST)
                .addJump(endOfIpV6DstCheck)
                .defineLabel(notIpV6SolicitedNodeMcast)
                .addCountAndDropIfBytesAtR0EqualsNoneOf(allIPv6Addrs, DROPPED_IPV6_NS_OTHER_HOST)
                .defineLabel(endOfIpV6DstCheck);

        // Hop limit not 255, NS requires hop limit to be 255 -> drop
        v6Gen.addLoad8(R0, IPV6_HOP_LIMIT_OFFSET)
                .addCountAndDropIfR0NotEquals(255, DROPPED_IPV6_NS_INVALID);

        // payload length < 24 (8 bytes ICMP6 header + 16 bytes target address) -> drop
        v6Gen.addLoad16(R0, IPV6_PAYLOAD_LEN_OFFSET)
                .addCountAndDropIfR0LessThan(24, DROPPED_IPV6_NS_INVALID);

        // ICMPv6 code not 0 -> drop
        v6Gen.addLoad8(R0, ICMP6_CODE_OFFSET)
                .addCountAndDropIfR0NotEquals(0, DROPPED_IPV6_NS_INVALID);

        // target address (ICMPv6 NS payload)
        //   1) is one of tentative addresses -> pass
        //   2) is none of {non-tentative, anycast} addresses -> drop
        final List<byte[]> tentativeIPv6Addrs = getIpv6Addresses(
                false, /* includeNonTentative */
                true, /* includeTentative */
                false /* includeAnycast */
        );
        v6Gen.addLoadImmediate(R0, ICMP6_NS_TARGET_IP_OFFSET);
        if (!tentativeIPv6Addrs.isEmpty()) {
            v6Gen.addCountAndPassIfBytesAtR0EqualsAnyOf(
                    tentativeIPv6Addrs, PASSED_IPV6_NS_TENTATIVE);
        }

        final List<byte[]> nonTentativeIpv6Addrs = getIpv6Addresses(
                true, /* includeNonTentative */
                false, /* includeTentative */
                true /* includeAnycast */
        );
        if (nonTentativeIpv6Addrs.isEmpty()) {
            v6Gen.addCountAndDrop(DROPPED_IPV6_NS_OTHER_HOST);
            return;
        }
        v6Gen.addCountAndDropIfBytesAtR0EqualsNoneOf(
                nonTentativeIpv6Addrs, DROPPED_IPV6_NS_OTHER_HOST);

        // if source ip is unspecified (::), it's DAD request -> pass
        v6Gen.addLoadImmediate(R0, IPV6_SRC_ADDR_OFFSET)
                .addCountAndPassIfBytesAtR0Equal(IPV6_UNSPECIFIED_ADDRESS, PASSED_IPV6_NS_DAD);

        // Only offload NUD/Address resolution packets that have SLLA as the their first option.
        // For option-less NUD packets or NUD/Address resolution packets where
        // the first option is not SLLA, pass them to the kernel for handling.
        // if payload len < 32 -> pass
        v6Gen.addLoad16(R0, IPV6_PAYLOAD_LEN_OFFSET)
                .addCountAndPassIfR0LessThan(32, PASSED_IPV6_NS_NO_SLLA_OPTION);

        // if the first option is not SLLA -> pass
        // 0                   1                   2                   3
        // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |     Type      |    Length     |Link-Layer Addr  |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        v6Gen.addLoad8(R0, ICMP6_NS_OPTION_TYPE_OFFSET)
                .addCountAndPassIfR0NotEquals(ICMPV6_ND_OPTION_SLLA,
                        PASSED_IPV6_NS_NO_SLLA_OPTION);

        // Src IPv6 address check:
        // if multicast address (FF::/8) or loopback address (00::/8) -> drop
        v6Gen.addLoad8(R0, IPV6_SRC_ADDR_OFFSET)
                .addCountAndDropIfR0IsOneOf(Set.of(0L, 0xffL), DROPPED_IPV6_NS_INVALID);

        // if multicast MAC in SLLA option -> drop
        v6Gen.addLoad8(R0, ICMP6_NS_OPTION_TYPE_OFFSET + 2)
                .addCountAndDropIfR0AnyBitsSet(1, DROPPED_IPV6_NS_INVALID);
        generateNonDadNaTransmitLocked(v6Gen);
        v6Gen.addCountAndDrop(Counter.DROPPED_IPV6_NS_REPLIED_NON_DAD);
    }

    /**
     * Generate filter code to process IPv6 packets. Execution of this code ends in either the
     * DROP_LABEL or PASS_LABEL, or falls off the end for ICMPv6 packets.
     * Preconditions:
     *  - Packet being filtered is IPv6
     */
    @GuardedBy("this")
    private void generateIPv6FilterLocked(ApfV4GeneratorBase<?> gen)
            throws IllegalInstructionException {
        // Here's a basic summary of what the IPv6 filter program does:
        //
        // if there is a hop-by-hop option present (e.g. MLD query)
        //   pass
        // if we're dropping multicast
        //   if it's not IPCMv6 or it's ICMPv6 but we're in doze mode:
        //     if it's multicast:
        //       drop
        //     pass
        // (APFv6+ specific logic) if it's ICMPv6 NS:
        //   if there are no IPv6 addresses (including link local address) on the interface:
        //     pass
        //   if MAC dst is none of known {unicast, multicast, broadcast} MAC addresses
        //     drop
        //   if IPv6 dst prefix is "ff02::1:ff00:0/104" but is none of solicited-node multicast
        //   IPv6 addresses:
        //     drop
        //   else if IPv6 dst is none of interface unicast IPv6 addresses (incl. anycast):
        //     drop
        //   if hop limit is not 255 (NS requires hop limit to be 255):
        //     drop
        //   if payload len < 24 (8 bytes ICMP6 header + 16 bytes target address):
        //     drop
        //   if ICMPv6 code is not 0:
        //     drop
        //   if target IP is one of tentative IPv6 addresses:
        //     pass
        //   if target IP is none of non-tentative IPv6 addresses (incl. anycast):
        //     drop
        //   if IPv6 src is unspecified (::):
        //     pass
        //   if payload len < 32 (8 bytes ICMP6 header + 16 bytes target address + 8 bytes option):
        //     pass
        //   if IPv6 src is multicast address (FF::/8) or loopback address (00::/8):
        //     drop
        //   if multicast MAC in SLLA option:
        //     drop
        //   transmit NA and drop
        // if it's ICMPv6 RS to any:
        //   drop
        // if it's ICMPv6 NA to anything in ff02::/120
        //   drop
        // if keepalive ack
        //   drop

        gen.addLoad8(R0, IPV6_NEXT_HEADER_OFFSET);

        // MLD packets set the router-alert hop-by-hop option.
        // TODO: be smarter about not blindly passing every packet with HBH options.
        gen.addCountAndPassIfR0Equals(IPPROTO_HOPOPTS, Counter.PASSED_MLD);

        // Drop multicast if the multicast filter is enabled.
        if (mMulticastFilter) {
            final String skipIPv6MulticastFilterLabel = gen.getUniqueLabel();
            final String dropAllIPv6MulticastsLabel = gen.getUniqueLabel();

            // While in doze mode, drop ICMPv6 multicast pings, let the others pass.
            // While awake, let all ICMPv6 multicasts through.
            if (mInDozeMode) {
                // Not ICMPv6? -> Proceed to multicast filtering
                gen.addJumpIfR0NotEquals(IPPROTO_ICMPV6, dropAllIPv6MulticastsLabel);

                // ICMPv6 but not ECHO? -> Skip the multicast filter.
                // (ICMPv6 ECHO requests will go through the multicast filter below).
                gen.addLoad8(R0, ICMP6_TYPE_OFFSET);
                gen.addJumpIfR0NotEquals(ICMPV6_ECHO_REQUEST_TYPE, skipIPv6MulticastFilterLabel);
            } else {
                gen.addJumpIfR0Equals(IPPROTO_ICMPV6, skipIPv6MulticastFilterLabel);
            }

            // Drop all other packets sent to ff00::/8 (multicast prefix).
            gen.defineLabel(dropAllIPv6MulticastsLabel);
            gen.addLoad8(R0, IPV6_DEST_ADDR_OFFSET);
            gen.addCountAndDropIfR0Equals(0xff, Counter.DROPPED_IPV6_NON_ICMP_MULTICAST);
            // If any keepalive filter matches, drop
            generateV6KeepaliveFilters(gen);
            // Not multicast. Pass.
            gen.addCountAndPass(Counter.PASSED_IPV6_UNICAST_NON_ICMP);
            gen.defineLabel(skipIPv6MulticastFilterLabel);
        } else {
            generateV6KeepaliveFilters(gen);
            // If not ICMPv6, pass.
            gen.addCountAndPassIfR0NotEquals(IPPROTO_ICMPV6, Counter.PASSED_IPV6_NON_ICMP);
        }

        // If we got this far, the packet is ICMPv6.  Drop some specific types.
        // Not ICMPv6 NS -> skip.
        gen.addLoad8(R0, ICMP6_TYPE_OFFSET); // warning: also used further below.
        final ApfV6Generator v6Gen = tryToConvertToApfV6Generator(gen);
        if (v6Gen != null && mShouldHandleNdOffload) {
            final String skipNsPacketFilter = v6Gen.getUniqueLabel();
            v6Gen.addJumpIfR0NotEquals(ICMPV6_NEIGHBOR_SOLICITATION, skipNsPacketFilter);
            generateNsFilterLocked(v6Gen);
            // End of NS filter. generateNsFilterLocked() method is terminal, so NS packet will be
            // either dropped or passed inside generateNsFilterLocked().
            v6Gen.defineLabel(skipNsPacketFilter);
        }

        // Add unsolicited multicast neighbor announcements filter
        String skipUnsolicitedMulticastNALabel = gen.getUniqueLabel();
        // Drop all router solicitations (b/32833400)
        gen.addCountAndDropIfR0Equals(ICMPV6_ROUTER_SOLICITATION,
                Counter.DROPPED_IPV6_ROUTER_SOLICITATION);
        // If not neighbor announcements, skip filter.
        gen.addJumpIfR0NotEquals(ICMPV6_NEIGHBOR_ADVERTISEMENT, skipUnsolicitedMulticastNALabel);
        // Drop all multicast NA to ff02::/120.
        // This is a way to cover ff02::1 and ff02::2 with a single JNEBS.
        // TODO: Drop only if they don't contain the address of on-link neighbours.
        final byte[] unsolicitedNaDropPrefix = Arrays.copyOf(IPV6_ALL_NODES_ADDRESS, 15);
        gen.addLoadImmediate(R0, IPV6_DEST_ADDR_OFFSET);
        gen.addJumpIfBytesAtR0NotEqual(unsolicitedNaDropPrefix, skipUnsolicitedMulticastNALabel);

        gen.addCountAndDrop(Counter.DROPPED_IPV6_MULTICAST_NA);
        gen.defineLabel(skipUnsolicitedMulticastNALabel);
    }

    /**
     * Generate filter code to process mDNS packets. Execution of this code ends in * DROP_LABEL
     * or PASS_LABEL if the packet is mDNS packets. Otherwise, skip this check.
     */
    @GuardedBy("this")
    private void generateMdnsFilterLocked(ApfV4GeneratorBase<?> gen)
            throws IllegalInstructionException {
        final String skipMdnsv4Filter = gen.getUniqueLabel();
        final String skipMdnsFilter = gen.getUniqueLabel();
        final String checkMdnsUdpPort = gen.getUniqueLabel();

        // Only turn on the filter if multicast filter is on and the qname allowlist is non-empty.
        if (!mMulticastFilter || mMdnsAllowList.isEmpty()) {
            return;
        }

        // Here's a basic summary of what the mDNS filter program does:
        //
        // A packet is considered as a multicast mDNS packet if it matches all the following
        // conditions
        //   1. its destination MAC address matches 01:00:5E:00:00:FB or 33:33:00:00:00:FB, for
        //   v4 and v6 respectively.
        //   2. it is an IPv4/IPv6 packet
        //   3. it is a UDP packet with port 5353

        // Check it's L2 mDNS multicast address.
        gen.addLoadImmediate(R0, ETH_DEST_ADDR_OFFSET);
        gen.addJumpIfBytesAtR0NotEqual(ETH_MULTICAST_MDNS_V4_MAC_ADDRESS, skipMdnsv4Filter);

        // Checks it's IPv4.
        gen.addLoad16(R0, ETH_ETHERTYPE_OFFSET);
        gen.addJumpIfR0NotEquals(ETH_P_IP, skipMdnsFilter);

        // Check it's not a fragment.
        gen.addLoad16(R0, IPV4_FRAGMENT_OFFSET_OFFSET);
        gen.addJumpIfR0AnyBitsSet(IPV4_FRAGMENT_MORE_FRAGS_MASK | IPV4_FRAGMENT_OFFSET_MASK,
                skipMdnsFilter);

        // Checks it's UDP.
        gen.addLoad8(R0, IPV4_PROTOCOL_OFFSET);
        gen.addJumpIfR0NotEquals(IPPROTO_UDP, skipMdnsFilter);

        // Set R1 to IPv4 header.
        gen.addLoadFromMemory(R1, MemorySlot.IPV4_HEADER_SIZE);
        gen.addJump(checkMdnsUdpPort);

        gen.defineLabel(skipMdnsv4Filter);

        // Checks it's L2 mDNS multicast address.
        // Relies on R0 containing the ethernet destination mac address offset.
        gen.addJumpIfBytesAtR0NotEqual(ETH_MULTICAST_MDNS_V6_MAC_ADDRESS, skipMdnsFilter);

        // Checks it's IPv6.
        gen.addLoad16(R0, ETH_ETHERTYPE_OFFSET);
        gen.addJumpIfR0NotEquals(ETH_P_IPV6, skipMdnsFilter);

        // Checks it's UDP.
        gen.addLoad8(R0, IPV6_NEXT_HEADER_OFFSET);
        gen.addJumpIfR0NotEquals(IPPROTO_UDP, skipMdnsFilter);

        // Set R1 to IPv6 header.
        gen.addLoadImmediate(R1, IPV6_HEADER_LEN);

        // Checks it's mDNS UDP port
        gen.defineLabel(checkMdnsUdpPort);
        gen.addLoad16Indexed(R0, TCP_UDP_DESTINATION_PORT_OFFSET);
        gen.addJumpIfR0NotEquals(MDNS_PORT, skipMdnsFilter);

        // TODO: implement APFv6 mDNS offload

        // end of mDNS filter
        gen.defineLabel(skipMdnsFilter);
    }

    /**
     * Generate filter code to drop IPv4 TCP packets on port 7.
     * <p>
     * On entry, we know it is IPv4 ethertype, but don't know anything else.
     * R0/R1 have nothing useful in them, and can be clobbered.
     */
    @GuardedBy("this")
    private void generateV4TcpPort7FilterLocked(ApfV4GeneratorBase<?> gen)
            throws IllegalInstructionException {
        final String skipPort7V4Filter = gen.getUniqueLabel();

        // Check it's TCP.
        gen.addLoad8(R0, IPV4_PROTOCOL_OFFSET);
        gen.addJumpIfR0NotEquals(IPPROTO_TCP, skipPort7V4Filter);

        // Check it's not a fragment or is the initial fragment.
        gen.addLoad16(R0, IPV4_FRAGMENT_OFFSET_OFFSET);
        gen.addJumpIfR0AnyBitsSet(IPV4_FRAGMENT_OFFSET_MASK, skipPort7V4Filter);

        // Check it's destination port 7.
        gen.addLoadFromMemory(R1, MemorySlot.IPV4_HEADER_SIZE);
        gen.addLoad16Indexed(R0, TCP_UDP_DESTINATION_PORT_OFFSET);
        gen.addJumpIfR0NotEquals(ECHO_PORT, skipPort7V4Filter);

        // Drop it.
        gen.addCountAndDrop(Counter.DROPPED_IPV4_TCP_PORT7_UNICAST);

        // Skip label.
        gen.defineLabel(skipPort7V4Filter);
    }

    @GuardedBy("this")
    private void generateV6KeepaliveFilters(ApfV4GeneratorBase<?> gen)
            throws IllegalInstructionException {
        generateKeepaliveFilters(gen, TcpKeepaliveAckV6.class, IPPROTO_TCP, IPV6_NEXT_HEADER_OFFSET,
                gen.getUniqueLabel());
    }

    /**
     * Begin generating an APF program to:
     * <ul>
     * <li>Drop/Pass 802.3 frames (based on policy)
     * <li>Drop packets with EtherType within the Black List
     * <li>Drop ARP requests not for us, if mIPv4Address is set,
     * <li>Drop IPv4 broadcast packets, except DHCP destined to our MAC,
     * <li>Drop IPv4 multicast packets, if mMulticastFilter,
     * <li>Pass all other IPv4 packets,
     * <li>Drop all broadcast non-IP non-ARP packets.
     * <li>Pass all non-ICMPv6 IPv6 packets,
     * <li>Pass all non-IPv4 and non-IPv6 packets,
     * <li>Drop IPv6 ICMPv6 NAs to anything in ff02::/120.
     * <li>Drop IPv6 ICMPv6 RSs.
     * <li>Filter IPv4 packets (see generateIPv4FilterLocked())
     * <li>Filter IPv6 packets (see generateIPv6FilterLocked())
     * <li>Let execution continue off the end of the program for IPv6 ICMPv6 packets. This allows
     *     insertion of RA filters here, or if there aren't any, just passes the packets.
     * </ul>
     */
    @GuardedBy("this")
    @VisibleForTesting
    protected ApfV4GeneratorBase<?> emitPrologueLocked() throws IllegalInstructionException {
        // This is guaranteed to succeed because of the check in maybeCreate.
        ApfV4GeneratorBase<?> gen;
        if (shouldUseApfV6Generator()) {
            gen = new ApfV6Generator(mApfVersionSupported, mApfRamSize,
                    mInstallableProgramSizeClamp);
        } else {
            gen = new ApfV4Generator(mApfVersionSupported, mApfRamSize,
                    mInstallableProgramSizeClamp);
        }

        if (hasDataAccess(mApfVersionSupported)) {
            if (gen instanceof ApfV4Generator) {
                // Increment TOTAL_PACKETS.
                // Only needed in APFv4.
                // In APFv6, the interpreter will increase the counter on packet receive.
                gen.addIncrementCounter(Counter.TOTAL_PACKETS);
            }

            gen.addLoadFromMemory(R0, MemorySlot.FILTER_AGE_SECONDS);
            gen.addStoreCounter(Counter.FILTER_AGE_SECONDS, R0);

            // requires a new enough APFv5+ interpreter, otherwise will be 0
            gen.addLoadFromMemory(R0, MemorySlot.FILTER_AGE_16384THS);
            gen.addStoreCounter(Counter.FILTER_AGE_16384THS, R0);

            // requires a new enough APFv5+ interpreter, otherwise will be 0
            gen.addLoadFromMemory(R0, MemorySlot.APF_VERSION);
            gen.addStoreCounter(Counter.APF_VERSION, R0);

            // store this program's sequential id, for later comparison
            gen.addLoadImmediate(R0, mNumProgramUpdates);
            gen.addStoreCounter(Counter.APF_PROGRAM_ID, R0);
        }

        // Here's a basic summary of what the initial program does:
        //
        // if it's a 802.3 Frame (ethtype < 0x0600):
        //    drop or pass based on configurations
        // if it has a ether-type that belongs to the black list
        //    drop
        // if it's ARP:
        //   insert ARP filter to drop or pass these appropriately
        // if it's IPv4:
        //   insert IPv4 filter to drop or pass these appropriately
        // if it's not IPv6:
        //   if it's broadcast:
        //     drop
        //   pass
        // insert IPv6 filter to drop, pass, or fall off the end for ICMPv6 packets

        gen.addLoad16(R0, ETH_ETHERTYPE_OFFSET);
        if (SdkLevel.isAtLeastV()) {
            // IPv4, ARP, IPv6, EAPOL, WAPI
            gen.addCountAndDropIfR0IsNoneOf(Set.of(0x0800L, 0x0806L, 0x86DDL, 0x888EL, 0x88B4L),
                    Counter.DROPPED_ETHERTYPE_NOT_ALLOWED);
        } else  {
            if (mDrop802_3Frames) {
                // drop 802.3 frames (ethtype < 0x0600)
                gen.addCountAndDropIfR0LessThan(ETH_TYPE_MIN, Counter.DROPPED_802_3_FRAME);
            }
            // Handle ether-type black list
            if (mEthTypeBlackList.length > 0) {
                final Set<Long> deniedEtherTypes = new ArraySet<>();
                for (int p : mEthTypeBlackList) {
                    deniedEtherTypes.add((long) p);
                }
                gen.addCountAndDropIfR0IsOneOf(deniedEtherTypes,
                        Counter.DROPPED_ETHERTYPE_NOT_ALLOWED);
            }
        }

        // Add ARP filters:
        String skipArpFiltersLabel = gen.getUniqueLabel();
        gen.addJumpIfR0NotEquals(ETH_P_ARP, skipArpFiltersLabel);
        generateArpFilterLocked(gen);
        gen.defineLabel(skipArpFiltersLabel);

        // Add mDNS filter:
        generateMdnsFilterLocked(gen);
        gen.addLoad16(R0, ETH_ETHERTYPE_OFFSET);

        // Add IPv4 filters:
        String skipIPv4FiltersLabel = gen.getUniqueLabel();
        gen.addJumpIfR0NotEquals(ETH_P_IP, skipIPv4FiltersLabel);
        generateIPv4FilterLocked(gen);
        gen.defineLabel(skipIPv4FiltersLabel);

        // Check for IPv6:
        // NOTE: Relies on R0 containing ethertype. This is safe because if we got here, we did
        // not execute the IPv4 filter, since this filter do not fall through, but either drop or
        // pass.
        String ipv6FilterLabel = gen.getUniqueLabel();
        gen.addJumpIfR0Equals(ETH_P_IPV6, ipv6FilterLabel);

        // Drop non-IP non-ARP broadcasts, pass the rest
        gen.addLoadImmediate(R0, ETH_DEST_ADDR_OFFSET);
        gen.addCountAndPassIfBytesAtR0NotEqual(ETHER_BROADCAST, Counter.PASSED_NON_IP_UNICAST);
        gen.addCountAndDrop(Counter.DROPPED_ETH_BROADCAST);

        // Add IPv6 filters:
        gen.defineLabel(ipv6FilterLabel);
        generateIPv6FilterLocked(gen);
        return gen;
    }

    /**
     * Append packet counting epilogue to the APF program.
     * <p>
     * Currently, the epilogue consists of two trampolines which count passed and dropped packets
     * before jumping to the actual PASS and DROP labels.
     */
    @GuardedBy("this")
    private void emitEpilogue(ApfV4GeneratorBase<?> gen) throws IllegalInstructionException {
        // Execution will reach here if none of the filters match, which will pass the packet to
        // the application processor.
        gen.addCountAndPass(Counter.PASSED_IPV6_ICMP);

        // TODO: merge the addCountTrampoline() into generate() method
        gen.addCountTrampoline();
    }

    /**
     * Generate and install a new filter program.
     */
    @GuardedBy("this")
    @SuppressWarnings("GuardedBy") // errorprone false positive on ra#generateFilterLocked
    @VisibleForTesting
    public void installNewProgramLocked() {
        ArrayList<Ra> rasToFilter = new ArrayList<>();
        final byte[] program;
        int programMinLft = Integer.MAX_VALUE;

        // Ensure the entire APF program uses the same time base.
        int timeSeconds = secondsSinceBoot();
        try {
            // Step 1: Determine how many RA filters we can fit in the program.
            ApfV4GeneratorBase<?> gen = emitPrologueLocked();

            // The epilogue normally goes after the RA filters, but add it early to include its
            // length when estimating the total.
            emitEpilogue(gen);

            // Can't fit the program even without any RA filters?
            if (gen.programLengthOverEstimate() > mMaximumApfProgramSize) {
                Log.e(TAG, "Program exceeds maximum size " + mMaximumApfProgramSize);
                sendNetworkQuirkMetrics(NetworkQuirkEvent.QE_APF_OVER_SIZE_FAILURE);
                return;
            }

            for (Ra ra : mRas) {
                // skip filter if it has expired.
                if (ra.getRemainingFilterLft(timeSeconds) <= 0) continue;
                ra.generateFilterLocked(gen, timeSeconds);
                // Stop if we get too big.
                if (gen.programLengthOverEstimate() > mMaximumApfProgramSize) {
                    if (VDBG) Log.d(TAG, "Past maximum program size, skipping RAs");
                    sendNetworkQuirkMetrics(NetworkQuirkEvent.QE_APF_OVER_SIZE_FAILURE);
                    break;
                }

                rasToFilter.add(ra);
            }

            // Step 2: Actually generate the program
            gen = emitPrologueLocked();
            for (Ra ra : rasToFilter) {
                ra.generateFilterLocked(gen, timeSeconds);
                programMinLft = Math.min(programMinLft, ra.getRemainingFilterLft(timeSeconds));
            }
            emitEpilogue(gen);
            program = gen.generate();
        } catch (IllegalInstructionException | IllegalStateException | IllegalArgumentException e) {
            Log.wtf(TAG, "Failed to generate APF program.", e);
            sendNetworkQuirkMetrics(NetworkQuirkEvent.QE_APF_GENERATE_FILTER_EXCEPTION);
            return;
        }
        if (mIsRunning) {
            // Update data snapshot every time we install a new program
            mIpClientCallback.startReadPacketFilter("new program install");
            if (!mIpClientCallback.installPacketFilter(program)) {
                sendNetworkQuirkMetrics(NetworkQuirkEvent.QE_APF_INSTALL_FAILURE);
            }
        }
        mLastTimeInstalledProgram = timeSeconds;
        mLastInstalledProgramMinLifetime = programMinLft;
        mLastInstalledProgram = program;
        mNumProgramUpdates++;
        mMaxProgramSize = Math.max(mMaxProgramSize, program.length);

        if (VDBG) {
            hexDump("Installing filter: ", program, program.length);
        }
    }

    private void hexDump(String msg, byte[] packet, int length) {
        log(msg + HexDump.toHexString(packet, 0, length, false /* lowercase */));
    }

    // Get the minimum value excludes zero. This is used for calculating the lowest lifetime values
    // in RA packets. Zero lifetimes are excluded because we want to detect whether there is any
    // unusually small lifetimes but zero lifetime is actually valid (cease to be a default router
    // or the option is no longer be used). Number of zero lifetime RAs is collected in a different
    // Metrics.
    private long getMinForPositiveValue(long oldMinValue, long value) {
        if (value < 1) return oldMinValue;
        return Math.min(oldMinValue, value);
    }

    private int getMinForPositiveValue(int oldMinValue, int value) {
        return (int) getMinForPositiveValue((long) oldMinValue, (long) value);
    }

    /**
     * Process an RA packet, updating the list of known RAs and installing a new APF program
     * if the current APF program should be updated.
     */
    @VisibleForTesting
    public synchronized void processRa(byte[] packet, int length) {
        if (VDBG) hexDump("Read packet = ", packet, length);

        final Ra ra;
        try {
            ra = new Ra(packet, length);
        } catch (Exception e) {
            Log.e(TAG, "Error parsing RA", e);
            mNumParseErrorRas++;
            return;
        }

        // Update info for Metrics
        mLowestRouterLifetimeSeconds = getMinForPositiveValue(
                mLowestRouterLifetimeSeconds, ra.routerLifetime());
        mLowestPioValidLifetimeSeconds = getMinForPositiveValue(
                mLowestPioValidLifetimeSeconds, ra.minPioValidLifetime());
        mLowestRioRouteLifetimeSeconds = getMinForPositiveValue(
                mLowestRioRouteLifetimeSeconds, ra.minRioRouteLifetime());
        mLowestRdnssLifetimeSeconds = getMinForPositiveValue(
                mLowestRdnssLifetimeSeconds, ra.minRdnssLifetime());

        // Remove all expired RA filters before trying to match the new RA.
        // TODO: matches() still checks that the old RA filter has not expired. Consider removing
        // that check.
        final int now = secondsSinceBoot();
        mRas.removeIf(item -> item.getRemainingFilterLft(now) <= 0);

        // Have we seen this RA before?
        for (int i = 0; i < mRas.size(); i++) {
            final Ra oldRa = mRas.get(i);
            final Ra.MatchType result = oldRa.matches(ra);
            if (result == Ra.MatchType.MATCH_PASS) {
                log("Updating RA from " + oldRa + " to " + ra);

                // Keep mRas in LRU order so as to prioritize generating filters for recently seen
                // RAs. LRU prioritizes this because RA filters are generated in order from mRas
                // until the filter program exceeds the maximum filter program size allowed by the
                // chipset, so RAs appearing earlier in mRas are more likely to make it into the
                // filter program.
                // TODO: consider sorting the RAs in order of increasing expiry time as well.
                // Swap to front of array.
                mRas.remove(i);
                mRas.add(0, ra);

                // Rate limit program installation
                if (mTokenBucket.get()) {
                    installNewProgramLocked();
                } else {
                    Log.e(TAG, "Failed to install prog for tracked RA, too many updates. " + ra);
                }
                return;
            } else if (result == Ra.MatchType.MATCH_DROP) {
                log("Ignoring RA " + ra + " which matches " + oldRa);
                return;
            }
        }
        mMaxDistinctRas = Math.max(mMaxDistinctRas, mRas.size() + 1);
        if (mRas.size() >= MAX_RAS) {
            // Remove the last (i.e. oldest) RA.
            mRas.remove(mRas.size() - 1);
        }
        log("Adding " + ra);
        mRas.add(0, ra);
        // Rate limit program installation
        if (mTokenBucket.get()) {
            installNewProgramLocked();
        } else {
            Log.e(TAG, "Failed to install prog for new RA, too many updates. " + ra);
        }
    }

    /**
     * Create an {@link ApfFilter} if {@code apfCapabilities} indicates support for packet
     * filtering using APF programs.
     */
    public static ApfFilter maybeCreate(Context context, ApfConfiguration config,
            InterfaceParams ifParams, IpClientCallbacksWrapper ipClientCallback,
            NetworkQuirkMetrics networkQuirkMetrics) {
        if (context == null || config == null || ifParams == null) return null;
        if (!ApfV4Generator.supportsVersion(config.apfVersionSupported)) {
            return null;
        }
        if (config.apfRamSize < 512) {
            Log.e(TAG, "Unacceptably small APF limit: " + config.apfRamSize);
            return null;
        }

        return new ApfFilter(context, config, ifParams, ipClientCallback, networkQuirkMetrics);
    }

    private synchronized void collectAndSendMetrics() {
        if (mIpClientRaInfoMetrics == null || mApfSessionInfoMetrics == null) return;
        final long sessionDurationMs = mClock.elapsedRealtime() - mSessionStartMs;
        if (sessionDurationMs < mMinMetricsSessionDurationMs) return;

        // Collect and send IpClientRaInfoMetrics.
        mIpClientRaInfoMetrics.setMaxNumberOfDistinctRas(mMaxDistinctRas);
        mIpClientRaInfoMetrics.setNumberOfZeroLifetimeRas(mNumZeroLifetimeRas);
        mIpClientRaInfoMetrics.setNumberOfParsingErrorRas(mNumParseErrorRas);
        mIpClientRaInfoMetrics.setLowestRouterLifetimeSeconds(mLowestRouterLifetimeSeconds);
        mIpClientRaInfoMetrics.setLowestPioValidLifetimeSeconds(mLowestPioValidLifetimeSeconds);
        mIpClientRaInfoMetrics.setLowestRioRouteLifetimeSeconds(mLowestRioRouteLifetimeSeconds);
        mIpClientRaInfoMetrics.setLowestRdnssLifetimeSeconds(mLowestRdnssLifetimeSeconds);
        mIpClientRaInfoMetrics.statsWrite();

        // Collect and send ApfSessionInfoMetrics.
        mApfSessionInfoMetrics.setVersion(mApfVersionSupported);
        mApfSessionInfoMetrics.setMemorySize(mApfRamSize);
        mApfSessionInfoMetrics.setApfSessionDurationSeconds(
                (int) (sessionDurationMs / DateUtils.SECOND_IN_MILLIS));
        mApfSessionInfoMetrics.setNumOfTimesApfProgramUpdated(mNumProgramUpdates);
        mApfSessionInfoMetrics.setMaxProgramSize(mMaxProgramSize);
        for (Map.Entry<Counter, Long> entry : mApfCounterTracker.getCounters().entrySet()) {
            if (entry.getValue() > 0) {
                mApfSessionInfoMetrics.addApfCounter(entry.getKey(), entry.getValue());
            }
        }
        mApfSessionInfoMetrics.statsWrite();
    }

    public synchronized void shutdown() {
        collectAndSendMetrics();
        if (mReceiveThread != null) {
            log("shutting down");
            mReceiveThread.halt();  // Also closes socket.
            mReceiveThread = null;
        }
        mRas.clear();
        mDependencies.removeBroadcastReceiver(mDeviceIdleReceiver);
    }

    public synchronized void setMulticastFilter(boolean isEnabled) {
        if (mMulticastFilter == isEnabled) return;
        mMulticastFilter = isEnabled;
        installNewProgramLocked();
    }

    @VisibleForTesting
    public synchronized void setDozeMode(boolean isEnabled) {
        if (mInDozeMode == isEnabled) return;
        mInDozeMode = isEnabled;
        installNewProgramLocked();
    }

    @VisibleForTesting
    public synchronized boolean isInDozeMode() {
        return mInDozeMode;
    }

    /** Retrieve the single IPv4 LinkAddress if there is one, otherwise return null. */
    private static LinkAddress retrieveIPv4LinkAddress(LinkProperties lp) {
        LinkAddress ipv4Address = null;
        for (LinkAddress address : lp.getLinkAddresses()) {
            if (!(address.getAddress() instanceof Inet4Address)) {
                continue;
            }
            if (ipv4Address != null && !ipv4Address.isSameAddressAs(address)) {
                // More than one IPv4 address, abort.
                return null;
            }
            ipv4Address = address;
        }
        return ipv4Address;
    }

    /** Retrieve the pair of IPv6 Inet6Address set, otherwise return pair with two empty set.
     *  The first element is a set containing tentative IPv6 addresses,
     *  the second element is a set containing non-tentative IPv6 addresses
     *  */
    private static Pair<Set<Inet6Address>, Set<Inet6Address>>
            retrieveIPv6LinkAddress(LinkProperties lp) {
        final Set<Inet6Address> tentativeAddrs = new ArraySet<>();
        final Set<Inet6Address> nonTentativeAddrs = new ArraySet<>();
        for (LinkAddress address : lp.getLinkAddresses()) {
            if (!(address.getAddress() instanceof Inet6Address)) {
                continue;
            }

            if ((address.getFlags() & IFA_F_TENTATIVE) == IFA_F_TENTATIVE) {
                tentativeAddrs.add((Inet6Address) address.getAddress());
            } else {
                nonTentativeAddrs.add((Inet6Address) address.getAddress());
            }
        }


        return new Pair<>(tentativeAddrs, nonTentativeAddrs);
    }

    public synchronized void setLinkProperties(LinkProperties lp) {
        // NOTE: Do not keep a copy of LinkProperties as it would further duplicate state.
        final LinkAddress ipv4Address = retrieveIPv4LinkAddress(lp);
        final byte[] addr = (ipv4Address != null) ? ipv4Address.getAddress().getAddress() : null;
        final int prefix = (ipv4Address != null) ? ipv4Address.getPrefixLength() : 0;
        final Pair<Set<Inet6Address>, Set<Inet6Address>>
                ipv6Addresses = retrieveIPv6LinkAddress(lp);

        if ((prefix == mIPv4PrefixLength)
                && Arrays.equals(addr, mIPv4Address)
                && ipv6Addresses.first.equals(mIPv6TentativeAddresses)
                && ipv6Addresses.second.equals(mIPv6NonTentativeAddresses)
        ) {
            return;
        }
        mIPv4Address = addr;
        mIPv4PrefixLength = prefix;
        mIPv6TentativeAddresses = ipv6Addresses.first;
        mIPv6NonTentativeAddresses = ipv6Addresses.second;

        installNewProgramLocked();
    }

    @Override
    public synchronized void updateClatInterfaceState(boolean add) {
        if (mHasClat == add) {
            return;
        }
        mHasClat = add;
        installNewProgramLocked();
    }

    @Override
    public boolean supportNdOffload() {
        return shouldUseApfV6Generator() && mShouldHandleNdOffload;
    }

    private boolean shouldUseApfV6Generator() {
        return SdkLevel.isAtLeastV() && ApfV6Generator.supportsVersion(mApfVersionSupported);
    }

    /**
     * Add TCP keepalive ack packet filter.
     * This will add a filter to drop acks to the keepalive packet passed as an argument.
     *
     * @param slot The index used to access the filter.
     * @param sentKeepalivePacket The attributes of the sent keepalive packet.
     */
    public synchronized void addTcpKeepalivePacketFilter(final int slot,
            final TcpKeepalivePacketDataParcelable sentKeepalivePacket) {
        log("Adding keepalive ack(" + slot + ")");
        if (null != mKeepalivePackets.get(slot)) {
            throw new IllegalArgumentException("Keepalive slot " + slot + " is occupied");
        }
        final int ipVersion = sentKeepalivePacket.srcAddress.length == 4 ? 4 : 6;
        mKeepalivePackets.put(slot, (ipVersion == 4)
                ? new TcpKeepaliveAckV4(sentKeepalivePacket)
                : new TcpKeepaliveAckV6(sentKeepalivePacket));
        installNewProgramLocked();
    }

    /**
     * Add NAT-T keepalive packet filter.
     * This will add a filter to drop NAT-T keepalive packet which is passed as an argument.
     *
     * @param slot The index used to access the filter.
     * @param sentKeepalivePacket The attributes of the sent keepalive packet.
     */
    public synchronized void addNattKeepalivePacketFilter(final int slot,
            final NattKeepalivePacketDataParcelable sentKeepalivePacket) {
        log("Adding NAT-T keepalive packet(" + slot + ")");
        if (null != mKeepalivePackets.get(slot)) {
            throw new IllegalArgumentException("NAT-T Keepalive slot " + slot + " is occupied");
        }

        // TODO : update ApfFilter to support dropping v6 keepalives
        if (sentKeepalivePacket.srcAddress.length != 4) {
            return;
        }

        mKeepalivePackets.put(slot, new NattKeepaliveResponse(sentKeepalivePacket));
        installNewProgramLocked();
    }

    /**
     * Remove keepalive packet filter.
     *
     * @param slot The index used to access the filter.
     */
    public synchronized void removeKeepalivePacketFilter(int slot) {
        log("Removing keepalive packet(" + slot + ")");
        mKeepalivePackets.remove(slot);
        installNewProgramLocked();
    }

    public synchronized void dump(IndentingPrintWriter pw) {
        pw.println(String.format(
                "Capabilities: { apfVersionSupported: %d, maximumApfProgramSize: %d }",
                mApfVersionSupported, mApfRamSize));
        pw.println("InstallableProgramSizeClamp: " + mInstallableProgramSizeClamp);
        pw.println("Filter update status: " + (mIsRunning ? "RUNNING" : "PAUSED"));
        pw.println("Receive thread: " + (mReceiveThread != null ? "RUNNING" : "STOPPED"));
        pw.println("Multicast: " + (mMulticastFilter ? "DROP" : "ALLOW"));
        pw.println("Minimum RDNSS lifetime: " + mMinRdnssLifetimeSec);
        pw.println("Interface MAC address: " + MacAddress.fromBytes(mHardwareAddress));
        pw.println("Multicast MAC addresses: ");
        pw.increaseIndent();
        for (byte[] addr : mDependencies.getEtherMulticastAddresses(mInterfaceParams.name)) {
            pw.println(MacAddress.fromBytes(addr));
        }
        pw.decreaseIndent();
        try {
            pw.println("IPv4 address: " + InetAddress.getByAddress(mIPv4Address).getHostAddress());
            pw.println("IPv6 non-tentative addresses: ");
            pw.increaseIndent();
            for (Inet6Address addr : mIPv6NonTentativeAddresses) {
                pw.println(addr.getHostAddress());
            }
            pw.decreaseIndent();
            pw.println("IPv6 tentative addresses: ");
            pw.increaseIndent();
            for (Inet6Address addr : mIPv6TentativeAddresses) {
                pw.println(addr.getHostAddress());
            }
            pw.decreaseIndent();
            pw.println("IPv6 anycast addresses:");
            pw.increaseIndent();
            final List<Inet6Address> anycastAddrs =
                    ProcfsParsingUtils.getAnycast6Addresses(mInterfaceParams.name);
            for (Inet6Address addr : anycastAddrs) {
                pw.println(addr.getHostAddress());
            }
            pw.decreaseIndent();
            pw.println("IPv6 multicast addresses:");
            pw.increaseIndent();
            final List<Inet6Address> multicastAddrs =
                    ProcfsParsingUtils.getIpv6MulticastAddresses(mInterfaceParams.name);
            for (Inet6Address addr : multicastAddrs) {
                pw.println(addr.getHostAddress());
            }
            pw.decreaseIndent();
        } catch (UnknownHostException|NullPointerException e) {}

        if (mLastTimeInstalledProgram == 0) {
            pw.println("No program installed.");
            return;
        }
        pw.println("Program updates: " + mNumProgramUpdates);
        pw.println(String.format(
                "Last program length %d, installed %ds ago, lifetime %ds",
                mLastInstalledProgram.length, secondsSinceBoot() - mLastTimeInstalledProgram,
                mLastInstalledProgramMinLifetime));

        pw.print("Denylisted Ethertypes:");
        for (int p : mEthTypeBlackList) {
            pw.print(String.format(" %04x", p));
        }
        pw.println();
        pw.println("RA filters:");
        pw.increaseIndent();
        for (Ra ra: mRas) {
            pw.println(ra);
            pw.increaseIndent();
            pw.println(String.format(
                    "Last seen %ds ago", secondsSinceBoot() - ra.mLastSeen));
            if (DBG) {
                pw.println("Last match:");
                pw.increaseIndent();
                pw.println(ra.getLastMatchingPacket());
                pw.decreaseIndent();
            }
            pw.decreaseIndent();
        }
        pw.decreaseIndent();

        pw.println("TCP Keepalive filters:");
        pw.increaseIndent();
        for (int i = 0; i < mKeepalivePackets.size(); ++i) {
            final KeepalivePacket keepalivePacket = mKeepalivePackets.valueAt(i);
            if (keepalivePacket instanceof TcpKeepaliveAck) {
                pw.print("Slot ");
                pw.print(mKeepalivePackets.keyAt(i));
                pw.print(": ");
                pw.println(keepalivePacket);
            }
        }
        pw.decreaseIndent();

        pw.println("NAT-T Keepalive filters:");
        pw.increaseIndent();
        for (int i = 0; i < mKeepalivePackets.size(); ++i) {
            final KeepalivePacket keepalivePacket = mKeepalivePackets.valueAt(i);
            if (keepalivePacket instanceof NattKeepaliveResponse) {
                pw.print("Slot ");
                pw.print(mKeepalivePackets.keyAt(i));
                pw.print(": ");
                pw.println(keepalivePacket);
            }
        }
        pw.decreaseIndent();

        if (DBG) {
            pw.println("Last program:");
            pw.increaseIndent();
            pw.println(HexDump.toHexString(mLastInstalledProgram, false /* lowercase */));
            pw.decreaseIndent();
        }

        pw.println("APF packet counters: ");
        pw.increaseIndent();
        if (!hasDataAccess(mApfVersionSupported)) {
            pw.println("APF counters not supported");
        } else if (mDataSnapshot == null) {
            pw.println("No last snapshot.");
        } else {
            try {
                Counter[] counters = Counter.class.getEnumConstants();
                for (Counter c : Arrays.asList(counters).subList(1, counters.length)) {
                    long value = ApfCounterTracker.getCounterValue(mDataSnapshot, c);
                    // Only print non-zero counters
                    if (value != 0) {
                        pw.println(c.toString() + ": " + value);
                    }

                    final Set<Counter> skipCheckCounters = Set.of(FILTER_AGE_SECONDS,
                            FILTER_AGE_16384THS);
                    if (!skipCheckCounters.contains(c)) {
                        // If the counter's value decreases, it may have been cleaned up or there
                        // may be a bug.
                        long oldValue = mApfCounterTracker.getCounters().getOrDefault(c, 0L);
                        if (value < oldValue) {
                            Log.e(TAG, String.format(
                                    "Apf Counter: %s unexpectedly decreased. oldValue: %d. "
                                            + "newValue: %d", c.toString(), oldValue, value));
                        }
                    }
                }
            } catch (ArrayIndexOutOfBoundsException e) {
                pw.println("Uh-oh: " + e);
            }
            if (VDBG) {
                pw.println("Raw data dump: ");
                pw.println(HexDump.dumpHexString(mDataSnapshot));
            }
        }
        pw.decreaseIndent();
    }

    /** Return ApfFilter update status for testing purposes. */
    public boolean isRunning() {
        return mIsRunning;
    }

    /** Pause ApfFilter updates for testing purposes. */
    public void pause() {
        mIsRunning = false;
    }

    /** Resume ApfFilter updates for testing purposes. */
    public void resume() {
        mIsRunning = true;
    }

    /** Return data snapshot as hex string for testing purposes. */
    public synchronized @Nullable String getDataSnapshotHexString() {
        if (mDataSnapshot == null) {
            return null;
        }
        return HexDump.toHexString(mDataSnapshot, 0, mDataSnapshot.length, false /* lowercase */);
    }

    // TODO: move to android.net.NetworkUtils
    @VisibleForTesting
    public static int ipv4BroadcastAddress(byte[] addrBytes, int prefixLength) {
        return bytesToBEInt(addrBytes) | (int) (Integer.toUnsignedLong(-1) >>> prefixLength);
    }

    private static int uint8(byte b) {
        return b & 0xff;
    }

    private static int getUint16(ByteBuffer buffer, int position) {
        return buffer.getShort(position) & 0xffff;
    }

    private static long getUint32(ByteBuffer buffer, int position) {
        return Integer.toUnsignedLong(buffer.getInt(position));
    }

    private static int getUint8(ByteBuffer buffer, int position) {
        return uint8(buffer.get(position));
    }

    private static int bytesToBEInt(byte[] bytes) {
        return (uint8(bytes[0]) << 24)
                + (uint8(bytes[1]) << 16)
                + (uint8(bytes[2]) << 8)
                + (uint8(bytes[3]));
    }

    private static byte[] concatArrays(final byte[]... arr) {
        int size = 0;
        for (byte[] a : arr) {
            size += a.length;
        }
        final byte[] result = new byte[size];
        int offset = 0;
        for (byte[] a : arr) {
            System.arraycopy(a, 0, result, offset, a.length);
            offset += a.length;
        }
        return result;
    }

    private void sendNetworkQuirkMetrics(final NetworkQuirkEvent event) {
        if (mNetworkQuirkMetrics == null) return;
        mNetworkQuirkMetrics.setEvent(event);
        mNetworkQuirkMetrics.statsWrite();
    }
}
