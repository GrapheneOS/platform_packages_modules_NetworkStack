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

import static android.net.dhcp6.Dhcp6Packet.PrefixDelegation;
import static android.net.util.NetworkConstants.RFC7421_PREFIX_LENGTH;
import static android.system.OsConstants.AF_INET6;
import static android.system.OsConstants.IPPROTO_UDP;
import static android.system.OsConstants.RT_SCOPE_UNIVERSE;
import static android.system.OsConstants.SOCK_DGRAM;
import static android.system.OsConstants.SOCK_NONBLOCK;

import static com.android.net.module.util.NetworkStackConstants.ALL_DHCP_RELAY_AGENTS_AND_SERVERS;
import static com.android.net.module.util.NetworkStackConstants.DHCP6_CLIENT_PORT;
import static com.android.net.module.util.NetworkStackConstants.DHCP6_SERVER_PORT;
import static com.android.net.module.util.NetworkStackConstants.IPV6_ADDR_ANY;
import static com.android.networkstack.apishim.ConstantsShim.IFA_F_MANAGETEMPADDR;
import static com.android.networkstack.apishim.ConstantsShim.IFA_F_NOPREFIXROUTE;
import static com.android.networkstack.util.NetworkStackUtils.createInet6AddressFromEui64;

import android.content.Context;
import android.net.IpPrefix;
import android.net.LinkAddress;
import android.net.ip.IpClient;
import android.net.util.SocketUtils;
import android.os.Handler;
import android.os.Message;
import android.os.SystemClock;
import android.system.ErrnoException;
import android.system.Os;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.android.internal.util.HexDump;
import com.android.internal.util.State;
import com.android.internal.util.StateMachine;
import com.android.internal.util.WakeupMessage;
import com.android.net.module.util.InterfaceParams;
import com.android.net.module.util.PacketReader;
import com.android.net.module.util.netlink.NetlinkUtils;

import java.io.FileDescriptor;
import java.io.IOException;
import java.net.Inet6Address;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Random;

/**
 * A DHCPv6 client.
 *
 * So far only support IA_PD (prefix delegation), not for IA_NA/IA_TA yet.
 *
 * @hide
 */
public class Dhcp6Client extends StateMachine {
    private static final String TAG = Dhcp6Client.class.getSimpleName();
    private static final boolean DBG = true;

    // Dhcp6Client shares the same handler with IpClient, define the base command range for
    // both public and private messages used in Dhcp6Client, to avoid commands overlap.
    // Public messages.
    private static final int PUBLIC_BASE = IpClient.DHCP6CLIENT_CMD_BASE;
    // Commands from controller to start/stop DHCPv6
    public static final int CMD_START_DHCP6 = PUBLIC_BASE + 1;
    public static final int CMD_STOP_DHCP6  = PUBLIC_BASE + 2;
    // Notification from DHCPv6 state machine post DHCPv6 discovery/renewal. Indicates
    // success/failure
    public static final int CMD_DHCP6_RESULT = PUBLIC_BASE + 3;
    // Message.arg1 arguments to CMD_DHCP6_RESULT notification
    public static final int DHCP6_PD_SUCCESS = 1;
    public static final int DHCP6_PD_PREFIX_EXPIRED = 2;
    public static final int DHCP6_PD_PREFIX_CHANGED = 3;

    // Notification from DHCPv6 state machine before quitting
    public static final int CMD_ON_QUIT = PUBLIC_BASE + 4;

    // Internal messages.
    private static final int PRIVATE_BASE        = IpClient.DHCP6CLIENT_CMD_BASE + 100;
    private static final int CMD_RECEIVED_PACKET = PRIVATE_BASE + 1;
    private static final int CMD_KICK            = PRIVATE_BASE + 2;
    private static final int CMD_DHCP6_PD_RENEW  = PRIVATE_BASE + 3;
    private static final int CMD_DHCP6_PD_REBIND = PRIVATE_BASE + 4;
    private static final int CMD_DHCP6_PD_EXPIRE = PRIVATE_BASE + 5;

    // Timers and timeouts.
    // TODO: comply with RFC8415 section 15(Reliability of Client-Initiated Message Exchanges)
    private static final int SECONDS           = 1000;
    private static final int FIRST_TIMEOUT_MS  =   1 * SECONDS;
    private static final int MAX_TIMEOUT_MS    = 512 * SECONDS;

    private int mTransId;
    private int mIaId;
    private long mTransStartMillis;
    @Nullable private PrefixDelegation mAdvertise;
    @Nullable private PrefixDelegation mReply;
    @Nullable private byte[] mServerDuid;

    // State variables.
    @NonNull private final Context mContext;
    @NonNull private final Random mRandom;
    @NonNull private final StateMachine mController;
    @NonNull private final WakeupMessage mKickAlarm;
    @NonNull private final WakeupMessage mRenewAlarm;
    @NonNull private final WakeupMessage mRebindAlarm;
    @NonNull private final WakeupMessage mExpiryAlarm;
    @NonNull private final InterfaceParams mIface;
    @NonNull private final Dhcp6PacketHandler mDhcp6PacketHandler;
    @NonNull private final byte[] mClientDuid;

    // States.
    private State mStoppedState = new StoppedState();
    private State mStartedState = new StartedState();
    private State mSolicitState = new SolicitState();
    private State mRequestState = new RequestState();
    private State mHaveLeaseState = new HaveLeaseState();
    private State mBoundState = new BoundState();
    private State mRenewState = new RenewState();
    private State mRebindState = new RebindState();

    private WakeupMessage makeWakeupMessage(String cmdName, int cmd) {
        cmdName = Dhcp6Client.class.getSimpleName() + "." + mIface.name + "." + cmdName;
        return new WakeupMessage(mContext, getHandler(), cmdName, cmd);
    }

    private Dhcp6Client(@NonNull final Context context, @NonNull final StateMachine controller,
            @NonNull final InterfaceParams iface) {
        super(TAG, controller.getHandler());

        mContext = context;
        mController = controller;
        mIface = iface;
        mClientDuid = Dhcp6Packet.createClientDuid(iface.macAddr);
        mDhcp6PacketHandler = new Dhcp6PacketHandler(getHandler());

        addState(mStoppedState);
        addState(mStartedState); {
            addState(mSolicitState, mStartedState);
            addState(mRequestState, mStartedState);
            addState(mHaveLeaseState, mStartedState); {
                addState(mBoundState, mHaveLeaseState);
                addState(mRenewState, mHaveLeaseState);
                addState(mRebindState, mHaveLeaseState);
            }
        }

        setInitialState(mStoppedState);

        mRandom = new Random();

        // Used to schedule packet retransmissions.
        mKickAlarm = makeWakeupMessage("KICK", CMD_KICK);
        // Used to schedule DHCP reacquisition.
        mRenewAlarm = makeWakeupMessage("RENEW", CMD_DHCP6_PD_RENEW);
        mRebindAlarm = makeWakeupMessage("REBIND", CMD_DHCP6_PD_REBIND);
        mExpiryAlarm = makeWakeupMessage("EXPIRY", CMD_DHCP6_PD_EXPIRE);
    }

    /**
     * Make a Dhcp6Client instance.
     */
    public static Dhcp6Client makeDhcp6Client(@NonNull final Context context,
            @NonNull final StateMachine controller, @NonNull final InterfaceParams ifParams) {
        final Dhcp6Client client = new Dhcp6Client(context, controller, ifParams);
        client.start();
        return client;
    }

    /**
     * Quit the Dhcp6 StateMachine.
     *
     * @hide
     */
    public void doQuit() {
        Log.d(TAG, "doQuit");
        quit();
    }

    @Override
    protected void onQuitting() {
        Log.d(TAG, "onQuitting");
        mController.sendMessage(CMD_ON_QUIT);
    }

    /**
     * Retransmits packets using jittered exponential backoff with an optional timeout. Packet
     * transmission is triggered by CMD_KICK, which is sent by an AlarmManager alarm. Kicks are
     * cancelled when leaving the state.
     *
     * Concrete subclasses must implement sendPacket, which is called when the alarm fires and a
     * packet needs to be transmitted, and receivePacket, which is triggered by CMD_RECEIVED_PACKET
     * sent by the receive thread.
     *
     * TODO: deduplicate with the similar code in DhcpClient.java
     */
    abstract class PacketRetransmittingState extends State {
        private int mTimer;

        @Override
        public void enter() {
            super.enter();
            mTimer = FIRST_TIMEOUT_MS;
            sendMessage(CMD_KICK);
        }

        @Override
        public boolean processMessage(Message message) {
            if (super.processMessage(message) == HANDLED) {
                return HANDLED;
            }

            switch (message.what) {
                case CMD_KICK:
                    sendPacket();
                    scheduleKick();
                    return HANDLED;
                case CMD_RECEIVED_PACKET:
                    receivePacket((Dhcp6Packet) message.obj);
                    return HANDLED;
                default:
                    return NOT_HANDLED;
            }
        }

        @Override
        public void exit() {
            super.exit();
            mKickAlarm.cancel();
        }

        protected abstract boolean sendPacket();
        protected abstract void receivePacket(Dhcp6Packet packet);

        protected int jitterTimer(int baseTimer) {
            int maxJitter = baseTimer / 10;
            int jitter = mRandom.nextInt(2 * maxJitter) - maxJitter;
            return baseTimer + jitter;
        }

        protected void scheduleKick() {
            long now = SystemClock.elapsedRealtime();
            long timeout = jitterTimer(mTimer);
            long alarmTime = now + timeout;
            mKickAlarm.schedule(alarmTime);
            mTimer *= 2;
            if (mTimer > MAX_TIMEOUT_MS) {
                mTimer = MAX_TIMEOUT_MS;
            }
        }
    }

    private void scheduleLeaseTimers() {
        final long now = SystemClock.elapsedRealtime();
        mRenewAlarm.schedule(now + mReply.t1 * (long) SECONDS);
        mRebindAlarm.schedule(now + mReply.t2 * (long) SECONDS);
        mExpiryAlarm.schedule(now + mReply.ipo.valid * (long) SECONDS);
        Log.d(TAG, "Scheduling IA_PD renewal in " + mReply.t1 + "s");
        Log.d(TAG, "Scheduling IA_PD rebind in " + mReply.t2 + "s");
        Log.d(TAG, "Scheduling IA_PD expiry in " + mReply.ipo.valid + "s");
    }

    private void notifyPrefixDelegation(int result, @Nullable final PrefixDelegation pd) {
        mController.sendMessage(CMD_DHCP6_RESULT, result, 0, pd);
    }

    private void clearDhcp6State() {
        mAdvertise = null;
        mReply = null;
        mServerDuid = null;
    }

    private void startNewTransaction() {
        mTransId = mRandom.nextInt() & 0xffffff;
        mTransStartMillis = SystemClock.elapsedRealtime();
    }

    private short getHundredthsOfSec() {
        return (short) ((SystemClock.elapsedRealtime() - mTransStartMillis) / 10);
    }

    @SuppressWarnings("ByteBufferBackingArray")
    private boolean sendSolicitPacket(final ByteBuffer iapd) {
        final ByteBuffer packet = Dhcp6Packet.buildSolicitPacket(mTransId,
                getHundredthsOfSec() /* elapsed time */, iapd.array(), mClientDuid,
                true /* rapidCommit */);
        return transmitPacket(packet, "solicit");
    }

    @SuppressWarnings("ByteBufferBackingArray")
    private boolean sendRequestPacket(final ByteBuffer iapd) {
        final ByteBuffer packet = Dhcp6Packet.buildRequestPacket(mTransId,
                getHundredthsOfSec() /* elapsed time */, iapd.array(), mClientDuid,
                mServerDuid);
        return transmitPacket(packet, "request");
    }

    @SuppressWarnings("ByteBufferBackingArray")
    private boolean sendRenewPacket(final ByteBuffer iapd) {
        final ByteBuffer packet = Dhcp6Packet.buildRenewPacket(mTransId,
                getHundredthsOfSec() /* elapsed time*/, iapd.array(), mClientDuid, mServerDuid);
        return transmitPacket(packet, "renew");
    }

    @SuppressWarnings("ByteBufferBackingArray")
    private boolean sendRebindPacket(final ByteBuffer iapd) {
        final ByteBuffer packet = Dhcp6Packet.buildRebindPacket(mTransId,
                getHundredthsOfSec() /* elapsed time */, iapd.array(), mClientDuid);
        return transmitPacket(packet, "rebind");
    }

    private ByteBuffer buildEmptyIaPdOption() {
        return Dhcp6Packet.buildIaPdOption(mIaId, 0 /* t1 */, 0 /* t2 */, 0 /* preferred */,
                0 /* valid */, new byte[16] /* empty prefix */, (byte) RFC7421_PREFIX_LENGTH);
    }

    private ByteBuffer buildIaPdOption(@NonNull final PrefixDelegation pd) {
        return Dhcp6Packet.buildIaPdOption(pd.iaid, pd.t1, pd.t2, pd.ipo.preferred, pd.ipo.valid,
                pd.ipo.prefix, pd.ipo.prefixLen);
    }

    /**
     * Parent state at which client does initialization of interface and packet handler, also
     * processes the CMD_STOP_DHCP6 command in this state which child states don't handle.
     */
    class StartedState extends State {
        @Override
        public void enter() {
            clearDhcp6State();
            if (mDhcp6PacketHandler.start()) return;
            Log.e(TAG, "Fail to start DHCPv6 Packet Handler");
            // We cannot call transitionTo because a transition is still in progress.
            // Instead, ensure that we process CMD_STOP_DHCP6 as soon as the transition is complete.
            deferMessage(obtainMessage(CMD_STOP_DHCP6));
        }

        @Override
        public void exit() {
            mDhcp6PacketHandler.stop();
            if (DBG) Log.d(TAG, "DHCPv6 Packet Handler stopped");
            clearDhcp6State();
        }

        @Override
        public boolean processMessage(Message message) {
            super.processMessage(message);
            switch (message.what) {
                case CMD_STOP_DHCP6:
                    transitionTo(mStoppedState);
                    return HANDLED;
                default:
                    return NOT_HANDLED;
            }
        }
    }

    /**
     * Initial state of DHCPv6 state machine.
     */
    class StoppedState extends State {
        @Override
        public boolean processMessage(Message message) {
            switch (message.what) {
                case CMD_START_DHCP6:
                    // TODO: store the delegated prefix in IpMemoryStore and start in REBIND instead
                    // of SOLICIT if there is already a valid prefix on this network.
                    transitionTo(mSolicitState);
                    return HANDLED;
                default:
                    return NOT_HANDLED;
            }
        }
    }

    /**
     * Client (re)transmits a Solicit message to locate DHCPv6 servers and processes the Advertise
     * message in this state.
     *
     * Note: Not implement DHCPv6 server selection, always request the first Advertise we receive.
     */
    class SolicitState extends PacketRetransmittingState {
        @Override
        public void enter() {
            super.enter();
            startNewTransaction();
            mIaId = mRandom.nextInt();
        }

        protected boolean sendPacket() {
            return sendSolicitPacket(buildEmptyIaPdOption());
        }

        // TODO: support multiple prefixes.
        protected void receivePacket(Dhcp6Packet packet) {
            if (!packet.isValid(mTransId, mClientDuid)) return;
            if (packet instanceof Dhcp6AdvertisePacket) {
                mAdvertise = packet.mPrefixDelegation;
                if (mAdvertise != null && mAdvertise.iaid == mIaId) {
                    Log.d(TAG, "Get prefix delegation option from Advertise: " + mAdvertise);
                    mServerDuid = packet.mServerDuid;
                    transitionTo(mRequestState);
                }
            } else if (packet instanceof Dhcp6ReplyPacket) {
                if (!packet.mRapidCommit) {
                    Log.e(TAG, "Server responded to SOLICIT with REPLY without rapid commit option"
                            + ", ignoring");
                    return;
                }
                final PrefixDelegation pd = packet.mPrefixDelegation;
                if (pd != null && pd.iaid == mIaId) {
                    Log.d(TAG, "Get prefix delegation option from RapidCommit Reply: " + pd);
                    mReply = pd;
                    mServerDuid = packet.mServerDuid;
                    transitionTo(mBoundState);
                }
            }
        }
    }

    /**
     * Client (re)transmits a Request message to request configuration from a specific server and
     * process the Reply message in this state.
     */
    class RequestState extends PacketRetransmittingState {
        protected boolean sendPacket() {
            return sendRequestPacket(buildIaPdOption(mAdvertise));
        }

        protected void receivePacket(Dhcp6Packet packet) {
            if (!(packet instanceof Dhcp6ReplyPacket)) return;
            if (!packet.isValid(mTransId, mClientDuid)) return;
            final PrefixDelegation pd = packet.mPrefixDelegation;
            if (pd != null && pd.iaid == mIaId) {
                Log.d(TAG, "Get prefix delegation option from Reply: " + pd);
                mReply = pd;
                transitionTo(mBoundState);
            }
        }
    }

    /**
     * Parent state of other states at which client has already obtained the lease from server.
     */
    class HaveLeaseState extends State {
        @Override
        public boolean processMessage(Message message) {
            switch (message.what) {
                case CMD_DHCP6_PD_EXPIRE:
                    notifyPrefixDelegation(DHCP6_PD_PREFIX_EXPIRED, null);
                    transitionTo(mSolicitState);
                    return HANDLED;
                default:
                    return NOT_HANDLED;
            }
        }

        @Override
        public void exit() {
            // Clear any extant alarms.
            mRenewAlarm.cancel();
            mRebindAlarm.cancel();
            mExpiryAlarm.cancel();
            clearDhcp6State();
        }
    }

    /**
     * Client has already obtained the lease(e.g. IA_PD option) from server and stays in Bound
     * state until T1 expires, and then transition to Renew state to extend the lease duration.
     */
    class BoundState extends State {
        @Override
        public void enter() {
            super.enter();
            scheduleLeaseTimers();

            // TODO: roll back to SOLICIT state after a delay if something wrong happens
            // instead of returning directly.
            if (!Dhcp6Packet.hasValidPrefixDelegation(mReply)) {
                Log.e(TAG, "Invalid prefix delegatioin " + mReply);
                return;
            }
            // Configure the IPv6 addresses based on the delegated prefix on the interface.
            // We've checked that delegated prefix is valid upon receiving the response
            // from DHCPv6 server, and the server may assign a prefix with length less
            // than 64. So for SLAAC use case we always set the prefix length to 64 even
            // if the delegated prefix length is less than 64.
            final IpPrefix prefix;
            try {
                prefix = new IpPrefix(Inet6Address.getByAddress(mReply.ipo.prefix),
                        RFC7421_PREFIX_LENGTH);
            } catch (UnknownHostException e) {
                Log.wtf(TAG, "Invalid delegated prefix "
                        + HexDump.toHexString(mReply.ipo.prefix));
                return;
            }
            // Create an IPv6 address from the interface mac address with IFA_F_MANAGETEMPADDR
            // flag, kernel will create another privacy IPv6 address on behalf of user space.
            // We don't need to remember IPv6 addresses that need to extend the lifetime every
            // time it enters BoundState.
            final Inet6Address address = createInet6AddressFromEui64(prefix,
                    mIface.macAddr.toByteArray());
            final int flags = IFA_F_NOPREFIXROUTE | IFA_F_MANAGETEMPADDR;
            final long now = SystemClock.elapsedRealtime();
            final long deprecationTime = now + mReply.ipo.preferred;
            final long expirationTime = now + mReply.ipo.valid;
            final LinkAddress la = new LinkAddress(address, RFC7421_PREFIX_LENGTH, flags,
                    RT_SCOPE_UNIVERSE /* scope */, deprecationTime, expirationTime);
            if (!la.isGlobalPreferred()) {
                Log.e(TAG, la + " is not a global IPv6 address, ignoring");
                return;
            }
            if (!NetlinkUtils.sendRtmNewAddressRequest(mIface.index, address,
                    (short) RFC7421_PREFIX_LENGTH,
                    flags, (byte) RT_SCOPE_UNIVERSE /* scope */,
                    mReply.ipo.preferred, mReply.ipo.valid)) {
                Log.e(TAG, "Failed to set IPv6 address " + address.getHostAddress()
                        + "%" + mIface.index);
                return;
            }
            notifyPrefixDelegation(DHCP6_PD_SUCCESS, mReply);
        }

        @Override
        public boolean processMessage(Message message) {
            super.processMessage(message);
            switch (message.what) {
                case CMD_DHCP6_PD_RENEW:
                    transitionTo(mRenewState);
                    return HANDLED;
                default:
                    return NOT_HANDLED;
            }
        }
    }

    abstract class ReacquireState extends PacketRetransmittingState {
        @Override
        public void enter() {
            super.enter();
            startNewTransaction();
        }

        protected void receivePacket(Dhcp6Packet packet) {
            if (!(packet instanceof Dhcp6ReplyPacket)) return;
            if (!packet.isValid(mTransId, mClientDuid)) return;
            final PrefixDelegation pd = packet.mPrefixDelegation;
            if (pd != null) {
                if (pd.iaid != mIaId
                        || !(Arrays.equals(pd.ipo.prefix, mReply.ipo.prefix)
                                && pd.ipo.prefixLen == mReply.ipo.prefixLen)) {
                    Log.i(TAG, "Renewal prefix " + HexDump.toHexString(pd.ipo.prefix)
                            + " does not match current prefix "
                            + HexDump.toHexString(mReply.ipo.prefix));
                    notifyPrefixDelegation(DHCP6_PD_PREFIX_CHANGED, null);
                    transitionTo(mSolicitState);
                    return;
                }
                mReply = pd;
                mServerDuid = packet.mServerDuid;
                // Once the delegated prefix gets refreshed successfully we have to extend the
                // preferred lifetime and valid lifetime of global IPv6 addresses, otherwise
                // these addresses will become depreacated finally and then provisioning failure
                // happens. So we transit to mBoundState to update the address with refreshed
                // preferred and valid lifetime via sending RTM_NEWADDR message, going back to
                // Bound state after a success update.
                transitionTo(mBoundState);
            }
        }
    }

    /**
     * Client enters Renew state when T1 expires and (re)transmits Renew message to the
     * server that originally provided the client's leases and configuration parameters to
     * extend the lifetimes on the leases assigned to the client.
     */
    class RenewState extends ReacquireState {
        @Override
        public boolean processMessage(Message message) {
            if (super.processMessage(message) == HANDLED) {
                return HANDLED;
            }
            switch (message.what) {
                case CMD_DHCP6_PD_REBIND:
                    transitionTo(mRebindState);
                    return HANDLED;
                default:
                    return NOT_HANDLED;
            }
        }

        protected boolean sendPacket() {
            return sendRenewPacket(buildIaPdOption(mReply));
        }
    }

    /**
     * Client enters Rebind state when T2 expires and (re)transmits Rebind message to any
     * available server to extend the lifetimes on the leases assigned to the client and to
     * update other configuration parameters.
     */
    class RebindState extends ReacquireState {
        protected boolean sendPacket() {
            return sendRebindPacket(buildIaPdOption(mReply));
        }
    }

    private class Dhcp6PacketHandler extends PacketReader {
        private FileDescriptor mUdpSock;

        Dhcp6PacketHandler(Handler handler) {
            super(handler);
        }

        @Override
        protected void handlePacket(byte[] recvbuf, int length) {
            try {
                final Dhcp6Packet packet = Dhcp6Packet.decodePacket(recvbuf, length);
                if (DBG) Log.d(TAG, "Received packet: " + packet);
                sendMessage(CMD_RECEIVED_PACKET, packet);
            } catch (Dhcp6Packet.ParseException e) {
                Log.e(TAG, "Can't parse DHCPv6 packet: " + e.getMessage());
            }
        }

        @Override
        protected FileDescriptor createFd() {
            try {
                mUdpSock = Os.socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
                SocketUtils.bindSocketToInterface(mUdpSock, mIface.name);
                Os.bind(mUdpSock, IPV6_ADDR_ANY, DHCP6_CLIENT_PORT);
            } catch (SocketException | ErrnoException e) {
                Log.e(TAG, "Error creating udp socket", e);
                closeFd(mUdpSock);
                mUdpSock = null;
                return null;
            }
            return mUdpSock;
        }

        @Override
        protected int readPacket(FileDescriptor fd, byte[] packetBuffer) throws Exception {
            try {
                return Os.read(fd, packetBuffer, 0, packetBuffer.length);
            } catch (IOException | ErrnoException e) {
                Log.e(TAG, "Fail to read packet");
                throw e;
            }
        }

        public int transmitPacket(final ByteBuffer buf) throws ErrnoException, SocketException {
            int ret = Os.sendto(mUdpSock, buf.array(), 0 /* byteOffset */,
                    buf.limit() /* byteCount */, 0 /* flags */, ALL_DHCP_RELAY_AGENTS_AND_SERVERS,
                    DHCP6_SERVER_PORT);
            return ret;
        }
    }

    @SuppressWarnings("ByteBufferBackingArray")
    private boolean transmitPacket(@NonNull final ByteBuffer buf,
            @NonNull final String description) {
        try {
            if (DBG) {
                Log.d(TAG, "Multicasting " + description + " to ff02::1:2" + " packet raw data: "
                        + HexDump.toHexString(buf.array(), 0, buf.limit()));
            }
            mDhcp6PacketHandler.transmitPacket(buf);
        } catch (ErrnoException | IOException e) {
            Log.e(TAG, "Can't send packet: ", e);
            return false;
        }
        return true;
    }
}
