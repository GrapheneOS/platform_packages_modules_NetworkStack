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
import static android.provider.DeviceConfig.NAMESPACE_CONNECTIVITY;
import static android.system.OsConstants.AF_INET6;
import static android.system.OsConstants.IFA_F_NODAD;
import static android.system.OsConstants.IPPROTO_UDP;
import static android.system.OsConstants.RT_SCOPE_UNIVERSE;
import static android.system.OsConstants.SOCK_DGRAM;
import static android.system.OsConstants.SOCK_NONBLOCK;

import static com.android.net.module.util.NetworkStackConstants.ALL_DHCP_RELAY_AGENTS_AND_SERVERS;
import static com.android.net.module.util.NetworkStackConstants.DHCP6_CLIENT_PORT;
import static com.android.net.module.util.NetworkStackConstants.DHCP6_SERVER_PORT;
import static com.android.net.module.util.NetworkStackConstants.IPV6_ADDR_ANY;
import static com.android.net.module.util.NetworkStackConstants.RFC7421_PREFIX_LENGTH;
import static com.android.networkstack.apishim.ConstantsShim.IFA_F_MANAGETEMPADDR;
import static com.android.networkstack.apishim.ConstantsShim.IFA_F_NOPREFIXROUTE;
import static com.android.networkstack.util.NetworkStackUtils.createInet6AddressFromEui64;
import static com.android.networkstack.util.NetworkStackUtils.macAddressToEui64;

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
import com.android.net.module.util.DeviceConfigUtils;
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
    public static final int DHCP6_PD_PREFIX_MSG_EXCHANGE_TERMINATED = 4;

    // Notification from DHCPv6 state machine before quitting
    public static final int CMD_ON_QUIT = PUBLIC_BASE + 4;

    // Internal messages.
    private static final int PRIVATE_BASE        = IpClient.DHCP6CLIENT_CMD_BASE + 100;
    private static final int CMD_RECEIVED_PACKET = PRIVATE_BASE + 1;
    private static final int CMD_KICK            = PRIVATE_BASE + 2;
    private static final int CMD_DHCP6_PD_RENEW  = PRIVATE_BASE + 3;
    private static final int CMD_DHCP6_PD_REBIND = PRIVATE_BASE + 4;
    private static final int CMD_DHCP6_PD_EXPIRE = PRIVATE_BASE + 5;

    // Transmission and Retransmission parameters in milliseconds.
    private static final int SECONDS            = 1000;
    private static final long SOL_TIMEOUT       =    1 * SECONDS;
    private static final long SOL_MAX_RT        = 3600 * SECONDS;
    private static final long REQ_TIMEOUT       =    1 * SECONDS;
    private static final long REQ_MAX_RT        =   30 * SECONDS;
    private static final int REQ_MAX_RC         =   10;
    private static final long REN_TIMEOUT       =   10 * SECONDS;
    private static final long REN_MAX_RT        =  600 * SECONDS;
    private static final long REB_TIMEOUT       =   10 * SECONDS;
    private static final long REB_MAX_RT        =  600 * SECONDS;

    // Per rfc8415#section-12, the IAID MUST be consistent across restarts.
    // Since currently only one IAID is supported, a well-known value can be used (0).
    private static final int IAID = 0;

    @Nullable private PrefixDelegation mAdvertise;
    @Nullable private PrefixDelegation mReply;
    @Nullable private byte[] mServerDuid;

    // State variables.
    @NonNull private final Dependencies mDependencies;
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

    /**
     * Encapsulates Dhcp6Client depencencies that's used for unit testing and
     * integration testing.
     */
    public static class Dependencies {
        /**
         * Read an integer DeviceConfig property.
         */
        public int getDeviceConfigPropertyInt(String name, int defaultValue) {
            return DeviceConfigUtils.getDeviceConfigPropertyInt(NAMESPACE_CONNECTIVITY, name,
                    defaultValue);
        }
    }

    private WakeupMessage makeWakeupMessage(String cmdName, int cmd) {
        cmdName = Dhcp6Client.class.getSimpleName() + "." + mIface.name + "." + cmdName;
        return new WakeupMessage(mContext, getHandler(), cmdName, cmd);
    }

    private Dhcp6Client(@NonNull final Context context, @NonNull final StateMachine controller,
            @NonNull final InterfaceParams iface, @NonNull final Dependencies deps) {
        super(TAG, controller.getHandler());

        mDependencies = deps;
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
            @NonNull final StateMachine controller, @NonNull final InterfaceParams ifParams,
            @NonNull final Dependencies deps) {
        final Dhcp6Client client = new Dhcp6Client(context, controller, ifParams, deps);
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
     * Retransmits packets per algorithm defined in RFC8415 section 15. Packet transmission is
     * triggered by CMD_KICK, which is sent by an AlarmManager alarm. Kicks are cancelled when
     * leaving the state.
     *
     * Concrete subclasses must initialize retransmission parameters and implement sendPacket,
     * which is called when the alarm fires and a packet needs to be transmitted, and receivePacket,
     * which is triggered by CMD_RECEIVED_PACKET sent by the receive thread.
     */
    abstract class MessageExchangeState extends State {
        private int mTransId = 0;
        private long mTransStartMs = 0;

        private long mRetransTimeout = -1;
        private int mRetransCount = 0;
        private final long mInitialDelayMs;
        private final long mInitialRetransTimeMs;
        private final long mMaxRetransTimeMs;
        private final int mMaxRetransCount;

        MessageExchangeState(final long delay, final long irt, final long mrt, final int mrc) {
            mInitialDelayMs = delay;
            mInitialRetransTimeMs = irt;
            mMaxRetransTimeMs = mrt;
            mMaxRetransCount = mrc;
        }

        @Override
        public void enter() {
            super.enter();
            // Every message exchange generates a new transaction id.
            mTransId = mRandom.nextInt() & 0xffffff;
            sendMessageDelayed(CMD_KICK, mInitialDelayMs);
        }

        private void handleKick() {
            // rfc8415#section-21.9: The elapsed time is measured from the time at which the
            // client sent the first message in the message exchange, and the elapsed-time field
            // is set to 0 in the first message in the message exchange.
            final long elapsedTimeMs;
            if (mRetransCount == 0) {
                elapsedTimeMs = 0;
                mTransStartMs = SystemClock.elapsedRealtime();
            } else {
                elapsedTimeMs = SystemClock.elapsedRealtime() - mTransStartMs;
            }

            sendPacket(mTransId, elapsedTimeMs);
            // Compares retransmission parameters and reschedules alarm accordingly.
            scheduleKick();
        }

        private void handleReceivedPacket(Dhcp6Packet packet) {
            if (packet.isValid(mTransId, mClientDuid)) {
                receivePacket(packet);
            }
        }

        @Override
        public boolean processMessage(Message message) {
            if (super.processMessage(message) == HANDLED) {
                return HANDLED;
            }

            switch (message.what) {
                case CMD_KICK:
                    handleKick();
                    return HANDLED;
                case CMD_RECEIVED_PACKET:
                    handleReceivedPacket((Dhcp6Packet) message.obj);
                    return HANDLED;
                default:
                    return NOT_HANDLED;
            }
        }

        @Override
        public void exit() {
            super.exit();
            mKickAlarm.cancel();
            mRetransTimeout = -1;
            mRetransCount = 0;
        }

        protected abstract boolean sendPacket(int transId, long elapsedTimeMs);
        protected abstract void receivePacket(Dhcp6Packet packet);
        // If the message exchange is considered to have failed according to the retransmission
        // mechanism(i.e. client has transmitted the message MRC times or MRD seconds has elapsed
        // since the first message transmission), this method will be called to roll back to Solicit
        // state and restart the configuration, and notify IpClient the DHCPv6 message exchange
        // failure if needed.
        protected void onMessageExchangeFailed() {}

        /**
         * Per RFC8415 section 15, each of the computations of a new RT includes a randomization
         * factor (RAND), which is a random number chosen with a uniform distribution between -0.1
         * and +0.1.
         */
        private double rand() {
            return mRandom.nextDouble() / 5 - 0.1;
        }

        protected void scheduleKick() {
            if (mRetransTimeout == -1) {
                // RT for the first message transmission is based on IRT.
                mRetransTimeout = mInitialRetransTimeMs + (long) (rand() * mInitialRetransTimeMs);
            } else {
                // RT for each subsequent message transmission is based on the previous value of RT.
                mRetransTimeout = 2 * mRetransTimeout + (long) (rand() * mRetransTimeout);
            }
            if (mMaxRetransTimeMs != 0 && mRetransTimeout > mMaxRetransTimeMs) {
                mRetransTimeout = mMaxRetransTimeMs + (long) (rand() * mMaxRetransTimeMs);
            }
            // Per RFC8415 section 18.2.4 and 18.2.5, MRD equals to the remaining time until
            // earliest T2(RenewState) or valid lifetimes of all leases in all IA have expired
            // (RebindState), and message exchange is terminated when the earliest time T2 is
            // reached, at which point client begins the Rebind message exchange, however, section
            // 15 says the message exchange fails(terminated) once MRD seconds have elapsed since
            // the client first transmitted the message. So far MRD is being used for Renew, Rebind
            // and Confirm message retransmission. Given we don't support Confirm message yet, we
            // can just use rebindTimeout and expirationTimeout on behalf of MRD which have been
            // scheduled in BoundState to simplify the implementation, therefore, we don't need to
            // explicitly assign the MRD in the subclasses.
            if (mMaxRetransCount != 0 && mRetransCount > mMaxRetransCount) {
                onMessageExchangeFailed();
                Log.i(TAG, "client has transmitted the message " + mMaxRetransCount
                        + " times, stopping retransmission");
                return;
            }
            mKickAlarm.schedule(SystemClock.elapsedRealtime() + mRetransTimeout);
            mRetransCount++;
        }
    }

    private void scheduleLeaseTimers() {
        // TODO: validate t1, t2, valid and preferred lifetimes before the timers are scheduled to
        // prevent packet storms due to low timeouts.
        int renewTimeout = mReply.t1;
        int rebindTimeout = mReply.t2;
        final long expirationTimeout = mReply.ipo.valid;

        // rfc8415#section-14.2: if t1 and / or t2 are 0, the client chooses an appropriate value.
        // rfc8415#section-21.21: Recommended values for T1 and T2 are 0.5 and 0.8 times the
        // shortest preferred lifetime of the prefixes in the IA_PD that the server is willing to
        // extend, respectively.
        if (renewTimeout == 0) {
            renewTimeout = (int) (mReply.ipo.preferred * 0.5);
        }
        if (rebindTimeout == 0) {
            rebindTimeout = (int) (mReply.ipo.preferred * 0.8);
        }

        // Note: message validation asserts that the received t1 <= t2 if both t1 > 0 and t2 > 0.
        // However, if t1 or t2 are 0, it is possible for renewTimeout to become larger than
        // rebindTimeout (and similarly, rebindTimeout to become larger than expirationTimeout).
        // For example: t1 = 0, t2 = 40, valid lft = 100 results in renewTimeout = 50, and
        // rebindTimeout = 40. Hence, their correct order must be asserted below.

        // If timeouts happen to coincide or are out of order, the former (in respect to the
        // specified provisioning lifecycle) can be skipped. This also takes care of the case where
        // the server sets t1 == t2 == valid lft, which indicates that the IA cannot be renewed, so
        // there is no point in trying.
        if (renewTimeout >= rebindTimeout) {
            // skip RENEW
            renewTimeout = 0;
        }
        if (rebindTimeout >= expirationTimeout) {
            // skip REBIND
            rebindTimeout = 0;
        }

        final long now = SystemClock.elapsedRealtime();
        if (renewTimeout > 0) {
            mRenewAlarm.schedule(now + renewTimeout * (long) SECONDS);
            Log.d(TAG, "Scheduling IA_PD renewal in " + renewTimeout + "s");
        }
        if (rebindTimeout > 0) {
            mRebindAlarm.schedule(now + rebindTimeout * (long) SECONDS);
            Log.d(TAG, "Scheduling IA_PD rebind in " + rebindTimeout + "s");
        }
        mExpiryAlarm.schedule(now + expirationTimeout * (long) SECONDS);
        Log.d(TAG, "Scheduling IA_PD expiry in " + expirationTimeout + "s");
    }

    private void notifyPrefixDelegation(int result, @Nullable final PrefixDelegation pd) {
        mController.sendMessage(CMD_DHCP6_RESULT, result, 0, pd);
    }

    private void clearDhcp6State() {
        mAdvertise = null;
        mReply = null;
        mServerDuid = null;
    }

    @SuppressWarnings("ByteBufferBackingArray")
    private boolean sendSolicitPacket(int transId, long elapsedTimeMs, final ByteBuffer iapd) {
        final ByteBuffer packet = Dhcp6Packet.buildSolicitPacket(transId, elapsedTimeMs,
                iapd.array(), mClientDuid, true /* rapidCommit */);
        return transmitPacket(packet, "solicit");
    }

    @SuppressWarnings("ByteBufferBackingArray")
    private boolean sendRequestPacket(int transId, long elapsedTimeMs, final ByteBuffer iapd) {
        final ByteBuffer packet = Dhcp6Packet.buildRequestPacket(transId, elapsedTimeMs,
                iapd.array(), mClientDuid, mServerDuid);
        return transmitPacket(packet, "request");
    }

    @SuppressWarnings("ByteBufferBackingArray")
    private boolean sendRenewPacket(int transId, long elapsedTimeMs, final ByteBuffer iapd) {
        final ByteBuffer packet = Dhcp6Packet.buildRenewPacket(transId, elapsedTimeMs,
                iapd.array(), mClientDuid, mServerDuid);
        return transmitPacket(packet, "renew");
    }

    @SuppressWarnings("ByteBufferBackingArray")
    private boolean sendRebindPacket(int transId, long elapsedTimeMs, final ByteBuffer iapd) {
        final ByteBuffer packet = Dhcp6Packet.buildRebindPacket(transId, elapsedTimeMs,
                iapd.array(), mClientDuid);
        return transmitPacket(packet, "rebind");
    }

    private ByteBuffer buildEmptyIaPdOption() {
        return Dhcp6Packet.buildIaPdOption(IAID, 0 /* t1 */, 0 /* t2 */, 0 /* preferred */,
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
    class SolicitState extends MessageExchangeState {
        SolicitState() {
            // First Solicit message should be delayed by a random amount of time between 0
            // and SOL_MAX_DELAY(1s).
            // TODO: request SOL_MAX_RT option from server.
            super((long) (new Random().nextDouble() * SECONDS) /* delay */, SOL_TIMEOUT /* IRT */,
                    SOL_MAX_RT /* MRT */, 0 /* MRC */);
        }

        @Override
        public void enter() {
            super.enter();
        }

        @Override
        protected boolean sendPacket(int transId, long elapsedTimeMs) {
            return sendSolicitPacket(transId, elapsedTimeMs, buildEmptyIaPdOption());
        }

        // TODO: support multiple prefixes.
        @Override
        protected void receivePacket(Dhcp6Packet packet) {
            if (packet instanceof Dhcp6AdvertisePacket) {
                mAdvertise = packet.mPrefixDelegation;
                if (mAdvertise != null && mAdvertise.iaid == IAID) {
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
                if (pd != null && pd.iaid == IAID) {
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
    class RequestState extends MessageExchangeState {
        RequestState() {
            super((long) 0 /* delay */, REQ_TIMEOUT /* IRT */, REQ_MAX_RT /* MRT */,
                    REQ_MAX_RC /* MRC */);
        }

        @Override
        protected boolean sendPacket(int transId, long elapsedTimeMs) {
            return sendRequestPacket(transId, elapsedTimeMs, buildIaPdOption(mAdvertise));
        }

        @Override
        protected void receivePacket(Dhcp6Packet packet) {
            if (!(packet instanceof Dhcp6ReplyPacket)) return;
            final PrefixDelegation pd = packet.mPrefixDelegation;
            if (pd != null && pd.iaid == IAID) {
                Log.d(TAG, "Get prefix delegation option from Reply: " + pd);
                mReply = pd;
                transitionTo(mBoundState);
            }
        }

        @Override
        protected void onMessageExchangeFailed() {
            transitionTo(mSolicitState);
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
                    macAddressToEui64(mIface.macAddr));
            final int flags = IFA_F_NOPREFIXROUTE | IFA_F_MANAGETEMPADDR | IFA_F_NODAD;
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

    abstract class ReacquireState extends MessageExchangeState {
        ReacquireState(final long irt, final long mrt) {
            super(0 /* delay */, irt, mrt, 0 /* MRC */);
        }

        @Override
        public void enter() {
            super.enter();
        }

        @Override
        protected void receivePacket(Dhcp6Packet packet) {
            if (!(packet instanceof Dhcp6ReplyPacket)) return;
            final PrefixDelegation pd = packet.mPrefixDelegation;
            if (pd != null) {
                if (pd.iaid != IAID
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
        RenewState() {
            super(REN_TIMEOUT, REN_MAX_RT);
        }

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

        @Override
        protected boolean sendPacket(int transId, long elapsedTimeMs) {
            return sendRenewPacket(transId, elapsedTimeMs, buildIaPdOption(mReply));
        }
    }

    /**
     * Client enters Rebind state when T2 expires and (re)transmits Rebind message to any
     * available server to extend the lifetimes on the leases assigned to the client and to
     * update other configuration parameters.
     */
    class RebindState extends ReacquireState {
        RebindState() {
            super(REB_TIMEOUT, REB_MAX_RT);
        }

        @Override
        protected boolean sendPacket(int transId, long elapsedTimeMs) {
            return sendRebindPacket(transId, elapsedTimeMs, buildIaPdOption(mReply));
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
                final Dhcp6Packet packet = Dhcp6Packet.decode(recvbuf, length);
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
