/*
 * Copyright (C) 2025 The Android Open Source Project
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

import static android.system.OsConstants.RT_SCOPE_UNIVERSE;

import android.annotation.NonNull;
import android.app.AlarmManager;
import android.content.Context;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.os.Handler;
import android.os.SystemClock;
import android.util.ArrayMap;
import android.util.Log;

import androidx.annotation.Nullable;

import com.android.net.module.util.HexDump;
import com.android.net.module.util.InterfaceParams;
import com.android.net.module.util.LinkPropertiesUtils;
import com.android.net.module.util.dhcp6.Dhcp6AddrRegReplyPacket;
import com.android.net.module.util.dhcp6.Dhcp6Packet;

import java.net.Inet6Address;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Random;

/**
 * Track the self-generated IPv6 addresses registration process via DHCPv6 message (RFC9686).
 *
 * <p>This class manages the registration and refresh of IPv6 addresses obtained through SLAAC. It
 * achieves this by sending DHCPv6 ADDR-REG-INFORM messages to the network and handling
 * corresponding ADDR-REG-REPLY messages. The key functionalities include:
 *
 * <ul>
 *   <li><strong>Address Tracking:</strong> It maintains a map of IPv6 addresses to their
 *       corresponding {@link RegistrationScheduler} instances. Each scheduler tracks the
 *       registration state, retransmission attempts, and refresh timers for a specific address.
 *   <li><strong>Message Transmission:</strong> It constructs and sends ADDR-REG-INFORM messages
 *       with the current address lifetimes and a unique transaction ID.
 *   <li><strong>Retransmission Logic:</strong> It implements a retransmission mechanism with
 *       exponential backoff and jitter, as specified in RFC8415.
 *   <li><strong>Refresh Scheduling:</strong> It schedules periodic refresh timers based on the
 *       address's valid lifetime, with a desync multiplier to avoid synchronized requests.
 *   <li><strong>Reply Handling:</strong> It processes ADDR-REG-REPLY messages, resets
 *       retransmission parameters, and schedules the next refresh timer.
 *   <li><strong>LinkProperties Updates:</strong> It responds to changes in link properties, adding,
 *       removing, or updating address registration based on the new properties.
 *   <li><strong>Alarm Management:</strong> It uses {@link AlarmManager} to schedule and trigger
 *       address registration and refresh events.
 * </ul>
 *
 * <p>The class operates as follows:
 *
 * <ol>
 *   <li>When a new IPv6 address is added to the LinkProperties, a {@link RegistrationScheduler} is
 *       created for it, and an initial registration message is scheduled.
 *   <li>When the timer expires, the scheduler sends an ADDR-REG-INFORM message.
 *   <li>If no ADDR-REG-REPLY is received, the scheduler retransmits the message with exponential
 *       backoff, up to a maximum number of attempts (MRC).
 *   <li>Upon receiving an ADDR-REG-REPLY, the scheduler resets the retransmission parameters and
 *       schedules a new refresh timer.
 *   <li>When the address's valid lifetime changes more than 1%, the scheduler updates the refresh
 *       timer and resets the retransmission parameters.
 *   <li>When an address is removed from the LinkProperties, its scheduler is removed.
 * </ol>
 * @hide
 */
public class Dhcp6AddrRegTracker {
    private static final String TAG = Dhcp6AddrRegTracker.class.getSimpleName();
    private static final boolean DBG = false;

    private final Handler mHandler;
    private final Random mRandom;
    private final Dhcp6PacketDispatcher mDhcp6PacketDispatcher;
    private final Dhcp6PacketDispatcher.MessageHandler mDhcp6MessageHandler;
    private final Map<Inet6Address, RegistrationScheduler> mTrackedAddresses = new ArrayMap<>();
    private final AlarmManager mAlarmManager;
    private final AlarmManager.OnAlarmListener mAddressRegistrationAlarm;
    private final String mInterfaceName;
    private final byte[] mClientDuid;

    private LinkProperties mLinkProperties;

    // A random value uniformly distributed between 0.9 and 1.1 (see RFC9686 section 4.6.1).
    private static final double sAddrRegDesyncMultiplier = (new Random()).nextDouble() * 0.2 + 0.9;

    private class RegistrationScheduler {
        private static final int IRT_MS = 1000; // 1s
        private static final int MRC = 3;

        // The IPv6 address to be registered.
        private Inet6Address mAddress;
        // The deprecation time of an IPv6 address to be registered.
        private long mDeprecationTimeMs;
        // The expiration time of an IPv6 address to be registered.
        private long mExpirationTimeMs;
        // Keep track of the current retry count. mRetryCount is set to 0 when a reply is
        // received or the address is updated.
        private int mRetryCount;
        // Track whether the event is currently scheduled; i.e. whether the address should be
        // registered when mEventTime is expired.
        private boolean mIsScheduled;
        // The time of the next event in milliseconds since boot.
        private long mEventTime;
        // The DHCPv6 transaction ID. Gets initialized and reset alongside mRetryCount.
        // Resetting the transaction ID ensures that no future replies can be matched to
        // this address registration operation anymore.
        private int mTransId;
        // The timestamp at which the DHCPv6 message retransmission starts.
        private long mTransStartMs;

        RegistrationScheduler(@NonNull final Inet6Address address, final long deprecationTimeMs,
                final long expirationTimeMs, final long now) {
            mAddress = address;
            mDeprecationTimeMs = deprecationTimeMs;
            mExpirationTimeMs = expirationTimeMs;
            mRetryCount = 0;
            mIsScheduled = true;
            mEventTime = now;
            mTransId = mRandom.nextInt() & 0xffffff;
        }

        /**
         * If an ADDR-REG-REPLY message is received for the address being registered or refreshed,
         * the client MUST stop retransmission, it can be done by setting the "mIsScheduled" to
         * false, see RFC9686 section 4.6.3.
         * TODO: support coalescing expired events
         */
        public final boolean isExpired(long now) {
            return mIsScheduled && (now >= mEventTime);
        }

        /**
         * Calculate the DHCPv6 message retransmission timeout per below formula.
         *
         *     f(n) = IRT * 2^n * random_in_range(85%, 115%)
         *
         * Per RFC8415 section 15 the retranmission algorithm is:
         *
         * RT for the first message transmission is based on IRT:
         *
         *     RT = IRT + RAND*IRT
         *
         * RT for each subsequent message transmission is based on the previous value of RT:
         *
         *     RT = 2*RTprev + RAND*RTprev
         *
         * Ignoring the jitter, this maps to:
         *
         *     RT = IRT * 2^(n) // n is the message tranmission count
         *
         * Accounting for the jitter, retransmissions occur at:
         *
         *     f(0) = [0.9, 1.1]s -> [90%, 110%]
         *     f(1) = [1.7, 2.3]s -> [85%, 115%]
         *     f(2) = [3.2, 4.8]s -> [80%, 120%]
         *
         * Select an average jitter random factor in the [85%, 115%] in a simple approximate way.
         */
        private double getRetransmissionTimeout(int retryCount) {
            final double randomFactor = mRandom.nextDouble() * 0.3 + 0.85;
            return IRT_MS * Math.pow(2, retryCount) * randomFactor;
        }

        /**
         * (Re)transmit an ADDR_REG_INFORM message to register/refresh an IPv6 address.
         */
        public void sendRegisterAddress(long now) {
            if (mRetryCount >= MRC) {
                Log.i(TAG, "Failed to register self-generated IPv6 " + mAddress);
                // Set mIsScheduled to false to indicate that the registration process for this
                // address has been stopped (see isExpired) due to exceeding the maximum retry
                // count (MRC). If this address is updated (e.g. lifetime changes by more than 1%),
                // the code will try to re-register immediately, which is working as intented.
                mIsScheduled = false;
                return;
            }

            // Calculate the next retransmission timestamp.
            mEventTime = now + (long) getRetransmissionTimeout(mRetryCount);
            if (mRetryCount == 0) mTransStartMs = now;

            // When the client retransmits the registration message, the lifetimes in the packet
            // MUST be updated so that they match the current lifetimes of the address.
            final long preferred = (mDeprecationTimeMs - now) / 1000;
            final long valid = (mExpirationTimeMs - now) / 1000;
            final ByteBuffer packet = Dhcp6Packet.buildAddrRegInformPacket(mTransId,
                    now - mTransStartMs /* elapsedTime */, mClientDuid, mAddress, preferred, valid);
            // DHCPv6 ADDR-REG-INFORM message MUST be sent from the address being registered per
            // RFC9686 section 4.2.
            transmitPacket(packet, mAddress);
            ++mRetryCount;
        }

        /**
         * Calculate the next SLAAC address registration fresh interval in seconds.
         *
         * This happens either when receiving an ADDR_REG_REPLY from the DHCPv6 server or the
         * updated link address lifetime changes more than 1%.
         *
         * Return the 80% of the SLAAC address's current valid lifetime, and applies a desync
         * multiplier, in order to avoid synchronization with other clients, which could cause a
         * large number of registration messages to reach the server at the same time.
         *
         * @param valid link address valid lifetime.
         */
        private long addrRegRefreshInterval(long valid) {
            return (long) (valid * 0.8 * sAddrRegDesyncMultiplier * 1000);
        }

        /**
         * Reset the registartion parameters when refreshing an address, i.e. receive the
         * ADDR_REG_REPLY or link address lifetime changes more than 1%, which requires to
         * schedule a new refresh.
         */
        private void resetTransactionParams() {
            mTransId = mRandom.nextInt() & 0xffffff;
            mRetryCount = 0;
            mTransStartMs = 0;
        }

        /**
         * Triggered when an ADDR_REG_REPLY message for the address being registered arrives.
         *
         * Stop the ADDR_REG_INFORM message retransmission and reset the retransmission parameters,
         * calculate a NextAddrRegRefreshTime for the address, but does not schedule any refreshes
         * per RFC9686 section 4.6.1.
         */
        private void onReply() {
            final long now = SystemClock.elapsedRealtime();
            resetTransactionParams();
            mIsScheduled = false;
            mEventTime = now + addrRegRefreshInterval(mExpirationTimeMs - now);
        }

        /**
         * Triggered iff the valid lifetime of a link address has changed by more than 1%.
         *
         * Per RFC9686 section 4.6.1 whenever the network changes the valid lifetime of an existing
         * address by more than 1%, e.g. by sending a PIO with a new valid lifetime, client should
         * calculates a new AddrRegRefreshInterval and schedule a refresh for
         * min(now + AddrRegRefreshInterval, NextAddrRegRefreshTime) to register this new lifetime
         * to DHCP server.
         */
        private void updateAddress(@NonNull final LinkAddress la, long now) {
            if (!la.getAddress().equals(mAddress)) {
                throw new IllegalStateException("link addresses to be updated don't match");
            }
            final long newValid = (la.getExpirationTime() - now) / 1000;
            mEventTime = Math.min(mEventTime, now + addrRegRefreshInterval(newValid));
            resetTransactionParams();
            mIsScheduled = true;
            mAddress = (Inet6Address) la.getAddress();
        }
    }

    private class AddressRegistrationAlarmListener implements AlarmManager.OnAlarmListener {
        @Override
        public void onAlarm() {
            dispatchRegistration(false /* dispatchOnlyTimer */);
        }
    }

    public Dhcp6AddrRegTracker(Context context, Handler handler, String ifName,
            Dhcp6PacketDispatcher dispatcher) {
        mHandler = handler;
        mAlarmManager = context.getSystemService(AlarmManager.class);
        mInterfaceName = ifName;
        mRandom = new Random();
        final InterfaceParams params = InterfaceParams.getByName(ifName);
        mClientDuid = Dhcp6Packet.createClientDuid(params.macAddr);
        mDhcp6PacketDispatcher = dispatcher;
        mDhcp6MessageHandler = (packet, dst) -> mHandler.post(() -> onReceive(packet, dst));
        mAddressRegistrationAlarm = new AddressRegistrationAlarmListener();
    }

    /**
     * Start the SLAAC address registration tracker.
     */
    public void start() {
        mDhcp6PacketDispatcher.registerHandler(
                mDhcp6MessageHandler,
                Dhcp6Packet.DHCP6_MESSAGE_TYPE_ADDR_REG_REPLY
        );
    }

    /**
     * Stop the SLAAC address registration tracker.
     */
    public void stop() {
        mDhcp6PacketDispatcher.unregisterHandler(mDhcp6MessageHandler);
        mAlarmManager.cancel(mAddressRegistrationAlarm);
        mTrackedAddresses.clear();
    }

    private void addAddress(LinkAddress la, long now) {
        final Inet6Address address = (Inet6Address) la.getAddress();
        final RegistrationScheduler scheduler = new RegistrationScheduler(
                address,
                la.getDeprecationTime(),
                la.getExpirationTime(),
                now);
        mTrackedAddresses.put(address, scheduler);
    }

    private void removeAddress(LinkAddress la) {
        mTrackedAddresses.remove((Inet6Address) la.getAddress());
    }

    private void updateAddress(LinkAddress la, long now) {
        final Inet6Address address = (Inet6Address) la.getAddress();
        RegistrationScheduler scheduler = mTrackedAddresses.get(address);
        if (scheduler == null) {
            throw new IllegalStateException("Fail to find the scheduler for " + address);
        }
        scheduler.updateAddress(la, now);
    }

    // Note that Android does not consider deprecated addresses to determine
    // provisioning state; however, these addresses can still be used and must
    // be registered.
    // This returns true for both GUAs and ULAs; both types of addresses
    // must be registered.
    private static boolean isRegistrableAddress(@NonNull final LinkAddress la) {
        return la.isIpv6() && la.getScope() == RT_SCOPE_UNIVERSE;
    }

    /**
     * Check whether or not the valid lifetime of a link address has changed by more than 1%.
     */
    private static boolean hasValidLifetimeChangedMoreThanOnePercent(long now, long oldExpiry,
            long newExpiry) {
        return Math.abs(newExpiry - oldExpiry) > (oldExpiry - now) * 0.01;
    }

    private static LinkAddress findLinkAddress(@NonNull List<LinkAddress> linkAddresses,
            @NonNull Inet6Address expect) {
        if (linkAddresses == null) {
            return null;
        }

        for (LinkAddress la : linkAddresses) {
            final Inet6Address address = (Inet6Address) la.getAddress();
            if (address.equals(expect)) return la;
        }
        return null;
    }

    /**
     * Updates the LinkProperties and checks whether the link addresses have changed.
     */
    public void setLinkProperties(LinkProperties newLp) {
        boolean shouldDispatchRegistration = false;
        boolean dispatchOnlyTimer = false;
        final long now = SystemClock.elapsedRealtime();
        final LinkPropertiesUtils.CompareOrUpdateResult<Integer, LinkAddress> addressDiff =
                new LinkPropertiesUtils.CompareOrUpdateResult<>(
                        mLinkProperties == null ? null : mLinkProperties.getLinkAddresses(),
                        newLp.getLinkAddresses(),
                        linkAddress -> Objects.hash(
                                linkAddress.getAddress(),
                                linkAddress.getPrefixLength()));
        for (LinkAddress la : addressDiff.added) {
            if (!isRegistrableAddress(la)) continue;
            addAddress(la, now);
            shouldDispatchRegistration = true;
            // Dispatch the ADDR_REG_INFORM immediately upon the initial addition of an address.
            dispatchOnlyTimer = false;
        }

        for (LinkAddress la : addressDiff.removed) {
            if (!isRegistrableAddress(la)) continue;
            removeAddress(la);
            shouldDispatchRegistration = true;
            // No need to immediately dispatch ADDR_REG_INFORM on address removal; simply reschedule
            // the next alarm based on the remaining addresses' mEventTime.
            dispatchOnlyTimer = true;
        }

        for (LinkAddress la : addressDiff.updated) {
            if (!isRegistrableAddress(la)) continue;
            final LinkAddress oldLinkAddress = findLinkAddress(
                    mLinkProperties.getLinkAddresses(), (Inet6Address) la.getAddress());
            if (!hasValidLifetimeChangedMoreThanOnePercent(now, oldLinkAddress.getExpirationTime(),
                    la.getExpirationTime())) {
                continue;
            }
            updateAddress(la, now);
            shouldDispatchRegistration = true;
            // Per RFC9686 section 4.6.1, if the refresh would be scheduled in the past, then the
            // refresh occurs immediately.
            dispatchOnlyTimer = false;
        }

        if (shouldDispatchRegistration) {
            dispatchRegistration(dispatchOnlyTimer);
        }

        mLinkProperties = newLp;
    }

    private void scheduleNextTimer() {
        // Find the minimum event time among all tracked addresses that are currently scheduled
        // (i.e., mIsScheduled is true). If no addresses are scheduled, no alarm is set.
        // An address is scheduled to be registered when:
        // - It is added for the first time.
        // - Its valid lifetime changes by more than 1%; for example, when a new RA is received that
        //   extends the lifetime.
        // - A retransmission is scheduled.
        // An address is unscheduled when:
        // - An ADDR_REG_REPLY message is received for it indicating successful registration.
        // - The maximum retransmission count is reached.
        long nextEvent = Long.MAX_VALUE;
        for (RegistrationScheduler scheduler : mTrackedAddresses.values()) {
            if (!scheduler.mIsScheduled) continue;
            nextEvent = Math.min(nextEvent, scheduler.mEventTime);
        }
        if (nextEvent == Long.MAX_VALUE) return;

        final String tag = TAG + "." + mInterfaceName + ".KICK";
        mAlarmManager.setExact(AlarmManager.ELAPSED_REALTIME_WAKEUP, nextEvent, tag,
                mAddressRegistrationAlarm, mHandler);
    }

    /**
     * Dispatch the address registration message transmission immediately if necessary, and
     * schedules the next alarm based on `mEventTime`.
     *
     * @param dispatchOnlyTimer bypass the immediate dispatch address registration message
     *                          transmission if it's true, otherwise, will only proceed to
     *                          schedule the next alarm based on 'mEventTime'.
     */
    private void dispatchRegistration(boolean dispatchOnlyTimer) {
        if (!dispatchOnlyTimer) {
            final long now = SystemClock.elapsedRealtime();
            for (Map.Entry<Inet6Address, RegistrationScheduler> entry
                    : mTrackedAddresses.entrySet()) {
                if (!entry.getValue().isExpired(now)) continue;
                entry.getValue().sendRegisterAddress(now);
            }
        }
        scheduleNextTimer();
    }

    private void onReceive(@NonNull Dhcp6Packet packet, @Nullable Inet6Address dst) {
        if (DBG) Log.d(TAG, "Received packet: " + packet);
        if (!(packet instanceof Dhcp6AddrRegReplyPacket)) return;
        if (!Arrays.equals(mClientDuid, packet.getClientDuid())) return;

        final Inet6Address address = ((Dhcp6AddrRegReplyPacket) packet).mIaAddress;
        if (address == null) {
            Log.e(TAG, "ADDR_REG_REPLY message doesn't include a valid IPv6 address " + address);
            return;
        }
        if (dst != null && !dst.equals(address)) {
            Log.e(TAG, "IPv6 destination address does not match the address being registered");
            return;
        }
        final RegistrationScheduler scheduler = mTrackedAddresses.get(address);
        if (scheduler == null) {
            Log.e(TAG, "Do not find a corresponding scheduler for IPv6 address " + address);
            return;
        }

        // Check if the transaction ID matches or not. This is intended behavior, because one
        // case is device receives the update before it receives the response. updateAddress will
        // change the mTransId, when the response arrives, the mTransId changes, and we throws
        // the response, that's the intended behavior, because we want to respect the updated
        // lifetime first.
        if (scheduler.mTransId != packet.getTransactionId()) {
            Log.e(TAG, "transId doesn't match");
            return;
        }
        scheduler.onReply();
        dispatchRegistration(true /* dispatchOnlyTimer */);
    }

    @SuppressWarnings("ByteBufferBackingArray")
    private int transmitPacket(@NonNull final ByteBuffer buf, @NonNull final Inet6Address src) {
        if (DBG) {
            Log.d(TAG, "Multicasting DHCPv6 addr-reg-inform packet to ff02::1:2"
                    + " from " + src
                    + " on interface " + mInterfaceName
                    + ", packet raw data: "
                    + HexDump.toHexString(buf.array(), 0, buf.limit()));
        }
        return mDhcp6PacketDispatcher.transmitPacket(buf, src);
    }
}
