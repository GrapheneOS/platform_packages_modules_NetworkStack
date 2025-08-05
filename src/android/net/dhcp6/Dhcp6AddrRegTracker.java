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

import com.android.net.module.util.InterfaceParams;
import com.android.net.module.util.LinkPropertiesUtils.CompareOrUpdateResult;
import com.android.net.module.util.dhcp6.Dhcp6AddrRegInformPacket;
import com.android.net.module.util.dhcp6.Dhcp6AddrRegReplyPacket;
import com.android.net.module.util.dhcp6.Dhcp6Packet;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
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
 *       corresponding {@link AddressTracker} instances. Each tracker tracks the
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
 *   <li>When a new IPv6 address is added to the LinkProperties, a {@link AddressTracker} is
 *       created for it, and an initial registration message is scheduled.
 *   <li>When the timer expires, the tracker sends an ADDR-REG-INFORM message.
 *   <li>If no ADDR-REG-REPLY is received, the tracker retransmits the message with exponential
 *       backoff, up to a maximum number of attempts (MRC).
 *   <li>Upon receiving an ADDR-REG-REPLY, the tracker resets the retransmission parameters and
 *       schedules a new refresh timer.
 *   <li>When the address's valid lifetime changes more than 1%, the tracker updates the refresh
 *       timer and resets the retransmission parameters.
 *   <li>When an address is removed from the LinkProperties, its tracker is removed.
 * </ol>
 *
 * Message coalescing as described in RFC9686 is explicitly unsupported, because it is unclear how
 * the code should interact with retries. Realistically, address lifetimes are already synchronized,
 * so that coalescing would not be particularly useful anyway.
 * @hide
 */
public class Dhcp6AddrRegTracker {
    private static final String TAG = Dhcp6AddrRegTracker.class.getSimpleName();
    private static final boolean DBG = false;

    private final Handler mHandler;
    private final Random mRandom;
    private final Dhcp6PacketDispatcher mDhcp6PacketDispatcher;
    private final Dhcp6PacketDispatcher.MessageHandler mDhcp6MessageHandler;
    private final Map<Inet6Address, AddressTracker> mTrackedAddresses = new ArrayMap<>();
    private final AlarmManager mAlarmManager;
    private final AlarmManager.OnAlarmListener mAddressRegistrationAlarm;
    private final String mInterfaceName;
    private final byte[] mClientDuid;

    // A random value uniformly distributed between 0.9 and 1.1 (see RFC9686 section 4.6.1).
    private static final double sAddrRegDesyncMultiplier = (new Random()).nextDouble() * 0.2 + 0.9;

    private static class Link6Address extends LinkAddress {
        Link6Address(LinkAddress la) {
            super(la.getAddress(), la.getPrefixLength(), la.getFlags(), la.getScope(),
                    la.getDeprecationTime(), la.getExpirationTime());

            // Ensure that the passed LinkAddress contains an IPv6 address. Otherwise, the cast in
            // getAddress will throw an exception.
            if (!(la.getAddress() instanceof Inet6Address)) {
                throw new IllegalStateException("Link6Address requires an IPv6 LinkAddress");
            }
        }

        /** Return the contained Inet6Address. */
        @Override
        public Inet6Address getAddress() {
            return (Inet6Address) super.getAddress();
        }

        /**
         * Return the remaining preferred lifetime for this address.
         *
         * @param nowMs The current time based on {@link SystemClock#elapsedRealtime}
         */
        public long getPreferredLifetimeMs(long nowMs) {
            return Math.max(0, getDeprecationTime() - nowMs);
        }

        /**
         * Return the remaining valid lifetime for this address.
         *
         * @param nowMs The current time based on {@link SystemClock#elapsedRealtime}
         */
        public long getValidLifetimeMs(long nowMs) {
            return Math.max(0, getExpirationTime() - nowMs);
        }
    }

    /**
     * Calculate the next SLAAC address registration refresh interval.
     *
     * Return 80% of the valid lifetime, applying a desync multiplier to avoid cross-device
     * synchronization.
     *
     * @param validMs link address valid lifetime in milliseconds.
     * @return the AddrRegRefreshInterval in milliseconds
     */
    private long addrRegRefreshInterval(long validMs) {
        return (long) (validMs * 0.8 * sAddrRegDesyncMultiplier);
    }

    private class AddressTracker {
        private static final int IRT_MS = 1000; // 1s
        private static final int MRC = 3;
        // Valid transaction IDs are 3 octets.
        private static final int INVALID_TRANS_ID = 0x1000000;

        // Contains the IPv6 address to be registered including its preferred and valid lifetimes.
        // The IPv6 address to be registered.
        private final Link6Address mAddress;
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

        AddressTracker(Link6Address address, long eventTime) {
            mAddress = address;
            mRetryCount = 0;
            mIsScheduled = true;
            mEventTime = eventTime;
            mTransId = mRandom.nextInt() & 0xffffff;
        }

        public Link6Address getAddress() {
            return mAddress;
        }

        /**
         * If an ADDR-REG-REPLY message is received for the address being registered or refreshed,
         * the client MUST stop retransmission, it can be done by setting the "mIsScheduled" to
         * false, see RFC9686 section 4.6.3.
         */
        public final boolean isExpired(long nowMs) {
            return mIsScheduled && (nowMs >= mEventTime);
        }

        /**
         * Calculates the retransmission delay using the formula:
         *
         *     delay(n) = IRT * 2^n * random_in_range(85%, 115%)
         *
         * This serves as a simplification of RFC8415's retransmission delay algorithm that applies
         * jitter at every step. A by the letter implementation of RFC8415 results in the following:
         *
         *     delay_rfc8415(0) = [0.9, 1.1]s -> [90%, 110%]
         *     delay_rfc8415(1) = [1.7, 2.3]s -> [85%, 115%]
         *     delay_rfc8415(2) = [3.2, 4.8]s -> [80%, 120%]
         *
         * This implementation applies +-15% of jitter to the final value.
         */
        private long getRetransmissionDelay(int retryCount) {
            final double randomFactor = mRandom.nextDouble() * 0.3 + 0.85;
            return (long) (IRT_MS * Math.pow(2, retryCount) * randomFactor);
        }

        public Dhcp6AddrRegInformPacket getAddrRegInformPacket(long nowMs) {
            if (mRetryCount == 0) mTransStartMs = nowMs;
            final long elapsedTimeMs = nowMs - mTransStartMs;

            // When the client retransmits the registration message, the lifetimes in the packet
            // MUST be updated so that they match the current lifetimes of the address.
            return new Dhcp6AddrRegInformPacket(
                    mTransId,
                    (int) elapsedTimeMs / 10 /* centiseconds */,
                    mClientDuid,
                    mAddress.getAddress(),
                    mAddress.getPreferredLifetimeMs(nowMs) / 1000,
                    mAddress.getValidLifetimeMs(nowMs) / 1000);
        }

        /** Increments the retry count and -- if necessary -- schedules the next event. */
        public void maybeScheduleNextEvent(long nowMs) {
            if (!mIsScheduled) throw new IllegalStateException("Processed unscheduled event");

            // Attempt to register the address MRC + 1 times: the initial attempt + MRC retries.
            if (mRetryCount >= MRC) {
                // The retry limit has been reached. Do not schedule another retry.
                mIsScheduled = false;
            } else {
                // Calculate the next retransmission timestamp only if the retry limit has not been
                // reached. This ensures that if the address is updated, registration is immediately
                // attempted.
                mEventTime = nowMs + getRetransmissionDelay(mRetryCount);
            }

            mRetryCount++;
        }

        private void markRegistrationSuccess(long nowMs) {
            // Ensure that no further responses are processed for this address by setting the
            // transaction ID to an invalid value. There is no need to reset the retry count,
            // because an address update creates a new AddressTracker object.
            mTransId = INVALID_TRANS_ID;

            // Update mEventTime but do not schedule the next event until the address is updated.
            mIsScheduled = false;
            mEventTime = nowMs + addrRegRefreshInterval(mAddress.getValidLifetimeMs(nowMs));
        }
    }

    private class AddressRegistrationAlarmListener implements AlarmManager.OnAlarmListener {
        @Override
        public void onAlarm() {
            dispatchRegistration(SystemClock.elapsedRealtime());
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
        mDhcp6MessageHandler = (packet, dst) -> mHandler.post(() -> onReceiveReply(packet, dst));
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

    // Note that Android does not consider deprecated addresses to determine
    // provisioning state; however, these addresses can still be used and must
    // be registered.
    // This returns true for both GUAs and ULAs; both types of addresses
    // must be registered.
    private static boolean isRegistrableAddress(@NonNull final LinkAddress la) {
        return la.isIpv6() && la.getScope() == RT_SCOPE_UNIVERSE;
    }

    /**
     * rfc9686 section 4.6.1 states that the AddrRegRefreshInterval is only recalculated if the
     * Valid Lifetime changes more than 1%. However, this mechanism does not work very well. In
     * particular, if an address is never renewed, but a router regularly sends a self-decrementing
     * RA, the 1% threshold approaches 0. Instead, this function checks whether the new valid
     * lifetime expires within 3s of the last valid lifetime that was last registered.
     */
    private static boolean isLifetimeChangeSignificant(long oldExpiryMs, long newExpiryMs) {
        return Math.abs(oldExpiryMs - newExpiryMs) >= 3_000 /* ms */;
    }

    /**
     * Updates the LinkProperties and checks whether the link addresses have changed.
     */
    public void setLinkProperties(LinkProperties newLp) {
        final long nowMs = SystemClock.elapsedRealtime();

        // Collect the LinkAddresses from all AddressTracker objects and compare them against
        // the new LinkProperties. Note that incompatible addresses, such as IPv4 or link-local
        // addresses, are part of the added list and subsequently ignored by checking the result of
        // isRegistrableAddress().
        final List<Link6Address> trackedLink6Addresses = mTrackedAddresses.values().stream()
                .map(AddressTracker::getAddress)
                .toList();

        final List<Link6Address> newLink6Addresses = newLp.getLinkAddresses().stream()
                .filter(la -> isRegistrableAddress(la))
                .map(la -> new Link6Address(la))
                .toList();

        final CompareOrUpdateResult<InetAddress, Link6Address> addressDiff =
                new CompareOrUpdateResult<>(
                        trackedLink6Addresses,
                        newLink6Addresses,
                        link6Address -> link6Address.getAddress());

        boolean hasUpdate = false;
        for (Link6Address la : addressDiff.added) {
            hasUpdate = true;
            mTrackedAddresses.put(la.getAddress(), new AddressTracker(la, nowMs));
        }

        for (Link6Address la : addressDiff.removed) {
            hasUpdate = true;
            mTrackedAddresses.remove(la.getAddress());
        }

        for (Link6Address la : addressDiff.updated) {
            final AddressTracker tracker = mTrackedAddresses.get(la.getAddress());

            // Comparing the lifetime against the last registered address inside the
            // AddressTracker object ensures that significant lifetime changes are handled
            // appropriately. I.e. if a router always updates the lifetime by less than 1%, the
            // first few lifetime changes will be ignored as per isLifetimeChangeSignificant();
            // however, in that case the AddressTracker does not get updated, so the lifetime
            // will eventually become sufficiently "out of sync".
            final long oldExpiryMs = tracker.mAddress.getExpirationTime();
            final long newExpiryMs = la.getExpirationTime();
            if (!isLifetimeChangeSignificant(oldExpiryMs, newExpiryMs)) {
                continue;
            }
            hasUpdate = true;

            // Handle updates as a remove & add operation. This requires setting the new event time
            // as defined in rfc9686:
            //
            //   Whenever the network changes the Valid Lifetime of an existing
            //   address by more than 1%, for example, by sending a Prefix Information
            //   Option (PIO) [RFC4861] with a new Valid Lifetime, the client
            //   calculates a new AddrRegRefreshInterval.  The client schedules a
            //   refresh for min(nowMs + AddrRegRefreshInterval,
            //   NextAddrRegRefreshTime).  If the refresh would be scheduled in the
            //   past, then the refresh occurs immediately.
            mTrackedAddresses.remove(la.getAddress());
            final long nextAddrRegRefreshTime = tracker.mEventTime;
            final long newValidMs = newExpiryMs - nowMs;
            final long addrRegRefreshInterval = addrRegRefreshInterval(newValidMs);

            final long refreshMs = Math.min(nowMs + addrRegRefreshInterval, nextAddrRegRefreshTime);
            mTrackedAddresses.put(la.getAddress(), new AddressTracker(la, refreshMs));
        }

        if (hasUpdate) {
            dispatchRegistration(nowMs);
        }
    }

    /**
     * Schedule a timer for the minimum event time among all tracked addresses that are currently
     * scheduled (i.e., mIsScheduled is true). If no addresses are scheduled, no alarm is set.
     * An address is scheduled to be registered when:
     * - It is added for the first time.
     * - Its valid lifetime changes by more than 1%; for example, when a new RA is received that
     *   extends the lifetime.
     * - A retransmission is scheduled.
     * An address is unscheduled when:
     * - An ADDR_REG_REPLY message is received for it indicating successful registration.
     * - The maximum retransmission count is reached.
     */
    private void scheduleNextTimer() {
        long nextEvent = Long.MAX_VALUE;
        for (AddressTracker tracker : mTrackedAddresses.values()) {
            if (!tracker.mIsScheduled) continue;
            nextEvent = Math.min(nextEvent, tracker.mEventTime);
        }
        if (nextEvent == Long.MAX_VALUE) return;

        final String tag = TAG + "." + mInterfaceName + ".KICK";
        mAlarmManager.setExact(AlarmManager.ELAPSED_REALTIME_WAKEUP, nextEvent, tag,
                mAddressRegistrationAlarm, mHandler);
    }

    private int transmitPacket(Dhcp6AddrRegInformPacket packet) {
        // DHCPv6 ADDR-REG-INFORM message MUST be sent from the address being registered
        // per RFC9686 section 4.2.
        return mDhcp6PacketDispatcher.transmitPacket(packet.buildPacket(), packet.mIaAddress);
    }

    /**
     * Send all address registration messages where the timer has expired and schedule the next
     * timer.
     */
    private void dispatchRegistration(long nowMs) {
        for (AddressTracker tracker : mTrackedAddresses.values()) {
            if (!tracker.isExpired(nowMs)) continue;
            final Dhcp6AddrRegInformPacket packet = tracker.getAddrRegInformPacket(nowMs);
            transmitPacket(packet);
            tracker.maybeScheduleNextEvent(nowMs);
        }
        scheduleNextTimer();
    }

    private void onReceiveReply(@NonNull Dhcp6Packet packet, @Nullable Inet6Address dst) {
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
        final AddressTracker tracker = mTrackedAddresses.get(address);
        if (tracker == null) {
            Log.e(TAG, "Do not find a corresponding tracker for IPv6 address " + address);
            return;
        }

        // Check if the transaction ID matches or not. This is intended behavior, because one
        // case is device receives the update before it receives the response. updateAddress will
        // change the mTransId, when the response arrives, the mTransId changes, and we throws
        // the response, that's the intended behavior, because we want to respect the updated
        // lifetime first.
        if (tracker.mTransId != packet.getTransactionId()) {
            Log.e(TAG, "transId doesn't match");
            return;
        }

        final long nowMs = SystemClock.elapsedRealtime();
        tracker.markRegistrationSuccess(nowMs);
        dispatchRegistration(nowMs);
    }
}
