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

import static android.system.OsConstants.AF_INET6;
import static android.system.OsConstants.IPV6_RECVPKTINFO;
import static android.system.OsConstants.IPPROTO_IPV6;
import static android.system.OsConstants.IPPROTO_UDP;
import static android.system.OsConstants.SOCK_DGRAM;
import static android.system.OsConstants.SOCK_NONBLOCK;

import static com.android.net.module.util.NetworkStackConstants.ALL_DHCP_RELAY_AGENTS_AND_SERVERS;
import static com.android.net.module.util.NetworkStackConstants.DHCP6_SERVER_PORT;
import static com.android.net.module.util.NetworkStackConstants.DHCP6_CLIENT_PORT;
import static com.android.net.module.util.NetworkStackConstants.DHCP_MAX_LENGTH;
import static com.android.net.module.util.NetworkStackConstants.IPV6_ADDR_ANY;

import android.net.util.SocketUtils;
import android.os.Handler;
import android.system.ErrnoException;
import android.system.Os;
import android.system.StructCmsghdr;
import android.system.StructMsghdr;
import android.util.Log;
import android.util.SparseArray;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.android.modules.utils.build.SdkLevel;
import com.android.net.module.util.FdEventsReader;
import com.android.net.module.util.Struct;
import com.android.net.module.util.dhcp6.Dhcp6Packet;
import com.android.net.module.util.structs.Ipv6PktInfo;

import java.io.FileDescriptor;
import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Objects;

/**
 * Dispatch DHCPv6 messages according to their DHCP Message type (see "Message Types" at
 * https://www.iana.org/assignments/dhcpv6-parameters/dhcpv6-parameters.xhtml).
 * @hide
 */
public class Dhcp6PacketDispatcher extends FdEventsReader<Dhcp6PacketDispatcher.Payload> {
    private static final String TAG = Dhcp6PacketDispatcher.class.getSimpleName();
    protected final String mInterfaceName;
    private final SparseArray<MessageHandler> mMessageHandlers = new SparseArray<>();
    // Indicate whether to use the control message APIs with ancillary data.
    private final boolean mUseControlMessageApi;

    // The {@link android.system.OsConstants#IPV6_PKTINFO} is only available from
    // Android 15 (API 35). This local definition is used to provide backward compatibility.
    private static final int IPV6_PKTINFO = 50;

    static final class Payload {
        final byte[] mBytes = new byte[DHCP_MAX_LENGTH];
        Inet6Address mDstAddr;
    }

    public interface MessageHandler {
        /**
         * Process a received DHCPv6 message.
         *
         * @param packet The DHCPv6 packet instance.
         * @param dst The destination IPv6 address of the received DHCPv6 message.
         *            This parameter is populated using {@link android.system.Os#recvmsg} with
         *            {@link android.system.OsConstants#IPV6_PKTINFO} ancillary data. It is only
         *            available on Android S (API 31) and above; for Android R (API 30) and earlier,
         *            this parameter will be null.
         */
        void handleMessage(@NonNull Dhcp6Packet packet, @Nullable Inet6Address dst);
    }

    public Dhcp6PacketDispatcher(Handler handler, String iface, boolean useControlMessageApi) {
        super(handler, new Payload());
        mInterfaceName = iface;
        mUseControlMessageApi = useControlMessageApi;
    }

    @Override
    protected int recvBufSize(@NonNull Payload buffer) {
        return buffer.mBytes.length;
    }

    /**
     * Register the specific DHCPv6 message types which are expected to receive.
     *
     * @param handler A {@link MessageHandler} instance that will process the received messages.
     * @param types An array of integers representing the expected DHCPv6 message types.
     */
    public void registerHandler(MessageHandler handler, byte... types) {
        for (byte type : types) {
            if (mMessageHandlers.contains(type)) {
                throw new IllegalStateException("The message handler already exists");
            }
            mMessageHandlers.put(type, handler);
        }
    }

    /**
     * Unregister the specific DHCPv6 message handler, and stops the reception of messages.
     *
     * @param handler A {@link MessageHandler} instance that will process the received messages.
     */
    public void unregisterHandler(MessageHandler handler) {
        for (int i = mMessageHandlers.size() - 1; i >= 0; i--) {
            final MessageHandler value = mMessageHandlers.valueAt(i);
            if (Objects.equals(value, handler)) {
                mMessageHandlers.removeAt(i);
            }
        }
    }

    @Override
    protected void handlePacket(@NonNull Payload payload, int length) {
        try {
            final Dhcp6Packet packet = Dhcp6Packet.decode(payload.mBytes, length);
            final byte type = packet.getMessageType();
            final MessageHandler handler = mMessageHandlers.get(type);
            if (handler == null) {
                return;
            }
            handler.handleMessage(packet, payload.mDstAddr);
        } catch (Dhcp6Packet.ParseException e) {
            Log.e(TAG, "Can't parse DHCPv6 packet: " + e.getMessage());
        }
    }

    @Override
    protected FileDescriptor createFd() {
        FileDescriptor socket = null;
        try {
            socket = Os.socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
            if (SdkLevel.isAtLeastS()) {
                Os.setsockoptInt(socket, IPPROTO_IPV6, IPV6_RECVPKTINFO, 1);
            }
            SocketUtils.bindSocketToInterface(socket, mInterfaceName);
            Os.bind(socket, IPV6_ADDR_ANY, DHCP6_CLIENT_PORT);
        } catch (SocketException | ErrnoException e) {
            Log.e(TAG, "Error creating udp socket", e);
            closeFd(socket);
            socket = null;
            return null;
        }
        return socket;
    }

    @Override
    protected int readPacket(@NonNull FileDescriptor fd,
            @NonNull Payload packetBuffer) throws Exception {
        if (mUseControlMessageApi) {
            final ByteBuffer payload = ByteBuffer.wrap(packetBuffer.mBytes);

            // The source address placehodler, will be filled by kernel.
            final InetSocketAddress msgName = new InetSocketAddress(0);

            // IPV6_PKTINFO control message placeholder, will be filled by the kernel with the
            // destination IPv6 address and interface index.
            final byte[] pktInfo = new byte[Struct.getSize(Ipv6PktInfo.class)];

            // The control message header array, expect to receive one control message:
            // IPV6_PKTINFO.
            final ByteBuffer[] msgIov = new ByteBuffer[] { payload };
            final StructCmsghdr[] msgControl = new StructCmsghdr[1];
            msgControl[0] = new StructCmsghdr(
                    IPPROTO_IPV6 /* cmsg_level */,
                    IPV6_PKTINFO /* cmsg_type */,
                    pktInfo /* cmsg_data */);
            final StructMsghdr msghdr = new StructMsghdr(
                    msgName,
                    msgIov,
                    msgControl,
                    0 /* msgflags */);

            final int read = Os.recvmsg(fd, msghdr, 0 /* flags */);
            if (msghdr.msg_control != null) {
                final StructCmsghdr cmsg = msghdr.msg_control[0];
                final ByteBuffer pktInfoBuf =
                        ByteBuffer.wrap(cmsg.cmsg_data, 0, (int) cmsg.cmsg_data.length);
                final Ipv6PktInfo info = Struct.parse(Ipv6PktInfo.class, pktInfoBuf);
                packetBuffer.mDstAddr = info.addr;
            }
            return read;
        } else {
            return Os.read(fd, packetBuffer.mBytes, 0, packetBuffer.mBytes.length);
        }
    }

    /**
     * Transmit a DHCPv6 message.
     *
     * @param buf The {@link ByteBuffer} instance containing the DHCPv6 message to be sent.
     */
    @SuppressWarnings("ByteBufferBackingArray")
    public int transmitPacket(@NonNull final ByteBuffer buf) {
        try {
            return Os.sendto(getFd(),
                    buf.array(),
                    0 /* byteOffset */,
                    buf.limit() /* byteCount */,
                    0 /* flags */,
                    ALL_DHCP_RELAY_AGENTS_AND_SERVERS,
                    DHCP6_SERVER_PORT);
        } catch (ErrnoException | IOException e) {
            Log.e(TAG, "Can't send packet: ", e);
            return -1;
        }
    }

    /**
     * Transmit a DHCPv6 message.
     *
     * @param buf The {@link ByteBuffer} instance containing the DHCPv6 message to be sent.
     * @param src The source IPv6 address from which the DHCPv6 message will originate.
     */
    public int transmitPacket(@NonNull final ByteBuffer buf, @NonNull final Inet6Address src) {
        try {
            // Destination address for the DHCPv6 message.
            final InetSocketAddress msgName = new InetSocketAddress(
                    ALL_DHCP_RELAY_AGENTS_AND_SERVERS, DHCP6_SERVER_PORT);

            // IPV6_PKTINFO control message (ancillary data).
            final Ipv6PktInfo pktInfo = new Ipv6PktInfo(src, Os.if_nametoindex(mInterfaceName));
            final ByteBuffer pktInfoBuf = ByteBuffer.allocate(Struct.getSize(Ipv6PktInfo.class));
            pktInfoBuf.order(ByteOrder.nativeOrder());
            pktInfo.writeToByteBuffer(pktInfoBuf);

            // The control message header array, expect to send one control message: IPV6_PKTINFO.
            final StructCmsghdr[] msgControl = new StructCmsghdr[1];
            msgControl[0] = new StructCmsghdr(
                    IPPROTO_IPV6 /* cmsg_level */,
                    IPV6_PKTINFO /* cmsg_type */,
                    pktInfoBuf.array() /* cmsg_data */);
            final ByteBuffer[] msgIov = new ByteBuffer[] { buf };
            final StructMsghdr msghdr = new StructMsghdr(
                    msgName,
                    msgIov,
                    msgControl,
                    0 /* msgflags */);
            return Os.sendmsg(getFd(), msghdr, 0 /* flags */);
        } catch (SocketException | ErrnoException e) {
            Log.e(TAG, "Can't send packet: ", e);
            return -1;
        }
    }
}
