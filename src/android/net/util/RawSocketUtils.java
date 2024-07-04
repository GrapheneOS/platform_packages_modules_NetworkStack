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

package android.net.util;

import static android.Manifest.permission.NETWORK_SETTINGS;
import static android.system.OsConstants.AF_PACKET;
import static android.system.OsConstants.SOCK_NONBLOCK;
import static android.system.OsConstants.SOCK_RAW;

import static com.android.net.module.util.NetworkStackConstants.ETHER_ADDR_LEN;
import static com.android.net.module.util.NetworkStackConstants.ETHER_DST_ADDR_OFFSET;
import static com.android.net.module.util.NetworkStackConstants.ETHER_TYPE_LENGTH;
import static com.android.net.module.util.NetworkStackConstants.ETHER_TYPE_OFFSET;

import android.annotation.RequiresPermission;
import android.content.Context;
import android.net.TetheringManager;
import android.system.Os;

import androidx.annotation.NonNull;

import com.android.internal.util.HexDump;

import java.io.FileDescriptor;
import java.net.NetworkInterface;
import java.net.SocketAddress;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public class RawSocketUtils {
    // For isTetheredInterface, a quick Tethering event callback is expected
    // since there's no start/stop Tethering involved. This timeout allows
    // system messages to be handled, preventing flaky test results.
    private static final int TETHERING_EVENT_CALLBACK_TIMEOUT_MS = 3000;

    /**
     * Send a raw packet represents in Hex format to the downstream interface.
     * <p>
     * Note that the target interface is limited to tethering downstream
     * for security considerations.
     */
    @RequiresPermission(NETWORK_SETTINGS)
    public static void sendRawPacketDownStream(@NonNull Context context, @NonNull String ifaceName,
                                     @NonNull String packetInHex) throws Exception {
        // 1. Verify Tethering Downstream Interface.
        enforceTetheredInterface(context, ifaceName);

        // 2. Hex to Byte Array Conversion
        final byte[] packetData = HexDump.hexStringToByteArray(packetInHex);
        final byte[] destMac = Arrays.copyOfRange(packetData, ETHER_DST_ADDR_OFFSET,
                ETHER_DST_ADDR_OFFSET + ETHER_ADDR_LEN);
        final byte[] etherTypeBytes = Arrays.copyOfRange(packetData, ETHER_TYPE_OFFSET,
                ETHER_TYPE_OFFSET + ETHER_TYPE_LENGTH);
        final int etherType = ((etherTypeBytes[0] & 0xFF) << 8) | (etherTypeBytes[1] & 0xFF);

        // 3. Obtain Network Interface
        final NetworkInterface iface = NetworkInterface.getByName(ifaceName);
        if (iface == null) {
            throw new IllegalArgumentException("Invalid network interface: " + ifaceName);
        }

        // 4. Construct and Send Packet.
        final SocketAddress addr = SocketUtils.makePacketSocketAddress(
                etherType,
                iface.getIndex(),
                destMac
        );
        final FileDescriptor sock = Os.socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, 0);
        try {
            Os.sendto(sock, packetData, 0, packetData.length, 0, addr);
        } finally {
            SocketUtils.closeSocket(sock);
        }
    }

    @RequiresPermission(NETWORK_SETTINGS)
    private static void enforceTetheredInterface(@NonNull Context context,
                                               @NonNull String interfaceName)
            throws ExecutionException, InterruptedException, TimeoutException {
        final TetheringManager tm = context.getSystemService(TetheringManager.class);
        final CompletableFuture<List<String>> tetheredInterfaces = new CompletableFuture<>();
        final TetheringManager.TetheringEventCallback callback =
                new TetheringManager.TetheringEventCallback() {
                    @Override
                    public void onTetheredInterfacesChanged(@NonNull List<String> interfaces) {
                        tetheredInterfaces.complete(interfaces);
                    }
                };
        tm.registerTetheringEventCallback(c -> c.run() /* executor */, callback);
        final List<String> tetheredIfaces = tetheredInterfaces.get(
                TETHERING_EVENT_CALLBACK_TIMEOUT_MS, TimeUnit.MILLISECONDS);
        if (!tetheredIfaces.contains(interfaceName)) {
            throw new SecurityException("Only tethered interfaces " + tetheredIfaces
                    + " are expected, but got " + interfaceName);
        }
    }
}
