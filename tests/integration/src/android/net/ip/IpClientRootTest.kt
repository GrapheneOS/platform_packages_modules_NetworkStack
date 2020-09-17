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

package android.net.ip

import android.Manifest
import android.Manifest.permission.READ_DEVICE_CONFIG
import android.Manifest.permission.WRITE_DEVICE_CONFIG
import android.net.IIpMemoryStore
import android.net.IIpMemoryStoreCallbacks
import android.net.networkstack.TestNetworkStackServiceClient
import android.net.util.NetworkStackUtils
import android.os.Process
import android.provider.DeviceConfig
import android.util.ArrayMap
import android.util.Log
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.AfterClass
import org.junit.BeforeClass
import org.mockito.ArgumentCaptor
import org.mockito.Mockito.timeout
import org.mockito.Mockito.verify
import java.lang.System.currentTimeMillis
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

// Stable AIDL method 5 in INetworkStackConnector is allowTestUid
private const val ALLOW_TEST_UID_INDEX = 5

/**
 * Tests for IpClient, run with root access but no signature permissions.
 *
 * Tests run from this class interact with the real network stack process and can affect system
 * state, e.g. by changing flags.
 * State should be restored at the end of the test, but is not guaranteed if the test process is
 * terminated during the run.
 */
class IpClientRootTest : IpClientIntegrationTestCommon() {
    companion object {
        private val TAG = IpClientRootTest::class.java.simpleName
        private val automation by lazy { InstrumentationRegistry.getInstrumentation().uiAutomation }
        private lateinit var nsClient: TestNetworkStackServiceClient

        private class IpMemoryStoreCallbacks(
            private val fetchedFuture: CompletableFuture<IIpMemoryStore>
        ) : IIpMemoryStoreCallbacks.Stub() {
            override fun onIpMemoryStoreFetched(ipMemoryStore: IIpMemoryStore) {
                fetchedFuture.complete(ipMemoryStore)
            }
            override fun getInterfaceVersion() = IIpMemoryStoreCallbacks.VERSION
            override fun getInterfaceHash() = IIpMemoryStoreCallbacks.HASH
        }

        @JvmStatic @BeforeClass
        fun setUpClass() {
            // Connect to the NetworkStack only once, as it is relatively expensive (~50ms plus any
            // polling time waiting for the test UID to be allowed), and there should be minimal
            // side-effects between tests compared to reconnecting every time.
            automation.adoptShellPermissionIdentity(Manifest.permission.NETWORK_SETTINGS)
            try {
                automation.executeShellCommand("su root service call network_stack " +
                        "$ALLOW_TEST_UID_INDEX i32 " + Process.myUid())
                // Connecting to the test service does not require allowing the test UID (binding is
                // always allowed with NETWORK_SETTINGS permissions on debuggable builds), but
                // allowing the test UID is required to call any method on the service.
                nsClient = TestNetworkStackServiceClient.connect()
                // Wait for oneway call to be processed: unfortunately there is no easy way to wait
                // for a success callback via the service shell command.
                // TODO: build a small native util that also waits for the success callback, bundle
                // it in the test APK, and run it as shell command as root instead.
                waitUntilTestUidAllowed()
            } finally {
                automation.dropShellPermissionIdentity()
            }
        }

        private fun waitUntilTestUidAllowed() {
            // Until the test UID is allowed, oneway binder calls will not receive any reply.
            // Call fetchIpMemoryStore (which has limited side-effects) repeatedly until any call
            // gets a callback.
            val limit = currentTimeMillis() + TEST_TIMEOUT_MS
            val fetchedFuture = CompletableFuture<IIpMemoryStore>()
            Log.i(TAG, "Starting multiple attempts to fetch IpMemoryStore; failures are expected")
            while (currentTimeMillis() < limit) {
                try {
                    nsClient.fetchIpMemoryStore(IpMemoryStoreCallbacks(fetchedFuture))
                    // The future may be completed by any previous call to fetchIpMemoryStore.
                    fetchedFuture.get(20, TimeUnit.MILLISECONDS)
                    Log.i(TAG, "Obtained IpMemoryStore")
                    return
                } catch (e: TimeoutException) {
                    // Fall through
                }
            }
        }

        @JvmStatic @AfterClass
        fun tearDownClass() {
            nsClient.disconnect()
            automation.adoptShellPermissionIdentity(Manifest.permission.NETWORK_SETTINGS)
            try {
                // Reset the test UID as -1.
                // This may not be called if the test process is terminated before completing,
                // however this is fine as the test UID is only usable on userdebug builds, and
                // the system does not reuse UIDs across apps until reboot.
                automation.executeShellCommand("su root service call network_stack " +
                        "$ALLOW_TEST_UID_INDEX i32 -1")
            } finally {
                automation.dropShellPermissionIdentity()
            }
        }
    }

    private val originalFlagValues = ArrayMap<String, String>()

    /**
     * Wrapper class for IIpClientCallbacks.
     *
     * Used to delegate method calls to mock interfaces used to verify the calls, while using
     * real implementations of the binder stub (such as [asBinder]) to properly receive the calls.
     */
    private class BinderCbWrapper(base: IIpClientCallbacks) :
            IIpClientCallbacks.Stub(), IIpClientCallbacks by base {
        // asBinder is implemented by both base class and delegate: specify explicitly
        override fun asBinder() = super.asBinder()
    }

    @After
    fun tearDownFlags() {
        if (testSkipped()) return
        automation.adoptShellPermissionIdentity(READ_DEVICE_CONFIG, WRITE_DEVICE_CONFIG)
        try {
            for ((key, value) in originalFlagValues.entries) {
                if (key == null) continue
                DeviceConfig.setProperty(DeviceConfig.NAMESPACE_CONNECTIVITY, key,
                        value, false /* makeDefault */)
            }
        } finally {
            automation.dropShellPermissionIdentity()
        }
    }

    override fun useNetworkStackSignature() = false

    override fun makeIIpClient(ifaceName: String, cbMock: IIpClientCallbacks): IIpClient {
        val ipClientCaptor = ArgumentCaptor.forClass(IIpClient::class.java)
        // Older versions of NetworkStack do not clear the calling identity when creating IpClient,
        // so READ_DEVICE_CONFIG is required to initialize it (b/168577898).
        automation.adoptShellPermissionIdentity(READ_DEVICE_CONFIG)
        try {
            nsClient.makeIpClient(ifaceName, BinderCbWrapper(cbMock))
            verify(cbMock, timeout(TEST_TIMEOUT_MS)).onIpClientCreated(ipClientCaptor.capture())
        } finally {
            automation.dropShellPermissionIdentity()
        }
        return ipClientCaptor.value
    }

    override fun setDhcpFeatures(
        isDhcpLeaseCacheEnabled: Boolean,
        isRapidCommitEnabled: Boolean,
        isDhcpIpConflictDetectEnabled: Boolean
    ) {
        automation.adoptShellPermissionIdentity(READ_DEVICE_CONFIG, WRITE_DEVICE_CONFIG)
        try {
            setFeatureEnabled(NetworkStackUtils.DHCP_INIT_REBOOT_VERSION, isDhcpLeaseCacheEnabled)
            setFeatureEnabled(NetworkStackUtils.DHCP_RAPID_COMMIT_VERSION, isRapidCommitEnabled)
            setFeatureEnabled(NetworkStackUtils.DHCP_IP_CONFLICT_DETECT_VERSION,
                    isDhcpIpConflictDetectEnabled)
        } finally {
            automation.dropShellPermissionIdentity()
        }
    }

    private fun setFeatureEnabled(feature: String, enabled: Boolean) {
        // Do not use computeIfAbsent as it would overwrite null values (flag originally unset)
        if (!originalFlagValues.containsKey(feature)) {
            originalFlagValues[feature] =
                    DeviceConfig.getProperty(DeviceConfig.NAMESPACE_CONNECTIVITY, feature)
        }
        // The feature is enabled if the flag is lower than the package version.
        // Package versions follow a standard format with 9 digits.
        // TODO: consider resetting flag values on reboot when set to special values like "1" or
        // "999999999"
        DeviceConfig.setProperty(DeviceConfig.NAMESPACE_CONNECTIVITY, feature,
                if (enabled) "1" else "999999999", false)
    }
}