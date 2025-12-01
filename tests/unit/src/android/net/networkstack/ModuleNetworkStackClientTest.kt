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

package android.net.networkstack

import android.net.IIpMemoryStoreCallbacks
import android.net.INetworkMonitorCallbacks
import android.net.INetworkStackConnector
import android.net.Network
import android.net.dhcp.DhcpServingParamsParcel
import android.net.dhcp.IDhcpServerCallbacks
import android.net.ip.IIpClientCallbacks
import android.os.IBinder
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SmallTest
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.ArgumentMatchers.any
import org.mockito.Mock
import org.mockito.Mockito.doAnswer
import org.mockito.Mockito.doReturn
import org.mockito.Mockito.never
import org.mockito.Mockito.timeout
import org.mockito.Mockito.verify
import org.mockito.MockitoAnnotations

@RunWith(AndroidJUnit4::class)
@SmallTest
class ModuleNetworkStackClientTest {
    private val TEST_IFNAME = "testiface"
    private val TEST_NETWORK = Network(43)
    private val TEST_TIMEOUT_MS = 2_000L

    @Mock
    private lateinit var deps: ModuleNetworkStackClient.Dependencies
    @Mock
    private lateinit var connectorBinder: IBinder
    @Mock
    private lateinit var connector: INetworkStackConnector
    @Mock
    private lateinit var ipClientCb: IIpClientCallbacks
    @Mock
    private lateinit var dhcpServerCb: IDhcpServerCallbacks
    @Mock
    private lateinit var networkMonitorCb: INetworkMonitorCallbacks
    @Mock
    private lateinit var ipMemoryStoreCb: IIpMemoryStoreCallbacks

    private var testRegisteredNetworkStack: IBinder? = null

    @Before
    fun setUp() {
        MockitoAnnotations.initMocks(this)
        doAnswer { testRegisteredNetworkStack }.`when`(deps).networkStack
        // Use DESCRIPTOR and not class name, as the descriptor is the original class name before
        // jarjar, and is always what is used to query the interface.
        doReturn(connector).`when`(connectorBinder).queryLocalInterface(
                INetworkStackConnector.DESCRIPTOR
        )
        doReturn(true).`when`(connectorBinder).isBinderAlive()
    }

    @After
    fun tearDown() {
        ModuleNetworkStackClient.resetInstanceForTest()
    }

    fun testIpClientServiceAvailableImmediately() {
        testRegisteredNetworkStack = connectorBinder
        ModuleNetworkStackClient.getInstance(deps).makeIpClient(TEST_IFNAME, ipClientCb)
        verify(connector).makeIpClient(TEST_IFNAME, ipClientCb)
    }

    @Test
    fun testIpClientServiceAvailableImmediately_binderNotAlive() {
        // Binder is not alive, so the client should start polling.
        doReturn(false).`when`(connectorBinder).isBinderAlive
        testRegisteredNetworkStack = connectorBinder
        ModuleNetworkStackClient.getInstance(deps).makeIpClient(TEST_IFNAME, ipClientCb)

        verify(deps, timeout(TEST_TIMEOUT_MS).atLeast(2)).networkStack
        verify(connector, never()).makeIpClient(any(), any())

        // Binder becomes alive, polling should succeed.
        doReturn(true).`when`(connectorBinder).isBinderAlive
        verify(connector, timeout(TEST_TIMEOUT_MS)).makeIpClient(TEST_IFNAME, ipClientCb)
    }

    @Test
    fun testIpClientServiceAvailableAfterPolling() {
        ModuleNetworkStackClient.getInstance(deps).makeIpClient(TEST_IFNAME, ipClientCb)

        verify(deps, timeout(TEST_TIMEOUT_MS).atLeast(2)).networkStack
        verify(connector, never()).makeIpClient(any(), any())
        testRegisteredNetworkStack = connectorBinder

        verify(connector, timeout(TEST_TIMEOUT_MS)).makeIpClient(TEST_IFNAME, ipClientCb)
    }

    @Test
    fun testIpClientServiceAvailableAfterPolling_binderNotAlive() {
        ModuleNetworkStackClient.getInstance(deps).makeIpClient(TEST_IFNAME, ipClientCb)

        verify(deps, timeout(TEST_TIMEOUT_MS).atLeast(2)).networkStack
        verify(connector, never()).makeIpClient(any(), any())

        // Service becomes available, but binder is not alive.
        doReturn(false).`when`(connectorBinder).isBinderAlive
        testRegisteredNetworkStack = connectorBinder
        verify(deps, timeout(TEST_TIMEOUT_MS).atLeast(4)).networkStack
        verify(connector, never()).makeIpClient(any(), any())

        // Binder becomes alive, polling should succeed.
        doReturn(true).`when`(connectorBinder).isBinderAlive
        verify(connector, timeout(TEST_TIMEOUT_MS)).makeIpClient(TEST_IFNAME, ipClientCb)
    }

    @Test
    fun testDhcpServerAvailableImmediately() {
        testRegisteredNetworkStack = connectorBinder
        val testParams = DhcpServingParamsParcel()
        ModuleNetworkStackClient.getInstance(deps).makeDhcpServer(
            TEST_IFNAME,
            testParams,
                dhcpServerCb
        )
        verify(connector).makeDhcpServer(TEST_IFNAME, testParams, dhcpServerCb)
    }

    @Test
    fun testNetworkMonitorAvailableImmediately() {
        testRegisteredNetworkStack = connectorBinder
        val testName = "NetworkMonitorName"
        ModuleNetworkStackClient.getInstance(deps).makeNetworkMonitor(
            TEST_NETWORK,
            testName,
                networkMonitorCb
        )
        verify(connector).makeNetworkMonitor(TEST_NETWORK, testName, networkMonitorCb)
    }

    @Test
    fun testIpMemoryStoreAvailableImmediately() {
        testRegisteredNetworkStack = connectorBinder
        ModuleNetworkStackClient.getInstance(deps).fetchIpMemoryStore(ipMemoryStoreCb)
        verify(connector).fetchIpMemoryStore(ipMemoryStoreCb)
    }
}
