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

package android.net.ip

import android.content.Context
import android.content.res.Resources
import android.net.NetworkStackIpMemoryStore
import android.net.dhcp.DhcpClient
import androidx.test.filters.SmallTest
import androidx.test.ext.junit.runners.AndroidJUnit4

import com.android.networkstack.R
import com.android.networkstack.metrics.IpProvisioningMetrics
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.Mockito.any
import org.mockito.Mockito.doReturn
import org.mockito.Mockito.mock
import org.mockito.Mockito.spy
import kotlin.test.assertEquals

const val HOSTNAME = "myhostname"
const val HOSTNAME1 = "myhostname1"
const val HOSTNAME2 = "myhostname2"
const val HOSTNAME3 = "myhostname3"
const val PROP1 = "ro.product.model"
const val PROP2 = "ro.product.name"
const val PROP3 = "ro.vendor.specialname"
const val PROP_EMPTY = "ro.product.name_empty"
const val PROP_INVALID = "ro.notproduct.and.notvendor"

/**
 * Unit tests for DhcpClient (currently only for its Dependencies class). Note that most of
 * DhcpClient's functionality is (and should be) tested in the IpClient integration tests and in the
 * DhcpPacket unit tests, not here. This test class is mostly intended to test small bits of
 * functionality that would be difficult to exercise in those larger tests.
 */
@RunWith(AndroidJUnit4::class)
@SmallTest
class DhcpClientTest {
    private val context = mock(Context::class.java)
    private val resources = mock(Resources::class.java)

    // This is a spy because DhcpClient.Dependencies is the actual class under test.
    // The tests mock some of the class's methods, exercise certain methods that end up calling
    // the mocked methods, and checks the results.
    private val deps = spy(DhcpClient.Dependencies(
        mock(NetworkStackIpMemoryStore::class.java),
        mock(IpProvisioningMetrics::class.java)))

    @Before
    fun setUp() {
        doReturn(resources).`when`(context).resources
        doReturn(HOSTNAME).`when`(deps).getDeviceName(any())
        doReturn(HOSTNAME1).`when`(deps).getSystemProperty(PROP1)
        doReturn(HOSTNAME2).`when`(deps).getSystemProperty(PROP2)
        doReturn(HOSTNAME2).`when`(deps).getSystemProperty(PROP_INVALID)
        doReturn(HOSTNAME3).`when`(deps).getSystemProperty(PROP3)
        doReturn("").`when`(deps).getSystemProperty(PROP_EMPTY)
    }

    private fun setHostnameProps(props: Array<String>?) {
        doReturn(props).`when`(resources).getStringArray(
            R.array.config_dhcp_client_hostname_preferred_props)
    }

    @Test
    fun testGetHostname_PropsSet() {
        setHostnameProps(null)
        assertEquals(HOSTNAME, deps.getCustomHostname(context))

        setHostnameProps(emptyArray())
        assertEquals(HOSTNAME, deps.getCustomHostname(context))

        setHostnameProps(arrayOf(PROP1, PROP2))
        assertEquals(HOSTNAME1, deps.getCustomHostname(context))

        setHostnameProps(arrayOf(PROP_INVALID, PROP1, PROP2))
        assertEquals(HOSTNAME1, deps.getCustomHostname(context))

        setHostnameProps(arrayOf(PROP_EMPTY, PROP2))
        assertEquals(HOSTNAME2, deps.getCustomHostname(context))

        setHostnameProps(arrayOf(PROP_EMPTY, PROP3))
        assertEquals(HOSTNAME3, deps.getCustomHostname(context))
    }
}
