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
package android.net.apf

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.apf.ApfLowPowerStandbyPortsSubscriber
import android.net.apf.ApfLowPowerStandbyPortsSubscriber.Callback
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.PowerManager
import android.os.PowerManager.LowPowerStandbyPortDescription
import androidx.test.filters.SmallTest
import com.android.testutils.DevSdkIgnoreRule
import com.android.testutils.DevSdkIgnoreRule.IgnoreUpTo
import com.android.testutils.DevSdkIgnoreRunner
import com.android.testutils.visibleOnHandlerThread
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.ArgumentCaptor
import org.mockito.ArgumentMatchers.any
import org.mockito.ArgumentMatchers.anyLong
import org.mockito.ArgumentMatchers.eq
import org.mockito.Captor
import org.mockito.Mock
import org.mockito.Mockito
import org.mockito.Mockito.doReturn
import org.mockito.Mockito.mock
import org.mockito.Mockito.never
import org.mockito.Mockito.reset
import org.mockito.Mockito.timeout
import org.mockito.Mockito.verify
import org.mockito.Mockito.verifyNoMoreInteractions
import org.mockito.Mockito.`when`
import org.mockito.MockitoAnnotations

@RunWith(DevSdkIgnoreRunner::class)
@SmallTest
@IgnoreUpTo(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class ApfLowPowerStandbyPortsSubscriberTest {

    @get:Rule
    val ignoreRule = DevSdkIgnoreRule()

    private val TAG = ApfLowPowerStandbyPortsSubscriberTest::class.java.simpleName

    private val handlerThread by lazy {
        HandlerThread("$TAG handler thread").apply { start() }
    }
    private val handler by lazy { Handler(handlerThread.looper) }

    @Mock
    private lateinit var mockCallback: Callback
    @Mock
    private lateinit var mockContext: Context
    @Mock
    private lateinit var mockPowerManager: PowerManager

    @Captor
    private lateinit var intentFilterCaptor: ArgumentCaptor<IntentFilter>
    @Captor
    private lateinit var portListCaptor: ArgumentCaptor<List<LowPowerStandbyPortDescription>>
    @Captor
    private lateinit var receiverCaptor: ArgumentCaptor<BroadcastReceiver>

    private lateinit var subscriber : ApfLowPowerStandbyPortsSubscriber

    @Before
    fun setUp() {
        MockitoAnnotations.initMocks(this)

        doReturn(mockPowerManager).`when`(mockContext).getSystemService(PowerManager::class.java)

        doReturn(
            listOf(
                LowPowerStandbyPortDescription(
                    LowPowerStandbyPortDescription.PROTOCOL_UDP,
                    LowPowerStandbyPortDescription.MATCH_PORT_LOCAL,
                    9999
                )
            )
        )
            .`when`(mockPowerManager)
            .getActiveLowPowerStandbyPorts()

        subscriber = ApfLowPowerStandbyPortsSubscriber(mockContext, handler, mockCallback)

        // Discard any calls using context (e.g. to get PowerManager) in subscriber constructor
        reset(mockContext)
    }

    @After
    fun tearDown() {
        handlerThread.quitSafely()
        handlerThread.join()
        Mockito.framework().clearInlineMocks()
    }

    @Test
    fun subscribeRegistersReceiverAndCallsCallback() {
        subscriber.subscribe()

        verify(mockContext).registerReceiver(
            any<BroadcastReceiver>(),
            intentFilterCaptor.capture()
        )
        assertEquals(
            listOf(PowerManager.ACTION_LOW_POWER_STANDBY_PORTS_CHANGED),
            intentFilterCaptor.value.actionsIterator().asSequence().toList()
        )
        verifyNoMoreInteractions(mockContext)

        verify(mockCallback, timeout(1000)).onLowPowerStandbyPortsChanged(
            listOf(
                LowPowerStandbyPortDescription(
                    LowPowerStandbyPortDescription.PROTOCOL_UDP,
                    LowPowerStandbyPortDescription.MATCH_PORT_LOCAL,
                    9999
                )
            )
        )
        verifyNoMoreInteractions(mockCallback)
    }

    @Test
    fun subscribeAgainHasNoEffect() {
        subscriber.subscribe()
        reset(mockContext)
        reset(mockCallback)
        subscriber.subscribe()

        verifyNoMoreInteractions(mockContext)

        verifyNoMoreInteractions(mockCallback)
    }

    @Test
    fun unsubscribeBeforeSubscribeHasNoEffect() {
        subscriber.unsubscribe()

        verifyNoMoreInteractions(mockContext)

        verifyNoMoreInteractions(mockCallback)
    }

    @Test
    fun unsubscribeUnregistersReceiverButDoesNotCallCallback() {
        subscriber.subscribe()
        verify(mockContext).registerReceiver(
            receiverCaptor.capture(),
            any<IntentFilter>()
        )
        reset(mockContext)
        reset(mockCallback)
        subscriber.unsubscribe()

        verify(mockContext).unregisterReceiver(eq(receiverCaptor.value))
        verifyNoMoreInteractions(mockContext)

        verifyNoMoreInteractions(mockCallback)
    }

    @Test
    fun unsubscribeAgainHasNoEffect() {
        subscriber.subscribe()
        subscriber.unsubscribe()
        reset(mockContext)
        reset(mockCallback)
        subscriber.unsubscribe()

        verifyNoMoreInteractions(mockContext)

        verifyNoMoreInteractions(mockCallback)
    }

    @Test
    fun lowPowerStandbyPortsChanged() {
        subscriber.subscribe()
        verify(mockContext).registerReceiver(
            receiverCaptor.capture(),
            any<IntentFilter>()
        )
        reset(mockContext)
        reset(mockCallback)

        doReturn(
            listOf(
                LowPowerStandbyPortDescription(
                    LowPowerStandbyPortDescription.PROTOCOL_UDP,
                    LowPowerStandbyPortDescription.MATCH_PORT_LOCAL,
                    1234
                ),
                LowPowerStandbyPortDescription(
                    LowPowerStandbyPortDescription.PROTOCOL_UDP,
                    LowPowerStandbyPortDescription.MATCH_PORT_LOCAL,
                    5678
                )
            )
        )
            .`when`(mockPowerManager)
            .getActiveLowPowerStandbyPorts()
        receiverCaptor.value.onReceive(mockContext,
            Intent(PowerManager.ACTION_LOW_POWER_STANDBY_PORTS_CHANGED))

        verify(mockCallback, timeout(1000)).onLowPowerStandbyPortsChanged(portListCaptor.capture())
        assertEquals(
            listOf(
                LowPowerStandbyPortDescription(
                    LowPowerStandbyPortDescription.PROTOCOL_UDP,
                    LowPowerStandbyPortDescription.MATCH_PORT_LOCAL,
                    1234
                ),
                LowPowerStandbyPortDescription(
                    LowPowerStandbyPortDescription.PROTOCOL_UDP,
                    LowPowerStandbyPortDescription.MATCH_PORT_LOCAL,
                    5678
                )
            ),
            portListCaptor.value
        )
        verifyNoMoreInteractions(mockCallback)
    }
}
