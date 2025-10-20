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
package android.net.apf;

import static android.os.PowerManager.LowPowerStandbyPortDescription;

import android.annotation.NonNull;
import android.annotation.RequiresApi;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Build;
import android.os.Handler;
import android.os.PowerManager;
import android.util.Log;

import java.util.List;

/**
 * Subscribes to low power standby ports changed broadcast events, so APF can manage offload rules
 * for low power standby port exemptions.
 */
@RequiresApi(Build.VERSION_CODES.VANILLA_ICE_CREAM)
public class ApfLowPowerStandbyPortsSubscriber {

    private static final String TAG = ApfLowPowerStandbyPortsSubscriber.class.getSimpleName();

    /**
     * Receives notifications about updated offload rules.
     */
    public interface Callback {
        /**
         * Notifies when the offload rules are updated.
         * <p>
         * This method is called on the handler thread.
         *
         * @param ports The updated list of low power standby port exemptions.
         */
        void onLowPowerStandbyPortsChanged(@NonNull List<LowPowerStandbyPortDescription> ports);
    }

    private class LowPowerStandbyPortsChangedReceiver extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {
            mHandler.post(() -> {
                updateLowPowerStandbyPorts();
            });
        }
    };

    private final Context mContext;
    private final Handler mHandler;
    private final Callback mCallback;

    private final PowerManager mPowerManager;

    private BroadcastReceiver mReceiver;

    public ApfLowPowerStandbyPortsSubscriber(@NonNull Context context, @NonNull Handler handler,
            @NonNull Callback callback) {
        mContext = context;
        mHandler = handler;
        mCallback = callback;
        mPowerManager = context.getSystemService(PowerManager.class);
    }

    // Schedules an update on the handler thread.
    private void updateLowPowerStandbyPorts() {
        notifyLowPowerStandbyPorts(mPowerManager.getActiveLowPowerStandbyPorts());
    }

    private void notifyLowPowerStandbyPorts(@NonNull List<LowPowerStandbyPortDescription> ports) {
        mCallback.onLowPowerStandbyPortsChanged(ports);
    }

    /**
     * Starts receiving events and notifying callbacks.
     */
    public void subscribe() {
        if (mReceiver != null) return;
        updateLowPowerStandbyPorts();
        mReceiver = new LowPowerStandbyPortsChangedReceiver();
        mContext.registerReceiver(mReceiver,
                new IntentFilter(PowerManager.ACTION_LOW_POWER_STANDBY_PORTS_CHANGED));
    }

    /**
     * Stops receiving events and notifying callbacks.
     */
    public void unsubscribe() {
        if (mReceiver == null) return;
        mContext.unregisterReceiver(mReceiver);
        mReceiver = null;
    }
}
