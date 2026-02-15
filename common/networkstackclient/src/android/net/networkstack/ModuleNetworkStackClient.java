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

package android.net.networkstack;

import android.annotation.NonNull;
import android.net.INetworkStackConnector;
import android.net.NetworkStack;
import android.os.IBinder;
import android.util.Log;

import com.android.internal.annotations.VisibleForTesting;

/**
 * A {@link NetworkStackClientBase} implementation for use within modules (not the system server).
 */
public class ModuleNetworkStackClient extends NetworkStackClientBase {
    private static final String TAG = ModuleNetworkStackClient.class.getSimpleName();
    private static ModuleNetworkStackClient sInstance;

    private final Dependencies mDeps;

    private ModuleNetworkStackClient(Dependencies deps) {
        mDeps = deps;
    }

    /**
     * Get an instance of the ModuleNetworkStackClient.
     */
    @NonNull
    public static ModuleNetworkStackClient getInstance() {
        return getInstance(new Dependencies());
    }

    /**
     * Get an instance of the ModuleNetworkStackClient. Only for tests.
     */
    @VisibleForTesting
    @NonNull
    public static synchronized ModuleNetworkStackClient getInstance(Dependencies deps) {
        if (sInstance == null) {
            sInstance = new ModuleNetworkStackClient(deps);
            sInstance.startPolling();
        }
        return sInstance;
    }

    @VisibleForTesting
    protected static synchronized void resetInstanceForTest() {
        sInstance = null;
    }

    @VisibleForTesting
    public static class Dependencies {
        public IBinder getNetworkStack() {
            return NetworkStack.getService();
        }
    }

    private IBinder getAliveNetworkStack() {
        final IBinder networkStack = mDeps.getNetworkStack();
        // If system server restarted, NetworkStack.getService() might temporarily return a stale
        // (i.e. dead) version of NetworkStack.
        if (networkStack != null && networkStack.isBinderAlive()) {
            return networkStack;
        }
        return null;
    }

    private void startPolling() {
        // If the service is already registered (as it will be most of the time), do not poll and
        // fulfill requests immediately.
        final IBinder nss = getAliveNetworkStack();
        if (nss != null) {
            // Calling onNetworkStackConnected here means that pending oneway Binder calls to the
            // NetworkStack get sent from the current thread and not a worker thread; this is fine
            // considering that those are only non-blocking, oneway Binder calls.
            onNetworkStackConnected(INetworkStackConnector.Stub.asInterface(nss));
            return;
        }
        new Thread(new PollingRunner()).start();
    }

    private class PollingRunner implements Runnable {

        private PollingRunner() {}

        @Override
        public void run() {
            // Block until the NetworkStack connector is registered in ServiceManager.
            IBinder nss;
            while ((nss = getAliveNetworkStack()) == null) {
                try {
                    Thread.sleep(200);
                } catch (InterruptedException e) {
                    Log.e(TAG, "Interrupted while waiting for NetworkStack connector", e);
                    // Keep trying, the system would just crash without a connector
                }
            }

            onNetworkStackConnected(INetworkStackConnector.Stub.asInterface(nss));
        }
    }
}
