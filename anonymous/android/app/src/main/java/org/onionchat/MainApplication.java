package org.onionchat;

import android.app.Application;
import android.content.Context;

/**
 * Application-level wiring (user-directed fix, 0.3.4):
 * the JS unlock flow was the ONLY thing that requested the TorService start,
 * and that path proved unreliable (stage stayed "never requested" with the
 * service never started). The Application is the earliest reliable hook the
 * process owns — so the daemon request fires HERE, natively, on every cold
 * start, long before the vault unlock screen even renders. Tor bootstrapping
 * (~20-60 s) overlaps the unlock screen instead of starting after it.
 */
public class MainApplication extends Application {
    @Override
    public void onCreate() {
        super.onCreate();
        final Context c = this;
        new Thread(() -> {
            try {
                TorBridge.kickStart(c);
            } catch (Throwable t) {
                /* kickStart already guards internally; belt-and-suspenders */
                org.onionchat.TorService.State.stage = "appkick-crashed";
                org.onionchat.TorService.State.lastError = "Application kickStart: " + t;
            }
        }, "app-tor-kick").start();
    }
}
