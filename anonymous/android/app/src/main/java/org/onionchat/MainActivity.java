package org.onionchat;

import android.Manifest;
import android.os.Build;
import android.os.Bundle;
import android.view.WindowManager;

import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {
    @Override
    public void onCreate(Bundle savedInstanceState) {
        /* registerPlugin MUST precede super.onCreate(): BridgeActivity.onCreate()
         * initializes the native bridge AND attaches the plugin list at that
         * moment; registering after is a no-op the bridge never learns about.
         * This was the UI/LiveData disconnect: JS saw NO TorBridge at all
         * ("tor: n/a", stage never requested) while the native daemon ran fine
         * from the Application-level kick. Do not move this line. */
        registerPlugin(TorBridge.class);
        super.onCreate(savedInstanceState);
        /* Screen security: no screenshots, no screen recording, no recents
         * thumbnails, black overlay when the app switcher shows — specified
         * feature from manifest §10. */
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        if (Build.VERSION.SDK_INT >= 33) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 7001);
        }
        /* voice calls (0.4.0): RECORD_AUDIO runtime permission — requested at
         * startup (not at call time) so the ring→answer path never stalls on
         * a system dialog; VoiceEngine treats an ungranted mic as an error. */
        if (checkSelfPermission(Manifest.permission.RECORD_AUDIO)
                != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.RECORD_AUDIO}, 7002);
        }
    }
}
