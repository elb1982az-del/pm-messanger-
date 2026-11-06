package org.onionchat;

import android.os.Bundle;
import android.view.WindowManager;

import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        /* Screen security: no screenshots, no screen recording, no recents
         * thumbnails, black overlay when the app switcher shows — specified
         * feature from manifest §10. */
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
    }
}

