package org.pm_messenger;

import android.content.Context;
import android.content.SharedPreferences;

import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

/**
 * Phase 4: lightweight JS↔native bridge. The WebView writes its poll cursor
 * and notification settings here; the watchdog service reads the same
 * SharedPreferences — the two engines never share one cursor.
 */
@CapacitorPlugin(name = "PMBridge")
public class PMBridge extends Plugin {

    @PluginMethod
    public void sync(PluginCall call) {
        Context c = getContext();
        SharedPreferences sp = c.getSharedPreferences("pm_state", Context.MODE_PRIVATE);
        sp.edit()
                .putInt("pm_last_index", call.getInt("lastIndex", 0))
                .putString("pm_device_id", call.getString("deviceId", ""))
                .putBoolean("pm_app_hidden", call.getBoolean("hidden", true))
                .putBoolean("pm_notify_on", call.getBoolean("notifyOn", true))
                .putString("pm_relay_url", call.getString("relayUrl", ""))
                .putString("pm_key_b64", call.getString("key", ""))
                .apply();
        call.resolve();
    }

    @PluginMethod
    public void startWatching(PluginCall call) {
        NotificationService.start(getContext());
        call.resolve();
    }
}
