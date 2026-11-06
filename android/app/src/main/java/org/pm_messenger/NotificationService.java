package org.pm_messenger;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.IBinder;
import android.util.Base64;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import androidx.core.app.NotificationCompat;

/**
 * Phase 4: native watchdog — polls the relay on a dedicated background thread
 * so system notifications keep firing even while the WebView/UI is locked.
 * Runs as a foreground service (dataSync), fully independent of the
 * front-end lifecycle: the JS loop holds the conversation UI, this thread
 * holds the alert duty. Cursor state is kept separately (pm_svc_index) so
 * the two never fight over the UI's replay cursor.
 */
public class NotificationService extends Service {
    private static final String TAG = "PM-Notifier";
    private static final String SP_NAME = "pm_state";
    private static final int FOREGROUND_ID = 2001;
    private static final int POLL_MS = 10000;
    private static final String CH_SERVICE = "pm-service";
    private static final String CH_ALERTS = "pm-alerts";

    private volatile boolean running = false;
    private Thread worker;
    private int alertId = 3000;

    @Override
    public IBinder onBind(Intent intent) { return null; }          // started service, not a bound one

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        startForeground(FOREGROUND_ID, buildForegroundNotification());
        if (!running) {
            running = true;
            worker = new Thread(this::loop, "pm-notifier");
            worker.start();
            Log.d(TAG, "watchdog thread started");
        }
        return START_STICKY;
    }

    public static void start(Context c) {
        c.startForegroundService(new Intent(c, NotificationService.class));
    }

    @Override
    public void onDestroy() {
        running = false;
        if (worker != null) worker.interrupt();
        Log.d(TAG, "watchdog stopped");
        super.onDestroy();
    }

    private Notification buildForegroundNotification() {
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        nm.createNotificationChannel(new NotificationChannel(
                CH_SERVICE, "P/M background watcher", NotificationManager.IMPORTANCE_MIN));
        return new NotificationCompat.Builder(this, CH_SERVICE)
                .setSmallIcon(android.R.drawable.stat_notify_chat)
                .setContentTitle("P/M")
                .setContentText("Watching for incoming encrypted messages")
                .setOngoing(true)
                .build();
    }

    private void loop() {
        while (running) {
            try { checkOnce(); } catch (Throwable t) { Log.d(TAG, "tick skipped: " + t); }
            try { Thread.sleep(POLL_MS); } catch (InterruptedException e) { break; }
        }
        stopSelf();
    }

    private void checkOnce() throws Exception {
        SharedPreferences sp = getSharedPreferences(SP_NAME, MODE_PRIVATE);
        String relay = sp.getString("pm_relay_url", null);
        String keyB64 = sp.getString("pm_key_b64", null);
        boolean notifyOn = sp.getBoolean("pm_notify_on", true);
        boolean appHidden = sp.getBoolean("pm_app_hidden", true);
        String deviceId = sp.getString("pm_device_id", "");
        int cur = sp.getInt("pm_svc_index", 0);
        if (relay == null || relay.isEmpty()) return;

        HttpURLConnection conn = (HttpURLConnection) new URL(relay + "/get?after=" + cur).openConnection();
        conn.setConnectTimeout(8000);
        conn.setReadTimeout(8000);
        String body;
        InputStream in = null;
        try {
            in = conn.getInputStream();
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) != -1) bo.write(buf, 0, n);
            body = new String(bo.toByteArray(), StandardCharsets.UTF_8);
        } finally {
            if (in != null) in.close();
            conn.disconnect();
        }

        JSONObject json = new JSONObject(body);
        JSONArray msgs = json.getJSONArray("messages");
        int last = json.optInt("last_index", cur);

        for (int i = 0; i < msgs.length(); i++) {
            JSONObject m = msgs.getJSONObject(i);
            if (deviceId.equals(m.optString("sender"))) continue;
            String payload = m.optString("payload", "");
            if (notifyOn && appHidden && !payload.isEmpty()) {
                notifyMsg(decryptPreview(payload, keyB64));
            }
        }

        sp.edit().putInt("pm_svc_index", Math.max(cur, last)).apply();
    }

    /**
     * Fernet (AES-128-CBC + HMAC-SHA256) decrypt in pure javax.crypto — same
     * format as the JS client (version byte 0x80, 8-byte ts, 16-byte IV, ct,
     * 32-byte HMAC over ts‖iv‖ct; key = 16 signing ‖ 16 encryption).
     * Media and undecryptable packets degrade to a generic label.
     */
    private String decryptPreview(String token, String keyB64) {
        try {
            if (keyB64 == null || keyB64.isEmpty()) return "New message";
            byte[] key = Base64.decode(keyB64, Base64.DEFAULT);
            byte[] data = Base64.decode(token, Base64.URL_SAFE | Base64.NO_WRAP);
            ByteBuffer bb = ByteBuffer.wrap(data);
            if (bb.get() != (byte) 0x80) return "New message";
            long ts = bb.getLong();
            byte[] rest = new byte[data.length - 9];
            bb.get(rest);
            if (rest.length <= 48) return "New message";
            byte[] iv = Arrays.copyOfRange(rest, 0, 16);
            byte[] ct = Arrays.copyOfRange(rest, 16, rest.length - 32);
            byte[] mac = Arrays.copyOfRange(rest, rest.length - 32, rest.length);

            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(new SecretKeySpec(key, 0, 16, "HmacSHA256"));
            byte[] macIn = ByteBuffer.allocate(8 + ct.length).putLong(ts).put(rest, 0, ct.length).array();
            if (!MessageDigest.isEqual(hmac.doFinal(macIn), mac)) return "New message";

            Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, 16, 16, "AES"), new IvParameterSpec(iv));
            byte[] padded = c.doFinal(ct);
            int pad = padded[padded.length - 1] & 0xFF;
            if (pad < 1 || pad > 16 || pad > padded.length) return "New message";
            String plain = new String(padded, 0, padded.length - pad, StandardCharsets.UTF_8);
            if (plain.startsWith("data:")) return "📷 New photo / voice note";
            return plain.length() > 80 ? plain.substring(0, 80) + "…" : plain;
        } catch (Throwable t) {
            return "New message";
        }
    }

    private void notifyMsg(String preview) {
        try {
            NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
            NotificationChannel ch = new NotificationChannel(
                    CH_ALERTS, "Messages", NotificationManager.IMPORTANCE_HIGH);
            ch.enableVibration(true);
            nm.createNotificationChannel(ch);
            Notification n = new NotificationCompat.Builder(this, CH_ALERTS)
                    .setSmallIcon(android.R.drawable.stat_notify_chat)
                    .setContentTitle("P/M")
                    .setContentText(preview)
                    .setAutoCancel(true)
                    .build();
            nm.notify(alertId++, n);
        } catch (Throwable t) {
            Log.d(TAG, "notify failed: " + t);
        }
    }
}
