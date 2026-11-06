package org.onionchat;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStreamReader;

/**
 * Anonymous — embedded Tor daemon (Phase 3).
 *
 * Runs the libtor.so shipped inside the APK (info.guardianproject:tor-android)
 * as a standalone tor process from nativeLibraryDir — the one location Android
 * 10+ still permits exec() from. Publishes OUR hidden service on virtual port
 * 9878 (mapped to the local HTTP inbox listener on 127.0.0.1:9878) and exposes
 * SOCKS5 on 127.0.0.1:9050 for outbound SOCKS-CONNECT deliveries.
 *
 * The hidden service identity (hostname file) persists across restarts, so the
 * onion address is stable for the life of the vault.
 *
 * All state is shared with TorBridge through TorService.State.
 */
public class TorService extends Service {

    public static final int HS_PORT = 9878;      // virtual port == local port

    /** Shared state bridge ( plugins + service ). */
    public static final class State {
        public static volatile boolean running = false;
        public static volatile boolean ready = false;
        public static volatile int bootstrapped = 0;
        public static volatile String onion = null;
        public static volatile String lastError = "";
        public static volatile StringBuilder logTail = new StringBuilder();
        public static final Object inboxLock = new Object();
        public static final java.util.ArrayDeque<String> inbox = new java.util.ArrayDeque<>();
    }

    private static Process torProc = null;

    @Override
    public IBinder onBind(Intent intent) { return null; }

    @Override
    public void onCreate() {
        super.onCreate();
        Notification n;
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationChannel ch = new NotificationChannel("tor", "Tor transport", NotificationManager.IMPORTANCE_LOW);
            ch.setShowBadge(false);
            NotificationManager nm = getSystemService(NotificationManager.class);
            if (nm != null) nm.createNotificationChannel(ch);
            n = new Notification.Builder(this, "tor")
                    .setSmallIcon(android.R.drawable.ic_lock_lock)
                    .setContentTitle("Anonymous")
                    .setContentText("Tor hidden-service transport running")
                    .setOngoing(true)
                    .build();
        } else {
            n = new Notification.Builder(this)
                    .setSmallIcon(android.R.drawable.ic_lock_lock)
                    .setContentTitle("Anonymous")
                    .setContentText("Tor hidden-service transport running")
                    .build();
        }
        startForeground(0x0C0FF, n);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (torProc == null || !isAlive(torProc)) spawnTor();
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        if (torProc != null) { try { torProc.destroy(); } catch (Throwable ignored) {} torProc = null; }
        State.running = false;
        State.ready = false;
        super.onDestroy();
    }

    private static boolean isAlive(Process p) {
        try { p.exitValue(); return false; } catch (IllegalThreadStateException e) { return true; }
    }

    private void spawnTor() {
        try {
            final File torDir = new File(getFilesDir(), "tor");      // private, app-owned
            final File hsDir = new File(torDir, "hidden_service");
            final File dataDir = new File(torDir, "data");
            hsDir.mkdirs();
            dataDir.mkdirs();

            final File torrcF = new File(torDir, "torrc");
            writeTorrc(torrcF, hsDir, dataDir);

            final String torBin = new File(getApplicationInfo().nativeLibraryDir, "libtor.so").getAbsolutePath();
            final String torrcPath = torrcF.getAbsolutePath();

            State.running = true;
            State.lastError = "";

            final Thread daemon = new Thread(() -> {
                try {
                    ProcessBuilder pb = new ProcessBuilder(torBin, "-f", torrcPath);
                    pb.redirectErrorStream(true);
                    synchronized (TorService.class) { torProc = pb.start(); }
                    Process p;
                    synchronized (TorService.class) { p = torProc; }
                    BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
                    String line;
                    while ((line = r.readLine()) != null) {
                        if (line.startsWith("Bootstrapped ")) {
                            try {
                                int pc = Integer.parseInt(line.split("\\s+")[1].replace("%", ""));
                                State.bootstrapped = pc;
                            } catch (Throwable unusedNum) { /* keep last */ }
                            if (line.contains("Bootstrapped 100%")) State.ready = true;
                        } else if (line.contains("[err]") || line.contains("[warn]")) {
                            State.lastError = line;
                        }
                        appendLog(line);
                    }
                    int code = p.waitFor();
                    State.running = false;
                    State.ready = false;
                    State.lastError = "tor exited (code " + code + ")";
                } catch (Throwable t) {
                    State.running = false;
                    State.ready = false;
                    State.lastError = String.valueOf(t);
                }
            }, "anon-tor");
            daemon.start();

            /* hostname watcher: tor writes hidden_service/hostname once the
             * service descriptor is published (identity persists on disk). */
            final File hostname = new File(hsDir, "hostname");
            final Thread onionWatch = new Thread(() -> {
                for (int i = 0; i < 3600 && !State.ready; i++) {
                    try {
                        Thread.sleep(2000);
                        if (hostname.exists() && hostname.length() > 0) {
                            String s = new String(readAll(hostname)).trim();
                            if (s.endsWith(".onion")) State.onion = s;
                        }
                        if (State.ready) break;
                    } catch (InterruptedException ie) { return; }
                    catch (Throwable ignored) { }
                }
            }, "anon-onion-watch");
            onionWatch.start();
        } catch (Throwable t) {
            State.running = false;
            State.lastError = String.valueOf(t);
        }
    }

    private static void appendLog(String line) {
        synchronized (State.logTail) {
            State.logTail.append(line).append('\n');
            if (State.logTail.length() > 8000) State.logTail.delete(0, State.logTail.length() - 4000);
        }
    }

    private static void writeTorrc(File out, File hsDir, File dataDir) throws Exception {
        StringBuilder sb = new StringBuilder();
        sb.append("# Anonymous - generated at start; content trivially regenerable\n");
        sb.append("RunAsDaemon 0\n");
        sb.append("SocksPort 127.0.0.1:9050\n");
        sb.append("SocksPolicy accept 127.0.0.1:*").append("\n");
        sb.append("DataDirectory ").append(dataDir.getAbsolutePath()).append("\n");
        sb.append("HiddenServiceDir ").append(hsDir.getAbsolutePath()).append("\n");
        sb.append("HiddenServicePort 9878 127.0.0.1:9878\n");
        sb.append("AvoidDiskWrites 1\n");
        sb.append("Log notice stdout\n");
        sb.append("NumEntryGuards 1\n");
        FileOutputStream fo = new FileOutputStream(out);
        fo.write(sb.toString().getBytes("UTF-8"));
        fo.close();
    }

    private static byte[] readAll(File f) throws Exception {
        java.io.FileInputStream in = new java.io.FileInputStream(f);
        byte[] b = new byte[(int) f.length()];
        int off = 0;
        while (off < b.length) { int n = in.read(b, off, b.length - off); if (n < 0) break; off += n; }
        in.close();
        return b;
    }
}
