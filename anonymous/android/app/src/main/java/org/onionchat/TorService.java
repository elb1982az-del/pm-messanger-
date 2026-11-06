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
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;

/**
 * Anonymous — embedded Tor daemon (Phase 3, revision 2).
 *
 * Runs the libtor.so shipped inside the APK (info.guardianproject:tor-android)
 * as a standalone tor process from nativeLibraryDir — the one location Android
 * 10+ still permits exec() from.
 *
 * Revision-2 initialization fixes:
 *   - bootstrap progress is read from tor's OWN FILE LOG (flushed per line by
 *     tor); the old stdout-pipe reader starved on block buffering and looked
 *     "stuck at 0%".
 *   - hard readiness: SOCKS5 port probe on 127.0.0.1:9050, independent of logs.
 *   - pre-flight exec check: libtor.so presence in nativeLibraryDir verified
 *     BEFORE ProcessBuilder; spawn/exit failures captured with exit code.
 *   - last 1200 chars of process output + tor.log reachable through
 *     TorBridge.status() → diagnosable from the UI, including [err] lines.
 *
 * Hidden service: virtual port 9878 → local HTTP inbox listener 127.0.0.1:9878.
 * Hidden-service identity persists across restarts (stable onion address).
 */
public class TorService extends Service {

    public static final int HS_PORT = 9878;
    public static final int SOCKS_PORT = 9050;

    /** Shared state bridge (plugins + service). */
    public static final class State {
        public static volatile boolean running = false;
        public static volatile boolean ready = false;
        public static volatile int bootstrapped = 0;
        public static volatile String onion = null;
        public static volatile String lastError = "";
        public static volatile boolean socksLive = false;
        public static volatile String streamTail = "";      // raw process stdin/stdout capture
        public static final StringBuilder logTail = new StringBuilder();
        public static final Object inboxLock = new Object();
        public static final java.util.ArrayDeque<String> inbox = new java.util.ArrayDeque<>();
    }

    private static Process torProc = null;
    private static final Object watcherLock = new Object();
    private static volatile boolean pollerAlive = false;

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
        State.socksLive = false;
        super.onDestroy();
    }

    private static boolean isAlive(Process p) {
        try { p.exitValue(); return false; } catch (IllegalThreadStateException e) { return true; }
    }

    private void spawnTor() {
        final File torDir = new File(getFilesDir(), "tor");       // private, app-owned
        final File hsDir = new File(torDir, "hidden_service");
        final File dataDir = new File(torDir, "data");
        final File logF = new File(torDir, "tor.log");
        hsDir.mkdirs();
        dataDir.mkdirs();

        /* pre-flight: the shared library MUST be present and readable */
        final File torBin = new File(getApplicationInfo().nativeLibraryDir, "libtor.so");
        if (!torBin.exists() || !torBin.canRead()) {
            State.running = false;
            State.lastError = "libtor.so missing/unreadable at " + torBin.getAbsolutePath();
            return;
        }
        if (!torBin.canExecute()) {
            State.lastError = "warning: libtor.so exec bit not confirmed; attempting exec anyway";
        }

        /* fresh log every launch — else stale percent values masquerade as progress */
        try { if (logF.exists()) logF.delete(); } catch (Throwable ignored) {}

        try { writeTorrc(torDir, hsDir, dataDir, logF); }
        catch (Throwable t) { State.running = false; State.lastError = "torrc write failed: " + t; return; }

        final String torrcPath = new File(torDir, "torrc").getAbsolutePath();
        final String torBinPath = torBin.getAbsolutePath();

        State.running = true;
        State.ready = false;
        State.bootstrapped = 0;
        State.socksLive = false;
        State.lastError = "";
        State.streamTail = "";
        synchronized (State.logTail) { State.logTail.setLength(0); }

        /* process thread: run tor, capture stdout+stderr merged (for diagnostics) */
        final Thread proc = new Thread(() -> {
            try {
                Process p = new ProcessBuilder(torBinPath, "-f", torrcPath)
                        .redirectErrorStream(true)
                        .start();
                synchronized (TorService.class) { torProc = p; }
                BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
                StringBuilder raw = new StringBuilder();
                String line;
                while ((line = r.readLine()) != null) {
                    raw.append(line).append('\n');
                    if (raw.length() > 8000) raw.delete(0, raw.length() - 4000);
                    State.streamTail = raw.toString();
                }
                int code = p.waitFor();
                onTorExit("tor exited (code " + code + ")");
            } catch (Throwable t) {
                String why = String.valueOf(t);
                Throwable inner = t.getCause();
                if (inner != null) why += " (" + inner + ")";
                onTorExit("tor spawn failed: " + why);
            }
        }, "anon-process");
        proc.start();

        /* single poller thread: file log parsing + socks probe + hostname */
        synchronized (watcherLock) {
            if (pollerAlive) return;
            pollerAlive = true;
        }
        final Thread poller = new Thread(() -> {
            int cycle = 0;
            try {
                while (State.running) {
                    Thread.sleep(1000);
                    cycle++;

                    /* 1. bootstrap % from tor's file log (written per line by tor,
                     *      immune to pipe buffering) */
                    String tail = readTail(logF, 16000);
                    if (tail != null && tail.length() > 0) {
                        /* keep a trimmed copy for the UI diagnostics panel */
                        synchronized (State.logTail) {
                            String t2 = tail.length() > 1200 ? tail.substring(tail.length() - 1200) : tail;
                            State.logTail.setLength(0);
                            State.logTail.append(t2);
                        }
                        /* last "Bootstrapped X%" line wins */
                        int cut = tail.lastIndexOf("Bootstrapped ");
                        if (cut >= 0) {
                            String seg = tail.substring(cut + "Bootstrapped ".length());
                            int pc = seg.indexOf('%');
                            if (pc > 0) {
                                String digits = seg.substring(0, pc).trim();
                                boolean allDigits = digits.length() > 0 && digits.length() <= 3;
                                for (int i = 0; allDigits && i < digits.length(); i++)
                                    allDigits = Character.isDigit(digits.charAt(i));
                                if (allDigits) {
                                    int pct = Integer.parseInt(digits);
                                    State.bootstrapped = pct;
                                    if (pct >= 100) { State.bootstrapped = 100; State.ready = true; }
                                }
                            }
                        }
                        int errAt = tail.indexOf("[err]");
                        if (errAt >= 0 && !State.ready) {
                            String eLine = tail.substring(errAt);
                            int nl = eLine.indexOf('\n');
                            if (nl > 0) eLine = eLine.substring(0, nl);
                            if (eLine.length() > 220) eLine = eLine.substring(0, 220);
                            if (!State.lastError.equals(eLine)) State.lastError = eLine;
                        }
                    }

                    /* 2. hidden service hostname (identity persists on disk) */
                    File hostname = new File(hsDir, "hostname");
                    if (hostname.exists() && hostname.length() > 0) {
                        String s = new String(readAll(hostname)).trim();
                        if (s.endsWith(".onion")) State.onion = s;
                    }

                    /* 3. hard SOCKS liveness probe every 3rd cycle */
                    if (cycle % 3 == 0) {
                        State.socksLive = probeSocks();
                    }
                }
            } catch (InterruptedException ie) {
                /* service torn down */
            } finally {
                synchronized (watcherLock) { pollerAlive = false; }
            }
        }, "anon-poller");
        poller.setDaemon(true);
        poller.start();
    }

    private void onTorExit(String msg) {
        State.running = false;
        State.ready = false;
        State.socksLive = false;
        State.lastError = msg;
    }

    /** tiny direct connection attempt: SOCKS listener != bootstrap, but proves
     *  the daemon is up and accepting — surfaced separately in status(). */
    private static boolean probeSocks() {
        try {
            java.net.Socket s = new java.net.Socket();
            s.connect(new java.net.InetSocketAddress("127.0.0.1", SOCKS_PORT), 400);
            s.close();
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    private static void writeTorrc(File torDir, File hsDir, File dataDir, File logF) throws Exception {
        StringBuilder sb = new StringBuilder();
        sb.append("# Anonymous - generated at start\n");
        sb.append("RunAsDaemon 0\n");
        sb.append("SocksPort 127.0.0.1:").append(SOCKS_PORT).append("\n");
        sb.append("SocksPolicy accept 127.0.0.1:*").append("\n");
        sb.append("DataDirectory ").append(dataDir.getAbsolutePath()).append("\n");
        sb.append("HiddenServiceDir ").append(hsDir.getAbsolutePath()).append("\n");
        sb.append("HiddenServicePort ").append(HS_PORT).append(" 127.0.0.1:").append(HS_PORT).append("\n");
        sb.append("AvoidDiskWrites 1\n");
        /* FILE log, not stdout: piped stdout is block-buffered and silently ate
         * every Bootstrapped line — the 0%-stuck bug. File log flushes per line. */
        sb.append("Log notice file ").append(logF.getAbsolutePath()).append("\n");
        sb.append("Log warn file ").append(logF.getAbsolutePath()).append("\n");
        sb.append("NumEntryGuards 1\n");
        FileOutputStream fo = new FileOutputStream(new File(torDir, "torrc"));
        fo.write(sb.toString().getBytes("UTF-8"));
        fo.close();
    }

    private static String readTail(File f, int max) {
        try {
            long len = f.length();
            if (len == 0) return "";
            FileInputStream in = new FileInputStream(f);
            long skip = Math.max(0, len - max);
            in.skip(skip);
            byte[] b = new byte[(int) (len - skip)];
            int got = 0;
            while (got < b.length) {
                int n = in.read(b, got, b.length - got);
                if (n < 0) break;
                got += n;
            }
            in.close();
            return new String(b, 0, got, "UTF-8");
        } catch (Throwable t) {
            return "";
        }
    }

    private static byte[] readAll(File f) throws Exception {
        FileInputStream in = new FileInputStream(f);
        byte[] b = new byte[(int) f.length()];
        int off = 0;
        while (off < b.length) { int n = in.read(b, off, b.length - off); if (n < 0) break; off += n; }
        in.close();
        return b;
    }
}
