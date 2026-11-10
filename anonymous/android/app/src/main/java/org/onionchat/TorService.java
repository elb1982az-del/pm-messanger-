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
 * Anonymous — embedded Tor daemon (Phase 3, revision 3).
 *
 * libtor.so exec'd from nativeLibraryDir; bootstrap read from tor's own FILE
 * log (per-line flushed); SOCKS liveness probed directly.
 *
 * Revision 3 — initial directory-connection fallback chain:
 *   The first outbound handshake can stall forever when (a) the network
 *   filters 9001/9030-style egress, (b) first-choice guards hang, or (c) the
 *   device clock is skewed so dir certs are rejected. Instead of a single
 *   do-or-die attempt we now run an ESCALATION LADDER:
 *
 *     attempt 1  default torrc + 60 hard-coded fallback directory mirrors
 *                (2026 fallback_dirs.inc, /8-diverse subset) on top of the
 *                compiled-in list
 *     attempt 2  + ReachableAddresses *:443,*:80 (port-filtered networks)
 *                + ClientPreferIPv6ORPort 0 (IPv4-first on v6-less DNS)
 *     attempt 3  same as 2 + NumEntryGuards 8 (fresh guard和弦 set)
 *     after 3    surface final diagnosis instead of retry-forever
 *
 *   A no-progress window of 90 s triggers the next rung; "Clock skew" lines
 *   from tor.log are diagnosed explicitly in State.error even mid-attempt.
 *   Process stdout is still captured, but ONLY epoch-gated results overwrite
 *   shared state, so escalated restarts can't corrupt the newer rung.
 */
public class TorService extends Service {

    public static final int HS_PORT = 9878;
    public static final int SOCKS_PORT = 9050;
    private static final int MAX_ATTEMPTS = 3;
    private static final long STALL_MS = 90000;          // no bootstrap movement → next rung

    /* Shared-state keys readable from the native plugin bridges. */
    public static final String EXEC_VIA_KEY = "execVia";

    public static final class State {
        public static volatile boolean running = false;
        public static volatile boolean ready = false;
        public static volatile int bootstrapped = 0;
        public static volatile String onion = null;
        public static volatile String lastError = "";
        public static volatile boolean socksLive = false;
        public static volatile String streamTail = "";
        public static volatile String execVia = "";
        public static volatile boolean clockSkew = false;
        /* lifecycle stage: set on every meaningful step so a silent death is
         * visible from the chip (start-request → asset-extract → chmod →
         * exec-probe → spawned → bootstrapping …). "start-requested" is set by
         * TorBridge.startTor BEFORE the service intent is even fired. */
        public static volatile String stage = "idle";
        public static volatile String torLogPath = "";   // absolute path of the live tor file log (set by spawnTor)
        public static volatile int attempt = 0;
        public static volatile int epoch = 0;
        public static volatile long attemptStartAt = 0L;
        public static volatile int maxSeen = 0;
        public static volatile long lastMoveAt = 0L;
        public static final StringBuilder logTail = new StringBuilder();
        public static final Object inboxLock = new Object();
        public static final java.util.ArrayDeque<String> inbox = new java.util.ArrayDeque<>();
    }

    private static Process torProc = null;
    private static final Object watcherLock = new Object();
    private static volatile boolean pollerAlive = false;
    private static volatile boolean ladderExhausted = false;

    private static final String FALLBACK_DIRS =
        "FallbackDir 136.243.177.133:9030 orport=9001 id=E86D858F2AAF9DE2A2B952A0BF864B7F35EDC8A3" + "\n" +
        "FallbackDir 46.59.46.23:9030 orport=9001 id=404CFFCA9CC29DF6562A5BCF2B6C72EDE1CE5B89" + "\n" +
        "FallbackDir 64.135.129.118:9030 orport=9001 id=E5F3EDD927148C5EB4D7CB71DCBC91382F57A7A7" + "\n" +
        "FallbackDir 84.234.19.76:9030 orport=9001 id=69B632F8B2BD3B59B3849C8072DB097A53A2D71A" + "\n" +
        "FallbackDir 94.16.106.22:9030 orport=443 id=1E976C08F940A9A78F93EC824783C1CDCD681AA7" + "\n" +
        "FallbackDir 147.135.129.138:9030 orport=9600 id=3E1EAC5527F50D9C8E8ACFD323D2629968A06BC1" + "\n" +
        "FallbackDir 37.46.199.86:9030 orport=4500 id=889EDCB19B237F20ADB525960C39E0B00398D6B1" + "\n" +
        "FallbackDir 107.173.164.60:9030 orport=443 id=6DA9B90E374AC7A350EB1D20474BAF5649F58303" + "\n" +
        "FallbackDir 140.122.185.230:9030 orport=9001 id=0B6827FEDC0FBB431B3617BBAA4C4B2372724D24" + "\n" +
        "FallbackDir 141.14.220.177:9030 orport=443 id=8CCED391D2E1B6ED1E78769FBDCFB70E5C91849D" + "\n" +
        "FallbackDir 96.9.98.129:9030 orport=443 id=B7E064587981FF8E3103EB1B96D335757F88549D" + "\n" +
        "FallbackDir 138.201.85.243:9030 orport=9080 id=062F5A38DED9F6899542530585D314A9660D7B41" + "\n" +
        "FallbackDir 86.94.237.139:9030 orport=11111 id=73853239A723BC147D9A251AFC8BD0A102CB75A4" + "\n" +
        "FallbackDir 185.243.218.233:9030 orport=13443 id=D342A468F1AFA93C9BD96D7ECDB5054F95662BE3" + "\n" +
        "FallbackDir 95.17.80.54:9030 orport=9006 id=710E61F0DE08051E38D8B1130D5657DD476E3222" + "\n" +
        "FallbackDir 89.58.17.228:9030 orport=46856 id=593A4431DA2E315883406AECE1D1188E02F23D8F" + "\n" +
        "FallbackDir 152.53.16.13:9030 orport=9001 id=174951D5335093FAA93F17A30D228B604F39AFC7" + "\n" +
        "FallbackDir 151.242.242.140:9030 orport=1945 id=6F89DF1ED6EC988F3C4C265C97D9860B2F5A3727" + "\n" +
        "FallbackDir 121.121.172.62:9030 orport=9001 id=E8F8295A3BBA9AA09A54134886916F1251247EDC" + "\n" +
        "FallbackDir 82.197.182.161:9030 orport=9001 id=61137FAC08E0AE62165D18FE8855CCCA26B6D631" + "\n" +
        "FallbackDir 79.117.25.8:9030 orport=8080 id=06A9826D82330E0D129E9EBB05936F908D698B76" + "\n" +
        "FallbackDir 45.66.35.35:9030 orport=1984 id=AA346E9FA38E9B83A044B61853B8A2CDB461D5AA" + "\n" +
        "FallbackDir 155.138.175.182:9030 orport=9001 id=8F974618611C2871522F086984B1A9CE1FD78197" + "\n" +
        "FallbackDir 65.108.72.156:9030 orport=465 id=15291291D81E404FB6BEC16D366608590D2B0247" + "\n" +
        "FallbackDir 5.230.76.193:9030 orport=9001 id=A4A6AB9EFC2427217DFFFFFD84C49E85336C3653" + "\n" +
        "FallbackDir 80.108.222.2:9030 orport=9001 id=F4C21445DBCB1B412248CA6AF18277E1F81486BC" + "\n" +
        "FallbackDir 77.160.53.97:9030 orport=9001 id=3CEA56B817455E13C4B063E7D3E7726C286F7C9B" + "\n" +
        "FallbackDir 190.120.229.98:9030 orport=443 id=3816B2B2F6E23AEAF8EF7070476F6AB6B96AAF8B" + "\n" +
        "FallbackDir 91.219.237.216:9030 orport=443 id=A2E327922875FF477B982200D30759B9A223BA3C" + "\n" +
        "FallbackDir 192.42.116.148:9030 orport=443 id=F1C7CF43C9CAA3CD2191E4303362B281B84D201C" + "\n" +
        "FallbackDir 31.14.96.18:9030 orport=443 id=6584688F1A0132BF1AB79E91EDF6F9602C7336C1" + "\n" +
        "FallbackDir 213.130.153.80:9030 orport=443 id=4C59B5141083044169D2B558C8970E390F817F2A" + "\n" +
        "FallbackDir 173.183.127.221:9030 orport=13325 id=2EF9902D8B8ACABE1326AD7C915684A1A76B8F3D" + "\n" +
        "FallbackDir 203.55.81.2:9030 orport=19005 id=98697EF93E26DD52CD96D3F998BF20B2A4162291" + "\n" +
        "FallbackDir 144.91.113.194:9030 orport=443 id=42BE2230702F3C276FD7BC9B52AB83708A6C7F5F" + "\n" +
        "FallbackDir 146.0.36.87:9030 orport=9003 id=83F02FD5FEA0B87A6FB18EEC52E3006766E1E92E" + "\n" +
        "FallbackDir 81.140.243.248:9030 orport=9001 id=34E6510BD69E89A69C82E7C065A6A062FFFA46A4" + "\n" +
        "FallbackDir 212.237.217.108:9030 orport=9001 id=28655D3058B0BAE840B0DB48DC078C1F773D1291" + "\n" +
        "FallbackDir 218.102.116.3:9030 orport=9001 id=CBAE85049E847CD5E197AAE539347F449DA2458D" + "\n" +
        "FallbackDir 51.195.201.37:9030 orport=9001 id=D953E6FE69DBC6DE3D1F8319BA7934A52D378608" + "\n" +
        "FallbackDir 134.199.203.40:9030 orport=9001 id=EC8E616CBFE5B9B36BED622A2D26C67485BCE0F2" + "\n" +
        "FallbackDir 217.85.173.241:9030 orport=9002 id=B34836F2027C14E4040478768986BFEA827B4628" + "\n" +
        "FallbackDir 194.164.169.85:9030 orport=443 id=8ADBF02AE4E17281D1B0CDE8DF9B13C575B581C5" + "\n" +
        "FallbackDir 157.131.42.46:9030 orport=9100 id=C1A16FF7A90B8E54149EF6143E92B115828FFCB3" + "\n" +
        "FallbackDir 74.215.157.209:9030 orport=9007 id=B3C24938490D7D7552648B920C49EC97BB1B244E" + "\n" +
        "FallbackDir 23.126.9.217:9030 orport=9001 id=630C50D3449206B7F2A536098BB2A9C7B4326AD9" + "\n" +
        "FallbackDir 193.235.207.216:9030 orport=9001 id=6104464F24A1AC0ED54773DB23FC6B37614F7233" + "\n" +
        "FallbackDir 8.5.2.30:9030 orport=8001 id=A24F11F300D397537617F00DC5BD29244B586B4D" + "\n" +
        "FallbackDir 162.19.245.108:9030 orport=9300 id=E33B5C653529AF909D2FA8569F662E432380D292" + "\n" +
        "FallbackDir 87.106.218.58:9030 orport=9001 id=D995FBCE853DF2A616C5897A264AA7989C9840E8" + "\n" +
        "FallbackDir 206.189.237.73:9030 orport=9001 id=CFFC204BEA064B0AA60FC9942891689D048316BC" + "\n" +
        "FallbackDir 188.119.123.165:9030 orport=9001 id=566C5E5F648F30E139C6C11439CBD8B84B864FB8" + "\n" +
        "FallbackDir 135.148.27.19:9030 orport=80 id=01F6015DB6C684651047FAA36465BEB3AE335CAD" + "\n" +
        "FallbackDir 93.174.85.152:9030 orport=443 id=16D0620AB08A091C93BA448769477E4C109FF570" + "\n" +
        "FallbackDir 116.255.1.163:9030 orport=9003 id=2BF235BA52D008701937C31583C4E5C2194E1628" + "\n" +
        "FallbackDir 62.210.222.112:9030 orport=443 id=1676D60967175C1A2D1104920C30231C24AE4E5E" + "\n" +
        "FallbackDir 129.153.176.17:9030 orport=9001 id=DF8D5C8BA8CBA68D86CC0B3A58010E0C2A5EFAB4" + "\n" +
        "FallbackDir 176.126.86.154:9030 orport=7654 id=75B7DF80373153133F869754528DF4F84F11E2C4" + "\n" +
        "FallbackDir 184.8.85.200:9030 orport=9001 id=2E076B0DC0BD738098C9AA6607687DCE11473CD0" + "\n" +
        "FallbackDir 150.40.126.134:9030 orport=443 id=B4F3EA150822E0C49DA49E6C4A0FDED2CB8A4540";

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
        try {
            /* control plane for the UI (0.3.7): /status /start /send /poll on
             * 127.0.0.1:9878 — the webview can reach this port with plain
             * fetch(), no Capacitor bridge needed. */
            TorBridge.startHttpListener(getApplicationContext());
            if (torProc == null || !isAlive(torProc)) {
                ladderExhausted = false;
                spawnTor();
            }
        } catch (Throwable t) {
            /* visible instead of killing the whole process */
            State.running = false;
            State.stage = "onStartCommand-crashed";
            State.lastError = "onStartCommand: " + t
                    + (t.getCause() != null ? " (" + t.getCause() + ")" : "");
        }
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        if (torProc != null) { try { torProc.destroy(); } catch (Throwable ignored) {} torProc = null; }
        State.running = false;
        State.ready = false;
        State.socksLive = false;
        synchronized (watcherLock) { pollerAlive = false; }
        super.onDestroy();
    }

    private static boolean isAlive(Process p) {
        try { p.exitValue(); return false; } catch (IllegalThreadStateException e) { return true; }
    }

    private void spawnTor() {
        State.stage = "spawn-entered";
        if (ladderExhausted) { State.stage = "ladder-exhausted"; return; }

        final File torDir = new File(getFilesDir(), "tor");
        final File binDir = new File(torDir, "bin");
        final File hsDir = new File(torDir, "hidden_service");
        final File dataDir = new File(torDir, "data");
        final File logF = new File(torDir, "tor.log");
        State.torLogPath = logF.getAbsolutePath();
        hsDir.mkdirs();
        dataDir.mkdirs();
        binDir.mkdirs();

        /* ---- rung 0: find an EXECUTABLE form of the daemon ----
         * Explicit dx/benissa-style extraction (user-directed): copy the binary
         * INTO the app's private data dir (getFilesDir()), chmod 700 explicitly
         * (Runtime + File API both attempted), then exec that copy primary.
         * Android 10+ stock W^X blocks filesDir exec for targetSdk>=29, so the
         * vendored nativeLibraryDir copy remains as the second candidate. */
        final File nativeLib = new File(getApplicationInfo().nativeLibraryDir, "libtor.so");
        final File privBin = new File(binDir, "libtor.so");

        File assetSrc = null;
        State.stage = "asset-lookup";
        try {
            String assetName = null;
            for (String abi : Build.SUPPORTED_ABIS) {
                if (abi.startsWith("arm64")) { assetName = "tor/libtor.arm64.so"; break; }
                if (abi.startsWith("armeabi")) { assetName = "tor/libtor.armv7.so"; break; }
                if (abi.startsWith("x86_64")) { assetName = "tor/libtor.x64.so"; break; }
                if (abi.startsWith("x86")) { assetName = "tor/libtor.x86.so"; break; }
            }
            if (assetName != null) {
                java.io.InputStream ais = getAssets().open(assetName);
                assetSrc = new File(torDir, "asset-src.so");
                FileOutputStream fos = new FileOutputStream(assetSrc);
                byte[] buf = new byte[1 << 16];
                int rn;
                while ((rn = ais.read(buf)) > 0) fos.write(buf, 0, rn);
                fos.close(); ais.close();
            }
        } catch (Throwable ignored) { assetSrc = null; }

        /* pick the executable source: prefer packaged asset, else nativeLibraryDir copy */
        final File copySrc = (assetSrc != null && assetSrc.length() > 0) ? assetSrc : nativeLib;
        String lastExecDenial = "";
        String execPath = null;

        /* candidate 1 (primary): private-dir copy + explicit chmod 700 */
        State.stage = "copying-into-filesDir";
        try {
            boolean needCopy = !privBin.exists() || privBin.length() != copySrc.length();
            if (needCopy) {
                FileInputStream fin = new FileInputStream(copySrc);
                FileOutputStream fout = new FileOutputStream(privBin);
                byte[] buf = new byte[1 << 16];
                int n;
                while ((n = fin.read(buf)) > 0) fout.write(buf, 0, n);
                fout.close(); fin.close();
            }
            /* exec bit: File API first, then explicit chmod via Runtime shell */
            State.stage = "chmod-700";
            privBin.setReadable(true, false);
            privBin.setWritable(true, false);
            boolean viaApi = privBin.setExecutable(true, false);
            boolean viaChmod = false;
            Process chmod = null;
            try {
                chmod = Runtime.getRuntime().exec(new String[]{"chmod", "700", privBin.getAbsolutePath()});
                int rc = 0; try { rc = chmod.waitFor(); } catch (InterruptedException ie) {}
                viaChmod = (rc == 0);
            } catch (Throwable ignoredT) {}
            String why = "copy:filesDir(chmod" + (viaChmod ? "700-ok" : (viaApi ? "api" : "FAILED")) + ")";
            try {
                Process probe = new ProcessBuilder(privBin.getAbsolutePath(), "-f", "/dev/null").start();
                try { probe.destroy(); } catch (Throwable ignoredP) {}
                execPath = privBin.getAbsolutePath();
                State.execVia = why;
            } catch (Throwable probeT) {
                lastExecDenial = "filesDir exec denied even after chmod: " + probeT + (probeT.getCause() != null ? " (" + probeT.getCause() + ")" : "");
            }
        } catch (Throwable tc) {
            lastExecDenial = "filesDir copy/chmod failed: " + tc;
        }

        /* candidate 2: vendored nativeLibraryDir copy (exec-legal by packaging) */
        if (execPath == null) State.stage = "trying-nativeLibraryDir";
        if (execPath == null && nativeLib.exists() && nativeLib.canRead()) {
            try {
                Process probe = new ProcessBuilder(nativeLib.getAbsolutePath(), "-f", "/dev/null").start();
                try { probe.destroy(); } catch (Throwable ignoredP) {}
                execPath = nativeLib.getAbsolutePath();
                State.execVia = "vendored:nativeLibraryDir";
            } catch (Throwable t) {
                lastExecDenial += " | nativeLibraryDir exec denied: " + t;
            }
        }
        if (assetSrc != null) { try { assetSrc.delete(); } catch (Throwable ignored) {} }

        if (execPath == null) {
            State.running = false;
            State.stage = "exec-blocked";
            State.lastError = "EXEC BLOCKED — filesDir (chmod 700) AND nativeLibraryDir both denied." +
                    " On stock Android 10+ the filesDir path needs permissive SELinux (Magisk: setenforce 0 or a magiskpolicy exec rule)." +
                    " " + lastExecDenial;
            return;
        }

        State.attempt++;
        State.epoch++;
        State.maxSeen = 0;
        State.bootstrapped = 0;
        State.ready = false;
        State.socksLive = false;
        State.lastError = "";
        State.attemptStartAt = System.currentTimeMillis();
        State.lastMoveAt = State.attemptStartAt;

        final int myEpoch = State.epoch;
        final int myAttempt = State.attempt;

        try { if (logF.exists()) logF.delete(); } catch (Throwable ignored) {}
        State.stage = "writing-torrc";
        try { writeTorrc(torDir, hsDir, dataDir, logF, myAttempt); }
        catch (Throwable t) { State.running = false; State.lastError = "torrc write failed: " + t; return; }

        final String torrcPath = new File(torDir, "torrc").getAbsolutePath();
        final String torBinPath = execPath;

        State.running = true;
        State.stage = "tor-spawned:" + (execPath.startsWith(getFilesDir().getAbsolutePath()) ? "files-dir" : "native-lib-dir");
        synchronized (State.logTail) { State.logTail.setLength(0); }

        final TorService self = this;

        /* process thread — epoch-gated: stale threads (killed rung) never overwrite
         * the state of a newer attempt */
        final Thread proc = new Thread(() -> {
            int code = -1;
            String exitWhy = null;
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
                code = p.waitFor();
                exitWhy = "tor exited (code " + code + ")";
            } catch (Throwable t) {
                String why = String.valueOf(t);
                Throwable inner = t.getCause();
                if (inner != null) why += " (" + inner + ")";
                exitWhy = "tor spawn failed: " + why;
            }
            if (State.epoch == myEpoch) {
                State.running = false;
                State.ready = false;
                State.socksLive = false;
                State.lastError = exitWhy;
            }
        }, "anon-process-" + myAttempt);
        proc.start();

        /* single poller: log parsing + stall ladder + hostname + socks probe */
        synchronized (watcherLock) {
            if (pollerAlive) return;
            pollerAlive = true;
        }
        final Thread poller = new Thread(() -> {
            int cycle = 0;
            try {
                while (!ladderExhausted) {
                    if (!State.running && State.attempt >= MAX_ATTEMPTS) { ladderExhausted = true; finalDiagnosis(); return; }
                    Thread.sleep(1000);
                    cycle++;

                    /* bootstrap % + error + clock-skew from the file log */
                    String tail = readTail(logF, 16000);
                    if (tail != null && tail.length() > 0) {
                        synchronized (State.logTail) {
                            String t2 = tail.length() > 1400 ? tail.substring(tail.length() - 1400) : tail;
                            State.logTail.setLength(0);
                            State.logTail.append(t2);
                        }
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
                        if (tail.indexOf("Clock skew", 0) >= 0 || tail.indexOf("clock is set", 0) >= 0) {
                            State.clockSkew = true;
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

                    /* progress tracking for the stall ladder */
                    if (State.bootstrapped > State.maxSeen) {
                        State.maxSeen = State.bootstrapped;
                        State.lastMoveAt = System.currentTimeMillis();
                    }
                    if (State.ready) continue;

                    /* hostname */
                    File hostname = new File(hsDir, "hostname");
                    if (!hostname.exists() || hostname.length() == 0) {
                        /* maybe still publishing */
                    } else {
                        String s = readAll(hostname).trim();
                        if (s.endsWith(".onion")) State.onion = s;
                    }

                    /* socks probe every 3rd cycle */
                    if (cycle % 3 == 0) State.socksLive = probeSocks();

                    /* escalation ladder */
                    long now = System.currentTimeMillis();
                    boolean stalled = now - State.lastMoveAt > STALL_MS;
                    if (stalled && self.canEscalate()) self.escalate();

                    /* final rung ran dry */
                    if (State.attempt >= MAX_ATTEMPTS && State.maxSeen < 100 && now - State.lastMoveAt > STALL_MS) {
                        ladderExhausted = true;
                        finalDiagnosis();
                        return;
                    }
                }
            } catch (InterruptedException ie) { /* teardown */
            } finally {
                synchronized (watcherLock) { pollerAlive = false; }
            }
        }, "anon-poller");
        poller.setDaemon(true);
        poller.start();
    }

    private static void finalDiagnosis() {
        StringBuilder d = new StringBuilder("bootstrap stalled across " + MAX_ATTEMPTS + " attempts (max " + State.maxSeen + "%)");
        if (State.clockSkew) d.append(" | CLOCK SKEW detected — set the device date/time correctly (WiFi vs local cellular clock drift), then restart tor");
        else if (State.maxSeen == 0) d.append(" | first dir handshake never completes — network likely filters tor egress (try restart tor, or another network on the phone)");
        State.lastError = d.toString();
        State.running = false;
        State.ready = false;
    }

    /* --- escalation hooks: kill current rung, re-spawn on the next rung --- */
    private boolean canEscalate() {
        return State.attempt < MAX_ATTEMPTS && State.maxSeen < 100;
    }

    private void escalate() {
        /* kill the stalled rung; epoch bump makes its reporting thread inert */
        Process p;
        synchronized (TorService.class) { p = torProc; }
        if (p != null) {
            try { p.destroy(); } catch (Throwable ignored) {}
        }
        try { Thread.sleep(700); } catch (InterruptedException ie) { return; }
        spawnTor();
    }

    /** tiny direct liveness probe on the SOCKS listener */
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

    private void writeTorrc(File torDir, File hsDir, File dataDir, File logF, int attempt) throws Exception {
        StringBuilder sb = new StringBuilder();
        sb.append("# Anonymous - attempt ").append(attempt).append("/").append(MAX_ATTEMPTS).append('\n');
        sb.append("RunAsDaemon 0\n");
        sb.append("SocksPort 127.0.0.1:").append(SOCKS_PORT).append("\n");
        /* explicit loopback-only SOCKS policy (user-directed, 0.3.11):
         * accept the two loopback families, reject everything else. Even though
         * SocksPort bound to 127.0.0.1 holds this invariant, stating it removes
         * any doubt and survives future SocksPort-form changes. */
        sb.append("SocksPolicy accept 127.0.0.1/8\n");
        sb.append("SocksPolicy accept ::1/128\n");
        sb.append("SocksPolicy reject *\n");
        sb.append("SocksPolicy accept 127.0.0.1:*").append("\n");
        sb.append("DataDirectory ").append(dataDir.getAbsolutePath()).append("\n");
        sb.append("HiddenServiceDir ").append(hsDir.getAbsolutePath()).append("\n");
        sb.append("HiddenServicePort ").append(HS_PORT).append(" 127.0.0.1:").append(HS_PORT).append("\n");
        sb.append("AvoidDiskWrites 1\n");
        sb.append("Log notice file ").append(logF.getAbsolutePath()).append("\n");
        sb.append("Log warn file ").append(logF.getAbsolutePath()).append("\n");
        sb.append("NumEntryGuards ").append(attempt >= 3 ? 8 : 1).append("\n");
        if (attempt >= 2) {
            sb.append("# rung-2+: egress-restricted networks reach the tor network via 80/443\n");
            sb.append("ReachableAddresses *:443,*:80\n");
            sb.append("ReachableAddresses *:9001\n");
            sb.append("ReachableAddresses *:9030\n");
            sb.append("ClientPreferIPv6ORPort 0\n");
        } else {
            sb.append("# rung-1: full egress, compiled-in fallback list\n");
        }
        /* pluggable transport (same dx-style vendoring): tor spawns this itself
         * from nativeLibraryDir — exec-legal like libtor.so. Bridge lines plug
         * in later (Phase 4); the plugin line is inert without UseBridges. */
        final File obfs4Bin = new File(getApplicationInfo().nativeLibraryDir, "libobfs4proxy.so");
        if (attempt >= 2 && obfs4Bin.exists() && obfs4Bin.canRead()) {
            sb.append("ClientTransportPlugin obfs4 exec ").append(obfs4Bin.getAbsolutePath()).append("\n");
        }
        /* hard-coded 2026 fallback directory mirrors — "/8-diverse subset" of
         * the official fallback_dirs.inc (dirport 9030 on each). Tried BEFORE
         * the compiled-in list, giving directory connectivity fresh peers even
         * when specific well-known IPs are filtered or stale. */
        sb.append("\n# fallback dir mirrors (subset of official fallback_dirs.inc)\n");
        sb.append(FALLBACK_DIRS);
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

    private static String readAll(File f) {
        try {
            FileInputStream in = new FileInputStream(f);
            byte[] b = new byte[(int) f.length()];
            int off = 0;
            while (off < b.length) { int n = in.read(b, off, b.length - off); if (n < 0) break; off += n; }
            in.close();
            return new String(b, 0, off, "UTF-8");
        } catch (Throwable t) {
            return "";
        }
    }
}
