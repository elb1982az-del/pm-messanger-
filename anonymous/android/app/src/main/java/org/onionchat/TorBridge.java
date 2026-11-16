package org.onionchat;

import android.content.Context;
import android.content.Intent;
import android.os.Build;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Locale;

/**
 * Anonymous — JS↔native Tor bridge (Phase 3).
 *
 *   startTor()    → boot the TorService foreground daemon
 *   status()      → { running, ready, bootstrapped, onion }
 *   sendMessage() → one SOCKS5 CONNECT through 127.0.0.1:9050 to
 *                   <peer>.onion:9878, HTTP POST /p with the wire token body
 *   pollInbox()   → drain the hidden-service inbox (tokens delivered to our
 *                   local HTTP listener on 127.0.0.1:9878)
 */
@CapacitorPlugin(name = "TorBridge")
public class TorBridge extends Plugin {

    private static final int SOCKS_PORT = 9050;
    private static final int HTTP_PORT = 9878;
    private static final int MAX_PAYLOAD = 4 * 1024 * 1024;   // hard cap per POST
    private static final int MAX_INBOX = 256;
    private static volatile boolean listenerStarted = false; /* legacy flag, superseded by listenerThread (0.3.18) */

    /**
     * Explicit daemon trigger, callable from ANY layer (Application, Activity)
     * without going through the JS bridge. Sets State.stage so the chip shows
     * the request happened even if the service never comes up.
     */
    public static void kickStart(Context c) {
        try {
            TorService.State.stage = "start-requested";
            Intent i = new Intent(c, TorService.class);
            if (Build.VERSION.SDK_INT >= 26) c.startForegroundService(i); else c.startService(i);
        } catch (Throwable t) {
            TorService.State.stage = "start-denied";
            if (t instanceof android.app.ForegroundServiceStartNotAllowedException
                    || (t.getCause() != null && t.getCause() instanceof android.app.ForegroundServiceStartNotAllowedException)) {
                TorService.State.lastError = "startTor denied (FGS start not allowed from this state): " + t;
            } else {
                TorService.State.lastError = "startTor failed: " + t;
            }
        }
    }

    @PluginMethod
    public void startTor(PluginCall call) {
        try {
            kickStart(getContext());
        } catch (Throwable t) {
            TorService.State.stage = "start-denied";
            TorService.State.lastError = "startTor failed: " + t;
        }
        try { startHttpListener(getContext()); } catch (Throwable t) {
            TorService.State.lastError += (TorService.State.lastError.isEmpty() ? "" : " | ")
                    + "http listener: " + t;
        }
        call.resolve();
    }

    @PluginMethod
    public void status(PluginCall call) {
        JSObject r = new JSObject();
        r.put("running", TorService.State.running);
        r.put("ready", TorService.State.ready);
        r.put("bootstrapped", TorService.State.bootstrapped);
        r.put("onion", TorService.State.onion == null ? "" : TorService.State.onion);
        r.put("socks", TorService.State.socksLive);
        r.put("error", TorService.State.lastError == null ? "" : TorService.State.lastError);
        r.put("execVia", TorService.State.execVia == null ? "" : TorService.State.execVia);
        r.put("stage", TorService.State.stage == null ? "" : TorService.State.stage);
        r.put("attempt", TorService.State.attempt);
        r.put("clockSkew", TorService.State.clockSkew);
        r.put("info", TorService.State.infoTail);
        r.put("listener", TorService.State.listenerStatus);
        r.put("hs", TorService.State.hsPublished);
        String log;
        synchronized (TorService.State.logTail) { log = TorService.State.logTail.toString(); }
        if (TorService.State.streamTail != null && TorService.State.streamTail.length() > 0)
            log = TorService.State.streamTail + "\n---\n" + log;
        if (log.length() > 1400) log = log.substring(log.length() - 1400);
        r.put("log", log);
        call.resolve(r);
    }

    @PluginMethod
    public void sendMessage(final PluginCall call) {
        final String onion = call.getString("onion", "");
        final String payload = call.getString("payload", "");
        final JSObject r = new JSObject();
        if (onion == null || !onion.endsWith(".onion") || payload.length() == 0 || payload.length() > MAX_PAYLOAD) {
            r.put("sent", false);
            r.put("error", "bad onion or payload inside 4MB cap");
            call.resolve(r);
            return;
        }
        new Thread(() -> {
            String err = "";
            boolean sent = false;
            try {
                sent = socksPost(onion, payload);
            } catch (Throwable t) {
                err = String.valueOf(t);
            }
            r.put("sent", sent);
            if (!err.isEmpty()) r.put("error", err);
            call.resolve(r);
        }, "anon-send").start();
    }

    @PluginMethod
    public void pollInbox(PluginCall call) {
        ArrayList<String> out = new ArrayList<>();
        synchronized (TorService.State.inboxLock) {
            String item;
            while ((item = TorService.State.inbox.pollLast()) != null) out.add(item);
        }
        JSObject r = new JSObject();
        r.put("inbox", out);
        call.resolve(r);
    }

    /* ---------------- SOCKS5 CONNECT + HTTP POST ---------------- */

    private static boolean socksPost(String onion, String payload) throws Exception {
        Socket s = new Socket();
        try {
            try {
                s.connect(new InetSocketAddress("127.0.0.1", SOCKS_PORT), 8000);
            } catch (Exception ce) {
                /* surface the errno AND tor's own verdict on the 9050 bind so a
                 * failed loopback tells us exactly which side refused */
                throw new Exception("SOCKS connect to 127.0.0.1:" + SOCKS_PORT + " failed: " + ce
                        + (ce.getCause() != null ? " → " + ce.getCause() : "")
                        + (torBindVerdict().isEmpty() ? "" : " | tor.log: " + torBindVerdict()));
            }
            s.setSoTimeout(180000);          // tor circuts can take tens of seconds
            OutputStream os = s.getOutputStream();
            InputStream is = s.getInputStream();

            /* hello: methods=[no-auth] */
            os.write(new byte[]{5, 1, 0});
            os.flush();
            byte[] hello = readFully(is, 2);
            if (hello[0] != 5 || hello[1] != 0) throw new Exception("socks hello refused");

            byte[] host = onion.getBytes(StandardCharsets.US_ASCII);
            ByteArrayOutputStream req = new ByteArrayOutputStream();
            req.write(5); req.write(1); req.write(0);
            req.write(3);                    // atyp = domain (onion)
            req.write(host.length);
            req.write(host);
            req.write((TorService.HS_PORT >> 8) & 0xff);
            req.write(TorService.HS_PORT & 0xff);
            os.write(req.toByteArray());
            os.flush();

            /* reply head: ver, rep, rsv, atyp */
            byte[] head = readFully(is, 4);
            if (head[1] != 0) {
                int rep = head[1] & 0xff;
                String rn = rep == 1 ? " general failure (circuit/rendezvous failed)"
                        : rep == 2 ? " not allowed"
                        : rep == 3 ? " network unreachable"
                        : rep == 4 ? " host unreachable"
                        : rep == 5 ? " connection refused"
                        : rep == 6 ? " TTL expired"
                        : rep == 7 ? " command not supported"
                        : rep == 8 ? " address type not supported" : "";
                throw new Exception("socks connect failed (rep " + rep + rn + ")"
                        + " | local 9878: " + localListenerLiveness()
                        + " | rung: " + TorService.State.attempt
                        + (hsLogVerdict().isEmpty() ? "" : " | HS log: " + hsLogVerdict()));
            }
            int atyp = head[3] & 0xff;
            int addrLen = (atyp == 1) ? 4 : (atyp == 3) ? (readFully(is, 1)[0] & 0xff) : 16;
            readFully(is, addrLen + 2);      // addr + port, discarded

            StringBuilder http = new StringBuilder();
            http.append("POST /p HTTP/1.1\r\n");
            http.append("Host: ").append(onion).append("\r\n");
            http.append("Content-Type: text/plain\r\n");
            http.append("Content-Length: ").append(payload.length()).append("\r\n");
            http.append("Connection: close\r\n\r\n");
            os.write(http.toString().getBytes(StandardCharsets.US_ASCII));
            os.write(payload.getBytes(StandardCharsets.UTF_8));
            os.flush();

            BufferedReader br = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8));
            String line = br.readLine();
            return line != null && line.contains(" 200 ");
        } finally {
            try { s.close(); } catch (Throwable ignored) {}
        }
    }

    /* Pull tor's own verdict on the SOCKS bind from its file log: does the log
     * show 9050 opened, or a bind failure (occupied address, etc.)? */
    private static String torBindVerdict() {
        try {
            String path = TorService.State.torLogPath;
            if (path == null || path.isEmpty()) return "";
            File logF = new File(path);
            if (!logF.exists()) return "";
            java.io.BufferedReader r = new java.io.BufferedReader(new java.io.InputStreamReader(new FileInputStream(logF), StandardCharsets.UTF_8));
            ArrayList<String> hits = new ArrayList<>();
            String line;
            while ((line = r.readLine()) != null) {
                if (line.indexOf("SocksPort") >= 0 || line.indexOf("Failed to bind") >= 0
                        || line.indexOf("Address already in use") >= 0 || line.indexOf("Opening Socks") >= 0
                        || line.indexOf("Failed to open") >= 0) {
                    hits.add(line.trim());
                    if (hits.size() > 4) hits.remove(0);
                }
            }
            r.close();
            if (hits.isEmpty()) return "";
            StringBuilder sb = new StringBuilder();
            for (String h : hits) sb.append(h).append(" ;; ");
            String out = sb.toString();
            if (out.length() > 320) out = out.substring(out.length() - 320);
            return out;
        } catch (Throwable ignored) { return ""; }
    }

    /* Hidden-service side verdicts for rep-1 diagnosis:
     *  - localListenerLiveness(): is our local 9878 target actually accepting?
     *  - hsLogVerdict(): latest hidden-service lifecycle lines from tor.log. */
    private static String localListenerLiveness() {
        Socket p = new Socket();
        try {
            p.connect(new InetSocketAddress("127.0.0.1", HTTP_PORT), 800);
            p.close();
            return "listening";
        } catch (Throwable t) {
            try { p.close(); } catch (Throwable ignored) {}
            return "DOWN (" + t + ")";
        }
    }

    private static String hsLogVerdict() {
        try {
            String path = TorService.State.torLogPath;
            if (path == null || path.isEmpty()) return "";
            File logF = new File(path);
            if (!logF.exists()) return "";
            java.io.BufferedReader r = new java.io.BufferedReader(new java.io.InputStreamReader(new FileInputStream(logF), StandardCharsets.UTF_8));
            ArrayList<String> hits = new ArrayList<>();
            String line;
            while ((line = r.readLine()) != null) {
                String low = line.toLowerCase(Locale.US);
                if (low.indexOf("hidden service") >= 0 || low.indexOf("descriptor") >= 0
                        || low.indexOf("intro") >= 0 || low.indexOf("rend") >= 0
                        || low.indexOf("onion") >= 0) {
                    hits.add(line.trim());
                    if (hits.size() > 4) hits.remove(0);
                }
            }
            r.close();
            if (hits.isEmpty()) return "";
            StringBuilder sb = new StringBuilder();
            for (String h : hits) sb.append(h).append(" ;; ");
            String out = sb.toString();
            if (out.length() > 320) out = out.substring(out.length() - 320);
            return out;
        } catch (Throwable ignored) { return ""; }
    }

    private static byte[] readFully(InputStream is, int n) throws Exception {
        byte[] out = new byte[n];
        int off = 0;
        while (off < n) {
            int got = is.read(out, off, n - off);
            if (got < 0) throw new Exception("socks stream closed early");
            off += got;
        }
        return out;
    }

    /* ---------------- local inbox HTTP listener ---------------- */

    /* Control plane owner. (package-private: TorService also starts it) */
    /** Liveness probe on the local 9878 listener (0.3.17): the started-flag
     * alone can lie when the thread dies without hitting the fatal catch,
     * which left the hidden service with nowhere to forward inbound
     * connections (ECONNREFUSED → socks rep 1 on every loopback). */
    static boolean localListenerLive() {
        try {
            java.net.Socket p = new java.net.Socket();
            p.connect(new InetSocketAddress("127.0.0.1", HTTP_PORT), 400);
            p.close();
            return true;
        } catch (Throwable t) {
            try { p.close(); } catch (Throwable ignored) {}
            return false;
        }
    }

    static void startHttpListener(Context ctx) {
        /* single-owner + liveness-aware guard (0.3.18): if a listener thread
         * is alive we NEVER spawn a second one — a live thread either accepts
         * (probe up) or is inside its bind-retry loop (probe down but will
         * bind the moment the port frees). */
        synchronized (listenerLock) {
            if (listenerThread != null && listenerThread.isAlive()) return;
            final Context appCtx = (ctx instanceof android.content.Context) ? ctx.getApplicationContext() : null;
            final Thread t = new Thread(() -> {
                ServerSocket srv = null;
                try {
                    /* bind-retry loop (0.3.18): device evidence showed
                     * EADDRINUSE while the port refused connects — some
                     * holder keeps a binding without listening. Retry every
                     * 2 s forever; the moment it frees, we own 9878. The
                     * holder's identity (uid + state from /proc) is recorded
                     * for the modal on every failed attempt. */
                    while (true) {
                        try {
                            srv = new ServerSocket();
                            srv.setReuseAddress(true);
                            srv.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), HTTP_PORT), 128);
                            TorService.State.listenerStatus = "up:9878";
                            break;
                        } catch (Throwable bex) {
                            try { if (srv != null) srv.close(); } catch (Throwable ignored) {}
                            srv = null;
                            TorService.State.listenerStatus = "bind-wait: " + bex.getClass().getSimpleName()
                                    + " | holder: " + portHolderVerdict();
                            Thread.sleep(2000);
                        }
                    }
                    acceptLoop(srv, appCtx);
                } catch (Throwable fatal) {
                    TorService.State.listenerStatus = "dead: " + fatal;
                    TorService.State.lastError = "inbox listener: " + fatal;
                }
            }, "anon-http-9878");
            t.setDaemon(true);
            listenerThread = t;
            t.start();
        }
    }

    private static final Object listenerLock = new Object();
    private static Thread listenerThread = null;

    /* the accept + dispatch loop, extracted so bind retries can precede it */
    private static void acceptLoop(ServerSocket srv, Context appCtx) throws Exception {
        while (!srv.isClosed()) {
                    final Socket s = srv.accept();
                    try {
                        s.setSoTimeout(10000);
                        BufferedReader br = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8));
                        String reqLine = br.readLine();
                        if (reqLine == null) { close(s); continue; }
                        int contentLength = 0;
                        String ln;
                        while ((ln = br.readLine()) != null && !ln.isEmpty()) {
                            String low = ln.toLowerCase(Locale.US);
                            if (low.startsWith("content-length:")) {
                                try { contentLength = Integer.parseInt(ln.substring(ln.indexOf(':') + 1).trim()); }
                                catch (NumberFormatException nf) { contentLength = 0; }
                            }
                        }
                        if (contentLength > MAX_PAYLOAD) { close(s); continue; }
                        char[] body = new char[contentLength];
                        int got = 0;
                        while (got < contentLength) {
                            int n = br.read(body, got, contentLength - got);
                            if (n < 0) break;
                            got += n;
                        }
                        final String payload = new String(body, 0, got);
                        /* ---- dispatch (0.3.7) ----
                         * The hidden service must deliver POST /p (peer traffic).
                         * Everything else is the local control plane the UI can
                         * reach with a plain fetch() from the webview — no
                         * Capacitor bridge required. CORS * + short answers. */
                        final String CORSP = "Access-Control-Allow-Origin: *\r\n"
                                + "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
                                + "Access-Control-Allow-Headers: *\r\n";
                        String rbody = "ok";
                        boolean handledPeer = false;
                        if (reqLine.startsWith("POST /p ")) {
                            synchronized (TorService.State.inboxLock) {
                                TorService.State.inbox.addFirst(payload);
                                while (TorService.State.inbox.size() > MAX_INBOX) TorService.State.inbox.pollLast();
                            }
                            handledPeer = true;
                        } else if (reqLine.startsWith("GET /status")) {
                            StringBuilder sb = new StringBuilder("{");
                            sb.append("\"running\":").append(TorService.State.running);
                            sb.append(",\"ready\":").append(TorService.State.ready);
                            sb.append(",\"bootstrapped\":").append(TorService.State.bootstrapped);
                            sb.append(",\"onion\":").append(json(TorService.State.onion));
                            sb.append(",\"socks\":").append(TorService.State.socksLive);
                            sb.append(",\"error\":").append(json(TorService.State.lastError));
                            sb.append(",\"execVia\":").append(json(TorService.State.execVia));
                            sb.append(",\"stage\":").append(json(TorService.State.stage));
                            sb.append(",\"attempt\":").append(TorService.State.attempt);
                            sb.append(",\"clockSkew\":").append(TorService.State.clockSkew);
                            sb.append(",\"info\":").append(json(TorService.State.infoTail == null ? "" : TorService.State.infoTail));
            sb.append(",\"listener\":").append(json(TorService.State.listenerStatus));
            sb.append(",\"hs\":").append(TorService.State.hsPublished);
                            String log;
                            synchronized (TorService.State.logTail) { log = TorService.State.logTail.toString(); }
                            if (TorService.State.streamTail != null && TorService.State.streamTail.length() > 0)
                                log = TorService.State.streamTail + "\n---\n" + log;
                            if (log.length() > 1400) log = log.substring(log.length() - 1400);
                            sb.append(",\"log\":").append(json(log));
                            sb.append("}");
                            rbody = sb.toString();
                        } else if (reqLine.startsWith("GET /start")) {
                            TorService.State.stage = "start-requested";
                            Context c = appCtx;
                            if (c == null) { rbody = "{\"error\":\"no context\"}"; }
                            else {
                                try {
                                    Intent i = new Intent(c, TorService.class);
                                    if (Build.VERSION.SDK_INT >= 26) c.startForegroundService(i); else c.startService(i);
                                    startHttpListener(c);
                                } catch (Throwable te) {
                                    TorService.State.stage = "start-denied";
                                    TorService.State.lastError = "http /start: " + te;
                                    rbody = "{\"error\":" + json(String.valueOf(te)) + "}";
                                }
                            }
                        } else if (reqLine.startsWith("POST /send") && !payload.isEmpty()) {
                            /* body format: "<onion>\n<payload>" — mirror of sendMessage */
                            int cut = payload.indexOf('\n');
                            String onion = cut > 0 ? payload.substring(0, cut).trim() : "";
                            String body2 = cut > 0 ? payload.substring(cut + 1) : "";
                            if (!onion.endsWith(".onion") || body2.length() == 0 || body2.length() > MAX_PAYLOAD) {
                                rbody = "{\"sent\":false,\"error\":\"bad onion or payload\"}";
                            } else {
                                boolean sent = false; String sErr = "";
                                try { sent = socksPost(onion, body2); } catch (Throwable te) { sErr = String.valueOf(te); }
                                rbody = sent ? "{\"sent\":true}"
                                        : "{\"sent\":false,\"error\":" + json(sErr) + "}";
                            }
                        } else if (reqLine.startsWith("GET /poll")) {
                            StringBuilder sb = new StringBuilder("{\"inbox\":[");
                            boolean first = true;
                            synchronized (TorService.State.inboxLock) {
                                String item;
                                while ((item = TorService.State.inbox.pollLast()) != null) {
                                    if (!first) sb.append(",");
                                    sb.append(json(item));
                                    first = false;
                                }
                            }
                            sb.append("]}");
                            rbody = sb.toString();
                        } else if (reqLine.startsWith("OPTIONS ")) {
                            rbody = "";
                        }
                        if (!handledPeer) {
                            byte[] rb = rbody.getBytes(StandardCharsets.UTF_8);
                            String resp = "HTTP/1.1 200 OK\r\n" + CORSP
                                    + "Content-Type: application/json\r\n"
                                    + "Content-Length: " + rb.length + "\r\n"
                                    + "Connection: close\r\n\r\n";
                            OutputStream os = s.getOutputStream();
                            os.write(resp.getBytes(StandardCharsets.US_ASCII));
                            if (rb.length > 0) os.write(rb);
                            os.flush();
                        }
                        close(s);
                    } catch (Throwable oneConn) {
                        close(s);
                    }
                }
    }

    /* Who is holding 9878? (0.3.18) Parse /proc/net/{tcp,tcp6} for the local
     * port and report socket state + owning uid — this names the mystery
     * EADDRINUSE holder on-device (our own zombie, another app, or a kernel
     * state that a plain bind error can't distinguish). */
    private static String portHolderVerdict() {
        StringBuilder out = new StringBuilder();
        try {
            final String hexPort = String.format("%04X", HTTP_PORT);
            for (String table : new String[]{"/proc/net/tcp", "/proc/net/tcp6"}) {
                try {
                    java.io.BufferedReader r = new java.io.BufferedReader(new java.io.InputStreamReader(new FileInputStream(table), StandardCharsets.UTF_8));
                    String ln = r.readLine(); /* header */
                    while ((ln = r.readLine()) != null) {
                        String[] f = ln.trim().split("\\s+");
                        if (f.length < 8) continue;
                        int colon = f[1].lastIndexOf(':');
                        if (colon < 0) continue;
                        String lp = f[1].substring(colon + 1);
                        if (!lp.equalsIgnoreCase(hexPort)) continue;
                        String st = f[3];
                        String stName = "0A".equals(st) ? "LISTEN" : "01".equals(st) ? "ESTABLISHED"
                                : "06".equals(st) ? "TIME_WAIT" : "08".equals(st) ? "CLOSE_WAIT"
                                : "03".equals(st) ? "SYN_SENT" : st;
                        String uid = f[7];
                        boolean ours = String.valueOf(android.os.Process.myUid()).equals(uid);
                        if (out.length() > 0) out.append(" ;; ");
                        out.append(table.endsWith("6") ? "tcp6 " : "tcp ")
                                .append("st=").append(stName).append(" uid=").append(uid)
                                .append(ours ? " (us)" : " (other app?)");
                    }
                    r.close();
                } catch (Throwable ignored) { }
            }
        } catch (Throwable ignored) { }
        return out.length() == 0 ? "no /proc entry (kernel-level oddity)" : out.toString();
    }

    /* Minimal JSON string encoder for the local control plane. */
    private static String json(String in) {
        if (in == null) return "\"\"";
        StringBuilder b = new StringBuilder(in.length() + 2);
        b.append('"');
        for (int i = 0; i < in.length(); i++) {
            char c = in.charAt(i);
            if (c == '"' || c == '\\') { b.append('\\').append(c); }
            else if (c == '\n') { b.append("\\n"); }
            else if (c == '\r') { b.append("\\r"); }
            else if (c == '\t') { b.append("\\t"); }
            else if (c < 0x20) { b.append(String.format("\\u%04x", (int) c)); }
            else b.append(c);
        }
        b.append('"');
        return b.toString();
    }

    private static void close(Socket s) {
        try { s.close(); } catch (Throwable ignored) {}
    }
}
