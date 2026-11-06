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
    private static volatile boolean listenerStarted = false;

    @PluginMethod
    public void startTor(PluginCall call) {
        Context c = getContext();
        Intent i = new Intent(c, TorService.class);
        if (Build.VERSION.SDK_INT >= 26) c.startForegroundService(i); else c.startService(i);
        startHttpListener();
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
            s.connect(new InetSocketAddress("127.0.0.1", SOCKS_PORT), 8000);
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
            if (head[1] != 0) throw new Exception("socks connect failed (rep " + (head[1] & 0xff) + ")");
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

    private static void startHttpListener() {
        if (listenerStarted) return;
        listenerStarted = true;
        final Thread t = new Thread(() -> {
            try {
                ServerSocket srv = new ServerSocket(HTTP_PORT, 128, InetAddress.getLoopbackAddress());
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
                        String resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                        OutputStream os = s.getOutputStream();
                        os.write(resp.getBytes(StandardCharsets.US_ASCII));
                        os.flush();
                        close(s);
                        if (reqLine.startsWith("POST /p ")) {
                            String payload = new String(body, 0, got);
                            synchronized (TorService.State.inboxLock) {
                                TorService.State.inbox.addFirst(payload);
                                while (TorService.State.inbox.size() > MAX_INBOX) TorService.State.inbox.pollLast();
                            }
                        }
                    } catch (Throwable oneConn) {
                        close(s);
                    }
                }
            } catch (Throwable fatal) {
                listenerStarted = false;
                TorService.State.lastError = "inbox listener: " + fatal;
            }
        }, "anon-http-9878");
        t.setDaemon(true);
        t.start();
    }

    private static void close(Socket s) {
        try { s.close(); } catch (Throwable ignored) {}
    }
}
