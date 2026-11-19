package org.onionchat;

import android.media.AudioFormat;
import android.media.AudioManager;
import android.media.AudioRecord;
import android.media.AudioTrack;
import android.media.MediaCodec;
import android.media.MediaCodecInfo;
import android.media.MediaCodecList;
import android.media.MediaFormat;
import android.media.MediaRecorder;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayDeque;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Anonymous voice engine (0.4.0) — Tor hidden-service voice calls.
 *
 * Two planes:
 *   - SIGNALING rides the existing ratchet path (JSON inside the encrypted
 *     plaintext, dispatched by the web layer).
 *   - AUDIO uses a dedicated hidden-service port (VOICE_PORT 9879, raw TCP,
 *     length-prefixed frames). Wire format:
 *        [8B plaintext callId preamble, once]
 *        [u16 BE length][12B GCM nonce][AES-GCM ct = AMR frame batch]
 *     The preamble lets the receiver arm the right call (tor gives the
 *     accept no caller identity).
 *
 * Codec: AMR-WB 16 kHz via MediaCodec (built into Android — no vendored
 * codec), ~8.85 kbps; falls back to AMR-NB 8 kHz / 4.75 kbps. Frames batched
 * up to 4 (80 ms) per wire frame.
 *
 * Jitter buffer: adaptive ConcurrentLinkedQueue between network and decoder
 * — target starts at 8 frames (~160 ms), grows on starvation (tor latency
 * spikes) up to 24 frames (~480 ms), drops oldest to catch up.
 *
 * All sockets bind/connect the IPv4 LITERAL 127.0.0.1 (0.3.21 lesson:
 * getLoopbackAddress() resolves ::1 on the reference device).
 */
public final class VoiceEngine {

    public static final int VOICE_PORT = 9879;

    private static final int SAMPLE_RATE_WB = 16000;
    private static final int SAMPLE_RATE_NB = 8000;
    private static final long ARM_WAIT_MS = 120000;  // incoming conn waits for the callee to arm (slow Accept must not kill the call)
    private static final long CONNECT_RETRY_MS = 5000;    // caller: pause between rendezvous retries
    private static final long CONNECT_DEADLINE_MS = 120000; // caller: keep trying across the whole ring window
    private static final int JITTER_START = 8;
    private static final int JITTER_MAX = 24;

    /* ---------------- shared state, surfaced to the chip modal ---------------- */

    public static final class CState {
        public static volatile String phase = "idle";   // idle|calling|ringing|active|ended
        public static volatile String cid = "";
        public static volatile String detail = "";
        public static volatile boolean micMuted = false;
        public static volatile boolean speaker = false;
        public static volatile boolean loopback = false; // voice-loopback test in progress
    }

    private static final Object lock = new Object();
    private static final SecureRandom rng = new SecureRandom();

    /* armed pending calls: callId hex → 16-byte call key */
    private static final Map<String, byte[]> armed = new java.util.HashMap<>();
    private static volatile Socket callSock = null;
    private static volatile byte[] callKey = null;
    private static volatile boolean loopbackMode = false;

    /* Call generation (0.4.3). Every teardown/start bumps it. Media threads
     * capture the generation they were started for and may only end/flip the
     * call when they are STILL that generation. Before this, a socket left
     * over from a reconnect (or a duplicate accept-path callStart) reached
     * recvLoop's finally and ran endCall("channel closed") against the brand
     * new call — exactly the "call and channel closed" verdict. */
    private static volatile long callGen = 0;

    private static final AtomicBoolean micRunning = new AtomicBoolean(false);
    public static final AtomicBoolean MIC_RUNNING = micRunning;
    private static final AtomicBoolean netRunning = new AtomicBoolean(false);
    private static final AtomicBoolean playRunning = new AtomicBoolean(false);
    private static volatile ConcurrentLinkedQueue<byte[]> jitterRef = null;
    private static Thread srvThread = null;

    private VoiceEngine() { }

    /* ======================= bridge-facing API ======================= */

    /** Caller: open the voice channel to the peer and start streaming both ways. */
    /** Idempotent: re-invoking with the SAME cid while a healthy channel for
     * it is already up (the accept-signal reconnect path) is a no-op — this
     * lets JS re-callStart on accept without killing a live channel. */
    public static void startOutgoing(String onion, String cidHex, String keyB64) {
        final String cid = cidHex == null ? "" : cidHex;
        final long gen;
        synchronized (lock) {
            boolean liveSock = callSock != null && !callSock.isClosed();
            /* Same-cid re-entry is a no-op while the channel is up OR still
             * connecting. The accept-signal path re-calls callStart; the old
             * "active only" guard let that path stopEverything() the live
             * client leg, whose recvLoop then ended the new call. */
            if (cid.equals(CState.cid)
                    && (("active".equals(CState.phase) && liveSock)
                        || "calling".equals(CState.phase))) {
                CState.detail = "client: already " + CState.phase + " (reconnect no-op)";
                return;
            }
            stopEverything();        // bumps callGen
            gen = callGen;
            CState.cid = cid;
            callKey = b64(keyB64);
            loopbackMode = false;
            CState.phase = "calling";
            CState.detail = "client: connecting";
        }
        clientThread(onion, cid, false, gen);
    }

    /** Callee: arm so an arriving 9879 connection carrying this cid is accepted. */
    public static void armIncoming(String cidHex, String keyB64) {
        final String cid = cidHex == null ? "" : cidHex;
        synchronized (lock) {
            /* double-tap Accept / duplicate invite must not tear down a live
             * or already-armed channel */
            byte[] existing = armed.get(cid);
            if (cid.equals(CState.cid) && existing != null) {
                CState.phase = "ringing";
                CState.detail = "server: already armed";
                ensureVoiceServer();
                return;
            }
            if (cid.equals(CState.cid) && "active".equals(CState.phase)) {
                CState.detail = "server: already active (arm no-op)";
                return;
            }
            stopEverything();        // bumps callGen
            CState.cid = cid;
            callKey = b64(keyB64);
            loopbackMode = false;
            armed.put(CState.cid, callKey);
            CState.phase = "ringing";
            CState.detail = "server: armed";
            ensureVoiceServer();
        }
    }

    /** Voice-loopback: mic → tor → own HS → own server → playback, one phone. */
    public static void startLoopback(String ownOnion) {
        final String cid = randomCid();
        final byte[] key = new byte[16];
        rng.nextBytes(key);
        final String keyB64 = android.util.Base64.encodeToString(key, android.util.Base64.NO_WRAP);
        final long gen;
        synchronized (lock) {
            stopEverything();        // bumps callGen
            gen = callGen;
            CState.cid = cid;
            callKey = key;
            loopbackMode = true;
            CState.loopback = true;
            CState.phase = "calling";
            CState.detail = "loopback: starting";
            armed.put(cid, key);            /* own server will match this */
        }
        ensureVoiceServer();
        clientThread(ownOnion, cid, true, gen);
    }

    public static void stopLoopback() {
        synchronized (lock) {
            stopEverything();
            CState.loopback = false;
            CState.phase = "idle";
            CState.detail = "loopback stopped";
        }
    }

    public static void endCall(String reason) {
        synchronized (lock) {
            stopEverything();        // bumps callGen; any older media thread is now inert
            CState.loopback = false;
            CState.phase = "ended";
            CState.detail = "ended: " + (reason == null ? "local" : reason);
        }
    }

    /** End the call ONLY if the caller's generation is still current. */
    private static void endCallFor(long gen, String reason) {
        synchronized (lock) {
            if (gen != callGen) return;          // stale socket/thread — never touch a newer call
            stopEverything();                    // bumps again
            CState.loopback = false;
            CState.phase = "ended";
            CState.detail = "ended: " + reason;
        }
    }

    public static void setMuted(boolean m) { CState.micMuted = m; }

    public static void setSpeaker(boolean on) {
        CState.speaker = on;
        try {
            android.content.Context ctx = TorService.appContext();
            AudioManager am = ctx == null ? null : (AudioManager) ctx.getSystemService(android.content.Context.AUDIO_SERVICE);
            if (am != null) {
                am.setMode(on ? AudioManager.MODE_IN_COMMUNICATION : AudioManager.MODE_NORMAL);
                am.setSpeakerphoneOn(on);
            }
        } catch (Throwable ignored) { }
    }

    /* ======================= voice server (both roles) ======================= */

    /** Hardened like the 9878 listener: single owner, v4-literal bind, bind-retry. */
    public static synchronized void ensureVoiceServer() {
        if (srvThread != null && srvThread.isAlive()) return;
        srvThread = new Thread(() -> {
            ServerSocket srv = null;
            try {
                while (true) {
                    try {
                        srv = new ServerSocket();
                        srv.setReuseAddress(true);
                        srv.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), VOICE_PORT), 16);
                        break;
                    } catch (Throwable bex) {
                        srv = null;
                        Thread.sleep(2000);
                    }
                }
                while (!srv.isClosed()) {
                    final Socket s = srv.accept();
                    new Thread(() -> handleIncoming(s), "anon-voice-accept").start();
                }
            } catch (Throwable fatal) {
                CState.detail = "voice server: " + fatal;
                srvThread = null;
            }
        }, "anon-voice-9879");
        srvThread.setDaemon(true);
        srvThread.start();
    }

    private static void handleIncoming(Socket s) {
        try {
            s.setSoTimeout(10000);
            InputStream is = s.getInputStream();
            byte[] cidB = readN(is, 8);
            if (cidB == null) { try { s.close(); } catch (Throwable ignored) {} return; }
            final String cid = bytesToHex(cidB);
            /* Media silence is legal. Clear the handshake timeout NOW, before
             * any media thread starts: the old code did this after startMedia,
             * so recvLoop's first read could still inherit the 10 s timeout
             * and kill a good call that had not sent a frame yet. */
            s.setSoTimeout(0);
            final long genAtAccept;
            synchronized (lock) { genAtAccept = callGen; }
            byte[] key = null;
            boolean isLoopback = false;
            long waited = 0;
            while (waited < ARM_WAIT_MS) {
                synchronized (lock) {
                    key = armed.get(cid);
                    isLoopback = loopbackMode && CState.cid.equals(cid);
                }
                if (key != null) break;
                synchronized (lock) {
                    /* a newer call/teardown superseded this waiting socket */
                    if (genAtAccept != callGen && armed.get(cid) == null) {
                        try { s.close(); } catch (Throwable ignored) {}
                        return;
                    }
                }
                Thread.sleep(500);
                waited += 500;
            }
            if (key == null) { try { s.close(); } catch (Throwable ignored) {} return; }
            synchronized (lock) {
                /* Close the race between reading `armed` and applying it: a
                 * teardown or a different call may have run in that window.
                 * Proceed only if this cid is still the intended call and (on
                 * a generation change) still armed. */
                if (genAtAccept != callGen) {
                    byte[] now = armed.get(cid);
                    if (now == null || !cid.equals(CState.cid)) {
                        try { s.close(); } catch (Throwable ignored) {}
                        return;
                    }
                    key = now;
                }
                isLoopback = loopbackMode && cid.equals(CState.cid);
                if (isLoopback) {
                    /* same process owns both legs: do NOT stop the client side */
                    long gen = callGen;
                    callSock = s;
                    CState.phase = "active";
                    CState.detail = "loopback: circuit up";
                    startMedia(s, false, true, gen);   /* server leg: receive+play only */
                } else {
                    stopEverything();        // bumps callGen
                    long gen = callGen;
                    callSock = s;
                    callKey = key;
                    CState.cid = cid;
                    CState.phase = "active";
                    CState.detail = "server: channel up";
                    startMedia(s, true, true, gen);
                }
            }
        } catch (Throwable t) {
            CState.detail = "voice accept: " + t;
            try { s.close(); } catch (Throwable ignored) {}
        }
    }

    /* ======================= client leg ======================= */

    private static void clientThread(String onion, String cid, boolean lb, long gen) {
        new Thread(() -> {
            Socket s = null;
            final long deadline = System.currentTimeMillis() + CONNECT_DEADLINE_MS;
            int attempt = 0;
            /* Keep trying for the whole ring window (0.4.3). The callee arms
             * only after a human taps Accept, and a v3 rendezvous can fail
             * transiently many times while that happens; the old two-shot
             * retry gave up ~53 s in and ended a call the peer could still
             * answer. */
            while (s == null) {
                synchronized (lock) {
                    if (gen != callGen || !cid.equals(CState.cid)) return;
                }
                try {
                    s = socksConnect(onion, VOICE_PORT, 45000);
                } catch (Throwable ce) {
                    attempt++;
                    boolean giveUp;
                    synchronized (lock) {
                        if (gen != callGen || !cid.equals(CState.cid)) return;
                        giveUp = System.currentTimeMillis() >= deadline;
                        CState.detail = "client: connect attempt " + attempt + " failed (" + ce + ")"
                                + (giveUp ? "" : " — retrying");
                        if (giveUp) CState.phase = "ended";
                    }
                    if (giveUp) return;
                    try { Thread.sleep(CONNECT_RETRY_MS); } catch (InterruptedException ie) { return; }
                }
            }
            try {
                OutputStream os = s.getOutputStream();
                os.write(hexToBytes(cid));
                os.flush();
                synchronized (lock) {
                    if (gen != callGen || !cid.equals(CState.cid)) {
                        try { s.close(); } catch (Throwable ignored) {}
                        return;
                    }
                    callSock = s;
                    if (lb) {
                        CState.detail = "loopback: circuit up";
                    } else {
                        /* channel is up, but the callee has not accepted yet —
                         * stay "calling" until the first media frame proves
                         * their capture side is live. */
                        CState.detail = "client: channel up — waiting for peer";
                    }
                }
                s.setSoTimeout(0);
                startMedia(s, true, !lb, gen);
            } catch (Throwable t) {
                synchronized (lock) {
                    if (gen == callGen) {
                        CState.detail = (lb ? "loopback failed: " : "client failed: ") + t;
                        if (!"active".equals(CState.phase)) CState.phase = "ended";
                    }
                }
                try { s.close(); } catch (Throwable ignored) {}
            }
        }, lb ? "anon-voice-lb" : "anon-voice-client").start();
    }

    /* ======================= media pipeline ======================= */

    private static void startMedia(Socket sock, boolean capture, boolean playback, long gen) {
        if (gen != callGen) return;                 // superseded before we started
        boolean wb = false;
        try { wb = hasCodec("audio/amr-wb"); } catch (Throwable t) { wb = false; }
        final int rate = wb ? SAMPLE_RATE_WB : SAMPLE_RATE_NB;
        final String mime = wb ? "audio/amr-wb" : "audio/3gpp";

        if (capture) {
            micRunning.set(true);
            Thread t = new Thread(() -> captureLoop(sock, mime, rate, gen), "anon-voice-mic");
            t.setDaemon(true);
            t.start();
        }
        if (playback) {
            /* the recv thread builds the jitter queue; the play thread drains it */
            netRunning.set(true);
            jitterRef = new ConcurrentLinkedQueue<>();
            Thread r = new Thread(() -> recvLoop(sock, gen), "anon-voice-recv");
            r.setDaemon(true);
            r.start();
            playRunning.set(true);
            Thread p = new Thread(() -> playLoop(mime, rate, gen), "anon-voice-play");
            p.setDaemon(true);
            p.start();
        }
    }

    private static void captureLoop(Socket sock, String mime, int rate, long gen) {
        MediaCodec enc = null;
        AudioRecord rec = null;
        try {
            int minBuf = AudioRecord.getMinBufferSize(rate, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT);
            rec = new AudioRecord(MediaRecorder.AudioSource.VOICE_COMMUNICATION, rate,
                    AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT, Math.max(minBuf * 2, 8192));
            if (rec.getState() != android.media.AudioRecord.STATE_INITIALIZED) throw new Exception("AudioRecord init failed (permission?)");
            rec.startRecording();

            MediaFormat f = MediaFormat.createAudioFormat(mime, rate, 1);
            f.setInteger(MediaFormat.KEY_BIT_RATE, wbRate(mime));
            enc = MediaCodec.createEncoderByType(mime);
            enc.configure(f, null, null, MediaCodec.CONFIGURE_FLAG_ENCODE);
            enc.start();

            long batchSeq = 0;
            ArrayDeque<byte[]> frameBatch = new ArrayDeque<>();
            MediaCodec.BufferInfo info = new MediaCodec.BufferInfo();
            short[] pcm = new short[rate / 50]; /* 20 ms */
            while (micRunning.get() && gen == callGen && !sock.isClosed()) {
                boolean muted = CState.micMuted;
                int got = rec.read(pcm, 0, pcm.length);
                if (got <= 0) { Thread.sleep(10); continue; }
                if (muted) for (int i = 0; i < got; i++) pcm[i] = 0;
                int inIdx = enc.dequeueInputBuffer(10000);
                if (inIdx >= 0) {
                    ByteBuffer ib = enc.getInputBuffer(inIdx);
                    ib.clear();
                    for (int i = 0; i < got; i++) ib.putShort(pcm[i]);
                    enc.queueInputBuffer(inIdx, 0, got * 2, batchSeq++, 0);
                }
                int outIdx = enc.dequeueOutputBuffer(info, 10000);
                while (outIdx >= 0 && info.size > 0) {
                    ByteBuffer ob = enc.getOutputBuffer(outIdx);
                    ob.position(info.offset);
                    ob.limit(info.offset + info.size);
                    byte[] frame = new byte[info.size];
                    ob.get(frame);
                    frameBatch.add(frame);
                    if (frameBatch.size() >= 4) {
                        sendFrame(sock, concat(frameBatch), gen);
                        frameBatch.clear();
                    }
                    enc.releaseOutputBuffer(outIdx, false);
                    outIdx = enc.dequeueOutputBuffer(info, 0);
                }
            }
        } catch (Throwable t) {
            synchronized (lock) {
                if (gen == callGen) CState.detail = "mic: " + t;
            }
        } finally {
            try { if (rec != null) rec.stop(); } catch (Throwable ignored) {}
            try { if (rec != null) rec.release(); } catch (Throwable ignored) {}
            try { if (enc != null) enc.stop(); } catch (Throwable ignored) {}
            try { if (enc != null) enc.release(); } catch (Throwable ignored) {}
            /* only the CURRENT call may clear the shared flag */
            if (gen == callGen) micRunning.set(false);
        }
    }

    private static void sendFrame(Socket sock, byte[] plain, long gen) {
        try {
            byte[] nonce = new byte[12];
            synchronized (rng) { rng.nextBytes(nonce); }
            byte[] ct = gcm(callKey, nonce, plain, true);
            byte[] framed = new byte[ct.length + 12];
            framed[0] = (byte) (((ct.length + 12) >> 8) & 0xff);
            framed[1] = (byte) ((ct.length + 12) & 0xff);
            System.arraycopy(nonce, 0, framed, 2, 12);
            System.arraycopy(ct, 0, framed, 14, ct.length);
            OutputStream os = sock.getOutputStream();
            os.write(framed);
            os.flush();
        } catch (Throwable t) {
            synchronized (lock) {
                if (gen != callGen) return;      // stale socket — never kill a live call
                CState.detail = "send: " + t;
            }
            endCallFor(gen, "send failed");
        }
    }

    private static void recvLoop(Socket sock, long gen) {
        try {
            InputStream is = sock.getInputStream();
            ConcurrentLinkedQueue<byte[]> jitter = jitterRef;
            if (jitter == null) jitter = new ConcurrentLinkedQueue<>();
            jitterRef = jitter;
            while (netRunning.get() && gen == callGen && !sock.isClosed()) {
                byte[] l2 = readN(is, 2);
                if (l2 == null) break;
                int framedLen = ((l2[0] & 0xff) << 8) | (l2[1] & 0xff);
                if (framedLen < 13 || framedLen > 4096) break;
                byte[] nonce = readN(is, 12);
                byte[] ct = readN(is, framedLen - 12);
                if (nonce == null || ct == null) break;
                byte[] plain;
                try { plain = gcm(callKey, nonce, ct, false); }
                catch (Throwable badFrame) { continue; }
                if (plain != null && plain.length > 0) {
                    /* first real audio from the peer = the callee accepted and
                     * their capture side is live; only now is the call active */
                    if (CState.phase.equals("calling")) {
                        synchronized (lock) {
                            if (gen == callGen && CState.phase.equals("calling")) {
                                CState.phase = "active";
                                CState.detail = "client: media flowing";
                            }
                        }
                    }
                    jitter.add(plain);
                    while (jitter.size() > JITTER_MAX) jitter.poll();
                }
            }
        } catch (Throwable t) {
            synchronized (lock) {
                if (gen == callGen) CState.detail = "recv: " + t;
            }
        } finally {
            if (gen == callGen) netRunning.set(false);
            /* Only THIS generation may end the call. A stale socket left over
             * from a reconnect previously ran endCall("channel closed") and
             * killed the live call seconds after it connected. */
            boolean lb;
            synchronized (lock) { lb = loopbackMode; }
            if (!lb) endCallFor(gen, "channel closed");
        }
    }

    private static void playLoop(String mime, int rate, long gen) {
        MediaCodec dec = null;
        AudioTrack track = null;
        try {
            MediaFormat f = MediaFormat.createAudioFormat(mime, rate, 1);
            dec = MediaCodec.createDecoderByType(mime);
            dec.configure(f, null, null, 0);
            dec.start();
            int minBuf = AudioTrack.getMinBufferSize(rate, AudioFormat.CHANNEL_OUT_MONO, AudioFormat.ENCODING_PCM_16BIT);
            track = new AudioTrack(AudioManager.STREAM_VOICE_CALL, rate,
                    AudioFormat.CHANNEL_OUT_MONO, AudioFormat.ENCODING_PCM_16BIT,
                    Math.max(minBuf * 2, 8192), AudioTrack.MODE_STREAM);
            track.play();

            MediaCodec.BufferInfo info = new MediaCodec.BufferInfo();
            int target = JITTER_START;
            while (playRunning.get() && gen == callGen) {
                ConcurrentLinkedQueue<byte[]> jitter = jitterRef;
                if (jitter == null) { Thread.sleep(20); continue; }
                byte[] frame = jitter.poll();
                if (frame == null) {
                    /* starvation: grow the target and emit 20 ms silence */
                    if (target < JITTER_MAX) target += 2;
                    short[] silence = new short[rate / 50];
                    track.write(silence, 0, silence.length);
                    continue;
                }
                if (jitter.size() > target * 2) {
                    while (jitter.size() > target) jitter.poll();
                }
                int inIdx = dec.dequeueInputBuffer(20000);
                if (inIdx >= 0) {
                    ByteBuffer ib = dec.getInputBuffer(inIdx);
                    ib.clear();
                    ib.put(frame);
                    dec.queueInputBuffer(inIdx, 0, frame.length, 0, 0);
                }
                int outIdx = dec.dequeueOutputBuffer(info, 20000);
                while (outIdx >= 0 && info.size > 0) {
                    ByteBuffer ob = dec.getOutputBuffer(outIdx);
                    ob.position(info.offset);
                    int shorts = info.size / 2;
                    short[] pcmOut = new short[shorts];
                    for (int i = 0; i < shorts; i++) pcmOut[i] = ob.getShort();
                    track.write(pcmOut, 0, pcmOut.length);
                    dec.releaseOutputBuffer(outIdx, false);
                    outIdx = dec.dequeueOutputBuffer(info, 0);
                }
            }
        } catch (Throwable t) {
            synchronized (lock) {
                if (gen == callGen) CState.detail = "play: " + t;
            }
        } finally {
            try { if (track != null) track.stop(); } catch (Throwable ignored) {}
            try { if (track != null) track.release(); } catch (Throwable ignored) {}
            try { if (dec != null) dec.stop(); } catch (Throwable ignored) {}
            try { if (dec != null) dec.release(); } catch (Throwable ignored) {}
            if (gen == callGen) playRunning.set(false);
        }
    }

    /* ======================= helpers ======================= */

    private static int wbRate(String mime) {
        return "audio/amr-wb".equals(mime) ? 8850 : 4750;
    }

    private static boolean hasCodec(String mime) {
        try {
            MediaCodecList list = new MediaCodecList(MediaCodecList.REGULAR_CODECS);
            for (MediaCodecInfo ci : list.getCodecInfos()) {
                if (!ci.isEncoder()) continue;
                for (String t : ci.getSupportedTypes()) if (mime.equals(t)) return true;
            }
        } catch (Throwable ignored) { }
        return false;
    }

    private static byte[] gcm(byte[] key, byte[] nonce, byte[] in, boolean encrypt) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE,
                new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        return c.doFinal(in);
    }

    private static byte[] readN(InputStream is, int n) throws Exception {
        byte[] out = new byte[n];
        int got = 0;
        while (got < n) {
            int r = is.read(out, got, n - got);
            if (r < 0) return null;
            got += r;
        }
        return out;
    }

    private static byte[] concat(ArrayDeque<byte[]> parts) {
        int n = 0;
        for (byte[] p : parts) n += p.length;
        byte[] out = new byte[n];
        int o = 0;
        for (byte[] p : parts) { System.arraycopy(p, 0, out, o, p.length); o += p.length; }
        return out;
    }

    /** SOCKS5 CONNECT through the local tor daemon; the socket stays open. */
    static Socket socksConnect(String onion, int port, int timeoutMs) throws Exception {
        Socket s = new Socket();
        s.connect(new InetSocketAddress("127.0.0.1", TorService.SOCKS_PORT), 8000);
        s.setSoTimeout(timeoutMs);
        OutputStream os = s.getOutputStream();
        InputStream is = s.getInputStream();
        os.write(new byte[]{5, 1, 0}); os.flush();
        byte[] hello = readN(is, 2);
        if (hello == null || hello[0] != 5 || hello[1] != 0) throw new Exception("socks hello refused");
        ByteArrayOutputStream req = new ByteArrayOutputStream();
        byte[] host = onion.getBytes(StandardCharsets.US_ASCII);
        req.write(5); req.write(1); req.write(0); req.write(3);
        req.write(host.length); req.write(host);
        req.write((port >> 8) & 0xff); req.write(port & 0xff);
        os.write(req.toByteArray()); os.flush();
        byte[] head = readN(is, 4);
        if (head == null) throw new Exception("socks connect failed (no reply)");
        if (head[1] != 0) throw new Exception("socks connect failed (rep " + (head[1] & 0xff) + ")");
        int atyp = head[3] & 0xff;
        int addrLen = (atyp == 1) ? 4 : (atyp == 3) ? (readN(is, 1)[0] & 0xff) : 16;
        readN(is, addrLen + 2);
        return s;
    }

    private static void stopEverything() {
        synchronized (lock) {
            callGen++;                       // invalidate every outstanding media thread
            micRunning.set(false);
            netRunning.set(false);
            playRunning.set(false);
            try { if (callSock != null) callSock.close(); } catch (Throwable ignored) {}
            callSock = null;
            jitterRef = null;
            armed.clear();
        }
    }

    private static byte[] b64(String s) {
        try { return android.util.Base64.decode(s, android.util.Base64.NO_WRAP); }
        catch (Throwable t) { return new byte[16]; }
    }

    public static String randomCid() {
        byte[] b = new byte[8];
        synchronized (rng) { rng.nextBytes(b); }
        return bytesToHex(b);
    }

    /** liveness probe on the voice server (9879) — same pattern as 9878. */
    public static boolean voiceServerLive() {
        java.net.Socket p = new java.net.Socket();
        try {
            p.connect(new InetSocketAddress("127.0.0.1", VOICE_PORT), 400);
            p.close();
            return true;
        } catch (Throwable t) {
            try { p.close(); } catch (Throwable ignored) {}
            return false;
        }
    }

    private static String bytesToHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    private static byte[] hexToBytes(String h) {
        h = h == null ? "" : h.trim();
        byte[] out = new byte[h.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(h.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
