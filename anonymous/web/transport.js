'use strict';
/*
 * Anonymous — Transport (Phase 3, rev2 in 0.3.6)
 * Onion transport on top of the TorBridge Capacitor plugin.
 *
 * Model:
 *   - tor runs as a foreground service holding libtor.so; SOCKS5 at 127.0.0.1:9050
 *   - our hidden service listens on virtual port 9878 → local HTTP 127.0.0.1:9878
 *   - send: SOCKS5 CONNECT to <peer>.onion:9878, HTTP POST /p with the whole
 *     wire token as body (tor wraps it; the peer's tor delivers it to its local
 *     listener; no TLS — anonymity comes from the onion routing itself)
 *   - receive: hidden service (onion) → our local listener → TorBridge inbox
 *     buffer; JS polls and matches tokens to stored contacts
 *
 * Bridge access (fixed 0.3.6 — THE root-cause unlock):
 *   Capacitor 8's injected native runtime does NOT populate `Capacitor.Plugins`
 *   (that walked away in the v7 runtime rewrite). A custom plugin is reached
 *   through `Capacitor.nativePromise(PLUGIN, METHOD, args)` — present on every
 *   Capacitor version since v1, zero build step. We try the classic
 *   `Capacitor.Plugins.TorBridge` proxy first (older runtimes + browsers with
 *   a bundled core) and fall back to nativePromise directly. A browser/dev
 *   page (no native bridge injected) correctly reports unavailable.
 *
 * Graceful degradation: browser/dev (no plugin) reports unavailable; when
 * tor is still bootstrapping everything queues in the vault outbox.
 */
(function(global) {

var PLUGIN = 'TorBridge';

function Transport() {
    // resolution: 'proxy' | 'native' | 'none' — surfaced for debugging in the chip modal
    this.mode = 'none';
    this.queueDrivenByVault = true;   // outbox lives in vault data (survives restarts)
    this.statusCache = { available: false, running: false, ready: false, onion: null, bootstrapped: 0 };
}

/* How do we talk to the plugin in this runtime?
 *   proxy : Capacitor.Plugins.TorBridge object exists (old runtimes / @capacitor/core bundled)
 *   native: injected native bridge runtime with nativePromise (Capacitor >= 7)
 *   none  : plain browser page — no native bridge was injected            */
Transport.prototype.detect = function() {
    var cap = global.Capacitor;
    if (cap) {
        var p = cap.Plugins && cap.Plugins[PLUGIN];
        if (p && typeof p.status === 'function') { this.mode = 'proxy'; return p; }
        if (typeof cap.nativePromise === 'function') { this.mode = 'native'; return null; }
    }
    /* 0.3.7 control-plane fallback: the local HTTP listener on 127.0.0.1:9878
     * (the hidden service's delivery port) answers GET /status, GET /start,
     * POST /send and GET /poll with CORS *. It is owned by TorService itself,
     * so it is alive whenever the daemon service is — independent of any
     * Capacitor bridge injection problem in this webview. */
    if (global.fetch) { this.mode = 'http'; return null; }
    this.mode = 'none';
    return null;
};

Transport.prototype.available = function() {
    if (this.mode === 'none') this.detect();
    return this.mode !== 'none';
};

/* Unified invoke: method proxy if a plugin object exists, nativePromise otherwise,
 * then the loopback HTTP control plane (port 9878) as the cross-check channel. */
Transport.prototype.call = async function(method, args) {
    args = args || {};
    var p = this.detect();
    if (this.mode === 'proxy' && p) return p[method](args);
    if (this.mode === 'native') {
        var r = await global.Capacitor.nativePromise(PLUGIN, method, args);
        // nativePromise may return undefined/null for void methods (startTor)
        return r || {};
    }
    if (this.mode === 'http') {
        var path = { startTor: '/start', status: '/status', pollInbox: '/poll', sendMessage: '/send' }[method];
        if (!path) throw new Error('no http control route for ' + method);
        var isPost = path === '/send';
        var ctl = await fetch('http://127.0.0.1:9878' + path, {
            method: isPost ? 'POST' : 'GET',
            body: isPost ? (args.onion + '\n' + args.payload) : undefined,
            signal: global.AbortSignal ? global.AbortSignal.timeout(8000) : undefined
        });
        var txt = await ctl.text();
        return txt ? JSON.parse(txt) : {};
    }
    throw new Error('tor bridge unavailable (runtime: no native bridge injected)');
};

/* Kick the foreground service; progress is read via status(). */
Transport.prototype.start = async function() {
    if (!this.available()) throw new Error('tor bridge unavailable (runtime: no native bridge injected)');
    try { await this.call('startTor', {}); }
    finally { try { await this.call('status', {}); } catch (e) {} } // refresh cache so the chip never lags
};

Transport.prototype.status = function() {
    if (!this.available()) {
        this.statusCache = { available: false, running: false, ready: false, onion: null, bootstrapped: 0, mode: 'none' };
        return Promise.resolve(this.statusCache);
    }
    return this.call('status', {}).then(function(r) {
        this.statusCache = {
            available: true,
            mode: this.mode,
            running: !!(r && (r.running || r.ready)),
            ready: !!(r && r.ready),
            onion: (r && r.onion) || null,
            bootstrapped: (r && r.bootstrapped) || 0,
            socks: !!(r && r.socks),
            error: (r && r.error) || '',
            execVia: (r && r.execVia) || '',
            stage: (r && r.stage) || '',
            attempt: (r && r.attempt) || 0,
            clockSkew: !!(r && r.clockSkew),
            hs: !!(r && r.hs),
            info: String((r && r.info) || ''),
            listener: String((r && r.listener) || ''),
            log: (r && r.log) || ''
        };
        return this.statusCache;
    }.bind(this)).catch(function(e) {
        this.statusCache = {
            available: true, mode: this.mode, running: false, ready: false, onion: null,
            bootstrapped: 0, error: String(e && e.message || e)
        };
        return this.statusCache;
    }.bind(this));
};

/* One attempt. Returns the full result {sent, unacked?, error?} — not just
 * the bool — so the UI can surface the native failure reason (socks rep,
 * timeout, …). `sent:true, unacked:true` means the whole HTTP POST body was
 * written to the peer's hidden service but the 200 ack never came back; the
 * message must NOT be reported as a delivery failure or retried forever. */
Transport.prototype.send = function(onion, wireToken) {
    if (!this.available()) return Promise.resolve({ sent: false, error: 'tor bridge unavailable' });
    return this.call('sendMessage', { onion: onion, payload: wireToken })
        .then(function(r) {
            var out = { sent: !!(r && r.sent), unacked: !!(r && r.unacked), error: (r && r.error) || '' };
            /* v0.4.1: remember the last failure verbatim so the tor modal can
             * show the exact socks rep / kernel verdict for PEER delivery —
             * loopback tells us our side works; this is the cross-device clue. */
            if (!out.sent && out.error) {
                Transport.lastSendErr = { onion: String(onion || ''), error: String(out.error), t: Date.now() };
            }
            if (out.sent && out.unacked) {
                /* visible in the tor modal: body WAS flushed, peer ack lost */
                Transport.lastSendUnacked = { onion: String(onion || ''), t: Date.now() };
            }
            return out;
        });
};

/* Drain the native inbox buffer. Returns array of wire tokens (order kept). */
Transport.prototype.poll = function() {
    if (!this.available()) return Promise.resolve([]);
    return this.call('pollInbox', {}).then(function(r) { return (r && r.inbox) || []; });
};

/* Generic bridge passthrough (0.4.0): voice-call methods ride the same
 * proxy/native resolution; http mode has no audio channel. */
Transport.prototype.callMethod = function(method, args) {
    if (!this.available() || this.mode === 'http') {
        return Promise.resolve({ unsupported: true });
    }
    return this.call(method, args || {}).then(function(r) { return r || {}; });
};

global.Transport = Transport;

})(typeof window !== 'undefined' ? window : globalThis);
