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
    if (!cap) { this.mode = 'none'; return null; }
    var p = cap.Plugins && cap.Plugins[PLUGIN];
    if (p && typeof p.status === 'function') { this.mode = 'proxy'; return p; }
    if (typeof cap.nativePromise === 'function') { this.mode = 'native'; return null; }
    this.mode = 'none';
    return null;
};

Transport.prototype.available = function() {
    if (this.mode === 'none') this.detect();
    return this.mode !== 'none';
};

/* Unified invoke: method proxy if a plugin object exists, nativePromise otherwise. */
Transport.prototype.call = async function(method, args) {
    var p = this.detect();
    if (this.mode === 'proxy' && p) return p[method](args || {});
    if (this.mode === 'native') {
        var r = await global.Capacitor.nativePromise(PLUGIN, method, args || {});
        // nativePromise may return undefined/null for void methods (startTor)
        return r || {};
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

/* One attempt. Returns true only if the POST was delivered through tor. */
Transport.prototype.send = function(onion, wireToken) {
    if (!this.available()) return Promise.reject(new Error('tor bridge unavailable'));
    return this.call('sendMessage', { onion: onion, payload: wireToken })
        .then(function(r) { return !!(r && r.sent); });
};

/* Drain the native inbox buffer. Returns array of wire tokens (order kept). */
Transport.prototype.poll = function() {
    if (!this.available()) return Promise.resolve([]);
    return this.call('pollInbox', {}).then(function(r) { return (r && r.inbox) || []; });
};

global.Transport = Transport;

})(typeof window !== 'undefined' ? window : globalThis);
