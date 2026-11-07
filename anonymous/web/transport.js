'use strict';
/*
 * Anonymous — Transport (Phase 3)
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
 * Graceful degradation: browser/dev (no plugin) reports unavailable; when
 * tor is still bootstrapping everything queues in the vault outbox.
 */
(function(global) {

function Transport() {
    const cap = global.Capacitor && global.Capacitor.Plugins;
    this.p = (cap && cap.TorBridge) || null;
    this.queueDrivenByVault = true;   // outbox lives in vault data (survives restarts)
    this.statusCache = { available: false, running: false, ready: false, onion: null, bootstrapped: 0 };
}

Transport.prototype.available = function() {
    return !!(this.p && typeof this.p.startTor === 'function' && typeof this.p.sendMessage === 'function');
};

/* Kick the foreground service; progress is read via status(). */
Transport.prototype.start = async function() {
    if (!this.available()) throw new Error('tor bridge unavailable (native plugin missing)');
    await this.p.startTor();
};

Transport.prototype.status = async function() {
    if (!this.available()) {
        this.statusCache = { available: false, running: false, ready: false, onion: null, bootstrapped: 0 };
        return this.statusCache;
    }
    try {
        const r = await this.p.status();
        this.statusCache = {
            available: true,
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
    } catch (e) {
        this.statusCache = { available: true, running: false, ready: false, onion: null, bootstrapped: 0, error: String(e && e.message || e) };
    }
    return this.statusCache;
};

/* One attempt. Returns true only if the POST was delivered through tor. */
Transport.prototype.send = async function(onion, wireToken) {
    if (!this.available()) throw new Error('tor bridge unavailable');
    const r = await this.p.sendMessage({ onion: onion, payload: wireToken });
    return !!(r && r.sent);
};

/* Drain the native inbox buffer. Returns array of wire tokens (order kept). */
Transport.prototype.poll = async function() {
    if (!this.available()) return [];
    const r = await this.p.pollInbox();
    return (r && r.inbox) || [];
};

global.Transport = Transport;

})(typeof window !== 'undefined' ? window : globalThis);
