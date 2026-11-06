'use strict';
/*
 * Anonymous — Vault (Phase 2)
 * All persistent app state — identity keys, contacts, ratchet sessions — is
 * stored ONLY inside this vault, AES-GCM encrypted with a key derived from
 * the user's passphrase (PBKDF2-SHA256, 300k iterations). Nothing plaintext
 * touches localStorage; chats live only in memory with self-destruction by
 * default (30-minute retention is enforced at the UI layer).
 */
(function(global) {

const TE = new TextEncoder();
const TD = new TextDecoder();
const ITER = 300000;
const VAULT_KEY = 'oc_vault_v1';

function subtle() {
    if (global.crypto && global.crypto.subtle) return global.crypto.subtle;
    throw new Error('WebCrypto subtle unavailable');
}

function u8ToB64(u8) {
    let s = '';
    for (let i = 0; i < u8.length; i += 3) {
        const a = u8[i], b = u8[i + 1], c = u8[i + 2];
        s += B64T[a >> 2];
        s += B64T[((a & 3) << 4) | ((b || 0) >> 4)];
        if (b === undefined) { s += '=='; return s; }
        s += B64T[((b & 15) << 2) | ((c || 0) >> 6)];
        if (c === undefined) { s += '='; return s; }
        s += B64T[c & 63];
    }
    return s;
}
const B64T = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function b64ToU8(s) {
    const clean = s.replace(/=+$/, '');
    const outLen = (clean.length * 3) >> 2;
    const out = new Uint8Array(outLen);
    let bits = 0, acc = 0, o = 0;
    for (let i = 0; i < clean.length; i++) {
        acc = (acc << 6) | B64T.indexOf(clean[i]);
        bits += 6;
        if (bits >= 8) { bits -= 8; out[o++] = (acc >> bits) & 0xff; }
    }
    return out;
}

async function deriveKey(pass, salt) {
    const key = await subtle().importKey('raw', TE.encode(pass), 'PBKDF2', false, ['deriveKey']);
    return subtle().deriveKey(
        { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: ITER },
        key, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

async function seal(obj, key) {
    const iv = global.crypto.getRandomValues(new Uint8Array(12));
    const pt = TE.encode(JSON.stringify(obj));
    const ct = new Uint8Array(await subtle().encrypt({ name: 'AES-GCM', iv }, key, pt));
    return { iv: u8ToB64(iv), ct: u8ToB64(ct) };
}

async function unseal(wrapped, key) {
    const pt = new Uint8Array(await subtle().decrypt(
        { name: 'AES-GCM', iv: b64ToU8(wrapped.iv) }, key, b64ToU8(wrapped.ct)));
    return JSON.parse(TD.decode(pt));
}

/**
 * The Vault holds the app's private state behind one passphrase.
 * storage[, optional]: injectable localStorage-like (selftest in Node).
 */
function Vault(storage) {
    this.store = storage || (typeof localStorage !== 'undefined' ? localStorage : null);
    if (!this.store) throw new Error('vault storage unavailable');
    this.key = null;
    this.data = null;
}

const proto = Vault.prototype;

/* true iff a sealed vault already exists (→ passphrase prompt shown on start) */
proto.exists = function() {
    try { return !!JSON.parse(this.store.getItem(VAULT_KEY) || 'null'); } catch (e) { return false; }
};

/* create a new empty vault state; OBVIOUSLY overwrites the old one */
proto.create = async function(pass, seedData) {
    const salt = global.crypto.getRandomValues(new Uint8Array(16));
    this.key = await deriveKey(pass, salt);
    this.data = seedData || { identity: null, contacts: {}, sessions: {}, settings: { notify: true, ringtone: 'pm', vibrate: true, retentionMin: 30 } };
    await this.persist(salt);
    return this.data;
};

/* unlock with passphrase; wrong-pass rejects (GCM auth) instead of corrupting */
proto.open = async function(pass) {
    const raw = JSON.parse(this.store.getItem(VAULT_KEY) || 'null');
    if (!raw) throw new Error('no vault on disk');
    const key = await deriveKey(pass, b64ToU8(raw.salt));
    try {
        this.data = await unseal(raw.payload, key);
    } catch (e) {
        throw new Error('wrong passphrase');
    }
    this.key = key;
    this.saltStore = raw.salt;
    return this.data;
};

/* re-seal current data (call on every mutation, cheap) */
proto.persist = async function(saltOverride) {
    if (!this.key || !this.data) throw new Error('vault locked');
    let salt;
    if (saltOverride instanceof Uint8Array) salt = saltOverride;             // fresh salt from create()
    else if (typeof saltOverride === 'string') salt = b64ToU8(saltOverride); // stable salt on re-save
    else salt = global.crypto.getRandomValues(new Uint8Array(16));
    const payload = await seal(this.data, this.key);
    this.store.setItem(VAULT_KEY, JSON.stringify({ v: 1, salt: u8ToB64(salt), payload }));
    try { this.saltStore = u8ToB64(salt); } catch (e) {}
};

proto.save = function(data) { this.data = data || this.data; return this.persist(this.saltStore); };

proto.lock = function() {
    this.key = null;      // key erased from memory
    this.data = null;
};

Object.defineProperty(proto, 'unlocked', {
    get: function() { return !!(this.key && this.data); }
});

/* additions to seedData default shape (Phase 3): contacts keyed by onion,
 * sessions store ratchet dumpState() blobs, tor inits }
 */
Vault.VAULT_KEY = VAULT_KEY;
Vault.u8ToB64 = u8ToB64;
Vault.b64ToU8 = b64ToU8;

global.Vault = Vault;

})(typeof window !== 'undefined' ? window : globalThis);
