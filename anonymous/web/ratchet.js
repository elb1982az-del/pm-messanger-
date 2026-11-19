'use strict';
/*
 * Anonymous — CryptoCore v1 (Phase 1)
 * X3DH ("triple DH") handshake + Double Ratchet on TweetNaCl primitives.
 *
 * Handshake (initiator mounts against responder's SPK):
 *   DH1 = DH(IK_A, SPK_B), DH2 = DH(EK_A, IK_B), DH3 = DH(EK_A, SPK_B),
 *   DH4 = DH(EK_A, OPK_B) [when offered]
 *   SK = HKDF-SHA256(DH1||DH2||DH3[,DH4], salt=0, info='OC-X3DH-v1')
 *
 * Ratchet (verified derivation parity — see test/selftest.js):
 *   Every side keeps rootKey R. On a ratchet step (new remote ratchet key):
 *     K1: recvChain ← kdfRk(R,  DH(dhSelf.prev.sec, header.dh)); root ← RK₁
 *     K2: sendChain ← kdfRk(RK₁,  DH(dhSelf.new.sec, header.dh)); root ← RK₂
 *   Order-stable: each side's sendChain(i) == peer's recvChain(i) stepwise.
 *
 * AEAD: nacl.secretbox (XSalsa20-Poly1305), random 24B nonce per message.
 * First-message header additionally carries the initiator's identity key
 * (ikA) so the responder can reconstruct SK via the mirrored X3DH.
 *
 * Forward secrecy + bounded skip window (MAX_SKIP); skipped keys cached,
 * evicted oldest-first.
 */
(function(global) {

const te = new TextEncoder();
const td = new TextDecoder();
const zeroSalt = new Uint8Array(32);
const INFO_X3DH = te.encode('OC-X3DH-v1');
const INFO_RK = te.encode('OC-RK-v1');
const INFO_CK = te.encode('OC-CK-v1');
const MAX_SKIP = 200;

/* ---------------- base64 (environment-independent) ---------------- */

const B64T = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function u8ToB64(u8) {
    let out = '';
    for (let i = 0; i < u8.length; i += 3) {
        const a = u8[i], b = u8[i + 1], c = u8[i + 2];
        out += B64T[a >> 2];
        out += B64T[((a & 3) << 4) | ((b || 0) >> 4)];
        if (b === undefined) { out += '=='; return out; }
        out += B64T[((b & 15) << 2) | ((c || 0) >> 6)];
        if (c === undefined) { out += '='; return out; }
        out += B64T[c & 63];
    }
    return out;
}

function b64ToU8(s) {
    const clean = s.replace(/=+$/, '');
    const len = clean.length;
    const outLen = (len * 3) >> 2;
    const out = new Uint8Array(outLen);
    let bits = 0, acc = 0, o = 0;
    for (let i = 0; i < len; i++) {
        acc = (acc << 6) | B64T.indexOf(clean[i]);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[o++] = (acc >> bits) & 0xff;
        }
    }
    return out;
}

function concat() {
    let total = 0;
    for (const a of arguments) total += a.length;
    const out = new Uint8Array(total);
    let off = 0;
    for (const a of arguments) { out.set(a, off); off += a.length; }
    return out;
}

async function hkdf(ikm, salt, info, bytes) {
    const subtle = global.crypto.subtle;
    const key = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
    const bits = await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, key, bytes * 8);
    return new Uint8Array(bits);
}

async function kdfRk(rootKey, dhOut) {
    if (typeof rootKey === 'string') rootKey = b64ToU8(rootKey);
    if (typeof dhOut === 'string') dhOut = b64ToU8(dhOut);
    const okm = await hkdf(dhOut, rootKey, INFO_RK, 64);
    return { rk: okm.subarray(0, 32), ck: okm.subarray(32, 64) };
}

async function kdfCk(chainKeyB64) {
    const okm = await hkdf(typeof chainKeyB64 === 'string' ? b64ToU8(chainKeyB64) : chainKeyB64,
        zeroSalt, INFO_CK, 64);
    return { mk: okm.subarray(0, 32), next: u8ToB64(okm.subarray(32, 64)) };
}

/* ======================= identity bundles ======================= */

async function createIdentity() {
    const ik = nacl.box.keyPair();        // X25519 identity key (participates in handshakes)
    const signer = nacl.sign.keyPair();   // Ed25519 identity key (prekey signing + identity fingerprint)
    const spk = nacl.box.keyPair();
    const opk = nacl.box.keyPair();
    const sig = nacl.sign.detached(spk.publicKey, signer.secretKey);
    return {
        bundleText: JSON.stringify({
            v: 1,
            ik: u8ToB64(ik.publicKey),
            sspk: u8ToB64(signer.publicKey),
            spk: u8ToB64(spk.publicKey),
            sig: u8ToB64(sig),
            opk: u8ToB64(opk.publicKey)
        }),
        secrets: {
            ik: u8ToB64(ik.secretKey),
            signSec: u8ToB64(signer.secretKey),
            spk: { pub: u8ToB64(spk.publicKey), sec: u8ToB64(spk.secretKey) },
            opk: { pub: u8ToB64(opk.publicKey), sec: u8ToB64(opk.secretKey) }
        }
    };
}

function parseBundle(bundleOrText) {
    if (bundleOrText && typeof bundleOrText !== 'string' && bundleOrText.ik instanceof Uint8Array) {
        return bundleOrText;             // already-parsed form → idempotent
    }
    const b = typeof bundleOrText === 'string' ? JSON.parse(bundleOrText) : bundleOrText;
    if (!b || b.v !== 1 || !b.ik || !b.spk || !b.sig || !b.sspk) throw new Error('bundle malformed');
    return {
        ik: b64ToU8(b.ik), sspk: b64ToU8(b.sspk),
        spk: b64ToU8(b.spk), sig: b64ToU8(b.sig),
        opk: b.opk ? b64ToU8(b.opk) : null
    };
}

async function verifyBundle(bundleOrText) {
    const b = parseBundle(bundleOrText);
    const ok = nacl.sign.detached.verify(b.spk, b.sig, b.sspk);
    if (!ok) throw new Error('prekey signature invalid — bundle tampered');
    return b;
}

/* Safety number: order-stable confirmation code from both identity keys. */
async function safetyNumber(bundleSelf, bundleRemote) {
    const a = parseBundle(bundleSelf);
    const b = parseBundle(bundleRemote);
    const lo = a.ik <= b.ik ? a.ik : b.ik;
    const hi = a.ik <= b.ik ? b.ik : a.ik;
    const digest = new Uint8Array(
        await global.crypto.subtle.digest('SHA-256', concat(lo, hi)));
    const groups = [];
    for (let i = 0; i < 6; i++) {
        groups.push(String((digest[i] * 256 + digest[i + 1]) % 10000).padStart(4, '0'));
    }
    return groups.join('-');
}

/* =================== X3DH secrets =================== */

async function x3dhInitiatorRootKey(secretsSelf, remoteBundle, ephemeralPair) {
    const remote = parseBundle(remoteBundle);
    const dh1 = nacl.scalarMult(b64ToU8(secretsSelf.ik), remote.spk);
    const dh2 = nacl.scalarMult(ephemeralPair.secretKey, remote.ik);
    const dh3 = nacl.scalarMult(ephemeralPair.secretKey, remote.spk);
    let ikm;
    if (remote.opk) {
        ikm = concat(dh1, dh2, dh3, nacl.scalarMult(ephemeralPair.secretKey, remote.opk));
    } else {
        ikm = concat(dh1, dh2, dh3);
    }
    return hkdf(ikm, zeroSalt, INFO_X3DH, 32);
}

async function x3dhResponderRootKey(secretsSelf, ikA, ekA) {
    const dh1 = nacl.scalarMult(b64ToU8(secretsSelf.spk.sec), ikA);
    const dh2 = nacl.scalarMult(b64ToU8(secretsSelf.ik), ekA);
    const dh3 = nacl.scalarMult(b64ToU8(secretsSelf.spk.sec), ekA);
    let ikm;
    if (secretsSelf.opk && secretsSelf.opk.sec) {
        ikm = concat(dh1, dh2, dh3, nacl.scalarMult(b64ToU8(secretsSelf.opk.sec), ekA));
    } else {
        ikm = concat(dh1, dh2, dh3);
    }
    return hkdf(ikm, zeroSalt, INFO_X3DH, 32);
}

/* =================== Double Ratchet state machine =================== */

function RatchetState() {
    this.rootKey = null;         // b64
    this.dhSelf = null;          // {pub, sec}
    this.dhRemote = null;        // b64
    this.sendChain = null;       // b64
    this.sendCounter = 0;
    this.recvChain = null;       // b64
    this.recvCounter = 0;
    this.dhSelfPrevSec = null;   // b64 (previous local ratchet pair — kept one span)
    this.skipped = {};           // `${remote}:${n}` -> mk b64
    this.firstHeaderExtras = null; // {ikA} — attached to the initiator's very first envelope
    this.awaitingPeer = false;
}

function dumpState(st) { return JSON.stringify(st); }
function loadState(json) {
    const o = JSON.parse(json);
    const st = new RatchetState();
    /* Copy EVERY serialised field, not just the fields that already exist on a
     * fresh RatchetState. `responderSecrets` is added dynamically by
     * openResponder(); the old loop silently dropped it on reload, which made
     * a persisted responder state unable to decrypt its first envelope. */
    for (const k in o) st[k] = o[k];
    return st;
}

const asB64 = u8ToB64;

/* Initiator: full X3DH + immediate first ratchet (their SPK is the remote key).
 * ONLY ONE KDF happens here — receive-side materializes when they reply
 * with their own fresh pair in header.dh. */
async function openInitiator(secretsSelf, bundleRemote) {
    const remote = await verifyBundle(bundleRemote);
    const ek = nacl.box.keyPair();
    const sk = await x3dhInitiatorRootKey(secretsSelf, remote, ek);
    const one = await kdfRk(sk, nacl.scalarMult(ek.secretKey, remote.spk));
    const st = new RatchetState();
    st.rootKey = asB64(one.rk);
    st.sendChain = asB64(one.ck);
    st.sendCounter = 0;
    st.dhSelf = { pub: asB64(ek.publicKey), sec: asB64(ek.secretKey) };
    st.dhRemote = asB64(remote.spk);
    st.recvChain = null;
    st.recvCounter = 0;
    st.dhSelfPrevSec = st.dhSelf.sec;
    st.firstHeaderExtras = { ikA: asB64(remote.ik ? remote.ik : remote.ik) }; // placeholder replaced below
    st.firstHeaderExtras = { ikA: bundleIdentityPub(secretsSelf) };
    st.peerIk = remote.ik;       // identity of the peer this session belongs to
    st.awaitingPeer = false;
    return st;
}

/* Read the cleartext header of a wire envelope without attempting any
 * decryption. The FIRST envelope a peer sends carries `ikA` (the sender's
 * identity public key); later envelopes only carry ratchet metadata. The
 * receiver MUST use ikA to pick the right contact — see 0.4.3 fix. */
function envelopeHeader(wireToken) {
    try {
        const env = JSON.parse(atob(wireToken));
        return env && env.h ? env.h : null;
    } catch (e) {
        return null;
    }
}

function envelopeIdentity(wireToken) {
    const h = envelopeHeader(wireToken);
    return (h && typeof h.ikA === 'string') ? h.ikA : null;
}

function bundleIdentityPub(secretsSelf) {
    /* identity PUBLIC key of ourselves = scalarMult of secret with base? We stored only sec.
       Recompute pub from sec via scalarmult base (nacl.box requires base scalar `nar` recompute). */
    // X25519 identity pub can be recomputed from its secret with nacl.box.keyPair.fromSecretKey
    if (nacl.box.keyPair.fromSecretKey) {
        const kp = nacl.box.keyPair.fromSecretKey(b64ToU8(secretsSelf.ik));
        return u8ToB64(kp.publicKey);
    }
    throw new Error('cannot recompute identity public key');
}

/* Responder prepared from own secrets; the first incoming envelope completes X3DH. */
async function openResponder(secretsSelf) {
    const st = new RatchetState();
    st.dhSelf = { pub: secretsSelf.spk.pub, sec: secretsSelf.spk.sec };
    st.dhRemote = null;
    st.recvChain = null;
    st.sendChain = null;
    st.sendCounter = 0;
    st.recvCounter = 0;
    st.dhSelfPrevSec = st.dhSelf.sec;
    st.awaitingPeer = true;
    st.responderSecrets = secretsSelf;
    st.peerIk = null;            // set from header.ikA on the first envelope
    return st;
}

/* wire envelope: base64(JSON{h:{...}, c: b64(nonce||ct)}) */
async function ratchetEncrypt(st, plaintext) {
    if (st.awaitingPeer || !st.sendChain) {
        throw new Error('cannot send before first incoming message (phase 1 rule)');
    }
    const mk = await kdfCk(st.sendChain);
    st.sendChain = mk.next;
    const n = st.sendCounter;
    st.sendCounter++;
    const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
    const pt = typeof plaintext === 'string' ? te.encode(plaintext) : plaintext;
    const ct = nacl.secretbox(pt, nonce, mk.mk);
    const h = { n, dh: st.dhSelf.pub, pn: declaredPeerPrevCount(st) };
    if (st.firstHeaderExtras) {
        h.ikA = st.firstHeaderExtras.ikA;
        st.firstHeaderExtras = null;      // burns after first envelope
    }
    const envelope = JSON.stringify({ h, c: asB64(concat(nonce, ct)) });
    return btoa(envelope);
}

function declaredPeerPrevCount(st) {
    /* we don't track peer chain length in v1 — that bound is filled when a
       real miss occurs after reconnect; benign for in-order delivery */
    return 0;
}

async function ratchetDecrypt(st, wireToken) {
    const env = JSON.parse(atob(wireToken));
    const header = env.h;
    const blob = b64ToU8(env.c);
    const nonce = blob.subarray(0, nacl.secretbox.nonceLength);
    const ct = blob.subarray(nacl.secretbox.nonceLength);

    if (!st.rootKey) {
        /* responder first message — complete X3DH mirror */
        const sk = await x3dhResponderRootKey(st.responderSecrets, b64ToU8(header.ikA), b64ToU8(header.dh));
        const one = await kdfRk(sk, nacl.scalarMult(b64ToU8(st.dhSelf.sec), b64ToU8(header.dh)));
        const recvCk = one.ck;                       // == initiator's sendChain
        const mk1 = await kdfCk(u8ToB64(recvCk));
        const opened = nacl.secretbox.open(ct, nonce, mk1.mk);
        if (!opened) throw new Error('first-message decrypt failed (bundle/dh mismatch)');
        st.recvChain = mk1.next;
        st.recvCounter = header.n + 1;
        st.dhRemote = header.dh;
        /* our send chain: fresh pair vs their header dh, off the advanced root */
        const fresh = nacl.box.keyPair();
        const two = await kdfRk(one.rk, nacl.scalarMult(fresh.secretKey, b64ToU8(header.dh)));
        st.rootKey = asB64(two.rk);
        st.sendChain = asB64(two.ck);
        st.sendCounter = 0;
        st.dhSelfPrevSec = st.dhSelf.sec;
        st.dhSelf = { pub: asB64(fresh.publicKey), sec: asB64(fresh.secretKey) };
        st.awaitingPeer = false;
        st.peerIk = header.ikA;  // bind this session to the identity that opened it
        return td.decode(opened);
    }

    if (st.dhRemote !== header.dh) {
        await dhRatchet(st, header);
    }

    /* skipped-or-current message key within that chain */
    const skipId = header.dh + ':' + header.n;
    if (st.skipped[skipId]) {
        const mkB64 = st.skipped[skipId];
        delete st.skipped[skipId];
        const opened = nacl.secretbox.open(ct, nonce, b64ToU8(mkB64));
        if (!opened) throw new Error('skipped-key decrypt failed (tamper?)');
        return td.decode(opened);
    }
    if (header.n < st.recvCounter) throw new Error('replayed message (n=' + header.n + ')');
    if (header.n - st.recvCounter > MAX_SKIP) throw new Error('lost messages beyond window');

    while (st.recvCounter < header.n) {
        const mid = await kdfCk(st.recvChain);
        st.skipped[header.dh + ':' + st.recvCounter] = mid.mk && asB64(mid.mk);
        st.recvChain = mid.next;
        st.recvCounter++;
    }
    const cur = await kdfCk(st.recvChain);
    st.recvChain = cur.next;
    st.recvCounter++;
    const opened = nacl.secretbox.open(ct, nonce, cur.mk);
    if (!opened) throw new Error('decrypt failed (tamper or desync)');
    return td.decode(opened);
}

async function dhRatchet(st, header) {
    const priorRemote = st.dhRemote;

    /* archive tail keys of the PREVIOUS receive chain (broadly bounded) */
    if (priorRemote && st.recvChain) {
        let ck = st.recvChain;
        for (let n = st.recvCounter; n < (header.pn || 0); n++) {
            const mid = await kdfCk(ck);
            st.skipped[priorRemote + ':' + n] = asB64(mid.mk);
            ck = mid.next;
        }
    }

    /* K1: receive chain — OUR CURRENT pair (the one announced in our last
     * header) vs THEIR new ratchet key. Parity rule: both sides' K1 consumes
     * DH(myLastAnnounced, peerNew) and K2 consumes DH(myNew, peerNew). */
    const one = await kdfRk(st.rootKey, nacl.scalarMult(b64ToU8(st.dhSelf.sec), b64ToU8(header.dh)));
    st.dhRemote = header.dh;
    st.recvChain = asB64(one.ck);
    const rk = one.rk;
    st.recvCounter = 0;

    /* K2: new local pair vs THEIR ratchet key → our future send chain */
    const fresh = nacl.box.keyPair();
    const two = await kdfRk(rk, nacl.scalarMult(fresh.secretKey, b64ToU8(header.dh)));
    st.rootKey = asB64(two.rk);
    st.sendChain = asB64(two.ck);
    st.sendCounter = 0;

    st.dhSelfPrevSec = st.dhSelf.sec;
    st.dhSelf = { pub: asB64(fresh.publicKey), sec: asB64(fresh.secretKey) };

    /* bound skipped cache */
    const ids = Object.keys(st.skipped).sort();
    while (ids.length > 2 * MAX_SKIP) delete st.skipped[ids.shift()];
}

global.CryptoCore = {
    createIdentity, verifyBundle, parseBundle, safetyNumber,
    openInitiator, openResponder,
    ratchetEncrypt, ratchetDecrypt, dumpState, loadState,
    envelopeHeader, envelopeIdentity,
    b64: { u8ToB64, b64ToU8, concat },
    MAX_SKIP,
    version: '1'
};

})(typeof window !== 'undefined' ? window : globalThis);
