'use strict';
/* Vault self-test (Phase 2): seal/unseal round trip, wrong-pass rejection,
 * persistence across open() cycles, plaintext-at-rest scan. Runs in Node. */
globalThis.nacl = require('tweetnacl');
require('../web/ratchet.js');
require('../web/vault.js');
const Vault = globalThis.Vault;

function makeStorage() {
    const m = new Map();
    return {
        getItem: k => (m.has(k) ? m.get(k) : null),
        setItem: (k, v) => m.set(k, String(v)),
        removeItem: k => m.delete(k),
        dump: () => [...m.entries()],
        keys: () => [...m.keys()]
    };
}

async function main() {
    let passed = 0;
    const failures = [];
    const ok = (cond, name) => { if (cond) passed++; else { failures.push(name); console.error('FAIL: ' + name); } };

    /* 1. create + exists */
    const store = makeStorage();
    const v1 = new Vault(store);
    ok(!v1.exists(), 'empty storage: exists() false');
    await v1.create('correct horse 🐴');
    ok(v1.exists(), 'created vault visible via exists()');
    ok(v1.unlocked, 'vault unlocked after create');

    /* 2. data shape + identity inside */
    v1.data.identity = { note: 'opaque-blob-XYZ' };
    await v1.save();

    /* 3. reopen with correct passphrase in a fresh Vault instance */
    const v2 = new Vault(store);
    const data = await v2.open('correct horse 🐴');
    ok(data.identity && data.identity.note === 'opaque-blob-XYZ', 'round trip across open() preserves data');
    ok(v2.unlocked, 'reopened vault unlocked');

    /* 4. wrong passphrase rejected, data NOT corrupted */
    const v3 = new Vault(store);
    let rejected = false;
    try { await v3.open('wrong-pass'); } catch (e) { rejected = String(e.message).indexOf('wrong passphrase') !== -1; }
    ok(rejected, 'wrong passphrase rejected with clean error');
    const again = new Vault(store);
    ok((await again.open('correct horse 🐴')).identity.note === 'opaque-blob-XYZ', 'vault intact after wrong-pass attempt');

    /* 5. lock() drops state */
    again.lock();
    ok(!again.unlocked, 'lock() clears key+data');

    /* 6. mutation + save persists for future opens */
    const v4 = new Vault(store);
    await v4.open('correct horse 🐴');
    v4.data.contacts = { abc123: { name: 'peer', bundleText: '{}' } };
    await v4.save();
    const v5 = new Vault(store);
    ok((await v5.open('correct horse 🐴')).contacts.abc123.name === 'peer', 'contacts mutation survives reopen');

    /* 7. plaintext-at-rest scan: only the sealed blob is in storage, and none
     *    of our secrets/keys/fields leak into it unencrypted */
    ok(store.keys().length === 1 && store.keys()[0] === Vault.VAULT_KEY, 'exactly one storage key (oc_vault_v1)');
    const raw = store.getItem(Vault.VAULT_KEY);
    const leaks = ['opaque-blob-XYZ', 'peer', 'bundleText', 'signSec', 'secretKey'];
    let leaked = leaks.filter(l => raw.indexOf(l) !== -1);
    ok(leaked.length === 0, 'no plaintext material in the stored blob (leaked: ' + leaked.join(',') + ')');
    ok(JSON.parse(raw).v === 1 && !!JSON.parse(raw).salt && !!JSON.parse(raw).payload, 'sealed blob shape {v,salt,payload}');

    /* 8. ratchet session dumps survive a vault seal/unseal and keep talking */
    const C = globalThis.CryptoCore;
    const A = await C.createIdentity();
    const B = await C.createIdentity();
    const stA = await C.openInitiator(A.secrets, B.bundleText);
    const stB = await C.openResponder(B.secrets);
    ok(await C.ratchetDecrypt(stB, await C.ratchetEncrypt(stA, 'pre-vault one')) === 'pre-vault one', 'pre-vault handshake turn 1');
    ok(await C.ratchetDecrypt(stA, await C.ratchetEncrypt(stB, 'pre-vault two')) === 'pre-vault two', 'pre-vault handshake turn 2');
    const store2 = makeStorage();
    const v6 = new Vault(store2);
    await v6.create('p2');
    v6.data.identity = A.bundleText;
    v6.data.sessions = { A: { dump: C.dumpState(stA) }, B: { dump: C.dumpState(stB) } };
    await v6.save();
    const v7 = new Vault(store2);
    const rdata = await v7.open('p2');
    const rA = C.loadState(rdata.sessions.A.dump);
    const rB = C.loadState(rdata.sessions.B.dump);
    ok(await C.ratchetDecrypt(rB, await C.ratchetEncrypt(rA, 'post-vault three')) === 'post-vault three', 'restored A sends → restored B decrypts');
    ok(await C.ratchetDecrypt(rA, await C.ratchetEncrypt(rB, 'post-vault four')) === 'post-vault four', 'restored B sends → restored A decrypts');

    console.log(passed + ' checks passed, ' + failures.length + ' failures');
    if (failures.length) { console.error('FAILURES: ' + failures.join(', ')); process.exit(1); }
}

main().catch(e => { console.error('HARNESS CRASH: ' + e.stack); process.exit(2); });
