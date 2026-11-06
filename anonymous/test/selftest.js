'use strict';
/* CryptoCore self-test: full X3DH+Ratchet gauntlet run in Node.
 * Exit code 0 only on full pass. */
const nacl = require('tweetnacl');
globalThis.nacl = nacl;
require('../web/ratchet.js');
const C = globalThis.CryptoCore;

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function main() {
    const failures = [];
    let passed = 0;
    const ok = (cond, name) => { if (cond) { passed++; } else { failures.push(name); console.error('FAIL: ' + name); } };

    /* 1. identity creation + bundle signature */
    const A = await C.createIdentity();
    const B = await C.createIdentity();
    const bA = JSON.parse(A.bundleText);
    const bB = JSON.parse(JSON.stringify(JSON.parse(B.bundleText)));
    const verifiedB = await C.verifyBundle(B.bundleText);
    ok(verifiedB.ik.length === 32, 'bundle verification ok');

    /* 2. tamper detection */
    let tamperCaught = false;
    {
        const tampered = JSON.parse(bB && B.bundleText);        // fresh copy
        const sigU8 = C.b64.b64ToU8(tampered.sig);
        sigU8[Tamper(sigU8)] ^= 1;
        tampered.sig = C.b64.u8ToB64(sigU8);
        try { await C.verifyBundle(JSON.stringify(tampered)); } catch (e) { tamperCaught = true; }
    }
    ok(tamperCaught, 'tampered prekey signature rejected');

    /* 3. safety number symmetric */
    const sn1 = await C.safetyNumber(A.bundleText, B.bundleText);
    const sn2 = await C.safetyNumber(B.bundleText, A.bundleText);
    ok(sn1 === sn2 && sn1.length === 29, 'safety number order-stable');

    /* 4. basic session: A initiates, sends, B replies */
    const stA = await C.openInitiator(A.secrets, B.bundleText);
    const stB = await C.openResponder(B.secrets);
    const m1 = await C.ratchetEncrypt(stA, 'hello α π 🚀');
    const d1 = await C.ratchetDecrypt(stB, m1);
    ok(d1 === 'hello α π 🚀', 'first message decrypt');

    const m1b = await C.ratchetEncrypt(stB, 'reply one');
    const d1b = await C.ratchetDecrypt(stA, m1b);
    ok(d1b === 'reply one', 'reply decrypt (their ratchet #1)');

    /* 5. long alternating run with real ratchets */
    let running = true;
    for (let i = 2; i <= 24; i++) {
        const from = i % 2 ? stA : stB;
        const to = i % 2 ? stB : stA;
        const tok = await C.ratchetEncrypt(from, 'round ' + i);
        const out = await C.ratchetDecrypt(to, tok);
        if (out !== 'round ' + i) { running = false; failures.push('round ' + i); console.error('FAIL at round ' + i + ': got ' + JSON.stringify(out)); break; }
    }
    ok(running, '24 alternating turns with ratchet steps');

    /* 6. out-of-order: two messages sent, second arrives first (post-bootstrap) */
    const stA2 = await C.openInitiator(A.secrets, B.bundleText);
    const stB2 = await C.openResponder(B.secrets);
    const bootstrap0 = await C.ratchetEncrypt(stA2, 'handshake 0');
    ok(await C.ratchetDecrypt(stB2, bootstrap0) === 'handshake 0', 'responder bootstrap decrypt');
    const bReply0 = await C.ratchetEncrypt(stB2, 'handshake reply 0');
    ok(await C.ratchetDecrypt(stA2, bReply0) === 'handshake reply 0', 'initiator first ratchet decrypt');
    const tok1 = await C.ratchetEncrypt(stA2, 'first');
    const tok2 = await C.ratchetEncrypt(stA2, 'second');
    const dSecond = await C.ratchetDecrypt(stB2, tok2);
    const dFirst = await C.ratchetDecrypt(stB2, tok1);
    ok(dSecond === 'second' && dFirst === 'first', 'out-of-order handled (skipped keys cached)');

    /* 7. tampered ciphertext rejected */
    let tamper2 = false;
    {
        const tokEnv = JSON.parse(atob(tok1));
        const ct = C.b64.b64ToU8(tokEnv.c);
        ct[ct.length - 1] ^= 1;                            // flip one bit
        tokEnv.c = C.b64.u8ToB64(ct);
        const badToken = btoa(JSON.stringify(tokEnv));
        try { await C.ratchetDecrypt(C.loadState(C.dumpState(stB2)), badToken); } catch (e) { tamper2 = true; }
    }
    ok(tamper2, 'bit-flip tamper rejected');

    /* 8. state serialization round trip preserves the session */
    const stA3 = C.loadState(C.dumpState(stA));
    const tok3 = await C.ratchetEncrypt(stA3, 'after serialize');
    const d3 = await C.ratchetDecrypt(stB, tok3);
    ok(d3 === 'after serialize', 'state dump/load round trip');

    /* 9. replay rejection */
    try { await C.ratchetDecrypt(stB, m1); failures.push('replay accepted!'); } catch (e) { passed++; }

    /* 10. 300-burst stress */
    let stressOk = true;
    try {
        const stA4 = await C.openInitiator(A.secrets, B.bundleText);
        const stB4 = await C.openResponder(B.secrets);
        for (let i = 0; i < 300; i++) {
            const tok = await C.ratchetEncrypt(stA4, 'burst ' + i);
            const out = await C.ratchetDecrypt(stB4, tok);
            if (out !== 'burst ' + i) throw new Error('stress mismatch at ' + i);
        }
        const back = await C.ratchetEncrypt(stB4, 'reverse end');
        if (await C.ratchetDecrypt(stA4, back) !== 'reverse end') throw new Error('reverse mismatch');
    } catch (e) { stressOk = false; failures.push('stress: ' + e.message); console.error('stress fail: ' + e.message); }
    ok(stressOk, '300-message burst + reverse turn');

    console.log(passed + ' checks passed, ' + failures.length + ' failures');
    if (failures.length) { console.error('FAILURES: ' + failures.join(', ')); process.exit(1); }
}

function Tamper(s) { return Math.floor(s.length / 2); }
main().catch(e => { console.error('HARNESS CRASH: ' + e.stack); process.exit(2); });
