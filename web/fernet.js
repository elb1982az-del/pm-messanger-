/* Fernet-compatible AES-128-CBC + HMAC-SHA256 using WebCrypto.
   Interoperable with python cryptography.fernet given the same 32-byte key. */
(function (global) {
  const B64U = {
    s2b: (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice(0, (4 - s.replace(/-/g, '+').replace(/_/g, '/').length % 4) % 4)), c => c.charCodeAt(0)),
    b2s: (bytes) => {
      let bin = ''; bytes.forEach(b => bin += String.fromCharCode(b));
      return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_'); // keep '=' padding: Fernet is standard-padded
    }
  };

  const hmacKey = (k16) => crypto.subtle.importKey('raw', k16, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
  const aesKey = (k16) => crypto.subtle.importKey('raw', k16, { name: 'AES-CBC' }, false, ['encrypt', 'decrypt']);

  function parseKey(keyB64) {
    const raw = B64U.s2b(keyB64);
    if (raw.length !== 32) throw new Error('key must be 32 bytes');
    return { signK: raw.slice(0, 16), aesK: raw.slice(16) };
  }
  const tsBe = () => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(Math.floor(Date.now() / 1000))); return b; };

  async function encrypt(keyB64, plaintext) {
    const { signK, aesK } = parseKey(keyB64);
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const msg = new TextEncoder().encode(plaintext);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, await aesKey(aesK), msg));
    const body = new Uint8Array(9 + 16 + ct.length);
    body[0] = 0x80; body.set(tsBe(), 1); body.set(iv, 9); body.set(ct, 25);
    const mac = new Uint8Array(await crypto.subtle.sign('HMAC', await hmacKey(signK), body));
    return B64U.b2s(new Uint8Array([...body, ...mac]));
  }

  async function decrypt(keyB64, token) {
    const { signK, aesK } = parseKey(keyB64);
    const bin = B64U.s2b(token);
    if (bin.length < 57 || bin[0] !== 0x80) throw new Error('malformed token');
    const ctLen = bin.length - 57;
    if (ctLen <= 0 || ctLen % 16) throw new Error('malformed token');
    const body = bin.slice(0, -32), mac = bin.slice(-32);
    const ok = await crypto.subtle.verify('HMAC', await hmacKey(signK), mac, body);
    if (!ok) throw new Error('HMAC check failed');
    const iv = body.slice(9, 25), ct = body.slice(25);
    const plain = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, await aesKey(aesK), ct));
    return new TextDecoder().decode(plain);
  }

  const api = { encrypt, decrypt };
  if (typeof module !== 'undefined' && module.exports) module.exports = api; // node (tests)
  global.FernetLite = api;                                                  // browser
})(typeof self !== 'undefined' ? self : this);
