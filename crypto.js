// Async crypto transforms: one-way hashing + reversible encryption.
// Unlike generators.js (random output), these take USER INPUT and transform it.
// Native Web Crypto wherever possible; bcrypt / argon2 / MD5 come from a WASM
// library that is loaded lazily — only fetched if one of those algorithms runs.
// All work happens in the browser; nothing is sent anywhere.

import {
  randomBytes,
  randomFromCharset,
  bytesToHex,
  bytesToBase64,
  bytesToBase64Url,
} from './generators.js';

const enc = new TextEncoder();
const dec = new TextDecoder();
const subtle = crypto.subtle;

// Django's get_random_string() salt alphabet (string.ascii_letters + digits).
const SALT_CHARS =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

// Pinned WASM hashing lib. base64-inlined wasm → single import, no extra fetch,
// works from a CDN on GitHub Pages with no build step.
const HASH_WASM_URL = 'https://esm.sh/hash-wasm@4.12.0';
let _hashWasm = null;
async function loadHashWasm() {
  if (!_hashWasm) {
    _hashWasm = import(/* @vite-ignore */ HASH_WASM_URL).catch((err) => {
      _hashWasm = null;
      throw new Error('Could not load the bcrypt/argon2/MD5 library (offline?)');
    });
  }
  return _hashWasm;
}

// ---------- byte helpers (decoders not in generators.js) ----------
function base64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function base64UrlToBytes(s) {
  let b64 = s.replaceAll('-', '+').replaceAll('_', '/');
  while (b64.length % 4) b64 += '=';
  return base64ToBytes(b64);
}

function concatBytes(...arrays) {
  let len = 0;
  for (const a of arrays) len += a.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

// ---------- One-way hashing ----------

// django.contrib.auth.hashers.PBKDF2PasswordHasher — verified byte-compatible
// with check_password(). Format: pbkdf2_sha256$<iterations>$<salt>$<b64 hash>.
export async function djangoPbkdf2(password, { iterations = 1000000 } = {}) {
  const salt = randomFromCharset(12, SALT_CHARS);
  const km = await subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, [
    'deriveBits',
  ]);
  const bits = await subtle.deriveBits(
    { name: 'PBKDF2', salt: enc.encode(salt), iterations, hash: 'SHA-256' },
    km,
    256,
  );
  const hash = bytesToBase64(new Uint8Array(bits));
  return `pbkdf2_sha256$${iterations}$${salt}$${hash}`;
}

// django.contrib.auth.hashers.Argon2PasswordHasher (argon2id, Django defaults).
export async function djangoArgon2(password) {
  const { argon2id } = await loadHashWasm();
  const encoded = await argon2id({
    password,
    salt: randomBytes(16),
    parallelism: 8,
    iterations: 2,
    memorySize: 102400,
    hashLength: 32,
    outputType: 'encoded',
  });
  // argon2id() → "$argon2id$v=19$..."; Django prepends its algorithm id.
  return 'argon2' + encoded;
}

// django.contrib.auth.hashers.BCryptSHA256PasswordHasher.
// Django SHA-256s the password (base64) before bcrypt to dodge bcrypt's 72-byte
// truncation, then stores bcrypt_sha256$<bcrypt hash>.
export async function djangoBcryptSha256(password, { costFactor = 12 } = {}) {
  const inner = await bcryptRaw(await sha256Base64(password), costFactor);
  return 'bcrypt_sha256$' + inner;
}

// Plain bcrypt — $2b$<cost>$<salt+hash>.
export async function bcryptHash(password, { costFactor = 12 } = {}) {
  return bcryptRaw(password, costFactor);
}

async function bcryptRaw(password, costFactor) {
  const { bcrypt } = await loadHashWasm();
  const hash = await bcrypt({
    password,
    salt: randomBytes(16),
    costFactor,
    outputType: 'encoded',
  });
  // hash-wasm emits the legacy "$2a$" tag; rewrite to "$2b$" to match Django /
  // modern tooling. The digest is identical for normal-length passwords, and
  // the rewritten hash verifies cleanly (checked against bcryptVerify).
  return hash.startsWith('$2a$') ? '$2b$' + hash.slice(4) : hash;
}

async function sha256Base64(text) {
  const buf = await subtle.digest('SHA-256', enc.encode(text));
  return bytesToBase64(new Uint8Array(buf));
}

export async function shaHex(text, algo) {
  const buf = await subtle.digest(algo, enc.encode(text));
  return bytesToHex(new Uint8Array(buf));
}

export async function md5Hex(text) {
  const { md5 } = await loadHashWasm();
  return md5(text);
}

// ---------- AES-256-GCM (passphrase-based, reversible) ----------
const AES_PBKDF2_ITERS = 200000;

async function deriveAesKey(passphrase, salt) {
  const km = await subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, [
    'deriveKey',
  ]);
  return subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: AES_PBKDF2_ITERS, hash: 'SHA-256' },
    km,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

// Output is base64( salt[16] || iv[12] || ciphertext+tag ).
export async function aesGcmEncrypt(plaintext, passphrase) {
  if (!passphrase) throw new Error('A key / passphrase is required');
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = await deriveAesKey(passphrase, salt);
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plaintext));
  return bytesToBase64(concatBytes(salt, iv, new Uint8Array(ct)));
}

export async function aesGcmDecrypt(token, passphrase) {
  if (!passphrase) throw new Error('A key / passphrase is required');
  let raw;
  try {
    raw = base64ToBytes(token.trim());
  } catch {
    throw new Error('Input is not valid base64');
  }
  if (raw.length < 16 + 12 + 16) throw new Error('Ciphertext is too short / malformed');
  const salt = raw.slice(0, 16);
  const iv = raw.slice(16, 28);
  const ct = raw.slice(28);
  const key = await deriveAesKey(passphrase, salt);
  try {
    const pt = await subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
    return dec.decode(pt);
  } catch {
    throw new Error('Decryption failed — wrong key or corrupted data');
  }
}

// ---------- Fernet (interops with Python cryptography.Fernet) ----------
// Token = urlsafe_b64( 0x80 || ts[8] || iv[16] || AES-128-CBC(pt) || HMAC[32] ).
// Key = urlsafe_b64 of 32 bytes: first 16 sign (HMAC), last 16 encrypt (AES).

function parseFernetKey(s) {
  let bytes;
  try {
    bytes = base64UrlToBytes((s || '').trim());
  } catch {
    throw new Error('Fernet key must be url-safe base64');
  }
  if (bytes.length !== 32) {
    throw new Error('Fernet key must decode to 32 bytes (use the "Fernet key" card)');
  }
  return bytes;
}

function writeUint64BE(arr, num) {
  const high = Math.floor(num / 0x100000000);
  const low = num >>> 0;
  arr[0] = (high >>> 24) & 0xff;
  arr[1] = (high >>> 16) & 0xff;
  arr[2] = (high >>> 8) & 0xff;
  arr[3] = high & 0xff;
  arr[4] = (low >>> 24) & 0xff;
  arr[5] = (low >>> 16) & 0xff;
  arr[6] = (low >>> 8) & 0xff;
  arr[7] = low & 0xff;
}

export async function fernetEncrypt(plaintext, keyStr) {
  const key = parseFernetKey(keyStr);
  const signingKey = key.slice(0, 16);
  const encKey = key.slice(16, 32);

  const ts = new Uint8Array(8);
  writeUint64BE(ts, Math.floor(Date.now() / 1000));
  const iv = randomBytes(16);

  const aesKey = await subtle.importKey('raw', encKey, { name: 'AES-CBC' }, false, [
    'encrypt',
  ]);
  // Web Crypto AES-CBC applies PKCS#7 padding automatically — exactly Fernet's scheme.
  const ct = new Uint8Array(
    await subtle.encrypt({ name: 'AES-CBC', iv }, aesKey, enc.encode(plaintext)),
  );

  const body = concatBytes(new Uint8Array([0x80]), ts, iv, ct);
  const hmacKey = await subtle.importKey(
    'raw',
    signingKey,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const mac = new Uint8Array(await subtle.sign('HMAC', hmacKey, body));
  return bytesToBase64Url(concatBytes(body, mac), { padding: true });
}

export async function fernetDecrypt(tokenStr, keyStr) {
  const key = parseFernetKey(keyStr);
  const signingKey = key.slice(0, 16);
  const encKey = key.slice(16, 32);

  let token;
  try {
    token = base64UrlToBytes((tokenStr || '').trim());
  } catch {
    throw new Error('Token is not valid url-safe base64');
  }
  if (token.length < 1 + 8 + 16 + 32) throw new Error('Token is too short / malformed');
  if (token[0] !== 0x80) throw new Error('Unsupported Fernet version');

  const mac = token.slice(token.length - 32);
  const body = token.slice(0, token.length - 32);
  const hmacKey = await subtle.importKey(
    'raw',
    signingKey,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify'],
  );
  if (!(await subtle.verify('HMAC', hmacKey, mac, body))) {
    throw new Error('HMAC check failed — wrong key or tampered token');
  }

  const iv = token.slice(9, 25);
  const ct = token.slice(25, token.length - 32);
  const aesKey = await subtle.importKey('raw', encKey, { name: 'AES-CBC' }, false, [
    'decrypt',
  ]);
  try {
    const pt = await subtle.decrypt({ name: 'AES-CBC', iv }, aesKey, ct);
    return dec.decode(pt);
  } catch {
    throw new Error('Decryption failed');
  }
}

// ---------- Card-facing dispatchers (called by app.js with an options object) ----------

export async function hashText({ algorithm = 'pbkdf2_sha256', text = '' } = {}) {
  switch (algorithm) {
    case 'pbkdf2_sha256':
      return djangoPbkdf2(text);
    case 'argon2':
      return djangoArgon2(text);
    case 'bcrypt_sha256':
      return djangoBcryptSha256(text);
    case 'bcrypt':
      return bcryptHash(text);
    case 'sha512':
      return shaHex(text, 'SHA-512');
    case 'sha384':
      return shaHex(text, 'SHA-384');
    case 'sha1':
      return shaHex(text, 'SHA-1');
    case 'md5':
      return md5Hex(text);
    case 'sha256':
    default:
      return shaHex(text, 'SHA-256');
  }
}

export async function cipherText({ format = 'aes-gcm', mode = 'encrypt', key = '', text = '' } = {}) {
  if (format === 'fernet') {
    return mode === 'decrypt' ? fernetDecrypt(text, key) : fernetEncrypt(text, key);
  }
  return mode === 'decrypt' ? aesGcmDecrypt(text, key) : aesGcmEncrypt(text, key);
}
