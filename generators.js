// Pure key/secret generation functions. No DOM, no side effects.
// Each generator takes an options object (where applicable) and returns a string.

// ---------- Charsets ----------
const LOWER = 'abcdefghijklmnopqrstuvwxyz';
const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const DIGITS = '0123456789';
const SYMBOLS = '!@#$%^&*()-_=+[]{};:,.<>?';
const ALPHA = LOWER + UPPER;
const ALPHANUMERIC = ALPHA + DIGITS;
const HEX_CHARS = '0123456789abcdef';
const NANO_DEFAULT = ALPHANUMERIC + '_-';
const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const AMBIGUOUS = '0OoIl1|`';

// ---------- Low-level helpers ----------
export function randomBytes(n) {
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return a;
}

export function bytesToHex(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
  return s;
}

export function bytesToBase64(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

export function bytesToBase64Url(bytes, { padding = false } = {}) {
  const b64 = bytesToBase64(bytes).replaceAll('+', '-').replaceAll('/', '_');
  return padding ? b64 : b64.replace(/=+$/, '');
}

// Bias-free sampling from a charset using rejection sampling.
// `byte % charset.length` skews the distribution unless 256 is a multiple
// of charset.length — for a security-tool site, the modulo shortcut is unacceptable.
export function randomFromCharset(length, charset) {
  const setLen = charset.length;
  if (setLen < 2 || setLen > 256) {
    throw new RangeError('charset length must be between 2 and 256');
  }
  const max = Math.floor(256 / setLen) * setLen;
  const out = new Array(length);
  let filled = 0;
  const drawSize = length + 16;
  while (filled < length) {
    const buf = new Uint8Array(drawSize);
    crypto.getRandomValues(buf);
    for (let i = 0; i < buf.length && filled < length; i++) {
      if (buf[i] < max) out[filled++] = charset[buf[i] % setLen];
    }
  }
  return out.join('');
}

// ---------- Framework presets ----------

// django.core.management.utils.get_random_secret_key()
export function djangoSecretKey() {
  return randomFromCharset(50, 'abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)');
}

// cryptography.fernet.Fernet.generate_key()
// 32 random bytes, urlsafe-base64-encoded WITH padding → 44 chars ending in '='
export function djangoFernetKey() {
  return bytesToBase64Url(randomBytes(32), { padding: true });
}

// secrets.token_hex(32) — 64 hex chars
export function flaskSecretKey() {
  return bytesToHex(randomBytes(32));
}

// rails secret — 128 hex chars (64 random bytes)
export function railsSecretKeyBase() {
  return bytesToHex(randomBytes(64));
}

// php artisan key:generate — 'base64:' + base64(32 bytes)
export function laravelAppKey() {
  return 'base64:' + bytesToBase64(randomBytes(32));
}

// openssl rand -base64 32 — what Auth.js / NextAuth docs recommend
export function nextAuthSecret() {
  return bytesToBase64(randomBytes(32));
}

// ---------- Tokens & secrets (configurable) ----------

export function jwtSecret({ bits = 256, encoding = 'base64' } = {}) {
  return encodeBytes(randomBytes(bits / 8), encoding);
}

export function encryptionKey({ bits = 256, encoding = 'base64' } = {}) {
  return encodeBytes(randomBytes(bits / 8), encoding);
}

export function apiKey({ length = 32, prefix = 'sk_live_', charset = 'alphanumeric' } = {}) {
  const cs = pickCharset(charset);
  return prefix + randomFromCharset(length, cs);
}

// Stripe-style: prefix + hex randomness
export function webhookSecret({ length = 32, prefix = 'whsec_' } = {}) {
  return prefix + bytesToHex(randomBytes(Math.ceil(length / 2))).slice(0, length);
}

// ---------- Identifiers ----------

export function uuidv4() {
  return crypto.randomUUID();
}

// RFC 9562 §5.7 — 48-bit unix-ms ts + version 7 + 12 rand_a + variant 10 + 62 rand_b
export function uuidv7() {
  const ts = Date.now();
  const tsHex = ts.toString(16).padStart(12, '0');
  const r = randomBytes(10);
  const rHex = bytesToHex(r);
  const a = tsHex.slice(0, 8);
  const b = tsHex.slice(8, 12);
  const c = '7' + rHex.slice(0, 3);
  const variantNibble = ((parseInt(rHex[3], 16) & 0x3) | 0x8).toString(16);
  const d = variantNibble + rHex.slice(4, 7);
  const e = rHex.slice(7, 19);
  return `${a}-${b}-${c}-${d}-${e}`;
}

export function nanoId({ length = 21 } = {}) {
  return randomFromCharset(length, NANO_DEFAULT);
}

// ULID — 26 chars Crockford base32 (10 ts + 16 random)
export function ulid() {
  let ts = BigInt(Date.now());
  let tsStr = '';
  for (let i = 0; i < 10; i++) {
    tsStr = CROCKFORD[Number(ts & 31n)] + tsStr;
    ts = ts >> 5n;
  }
  return tsStr + randomFromCharset(16, CROCKFORD);
}

// MongoDB ObjectId — 24 hex chars (4-byte unix-s timestamp + 8 random bytes)
export function mongoObjectId() {
  const t = Math.floor(Date.now() / 1000);
  const tHex = t.toString(16).padStart(8, '0');
  return tHex + bytesToHex(randomBytes(8));
}

// ---------- Passwords ----------

export function password({
  length = 20,
  lower = true,
  upper = true,
  digits = true,
  symbols = true,
  excludeAmbiguous = false,
} = {}) {
  let charset = '';
  if (lower) charset += LOWER;
  if (upper) charset += UPPER;
  if (digits) charset += DIGITS;
  if (symbols) charset += SYMBOLS;
  if (!charset) charset = LOWER;
  if (excludeAmbiguous) {
    const drop = new Set(AMBIGUOUS);
    charset = [...charset].filter((c) => !drop.has(c)).join('');
  }
  return randomFromCharset(length, charset);
}

export function pin({ length = 6 } = {}) {
  return randomFromCharset(length, DIGITS);
}

// ---------- Custom ----------

export function customRandom({
  length = 32,
  encoding = 'alphanumeric',
  prefix = '',
  charset = '',
} = {}) {
  if (charset && charset.length >= 2) {
    return prefix + randomFromCharset(length, charset.slice(0, 256));
  }
  if (encoding === 'hex') {
    return prefix + bytesToHex(randomBytes(Math.ceil(length / 2))).slice(0, length);
  }
  if (encoding === 'base64' || encoding === 'base64url') {
    const bytes = randomBytes(Math.ceil((length * 6) / 8) + 2);
    const out = encoding === 'base64url'
      ? bytesToBase64Url(bytes)
      : bytesToBase64(bytes).replace(/=+$/, '');
    return prefix + out.slice(0, length);
  }
  return prefix + randomFromCharset(length, pickCharset(encoding));
}

// ---------- Internal helpers ----------

function encodeBytes(bytes, encoding) {
  if (encoding === 'hex') return bytesToHex(bytes);
  if (encoding === 'base64url') return bytesToBase64Url(bytes);
  return bytesToBase64(bytes);
}

function pickCharset(name) {
  switch (name) {
    case 'hex':
      return HEX_CHARS;
    case 'alpha':
      return ALPHA;
    case 'numeric':
      return DIGITS;
    case 'lower':
      return LOWER;
    case 'upper':
      return UPPER;
    case 'alphanumeric':
    default:
      return ALPHANUMERIC;
  }
}
