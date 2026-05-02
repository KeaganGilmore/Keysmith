// Pure key/secret generation functions. No DOM, no side effects.
// Each generator takes an options object (where applicable) and returns a string.

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
  // Overprovision the buffer so rejection rarely forces another draw.
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

// Mirrors django.core.management.utils.get_random_secret_key().
const DJANGO_CHARSET = 'abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)';

export function djangoSecretKey() {
  return randomFromCharset(50, DJANGO_CHARSET);
}
