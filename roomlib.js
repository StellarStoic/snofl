// The room's pure half: page identity, the key that identity derives, and proof of work.
//
// A page on snofl.com is defined entirely by its URL — that is the product. So the URL is also what
// makes a page's room: hash the parameters and you have an identifier two strangers holding the same
// link will compute identically, and derive a key from it that nobody without the link can compute at
// all. That is "private by link": the relay stores ciphertext, the people the creator handed the link to
// read it, and there is no account to create and no server to ask.
//
// Nothing here touches the DOM or the network, so it can be tested in node against real vectors.

// ------------------------------------------------------------------------------------------------
// SHA-256, in plain JS. The browser's crypto.subtle is async, which is useless for a mining loop, and
// the site already ships a pure-JS sha256 that is not tuned for this. This one is measured: ~60k
// hashes/s per core. Verified against WebCrypto in the tests, not trusted on its own.
// ------------------------------------------------------------------------------------------------
const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

const scratch = new Uint8Array(64);
const scratchView = new DataView(scratch.buffer);

/** SHA-256 of a byte array. Synchronous, allocation-light, no state shared between calls. */
export function sha256(bytes) {
  const H = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                             0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
  const bitLen = bytes.length * 8;
  // one block for the message plus 0x80 plus the 8-byte length, rounded up: length+8, not length+9,
  // or a 55-byte message gets a second empty block and the digest is wrong
  const paddedLength = (((bytes.length + 8) >> 6) + 1) << 6;
  const padded = new Uint8Array(paddedLength);
  padded.set(bytes);
  padded[bytes.length] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(paddedLength - 8, Math.floor(bitLen / 0x100000000));
  view.setUint32(paddedLength - 4, bitLen >>> 0);
  const w = new Uint32Array(64);
  for (let offset = 0; offset < paddedLength; offset += 64) {
    for (let i = 0; i < 16; i++) w[i] = view.getUint32(offset + i * 4);
    for (let i = 16; i < 64; i++) {
      const a = w[i - 15];
      const b = w[i - 2];
      const s0 = ((a >>> 7) | (a << 25)) ^ ((a >>> 18) | (a << 14)) ^ (a >>> 3);
      const s1 = ((b >>> 17) | (b << 15)) ^ ((b >>> 19) | (b << 13)) ^ (b >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
    for (let i = 0; i < 64; i++) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0;
      d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0; H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0; H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
  }
  const out = new Uint8Array(32);
  const outView = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) outView.setUint32(i * 4, H[i]);
  return out;
}

export function toHex(bytes) {
  let out = '';
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0');
  return out;
}

export function fromHex(hex) {
  const clean = hex.trim().toLowerCase();
  if (clean.length % 2) throw new Error('hex length must be even');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function utf8(text) {
  return new TextEncoder().encode(text);
}

/** How many leading zero bits a hash has — the NIP-13 difficulty measure. */
export function leadingZeroBits(bytes) {
  let bits = 0;
  for (const byte of bytes) {
    if (byte === 0) {
      bits += 8;
      continue;
    }
    bits += Math.clz32(byte) - 24;
    break;
  }
  return bits;
}

// ------------------------------------------------------------------------------------------------
// Page identity
// ------------------------------------------------------------------------------------------------
// Parameters that control the room itself rather than describe the page. They are left out of the
// identity on purpose: turning a room's difficulty up must not split it into a different room.
export const ROOM_CONTROL_PARAMS = new Set(['w']);

/**
 * The page's identity string: every parameter that defines the page, in a canonical order.
 *
 * Two links that differ in any way a reader can see are two different pages — and therefore two
 * different rooms. That is what "even a slight change gives a new room" means, and it is the honest
 * behaviour: the page is the link.
 */
export function pageIdentity(search) {
  const params = new URLSearchParams(search || '');
  const pairs = [...params.entries()].filter(([key]) => !ROOM_CONTROL_PARAMS.has(key));
  pairs.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0));
  return pairs.map(([key, value]) => `${key}=${value}`).join('&');
}

/** The room id: a hash of that identity. This is the `h` tag every message carries. */
export function pageId(search) {
  return toHex(sha256(utf8('snofl-page-v1:' + pageIdentity(search))));
}

/** Difficulty for this page: the `w` parameter if the creator set one, otherwise the default. */
export function roomDifficulty(search, fallback = 20) {
  const value = Number(new URLSearchParams(search || '').get('w'));
  if (!Number.isFinite(value) || value <= 0) return fallback;
  return Math.max(1, Math.min(32, Math.floor(value)));
}

// ------------------------------------------------------------------------------------------------
// The key: private by link
// ------------------------------------------------------------------------------------------------
const ROOM_SALT = utf8('snofl-room-v1');
const ROOM_INFO = utf8('aes-gcm-256');
const CONTENT_PREFIX = 'snoflroom1:';

/**
 * Derive the room's AES-GCM key from the page identity.
 *
 * HKDF over the identity hash: every reader with the link derives the same key, and the relays hold
 * nothing but ciphertext. Not forward-secret and not un-invitable — a leaked link leaks the room, which
 * is the same deal as the page itself.
 */
export async function roomKey(identity, subtle) {
  const api = subtle || globalThis.crypto?.subtle;
  if (!api) throw new Error('WebCrypto is unavailable in this browser');
  const material = await api.importKey('raw', sha256(utf8('snofl-rooms-key:' + identity)), 'HKDF', false, ['deriveKey']);
  return api.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: ROOM_SALT, info: ROOM_INFO },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

function toBase64(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function fromBase64(text) {
  const binary = atob(text);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/**
 * The associated data a message is bound to: the room, the author and the timestamp.
 *
 * AES-GCM proves the ciphertext was not touched, but says nothing about the fields beside it — so a relay
 * could take a real encrypted message and republish it under another author's pubkey, or another time.
 * Feeding those fields in as associated data makes any such edit fail to decrypt, which is the difference
 * between "the words are authentic" and "the attribution is".
 */
export function messageAad(roomId, pubkey, createdAt) {
  return utf8(`snofl-room-aad-v1:${roomId}:${String(pubkey).toLowerCase()}:${createdAt}`);
}

/** Encrypt one message for the room. The output is what goes into a kind-1 event's content. */
export async function encryptMessage(key, text, options = {}) {
  const { subtle, aad } = options;
  const api = subtle || globalThis.crypto?.subtle;
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const params = { name: 'AES-GCM', iv };
  if (aad) params.additionalData = aad;
  const ciphertext = new Uint8Array(await api.encrypt(params, key, utf8(text)));
  const joined = new Uint8Array(iv.length + ciphertext.length);
  joined.set(iv);
  joined.set(ciphertext, iv.length);
  return CONTENT_PREFIX + toBase64(joined);
}

/** Read one message. Returns null for anything this room cannot read — foreign content, wrong key,
 *  or fields that were changed after it was written. */
export async function decryptMessage(key, content, options = {}) {
  const { subtle, aad } = options;
  if (typeof content !== 'string' || !content.startsWith(CONTENT_PREFIX)) return null;
  const api = subtle || globalThis.crypto?.subtle;
  let raw;
  try {
    raw = fromBase64(content.slice(CONTENT_PREFIX.length));
  } catch {
    return null;
  }
  if (raw.length < 13) return null;
  try {
    const params = { name: 'AES-GCM', iv: raw.slice(0, 12) };
    if (aad) params.additionalData = aad;
    const plain = await api.decrypt(params, key, raw.slice(12));
    return new TextDecoder().decode(plain);
  } catch {
    return null;
  }
}

// ------------------------------------------------------------------------------------------------
// Events and proof of work
// ------------------------------------------------------------------------------------------------
/** The NIP-01 serialization an event id is the hash of — the same bytes the page already signs. */
export function eventSerialization(event) {
  return JSON.stringify([
    0,
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags,
    event.content,
  ]);
}

export function eventId(event) {
  return toHex(sha256(utf8(eventSerialization(event))));
}

/** The nonce tag as NIP-13 defines it, or null when the event carries none. */
export function nonceTag(tags) {
  const tag = (tags || []).find((entry) => Array.isArray(entry) && entry[0] === 'nonce');
  if (!tag || tag.length < 3) return null;
  const nonce = Number(tag[1]);
  const target = Number(tag[2]);
  if (!Number.isFinite(nonce) || !Number.isFinite(target)) return null;
  return { nonce, target };
}

/**
 * Mine the event until its id has `bits` leading zero bits, then hand it back with the winning nonce.
 *
 * Mining happens before signing — the id covers the tags, and the signature is computed over the id, so
 * the signature never has to be redone. `onProgress` is called with the attempt count so the page can
 * say what it is doing; `yieldEvery` keeps the main thread breathing.
 */
export async function mineEvent(event, bits, options = {}) {
  const { onProgress, yieldEvery = 4096, maxAttempts = Infinity, now = () => Date.now() } = options;
  const tags = event.tags.filter((entry) => !(Array.isArray(entry) && entry[0] === 'nonce'));
  tags.push(['nonce', '0', String(bits)]);
  const candidate = { ...event, tags };
  const started = now();
  let attempts = 0;
  const nonceIndex = tags.length - 1;
  for (;;) {
    const id = eventId(candidate);
    if (leadingZeroBits(fromHex(id)) >= bits) {
      candidate.id = id;
      return { event: candidate, id, nonce: tags[nonceIndex][1], attempts: attempts + 1, ms: now() - started };
    }
    attempts += 1;
    if (attempts >= maxAttempts) {
      throw new Error(`no nonce found in ${attempts} attempts`);
    }
    tags[nonceIndex][1] = String(attempts);
    if (attempts % yieldEvery === 0) {
      if (onProgress) onProgress({ attempts, ms: now() - started });
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
  }
}

/** Check an event's work before it is displayed: the id must match and have the bits it claims. */
export function verifyProofOfWork(event) {
  const tag = nonceTag(event.tags);
  if (!tag) return { ok: false, bits: 0, reason: 'no nonce tag' };
  const computed = eventId(event);
  if (computed !== event.id) return { ok: false, bits: 0, reason: 'id does not match the event' };
  const bits = leadingZeroBits(fromHex(computed));
  if (bits < tag.target) return { ok: false, bits, reason: `only ${bits} bits, claimed ${tag.target}` };
  return { ok: true, bits, target: tag.target };
}
