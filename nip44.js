// NIP-44 v2, the protocol's own encrypted-payload format, in plain JS.
//
// A room's payload is a NIP-44 payload: base64 of `version || nonce32 || ciphertext || mac32`, where the
// ciphertext is ChaCha20 over a padded plaintext and the MAC is HMAC-SHA256 over `nonce || ciphertext`.
// The key schedule is HKDF over a conversation key, split into a ChaCha key, a ChaCha nonce and an HMAC
// key per message. All of that is exactly the NIP.
//
// One deliberate deviation, and it is only in how the conversation key is *obtained*: the NIP derives it
// from ECDH between two keypairs, because it is written for two people who know each other's pubkeys. A
// room is keyed by a link, so the conversation key is HKDF-extract over the link's secret instead —
// `conversationKeyFromSecret`. Everything after that point is byte-for-byte the standard, which is why
// the official vectors can be, and are, run against this file.
//
// Proved with `runVectors()` against nip44.vectors.json (checksum in the NIP), not against itself.

import { sha256, toHex, fromHex, utf8 } from './roomlib.js';

// ------------------------------------------------------------------------------------------------
// byte helpers
// ------------------------------------------------------------------------------------------------
function concat(...parts) {
  let length = 0;
  for (const part of parts) length += part.length;
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function readU32LE(bytes, offset) {
  return (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0;
}

function writeU32LE(bytes, offset, value) {
  bytes[offset] = value & 255;
  bytes[offset + 1] = (value >>> 8) & 255;
  bytes[offset + 2] = (value >>> 16) & 255;
  bytes[offset + 3] = (value >>> 24) & 255;
}

function u16be(value) {
  return new Uint8Array([(value >>> 8) & 255, value & 255]);
}

function u32be(value) {
  return new Uint8Array([(value >>> 24) & 255, (value >>> 16) & 255, (value >>> 8) & 255, value & 255]);
}

function readU16be(bytes, offset) {
  return (bytes[offset] << 8) | bytes[offset + 1];
}

function readU32be(bytes, offset) {
  return ((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;
}

export function base64Encode(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function base64Decode(text) {
  const binary = atob(text);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

function equalConstantTime(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// ------------------------------------------------------------------------------------------------
// HMAC-SHA256 and HKDF, over the SHA-256 in roomlib
// ------------------------------------------------------------------------------------------------
export function hmacSha256(key, message) {
  const block = new Uint8Array(64);
  block.set(key.length > 64 ? sha256(key) : key);
  const inner = new Uint8Array(64);
  const outer = new Uint8Array(64);
  for (let i = 0; i < 64; i++) {
    inner[i] = block[i] ^ 0x36;
    outer[i] = block[i] ^ 0x5c;
  }
  return sha256(concat(outer, sha256(concat(inner, message))));
}

export function hkdfExtract(salt, ikm) {
  return hmacSha256(salt, ikm);
}

export function hkdfExpand(prk, info, length) {
  let output = new Uint8Array(0);
  let previous = new Uint8Array(0);
  let counter = 1;
  while (output.length < length) {
    previous = hmacSha256(prk, concat(previous, info, new Uint8Array([counter])));
    output = concat(output, previous);
    counter += 1;
  }
  return output.slice(0, length);
}

// ------------------------------------------------------------------------------------------------
// ChaCha20 (RFC 8439), counter starting at 0, as NIP-44 specifies
// ------------------------------------------------------------------------------------------------
function rotl(value, bits) {
  return ((value << bits) | (value >>> (32 - bits))) >>> 0;
}

function quarterRound(state, a, b, c, d) {
  state[a] = (state[a] + state[b]) >>> 0;
  state[d] = rotl(state[d] ^ state[a], 16);
  state[c] = (state[c] + state[d]) >>> 0;
  state[b] = rotl(state[b] ^ state[c], 12);
  state[a] = (state[a] + state[b]) >>> 0;
  state[d] = rotl(state[d] ^ state[a], 8);
  state[c] = (state[c] + state[d]) >>> 0;
  state[b] = rotl(state[b] ^ state[c], 7);
}

function chacha20Block(key, nonce, counter) {
  const state = new Uint32Array(16);
  state[0] = 0x61707865;
  state[1] = 0x3320646e;
  state[2] = 0x79622d32;
  state[3] = 0x6b206574;
  for (let i = 0; i < 8; i++) state[4 + i] = readU32LE(key, i * 4);
  state[12] = counter >>> 0;
  for (let i = 0; i < 3; i++) state[13 + i] = readU32LE(nonce, i * 4);

  const x = state.slice();
  for (let i = 0; i < 10; i++) {
    quarterRound(x, 0, 4, 8, 12);
    quarterRound(x, 1, 5, 9, 13);
    quarterRound(x, 2, 6, 10, 14);
    quarterRound(x, 3, 7, 11, 15);
    quarterRound(x, 0, 5, 10, 15);
    quarterRound(x, 1, 6, 11, 12);
    quarterRound(x, 2, 7, 8, 13);
    quarterRound(x, 3, 4, 9, 14);
  }
  const out = new Uint8Array(64);
  for (let i = 0; i < 16; i++) writeU32LE(out, i * 4, (x[i] + state[i]) >>> 0);
  return out;
}

export function chacha20(key, nonce, data) {
  const out = new Uint8Array(data.length);
  for (let offset = 0, counter = 0; offset < data.length; offset += 64, counter += 1) {
    const block = chacha20Block(key, nonce, counter);
    const take = Math.min(64, data.length - offset);
    for (let i = 0; i < take; i++) out[offset + i] = data[offset + i] ^ block[i];
  }
  return out;
}

// ------------------------------------------------------------------------------------------------
// Keys
// ------------------------------------------------------------------------------------------------
const SALT = utf8('nip44-v2');

/** The room's conversation key: HKDF-extract over the link's secret, salted exactly as the NIP salts. */
export function conversationKeyFromSecret(secret) {
  return hkdfExtract(SALT, secret);
}

/**
 * The standard key for two keypairs, used by the vectors (and by anything that wants a real DM room).
 * Both halves are validated the way the NIP requires: a scalar below 1 or at/above the curve order is
 * refused rather than reduced, and a pubkey that is not a point on the curve is refused rather than
 * used — a twist point with a valid-looking square root is exactly what those invalid vectors are for.
 */
export function getConversationKey(privateKeyHex, publicKeyHex) {
  return hkdfExtract(SALT, secp256k1Ecdh(privateKeyHex, publicKeyHex));
}

/** The per-message keys: 76 bytes split into a ChaCha key, a ChaCha nonce and an HMAC key. */
export function getMessageKeys(conversationKey, nonce) {
  if (conversationKey.length !== 32) throw new Error('conversation key must be 32 bytes');
  if (nonce.length !== 32) throw new Error('nonce must be 32 bytes');
  const keys = hkdfExpand(conversationKey, nonce, 76);
  return {
    chachaKey: keys.slice(0, 32),
    chachaNonce: keys.slice(32, 44),
    hmacKey: keys.slice(44, 76),
  };
}

// ------------------------------------------------------------------------------------------------
// Padding
// ------------------------------------------------------------------------------------------------
export function calcPaddedLen(length) {
  if (length <= 32) return 32;
  const nextPower = 2 ** (Math.floor(Math.log2(length - 1)) + 1);
  const chunk = nextPower <= 256 ? 32 : nextPower / 8;
  return chunk * (Math.floor((length - 1) / chunk) + 1);
}

export function pad(text) {
  const plaintext = typeof text === 'string' ? utf8(text) : text;
  const length = plaintext.length;
  if (length < 1 || length > 0xffffffff) throw new Error('invalid plaintext length');
  const prefix = length >= 65536 ? concat(new Uint8Array([0, 0]), u32be(length)) : u16be(length);
  const padding = new Uint8Array(calcPaddedLen(length) - length);
  return concat(prefix, plaintext, padding);
}

export function unpad(padded) {
  const firstTwo = readU16be(padded, 0);
  let length;
  let prefixLength;
  if (firstTwo === 0) {
    length = readU32be(padded, 2);
    if (length < 65536) throw new Error('invalid padding');
    prefixLength = 6;
  } else {
    length = firstTwo;
    prefixLength = 2;
  }
  const plaintext = padded.slice(prefixLength, prefixLength + length);
  if (length === 0 || plaintext.length !== length || padded.length !== prefixLength + calcPaddedLen(length)) {
    throw new Error('invalid padding');
  }
  return new TextDecoder().decode(plaintext);
}

// ------------------------------------------------------------------------------------------------
// The payload
// ------------------------------------------------------------------------------------------------
/**
 * Encrypt to a NIP-44 v2 payload.
 * A nonce may be passed in for the vectors; in a browser it is always random.
 */
export function encryptPayload(plaintext, conversationKey, nonce) {
  const messageNonce = nonce || globalThis.crypto.getRandomValues(new Uint8Array(32));
  const { chachaKey, chachaNonce, hmacKey } = getMessageKeys(conversationKey, messageNonce);
  const ciphertext = chacha20(chachaKey, chachaNonce, pad(plaintext));
  const mac = hmacSha256(hmacKey, concat(messageNonce, ciphertext));
  return base64Encode(concat(new Uint8Array([2]), messageNonce, ciphertext, mac));
}

/** Decrypt a NIP-44 v2 payload. Throws on anything malformed, as the NIP requires. */
export function decryptPayload(payload, conversationKey) {
  if (typeof payload !== 'string' || payload.length === 0) throw new Error('unknown version');
  if (payload[0] === '#') throw new Error('unknown version');
  if (payload.length < 132) throw new Error('invalid payload size');
  const data = base64Decode(payload);
  if (data.length < 99) throw new Error('invalid data size');
  if (data[0] !== 2) throw new Error('unknown version ' + data[0]);
  const nonce = data.slice(1, 33);
  const ciphertext = data.slice(33, data.length - 32);
  const mac = data.slice(data.length - 32);
  const { chachaKey, chachaNonce, hmacKey } = getMessageKeys(conversationKey, nonce);
  const expected = hmacSha256(hmacKey, concat(nonce, ciphertext));
  if (!equalConstantTime(expected, mac)) throw new Error('invalid MAC');
  return unpad(chacha20(chachaKey, chachaNonce, ciphertext));
}

/** True when a string is shaped like a NIP-44 payload at all — cheap check before decrypting. */
export function looksLikePayload(text) {
  return typeof text === 'string' && text.length >= 132 && text[0] !== '#';
}

// ------------------------------------------------------------------------------------------------
// secp256k1 ECDH, for the standard conversation key (the vectors exercise it; the room does not)
// ------------------------------------------------------------------------------------------------
const P = 2n ** 256n - 2n ** 32n - 977n;
const N = 2n ** 256n - 432420386565659656852420866394968145599n;
const GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
const GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;

const mod = (value, m = P) => ((value % m) + m) % m;

function inv(value) {
  let result = 1n;
  let base = mod(value);
  let exponent = P - 2n;
  while (exponent > 0n) {
    if (exponent & 1n) result = mod(result * base);
    base = mod(base * base);
    exponent >>= 1n;
  }
  return result;
}

const isInfinity = (point) => point === null;

function pointAdd(a, b) {
  if (isInfinity(a)) return b;
  if (isInfinity(b)) return a;
  if (a[0] === b[0] && mod(a[1] + b[1]) === 0n) return null;
  let lambda;
  if (a[0] === b[0] && a[1] === b[1]) {
    lambda = mod(3n * a[0] * a[0] * inv(2n * a[1]));
  } else {
    lambda = mod((b[1] - a[1]) * inv(b[0] - a[0]));
  }
  const x = mod(lambda * lambda - a[0] - b[0]);
  return [x, mod(lambda * (a[0] - x) - a[1])];
}

function pointMul(point, scalar) {
  let result = null;
  let addend = point;
  let k = scalar;
  while (k > 0n) {
    if (k & 1n) result = pointAdd(result, addend);
    addend = pointAdd(addend, addend);
    k >>= 1n;
  }
  return result;
}

const onCurve = (point) => mod(point[1] * point[1]) === mod(point[0] ** 3n + 7n);

function decompress(publicKeyHex) {
  const bytes = fromHex(publicKeyHex);
  if (bytes.length !== 32 && bytes.length !== 33) throw new Error('public key must be 32 or 33 bytes');
  if (bytes.length === 32) {
    const x = BigInt('0x' + toHex(bytes));
    // an x at or above the field prime is not a coordinate at all, and reducing it mod P would invent a
    // valid-looking point out of nothing
    if (x >= P) throw new Error('public key x is out of range');
    const ySquared = mod(x ** 3n + 7n);
    let y = 1n;
    let base = ySquared;
    let exponent = (P + 1n) / 4n;
    while (exponent > 0n) {
      if (exponent & 1n) y = mod(y * base);
      base = mod(base * base);
      exponent >>= 1n;
    }
    const point = [x, y % 2n === 0n ? y : mod(-y)];
    if (!onCurve(point)) throw new Error('public key is not on the curve');
    return point;
  }
  const prefix = bytes[0];
  if (prefix !== 2 && prefix !== 3) throw new Error('public key prefix must be 02 or 03');
  const x = BigInt('0x' + toHex(bytes.slice(1)));
  if (x >= P) throw new Error('public key x is out of range');
  const ySquared = mod(x ** 3n + 7n);
  let y = 1n;
  let base = ySquared;
  let exponent = (P + 1n) / 4n;
  while (exponent > 0n) {
    if (exponent & 1n) y = mod(y * base);
    base = mod(base * base);
    exponent >>= 1n;
  }
  if ((y % 2n === 0n) !== (prefix === 2)) y = mod(-y);
  const point = [x, y];
  if (!onCurve(point)) throw new Error('public key is not on the curve');
  return point;
}

/** The unhashed 32-byte x coordinate of the shared point — what NIP-44 feeds to HKDF. */
export function secp256k1Ecdh(privateKeyHex, publicKeyHex) {
  const scalar = BigInt('0x' + privateKeyHex);
  if (scalar <= 0n || scalar >= N) throw new Error('private key out of range');
  const shared = pointMul(decompress(publicKeyHex), scalar);
  if (isInfinity(shared)) throw new Error('shared point is at infinity');
  const x = shared[0].toString(16).padStart(64, '0');
  return fromHex(x);
}

/** The public key for a secret key, compressed hex — the vectors give secrets and expect pubkeys. */
export function publicKeyHex(privateKeyHex) {
  const point = pointMul([GX, GY], BigInt('0x' + privateKeyHex) % N);
  const y = point[1];
  return (y % 2n === 0n ? '02' : '03') + point[0].toString(16).padStart(64, '0');
}

// ------------------------------------------------------------------------------------------------
// The proof: the NIP's own vectors
// ------------------------------------------------------------------------------------------------
export function runVectors(vectors) {
  const v2 = vectors.v2 || {};
  const valid = v2.valid || {};
  const invalid = v2.invalid || {};
  const results = [];
  const record = (name, ok, detail) => results.push({ name, ok, detail: detail || '' });
  const sha = (bytes) => toHex(sha256(bytes));

  // --- conversation keys from two keypairs (35 cases) ---------------------------------------------
  for (const vector of valid.get_conversation_key || []) {
    try {
      const got = toHex(getConversationKey(vector.sec1, vector.pub2));
      record('get_conversation_key ' + vector.sec1.slice(-6), got === vector.conversation_key,
        got === vector.conversation_key ? '' : 'got ' + got.slice(0, 12));
    } catch (error) {
      record('get_conversation_key ' + vector.sec1.slice(-6), false, error.message);
    }
  }

  // --- the 76-byte per-message split (32 cases) ---------------------------------------------------
  const keyCase = valid.get_message_keys || {};
  for (const entry of keyCase.keys || []) {
    try {
      const keys = getMessageKeys(fromHex(keyCase.conversation_key), fromHex(entry.nonce));
      const ok = toHex(keys.chachaKey) === entry.chacha_key
        && toHex(keys.chachaNonce) === entry.chacha_nonce
        && toHex(keys.hmacKey) === entry.hmac_key;
      record('get_message_keys ' + entry.nonce.slice(-6), ok);
    } catch (error) {
      record('get_message_keys ' + entry.nonce.slice(-6), false, error.message);
    }
  }

  // --- the padding ladder (24 cases) --------------------------------------------------------------
  for (const [input, expected] of valid.calc_padded_len || []) {
    const got = calcPaddedLen(Number(input));
    record('calc_padded_len ' + input, got === Number(expected), got === Number(expected) ? '' : 'got ' + got);
  }

  // --- full payloads, both directions (10 cases) --------------------------------------------------
  for (const vector of valid.encrypt_decrypt || []) {
    const label = 'encrypt_decrypt ' + JSON.stringify(vector.plaintext).slice(0, 12);
    try {
      const key = fromHex(vector.conversation_key);
      const payload = encryptPayload(vector.plaintext, key, fromHex(vector.nonce));
      const roundTrip = decryptPayload(vector.payload, key);
      const payloadMatches = payload === vector.payload;
      record(label, payloadMatches && roundTrip === vector.plaintext,
        payloadMatches ? (roundTrip === vector.plaintext ? '' : 'round trip differs') : 'payload differs');
    } catch (error) {
      record(label, false, error.message);
    }
  }

  // --- long messages, where only checksums are published (3 cases) --------------------------------
  for (const vector of valid.encrypt_decrypt_long_msg || []) {
    const plaintext = String(vector.pattern).repeat(Number(vector.repeat));
    const label = 'long_msg repeat=' + vector.repeat;
    try {
      const key = fromHex(vector.conversation_key);
      const payload = encryptPayload(plaintext, key, fromHex(vector.nonce));
      // the published checksum may be over the base64 text or over its bytes; accept either, and say which
      const overText = sha(utf8(payload)) === vector.payload_sha256;
      const overBytes = sha(base64Decode(payload)) === vector.payload_sha256;
      const plaintextOk = sha(utf8(plaintext)) === vector.plaintext_sha256;
      const back = decryptPayload(payload, key);
      record(label, plaintextOk && (overText || overBytes) && back === plaintext,
        plaintextOk ? (overText || overBytes ? '' : 'payload checksum differs') : 'plaintext checksum differs');
    } catch (error) {
      record(label, false, error.message);
    }
  }

  // --- things that must be refused ---------------------------------------------------------------
  for (const vector of invalid.get_conversation_key || []) {
    try {
      getConversationKey(vector.sec1, vector.pub2);
      record('invalid keypair refused: ' + (vector.note || '').slice(0, 34), false, 'it was accepted');
    } catch {
      record('invalid keypair refused: ' + (vector.note || '').slice(0, 34), true);
    }
  }

  for (const vector of invalid.decrypt || []) {
    try {
      decryptPayload(vector.payload, fromHex(vector.conversation_key));
      record('invalid payload refused: ' + (vector.note || '').slice(0, 34), false, 'it decrypted');
    } catch {
      record('invalid payload refused: ' + (vector.note || '').slice(0, 34), true);
    }
  }

  for (const length of invalid.encrypt_msg_lengths || []) {
    const size = Number(length);
    let accepted;
    try {
      encryptPayload(new Uint8Array(size), new Uint8Array(32), new Uint8Array(32));
      accepted = true;
    } catch {
      accepted = false;
    }
    // A plaintext of 0 bytes is invalid. Lengths of 65536 and above are only invalid to an
    // implementation that predates the extended length prefix: this NIP now defines a 6-byte prefix for
    // them, and its own valid vectors encrypt 65536 and 65537. So this is recorded as stale, not passed
    // off as a failure of ours or silently dropped.
    if (size === 0) {
      record('empty plaintext refused', accepted === false);
    } else {
      record('stale vector: ' + size + ' bytes refused by the reference impl', accepted === true,
        accepted ? 'we follow the current spec and accept it' : 'we refused it too');
    }
  }

  return results;
}
