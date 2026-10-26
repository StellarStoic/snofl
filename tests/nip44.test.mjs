// NIP-44 v2 in this repo, tested against the NIP's own vectors and then used the way the room uses it.
//
// The vectors are the point: they were written by someone else, published with a checksum, and they
// cover the parts where a mistake is invisible — the 76-byte key split, the padding ladder including the
// 6-byte extended prefix, and the invalid inputs a lenient implementation would happily accept (a
// secret at or above the curve order, a pubkey off the curve, a payload with a bad MAC).

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
  runVectors, encryptPayload, decryptPayload, calcPaddedLen, pad, unpad,
  conversationKeyFromSecret, getConversationKey, publicKeyHex, looksLikePayload,
} from '../nip44.js';
import { pageId, pageSecret, utf8, sha256, toHex } from '../roomlib.js';

const vectors = JSON.parse(readFileSync(fileURLToPath(new URL('./nip44.vectors.json', import.meta.url)), 'utf8'));

test('every published NIP-44 vector passes', () => {
  const results = runVectors(vectors);
  const failures = results.filter((entry) => !entry.ok);
  assert.deepEqual(failures.map((f) => `${f.name}: ${f.detail}`), [],
    `${results.length - failures.length} of ${results.length} checks passed`);
  // and the suite really did cover each group, so "all passed" is not "all skipped"
  const names = results.map((entry) => entry.name);
  for (const group of ['get_conversation_key', 'get_message_keys', 'calc_padded_len',
                       'encrypt_decrypt', 'long_msg', 'invalid']) {
    assert.ok(names.some((name) => name.startsWith(group)), `no checks ran for ${group}`);
  }
  assert.ok(results.length >= 120, `only ${results.length} checks ran`);
});

test('the room\'s conversation key comes from the link, exactly as the NIP derives its own', () => {
  const secret = pageSecret('?t=Room&p=Hello');
  const key = conversationKeyFromSecret(secret);
  assert.equal(key.length, 32);
  assert.deepEqual([...key], [...conversationKeyFromSecret(pageSecret('?p=Hello&t=Room'))],
    'the same page in another parameter order is the same room key');
  assert.notDeepEqual([...key], [...conversationKeyFromSecret(pageSecret('?t=Room&p=Hello!'))]);

  // two different pages cannot read each other
  const theirs = conversationKeyFromSecret(pageSecret('?t=Elsewhere'));
  const payload = encryptPayload('hello room', key);
  assert.equal(decryptPayload(payload, key), 'hello room');
  assert.throws(() => decryptPayload(payload, theirs), /invalid MAC/);
});

test('a payload is the standard shape, and a reader can tell one from noise', () => {
  const key = conversationKeyFromSecret(pageSecret('?t=Shape'));
  const payload = encryptPayload('hello', key);

  assert.match(payload, /^[A-Za-z0-9+/=]+$/, 'base64, version byte included');
  const decoded = Buffer.from(payload, 'base64');
  assert.equal(decoded[0], 2, 'version 2');
  assert.ok(decoded.length >= 99, 'nonce, ciphertext and mac are all present');
  assert.ok(decoded.length - 65 >= 34, 'padded plaintext of at least 32 bytes plus its prefix');

  assert.equal(looksLikePayload(payload), true);
  assert.equal(looksLikePayload('snoflroom1:whatever'), false);
  assert.equal(looksLikePayload('short'), false);
});

test('the author and time travel inside the ciphertext, so a relay cannot re-attribute a message', () => {
  const key = conversationKeyFromSecret(pageSecret('?t=Attribution'));
  const author = 'ab'.repeat(32);
  const other = 'cd'.repeat(32);
  const createdAt = 1761600000;

  const packed = JSON.stringify({ v: 1, p: author, c: createdAt, m: 'the coffee was cold' });
  const payload = encryptPayload(packed, key);

  const read = (event) => {
    const body = JSON.parse(decryptPayload(payload, key));
    if (String(body.p).toLowerCase() !== String(event.pubkey).toLowerCase()) return null;
    if (Number(body.c) !== Number(event.created_at)) return null;
    return body.m;
  };

  assert.equal(read({ pubkey: author, created_at: createdAt }), 'the coffee was cold');
  // the attacker has the ciphertext, not the author's key: swapping who said it breaks the check
  assert.equal(read({ pubkey: other, created_at: createdAt }), null);
  // and so does moving it in time
  assert.equal(read({ pubkey: author, created_at: createdAt + 60 }), null);
});

test('padding follows the published ladder, including the extended prefix', () => {
  assert.equal(calcPaddedLen(1), 32);
  assert.equal(calcPaddedLen(32), 32);
  assert.equal(calcPaddedLen(33), 64);
  assert.equal(calcPaddedLen(65535), 65536);
  assert.equal(calcPaddedLen(65536), 65536);
  assert.equal(calcPaddedLen(65537), 81920);

  // a 65536-byte message needs the 6-byte prefix, and survives the round trip
  const long = 'x'.repeat(65536);
  const padded = pad(long);
  assert.equal(padded[0], 0);
  assert.equal(padded[1], 0);
  assert.equal(unpad(padded), long);

  // the short form keeps its 2-byte prefix
  const short = pad('x'.repeat(10));
  assert.equal(short.length, 34);
  assert.equal(unpad(short), 'x'.repeat(10));
});

test('the standard keypair path still works, so the file is not only good for link rooms', () => {
  const secretA = '01'.padStart(64, '0');
  const secretB = '02'.padStart(64, '0');
  const pubB = publicKeyHex(secretB);
  const pubA = publicKeyHex(secretA);
  const keyFromA = getConversationKey(secretA, pubB);
  const keyFromB = getConversationKey(secretB, pubA);
  assert.equal(toHex(keyFromA), toHex(keyFromB), 'both sides derive the same conversation key');

  const payload = encryptPayload('a direct message', keyFromB);
  assert.equal(decryptPayload(payload, keyFromA), 'a direct message');
});

test('a room id and a room secret are different things', () => {
  const search = '?t=Separate';
  assert.notEqual(pageId(search), toHex(pageSecret(search)));
  assert.equal(toHex(sha256(utf8('nope'))).length, 64);
});
