// The room's pure half, tested in node against WebCrypto and against the serialization this site
// already signs — because the expensive mistakes here are silent: a hash that is subtly wrong still
// produces hex, a page identity that changes with parameter order quietly splits a room in two, and a
// mining loop that never verifies what it found is just a spinner.

import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';

import {
  sha256, toHex, fromHex, leadingZeroBits, utf8,
  pageIdentity, pageId, roomDifficulty, ROOM_CONTROL_PARAMS,
  roomKey, encryptMessage, decryptMessage, messageAad,
  eventSerialization, eventId, mineEvent, verifyProofOfWork, nonceTag,
} from '../roomlib.js';

const subtle = webcrypto.subtle;

test('sha256 agrees with WebCrypto on every length that matters', async () => {
  // every remainder class around the padding boundary, plus the empty string
  for (const length of [0, 1, 3, 55, 56, 63, 64, 65, 119, 120, 200, 1000]) {
    const bytes = new Uint8Array(length);
    for (let i = 0; i < length; i++) bytes[i] = (i * 37 + 11) & 255;
    const mine = toHex(sha256(bytes));
    const reference = toHex(new Uint8Array(await subtle.digest('SHA-256', bytes)));
    assert.equal(mine, reference, `length ${length}`);
  }
  assert.equal(toHex(sha256(utf8(''))), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
});

test('leading-zero-bit counting is the NIP-13 measure', () => {
  assert.equal(leadingZeroBits(fromHex('00')), 8);
  assert.equal(leadingZeroBits(fromHex('0001')), 15);
  assert.equal(leadingZeroBits(fromHex('80')), 0);
  assert.equal(leadingZeroBits(fromHex('0f')), 4);
  assert.equal(leadingZeroBits(fromHex('00' + '00' + 'ff')), 16);
});

test('the page identity does not depend on parameter order, but does depend on everything else', () => {
  const a = pageIdentity('?t=Hello&p=World&f=3');
  const b = pageIdentity('?p=World&f=3&t=Hello');
  assert.equal(a, b, 'the same page in another order is the same room');
  assert.equal(a, 'f=3&p=World&t=Hello');

  // "even a slight change gives a new room"
  assert.notEqual(pageId('?t=Hello&p=World'), pageId('?t=Hello&p=world'));
  assert.notEqual(pageId('?t=Hello&p=World'), pageId('?t=Hello&p=World '));
  assert.notEqual(pageId('?t=Hello'), pageId('?t=Hello&p='));

  // the room's own controls are not part of the page
  for (const key of ROOM_CONTROL_PARAMS) {
    assert.equal(pageIdentity(`?t=Hello&${key}=22`), pageIdentity('?t=Hello'), `${key} must not split a room`);
    assert.equal(pageId(`?t=Hello&${key}=22`), pageId('?t=Hello'));
  }
});

test('the page id is a hash, and stable across reads of the same link', () => {
  const id = pageId('?t=Test&b=5');
  assert.match(id, /^[0-9a-f]{64}$/);
  assert.equal(id, pageId('?t=Test&b=5'));
  assert.notEqual(id, pageId('?t=Test&b=6'));
});

test('difficulty comes from w, is clamped, and falls back to the default', () => {
  assert.equal(roomDifficulty('?t=x'), 20);
  assert.equal(roomDifficulty('?t=x&w=22'), 22);
  assert.equal(roomDifficulty('?t=x&w=0'), 20);
  assert.equal(roomDifficulty('?t=x&w=nonsense'), 20);
  assert.equal(roomDifficulty('?t=x&w=99'), 32);
  assert.equal(roomDifficulty('?t=x&w=3.7'), 3);
});

test('messages round-trip under the key the link derives', async () => {
  const identity = pageIdentity('?t=Coffee&p=Nice');
  const key = await roomKey(identity, subtle);
  const text = 'Anyone here? · ☕ · <b>not html</b>';
  const encrypted = await encryptMessage(key, text, { subtle });

  assert.match(encrypted, /^snoflroom1:/);
  assert.ok(!encrypted.includes('Coffee'), 'the plaintext must not survive in the content');
  assert.equal(await decryptMessage(key, encrypted, { subtle }), text);

  // the same link, read on another machine, derives the same key
  const sameKey = await roomKey(pageIdentity('?p=Nice&t=Coffee'), subtle);
  assert.equal(await decryptMessage(sameKey, encrypted, { subtle }), text);
});

test('a different link cannot read the room, and tampering is refused, not thrown', async () => {
  const key = await roomKey(pageIdentity('?t=A'), subtle);
  const other = await roomKey(pageIdentity('?t=B'), subtle);
  const encrypted = await encryptMessage(key, 'secret', { subtle });

  assert.equal(await decryptMessage(other, encrypted, { subtle }), null, 'another page must read nothing');

  const body = encrypted.slice('snoflroom1:'.length);
  const bytes = Buffer.from(body, 'base64');
  bytes[bytes.length - 1] ^= 0x01;
  assert.equal(await decryptMessage(key, 'snoflroom1:' + bytes.toString('base64'), { subtle }), null,
    'AES-GCM must reject a flipped bit rather than return rubbish');

  assert.equal(await decryptMessage(key, 'plain text, not for this room', { subtle }), null);
  assert.equal(await decryptMessage(key, 'snoflroom1:$$$not base64$$$', { subtle }), null);
});

test('the event id is the hash of the serialization the site already signs', async () => {
  const event = {
    pubkey: 'ab'.repeat(32),
    created_at: 1761600000,
    kind: 1,
    tags: [['h', 'deadbeef'], ['t', 'coffee']],
    content: 'snoflroom1:xyz',
  };
  // exactly what index.html's signEvent() serializes
  const expected = toHex(sha256(utf8(JSON.stringify([0, event.pubkey, event.created_at, event.kind, event.tags, event.content]))));
  assert.equal(eventSerialization(event), JSON.stringify([0, event.pubkey, event.created_at, event.kind, event.tags, event.content]));
  assert.equal(eventId(event), expected);
  const viaWebCrypto = toHex(new Uint8Array(await subtle.digest('SHA-256', utf8(eventSerialization(event)))));
  assert.equal(eventId(event), viaWebCrypto);
});

test('mining finds a nonce that passes verification, and a tampered id fails it', async () => {
  const event = {
    pubkey: 'cd'.repeat(32),
    created_at: 1761600000,
    kind: 1,
    tags: [['h', 'room']],
    content: 'snoflroom1:hello',
  };
  const seen = [];
  const mined = await mineEvent(event, 8, { onProgress: (p) => seen.push(p.attempts), yieldEvery: 16 });
  assert.ok(mined.attempts >= 1);
  assert.equal(mined.event.tags.at(-1)[0], 'nonce');
  assert.equal(mined.event.tags.at(-1)[2], '8');
  assert.ok(leadingZeroBits(fromHex(mined.id)) >= 8, 'the id really has the bits');

  const verdict = verifyProofOfWork({ ...mined.event, id: mined.id });
  assert.equal(verdict.ok, true);
  assert.ok(verdict.bits >= 8);

  // an id that does not match its content is refused even if it looks hard
  const forged = { ...mined.event, id: '00'.repeat(32) };
  assert.equal(verifyProofOfWork(forged).ok, false);
  assert.match(verifyProofOfWork(forged).reason, /does not match/);

  // and an event that claims more work than it did is refused — the claim has to be hashed into the id
  // for that check to be the one that fires, otherwise the id simply no longer matches
  const overTags = [['h', 'room'], ['nonce', mined.nonce, '32']];
  const overclaim = { ...mined.event, tags: overTags, id: eventId({ ...mined.event, tags: overTags }) };
  const claim = verifyProofOfWork(overclaim);
  assert.equal(claim.ok, false);
  assert.match(claim.reason, /only .* bits, claimed 32/);
});

test('an event with no nonce is reported, not thrown on', () => {
  assert.equal(nonceTag([['h', 'x']]), null);
  const verdict = verifyProofOfWork({ pubkey: 'aa'.repeat(32), created_at: 1, kind: 1, tags: [['h', 'x']], content: '', id: '00'.repeat(32) });
  assert.equal(verdict.ok, false);
  assert.equal(verdict.reason, 'no nonce tag');
});

test('a message is bound to its author and time, so a relay cannot re-attribute it', async () => {
  const identity = pageIdentity('?t=Bound');
  const key = await roomKey(identity, subtle);
  const roomId = pageId('?t=Bound');
  const author = 'ab'.repeat(32);
  const createdAt = 1761600000;
  const aad = messageAad(roomId, author, createdAt);

  const encrypted = await encryptMessage(key, 'the coffee was cold', { subtle, aad });
  assert.equal(await decryptMessage(key, encrypted, { subtle, aad }), 'the coffee was cold');

  // another author, the same message: the attacker has the ciphertext but not the plaintext
  const impostor = messageAad(roomId, 'cd'.repeat(32), createdAt);
  assert.equal(await decryptMessage(key, encrypted, { subtle, aad: impostor }), null);

  // another time on the same message
  assert.equal(await decryptMessage(key, encrypted, { subtle, aad: messageAad(roomId, author, createdAt + 1) }), null);

  // another room on the same relay
  assert.equal(await decryptMessage(key, encrypted, { subtle, aad: messageAad(pageId('?t=Other'), author, createdAt) }), null);
});
