// The room's write path and read path, wired together the way the page does it — without a browser.
//
// What this cannot cover: the WebSocket exchange with a relay and the DOM. What it can cover is the part
// where a mistake is silent and permanent: an event that is encrypted for one page but tagged for
// another, work that does not cover the event actually published, or a reader whose key does not open
// what the writer produced.

import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';

import {
  pageIdentity, pageId, roomDifficulty, roomKey,
  encryptMessage, decryptMessage, mineEvent, verifyProofOfWork, eventId, messageAad,
} from '../roomlib.js';

const subtle = webcrypto.subtle;
const LINK = '?t=Coffee+in+Ljubljana&s=Somebody+left+a+review&p=The+flat+white+was+perfect&f=7&b=42';

/** Exactly what room.js does on submit, minus the WebSocket. */
async function composeMessage(search, text, { pubkey = 'ab'.repeat(32), difficulty = 10 } = {}) {
  const identity = pageIdentity(search);
  const roomId = pageId(search);
  const key = await roomKey(identity, subtle);
  const createdAt = 1761600000;
  const content = await encryptMessage(key, text, { subtle, aad: messageAad(roomId, pubkey, createdAt) });
  const draft = {
    pubkey,
    created_at: createdAt,
    kind: 1,
    tags: [['h', roomId], ['t', 'snofl-room']],
    content,
  };
  const mined = await mineEvent(draft, difficulty, { yieldEvery: 64 });
  return { ...mined.event, id: mined.id };
}

/** Exactly what room.js does on read. */
async function readMessage(search, event) {
  const key = await roomKey(pageIdentity(search), subtle);
  const verdict = verifyProofOfWork(event);
  if (!verdict.ok) return null;
  const text = await decryptMessage(key, event.content, { subtle, aad: messageAad(pageId(search), event.pubkey, event.created_at) });
  // room.js does exactly this: a payload this room cannot open is not a message, it is silence
  return text === null ? null : { text, bits: verdict.bits };
}

test('a message written for a link is readable from that link, and from nothing else', async () => {
  const event = await composeMessage(LINK, 'Anyone here? The coffee machine is broken.');

  const same = await readMessage(LINK, event);
  assert.equal(same.text, 'Anyone here? The coffee machine is broken.');
  assert.ok(same.bits >= 10);

  // the parameters in another order are the same page
  const reordered = '?b=42&f=7&p=The+flat+white+was+perfect&s=Somebody+left+a+review&t=Coffee+in+Ljubljana';
  assert.equal((await readMessage(reordered, event)).text, same.text);

  // a single character different is a different page, and a different room
  const edited = LINK.replace('perfect', 'perfect.');
  assert.equal(await readMessage(edited, event), null);
  // and so is a page with an extra parameter
  assert.equal(await readMessage(LINK + '&m=1', event), null);
});

test('the room id in the tag is the one the payload is encrypted for', async () => {
  const event = await composeMessage(LINK, 'hello');
  const hTag = event.tags.find((tag) => tag[0] === 'h');
  assert.equal(hTag[1], pageId(LINK));
  assert.equal(hTag[1], pageId('?f=7&b=42&t=Coffee+in+Ljubljana&s=Somebody+left+a+review&p=The+flat+white+was+perfect'));

  // a relay's `#h` filter would find this event for its own page and for no other
  const otherRoom = pageId(LINK + '&x=1');
  assert.notEqual(hTag[1], otherRoom);
});

test('the work covers the published event, including the nonce it carries', async () => {
  const event = await composeMessage(LINK, 'proof of work', { difficulty: 12 });
  assert.equal(event.id, eventId(event), 'the id published must be the hash of what was published');
  const verdict = verifyProofOfWork(event);
  assert.equal(verdict.ok, true);
  assert.ok(verdict.bits >= 12);

  // publishing it with the content swapped out invalidates both the id and the work
  const tampered = { ...event, content: 'snoflroom1:AAAA' };
  assert.equal(verifyProofOfWork(tampered).ok, false);
});

test('a page can ask for its own difficulty, and messages still verify at it', async () => {
  assert.equal(roomDifficulty(LINK), 20, 'the default when the creator asks for nothing');
  assert.equal(roomDifficulty(LINK + '&w=22'), 22);
  const event = await composeMessage(LINK + '&w=11', 'difficult room', { difficulty: 11 });
  assert.ok(verifyProofOfWork(event).bits >= 11);
  // the difficulty parameter does not move the room
  assert.equal(pageId(LINK + '&w=11'), pageId(LINK));
});

test('what a stranger with the link cannot do', async () => {
  const event = await composeMessage(LINK, 'private words');

  // the ciphertext leaks no plaintext, and the author is visible only as a pubkey
  assert.ok(!event.content.includes('private'));
  assert.equal(typeof event.pubkey, 'string');

  // an event stripped of its work is not shown, even though it decrypts fine
  const noWork = { ...event, tags: event.tags.filter((tag) => tag[0] !== 'nonce') };
  assert.equal(verifyProofOfWork(noWork).ok, false);
  assert.equal(await readMessage(LINK, noWork), null, 'the reader refuses it before decrypting');

  // and a correctly-worked event whose content was produced for another room does not decrypt
  const elsewhere = await composeMessage(LINK + '&x=2', 'other room');
  assert.equal(await readMessage(LINK, elsewhere), null);
});
