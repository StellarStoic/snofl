// NIP-88 in the room: the poll's shape, its counting rule, and what a malformed payload is allowed to do.
import test from 'node:test';
import assert from 'node:assert/strict';

import {
  packPoll, packPollVote, unpackRoomMessage, tallyPoll, pollIsClosed, pollMaxAnswers, newPollId,
  POLL_MAX_OPTIONS, POLL_MIN_OPTIONS,
} from '../roomlib.js';

const PUB = 'a'.repeat(64);
const EVENT = { pubkey: PUB, created_at: 1_700_000_000 };

const read = (plaintext, event = EVENT) => unpackRoomMessage(plaintext, event);

test('a poll round-trips with NIP-88 field names and no chat text', () => {
  const packed = packPoll(PUB, EVENT.created_at, {
    id: 'poll-one',
    question: 'Where do we meet?',
    options: [['a', 'The hut'], ['b', 'The ridge']],
    type: 'multi',
    endsAt: 1_800_000_000,
  });
  const body = JSON.parse(packed);
  assert.equal(body.m, '', 'a poll is not a chat message');
  assert.equal(body.poll.t, 'multi');
  assert.equal(body.poll.e, 1_800_000_000, 'endsAt travels as NIP-88 names it');
  assert.deepEqual(body.poll.o, [['a', 'The hut'], ['b', 'The ridge']]);

  const read1 = read(packed);
  assert.equal(read1.text, '');
  assert.equal(read1.vote, null);
  assert.deepEqual(read1.poll.options, [
    { id: 'a', label: 'The hut' },
    { id: 'b', label: 'The ridge' },
  ]);
  assert.equal(read1.poll.type, 'multi');
});

test('an answer names its poll and carries the options chosen, deduplicated', () => {
  const packed = packPollVote(PUB, EVENT.created_at, 'poll-one', ['b', 'b', 'a']);
  const read1 = read(packed);
  assert.deepEqual(read1.vote, { pollId: 'poll-one', options: ['b', 'a'] });
  assert.equal(read1.poll, null);
  assert.equal(read1.text, '');
});

test('the envelope still refuses a payload whose author or time was swapped by a relay', () => {
  const packed = packPoll(PUB, EVENT.created_at, {
    id: 'p', question: 'q', options: [['a', 'x'], ['b', 'y']],
  });
  assert.equal(read(packed, { pubkey: 'b'.repeat(64), created_at: EVENT.created_at }), null, 'other author');
  assert.equal(read(packed, { pubkey: PUB, created_at: EVENT.created_at + 1 }), null, 'other timestamp');
});

test('a poll with too few or too many options, or an empty one, is not read', () => {
  // packPoll refuses to build these, so the bad shapes are written by hand: the reader must be just as strict
  const bad = (options) => JSON.stringify({
    v: 1, p: PUB, c: EVENT.created_at, m: '', poll: { id: 'p', q: 'q', o: options, t: 'single', e: 0 },
  });
  assert.equal(read(bad([['a', 'one']])), null, `${POLL_MIN_OPTIONS} is the floor`);
  assert.equal(read(bad(Array.from({ length: POLL_MAX_OPTIONS + 1 }, (unused, i) => [`o${i}`, `Option ${i}`]))), null,
    `${POLL_MAX_OPTIONS} is the ceiling`);
  assert.equal(read(bad([['a', 'same'], ['a', 'same id']])), null, 'duplicate ids are ambiguous');
  assert.equal(read(bad([['a', '']])), null, 'a label is required');
});

test('packPoll refuses to build what the room would refuse to read', () => {
  assert.throws(() => packPoll(PUB, EVENT.created_at, { question: 'q', options: [['a', 'one']] }), /2-6 options/);
  assert.throws(() => packPoll(PUB, EVENT.created_at, { question: '', options: [['a', '1'], ['b', '2']] }), /question/);
  assert.throws(() => packPollVote(PUB, EVENT.created_at, 'poll-one', []), /at least one/);
  assert.throws(() => packPollVote(PUB, EVENT.created_at, '', ['a']), /poll it answers/);
});

test('one answer per pubkey, newest wins, and only known options count (NIP-88)', () => {
  const options = [{ id: 'a', label: 'A' }, { id: 'b', label: 'B' }, { id: 'c', label: 'C' }];
  const votes = new Map([
    ['pk1', { options: ['a'], created_at: 10 }],
    ['pk2', { options: ['b'], created_at: 11 }],
    ['pk3', { options: ['a', 'c'], created_at: 12 }],
    ['pk4', { options: ['zzz'], created_at: 13 }],   // an option that does not exist
  ]);
  const { rows, voters } = tallyPoll(options, votes);
  assert.equal(voters, 4);
  assert.deepEqual(rows.map((row) => row.count), [2, 1, 1]);
  assert.equal(rows[0].share, 0.5);
});

test('an empty poll divides by nothing instead of by zero', () => {
  const { rows, voters } = tallyPoll([{ id: 'a', label: 'A' }, { id: 'b', label: 'B' }], new Map());
  assert.equal(voters, 0);
  assert.deepEqual(rows.map((row) => row.share), [0, 0]);
});

test('a poll closes at endsAt and stays open without one', () => {
  assert.equal(pollIsClosed({ endsAt: 100 }, 101), true);
  assert.equal(pollIsClosed({ endsAt: 100 }, 100), true);
  assert.equal(pollIsClosed({ endsAt: 100 }, 99), false);
  assert.equal(pollIsClosed({ endsAt: 0 }, 10 ** 12), false);
  assert.equal(pollIsClosed(null, 1), false);
});

test('two polls made at the same moment do not share an id', () => {
  const ids = new Set(Array.from({ length: 50 }, () => newPollId()));
  assert.equal(ids.size, 50);
  assert.ok([...ids].every((id) => /^[0-9a-f]{10}$/.test(id)));
});

test('how many answers one person may give travels with the poll, in NIP-88 terms', () => {
  const options = [['a', 'A'], ['b', 'B'], ['c', 'C'], ['d', 'D']];
  const build = (max) => unpackRoomMessage(
    packPoll(PUB, EVENT.created_at, { id: 'p', question: 'q', options, max }), EVENT).poll;

  const one = JSON.parse(packPoll(PUB, EVENT.created_at, { id: 'p', question: 'q', options, max: 1 }));
  assert.equal(one.poll.t, 'single', 'one answer is NIP-88 singlechoice');
  assert.equal(one.poll.mx, 1);

  const three = JSON.parse(packPoll(PUB, EVENT.created_at, { id: 'p', question: 'q', options, max: 3 }));
  assert.equal(three.poll.t, 'multi', 'more than one is multiplechoice');
  assert.equal(three.poll.mx, 3, 'and the exact ceiling rides beside it');

  assert.equal(build(1).max, 1);
  assert.equal(build(3).max, 3);
  assert.equal(pollMaxAnswers(build(1)), 1);
  assert.equal(pollMaxAnswers(build(3)), 3);
});

test('a ceiling can never exceed the options, and a legacy poll keeps NIP-88 behaviour', () => {
  const options = [['a', 'A'], ['b', 'B']];
  assert.equal(unpackRoomMessage(packPoll(PUB, EVENT.created_at, { id: 'p', question: 'q', options, max: 9 }), EVENT).poll.max, 2,
    'asking for more answers than there are options is clamped');

  const legacy = (type) => unpackRoomMessage(JSON.stringify({
    v: 1, p: PUB, c: EVENT.created_at, m: '', poll: { id: 'old', q: 'q', o: options, t: type, e: 0 },
  }), EVENT).poll;

  assert.equal(legacy('single').max, 1);
  assert.equal(legacy('multi').max, 2, 'a poll from before the ceiling means "any number", as NIP-88 reads it');
  assert.equal(pollMaxAnswers(legacy('multi')), 2);
});

test('an answer cannot carry more options than the poll allows', () => {
  const packed = JSON.parse(packPollVote(PUB, EVENT.created_at, 'p', ['a', 'b', 'c'], 2));
  assert.deepEqual(packed.pv.s, ['a', 'b'], 'the ceiling truncates rather than refusing the answer');
  const unlimited = JSON.parse(packPollVote(PUB, EVENT.created_at, 'p', ['a', 'b', 'c'], 3));
  assert.deepEqual(unlimited.pv.s, ['a', 'b', 'c']);
});
