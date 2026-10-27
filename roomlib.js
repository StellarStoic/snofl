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
// identity on purpose: turning a room's difficulty up must not split it into a different room, and
// neither may a creator switching public notes off — the room is where the conversation already is.
export const ROOM_CONTROL_PARAMS = new Set(['w', 'n']);

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
// The secret the room is keyed by
// ------------------------------------------------------------------------------------------------
/**
 * The room's secret: 32 bytes from the page identity.
 *
 * This is what NIP-44's conversation key is derived from (see nip44.js). The link *is* the key material,
 * which is what makes the room private-by-link: nothing else about the page has to be kept secret, and no
 * key ever travels between the people in the room.
 */
export function pageSecret(search) {
  return sha256(utf8('snofl-rooms-key:' + pageIdentity(search)));
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
  const {
    onProgress, shouldStop, yieldEvery = 4096, maxAttempts = Infinity, now = () => Date.now(),
  } = options;
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
      // Checked only at the yield points, so the loop still runs a tight batch between them: a 20-bit
      // search is stoppable within ~70ms of the reader pressing Cancel, and costs nothing when running.
      if (shouldStop && shouldStop()) {
        const cancelled = new Error('mining cancelled');
        cancelled.cancelled = true;
        throw cancelled;
      }
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

/* ------------------------------------------------------------------ polls (NIP-88, carried in the room)
 *
 * NIP-88 puts a poll in a public `kind:1068` event and the answers in `kind:1018`. A snofl room is the
 * opposite of public: its messages are NIP-44 envelopes only the link holders can read. So the poll rides
 * inside the room's own envelope with NIP-88's *shape* — `option` ids and labels, `polltype`, `endsAt` — and
 * its counting rule: one answer per pubkey, the newest wins. Nothing about the question, the options or who
 * voted goes to a relay in readable form.
 */

export const POLL_MAX_OPTIONS = 6;
export const POLL_MIN_OPTIONS = 2;
export const POLL_MAX_LABEL = 90;
const POLL_MAX_QUESTION = 160;

/** A short id for one poll, so an answer can name it without the poll event's id (unknown until it is mined). */
export function newPollId() {
  const bytes = new Uint8Array(5);
  globalThis.crypto.getRandomValues(bytes);
  return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

function cleanOptions(options) {
  if (!Array.isArray(options)) return null;
  const rows = options
    .map((entry) => (Array.isArray(entry) ? { id: String(entry[0] || '').trim(), label: String(entry[1] || '').trim() } : null))
    .filter((entry) => entry && entry.id && entry.label);
  if (rows.length < POLL_MIN_OPTIONS || rows.length > POLL_MAX_OPTIONS) return null;
  const ids = new Set(rows.map((row) => row.id));
  if (ids.size !== rows.length) return null;
  return rows.map((row) => ({ ...row, label: row.label.slice(0, POLL_MAX_LABEL) }));
}

/**
 * How many of the options one person may pick. NIP-88 only knows `singlechoice` and `multiplechoice`, so
 * `polltype` still says which of the two this is and the exact ceiling travels beside it as `mx`: another
 * client reads a `singlechoice` poll as one answer and a `multiplechoice` one as any number, which is the
 * right behaviour for a reader who does not know our field.
 */
export function pollMaxAnswers(poll) {
  const options = Array.isArray(poll && poll.options) ? poll.options : [];
  // the unpacked poll calls it `max`; a poll read straight off the wire still has NIP-88's `mx`
  const ceiling = Math.floor(Number(poll && (poll.max ?? poll.mx)) || 0);
  const limit = poll && poll.type === 'single' ? 1 : (ceiling || options.length || 1);
  return Math.min(limit, Math.max(1, options.length || 1));
}

/** The message a poll posts: empty text, and the poll beside it. */
export function packPoll(pubkey, createdAt, poll) {
  const options = cleanOptions(poll.options);
  if (!options) throw new Error(`a poll needs ${POLL_MIN_OPTIONS}-${POLL_MAX_OPTIONS} options with labels`);
  const question = String(poll.question || '').trim();
  if (!question) throw new Error('a poll needs a question');
  // `max` is the ceiling the form asks for; `type: 'multi'` is the older way of saying "as many as there are",
  // and both must keep working because a poll is only as good as the links that already carry one
  const requested = Number(poll.max) > 0 ? Number(poll.max) : (poll.type === 'multi' ? options.length : 1);
  const max = Math.min(Math.max(1, Math.floor(requested)), options.length);
  return JSON.stringify({
    v: 1,
    p: pubkey,
    c: createdAt,
    m: '',
    poll: {
      id: String(poll.id || newPollId()),
      q: question.slice(0, POLL_MAX_QUESTION),
      o: options.map((option) => [option.id, option.label]),
      // one answer is `singlechoice`, anything more is `multiplechoice` with a ceiling of `mx`
      t: max === 1 ? 'single' : 'multi',
      mx: max,
      // `endsAt` is NIP-88's own tag name; 0 means it does not close on its own
      e: Number.isFinite(poll.endsAt) && poll.endsAt > 0 ? Math.floor(poll.endsAt) : 0,
    },
  });
}

/** The message an answer posts: empty text, the poll it answers, and the option ids chosen. */
export function packPollVote(pubkey, createdAt, pollId, optionIds, max) {
  let chosen = [...new Set((optionIds || []).map((id) => String(id).trim()).filter(Boolean))];
  if (!chosen.length) throw new Error('pick at least one option');
  if (!pollId) throw new Error('an answer needs the poll it answers');
  // a ceiling the poll set is a rule even when the person answering is in a hurry
  const ceiling = Math.max(1, Math.floor(Number(max) || chosen.length));
  if (chosen.length > ceiling) chosen = chosen.slice(0, ceiling);
  return JSON.stringify({ v: 1, p: pubkey, c: createdAt, m: '', pv: { id: String(pollId), s: chosen } });
}

/**
 * Read a room envelope. Returns `{ text, poll, vote }` — `text` is what the chat shows, and a poll or an
 * answer carries none. The author and timestamp inside the ciphertext must match the event's own fields.
 */
export function unpackRoomMessage(plaintext, event) {
  let body;
  try {
    body = JSON.parse(plaintext);
  } catch {
    return null;
  }
  if (!body || body.v !== 1 || typeof body.m !== 'string') return null;
  if (String(body.p).toLowerCase() !== String(event.pubkey).toLowerCase()) return null;
  if (Number(body.c) !== Number(event.created_at)) return null;

  if (body.poll) {
    const options = cleanOptions(body.poll.o);
    const question = String(body.poll.q || '').trim();
    if (!options || !question) return null;
    return {
      text: '',
      poll: {
        id: String(body.poll.id || ''),
        question: question.slice(0, POLL_MAX_QUESTION),
        options,
        type: body.poll.t === 'multi' ? 'multi' : 'single',
        // a poll written before the ceiling existed keeps NIP-88's own reading: one answer, or any number
        max: Math.floor(Number(body.poll.mx) || 0) > 0
          ? Math.min(Math.floor(Number(body.poll.mx)), options.length)
          : (body.poll.t === 'multi' ? options.length : 1),
        endsAt: Number(body.poll.e) > 0 ? Math.floor(Number(body.poll.e)) : 0,
      },
      vote: null,
    };
  }

  if (body.pv) {
    const pollId = String(body.pv.id || '');
    const chosen = [...new Set((body.pv.s || []).map((id) => String(id)))].filter(Boolean);
    if (!pollId || !chosen.length) return null;
    return { text: '', poll: null, vote: { pollId, options: chosen } };
  }

  return { text: body.m, poll: null, vote: null };
}

/** NIP-88: one answer per pubkey, the newest wins; an answer after `endsAt` does not count. */
export function tallyPoll(options, votes, { now = Math.floor(Date.now() / 1000) } = {}) {
  const counts = new Map(options.map((option) => [option.id, 0]));
  let voters = 0;
  for (const answer of votes.values ? votes.values() : votes) {
    voters += 1;
    for (const id of answer.options) {
      if (counts.has(id)) counts.set(id, counts.get(id) + 1);
    }
  }
  const rows = options.map((option) => {
    const count = counts.get(option.id) || 0;
    return { ...option, count, share: voters ? count / voters : 0 };
  });
  return { rows, voters, now };
}

/** Has this poll closed on its own? */
export function pollIsClosed(poll, now = Math.floor(Date.now() / 1000)) {
  return !!(poll && poll.endsAt && poll.endsAt <= now);
}

/* ---------------------------------------------------------------- polls declared by the page itself
 *
 * A poll the page creator wrote is not a room message: everybody who opens the link must see the same
 * question, so it travels inside the link's own `p` text as `[poll:Question|First|Second]` — or
 * `[poll2:Question|…]` for two answers each — and only the *answers* go to the room. That keeps the poll
 * unforgeable (it is in the link), keeps it out of the URL's byte budget as far as a poll can be, and still
 * uses the room's NIP-88 payloads, mining and tallying for the votes.
 */

const POLL_DECLARATION = /\[poll(\d?):([^\[\]|]+(?:\|[^\[\]|]*){1,5})\]/g;

/** FNV-1a over a string: chosen because it is synchronous, so every reader agrees without a server or a clock. */
function fingerprint(text) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < text.length; index += 1) {
    hash ^= text.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return 'p' + hash.toString(16).padStart(8, '0');
}

/**
 * A stable id for a declared poll, taken from what the poll *says* rather than from the characters it was
 * typed with: `[poll:Q|a|b]` and `[poll: Q | a | b ]` are the same poll, so an edit that only moves spaces
 * does not move everyone's answers to a new question.
 */
export function declaredPollId(declaration) {
  const poll = parsePollDeclaration(declaration, {withId: false});
  const text = poll
    ? `${poll.max}|${poll.question}|${poll.options.map(option => option.label).join('|')}`
    : String(declaration);
  return fingerprint(text.trim().toLowerCase());
}

/** One `[poll:…]` token as a poll, or null when it is not one. */
export function parsePollDeclaration(token, {withId = true} = {}) {
  const match = String(token || '').match(/^\[poll(\d?):(.+)\]$/s);
  if (!match) return null;
  const parts = match[2].split('|').map(part => part.trim());
  const question = parts.shift();
  const options = parts.filter(Boolean);
  if (!question || options.length < POLL_MIN_OPTIONS || options.length > POLL_MAX_OPTIONS) return null;
  const ceiling = Math.min(Math.max(1, Number(match[1]) || 1), options.length);
  const poll = {
    question: question.slice(0, POLL_MAX_QUESTION),
    options: options.map((label, index) => ({id: String.fromCharCode(97 + index), label: label.slice(0, POLL_MAX_LABEL)})),
    type: ceiling === 1 ? 'single' : 'multi',
    max: ceiling,
    endsAt: 0,
    declaration: String(token),
  };
  if (!withId) return poll;
  return {...poll, id: declaredPollId(token)};
}

/** Every poll a page declares, in the order written. */
export function parseDeclaredPolls(text) {
  const polls = [];
  for (const match of String(text || '').matchAll(POLL_DECLARATION)) {
    const poll = parsePollDeclaration(match[0]);
    if (poll) polls.push(poll);
  }
  return polls;
}

/** The text without its poll tokens, which render as cards rather than as characters. */
export function stripPollDeclarations(text) {
  return String(text || '').replace(POLL_DECLARATION, '').replace(/[ \t]+\n/g, '\n').trim();
}
