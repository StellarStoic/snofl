// The room under a page: one encrypted thread per link, on the relays the page's creator chose.
//
// Everything a reader sees is derived from the URL — the room id, the key, the difficulty — so there is
// no account, no membership, and nothing to sign up for. The relays store ciphertext; the people holding
// the link read it. Anyone with the link can post, which is the point of the product and also its price:
// a leaked link leaks the room.

import {
  pageIdentity,
  pageId,
  pageSecret,
  roomDifficulty,
  mineEvent,
  verifyProofOfWork,
  toHex,
  fromHex,
  packPoll,
  packPollVote,
  unpackRoomMessage,
  tallyPoll,
  pollIsClosed,
  pollMaxAnswers,
  newPollId,
  parseDeclaredPolls,
  POLL_MAX_OPTIONS,
  POLL_MIN_OPTIONS,
} from './roomlib.js';
import { conversationKeyFromSecret, encryptPayload, decryptPayload, looksLikePayload } from './nip44.js';

const DEFAULT_RELAYS = [
  'wss://relay.nostr.band',
  'wss://relay.damus.io',
  'wss://relay.primal.net',
  'wss://relay.snort.social',
  'wss://nos.lol',
];

/** The plaintext a room message carries. NIP-44 gives us no associated data, so the author and the
 *  timestamp ride inside the ciphertext and are compared with the event's own fields on read — a relay
 *  that swaps either one gets a message nobody displays. */
function packMessage(pubkey, createdAt, text) {
  return JSON.stringify({ v: 1, p: pubkey, c: createdAt, m: text });
}

/** What one envelope carries: chat text, a poll, or an answer to one. None of the three is displayed twice. */
function unpackMessage(plaintext, event) {
  return unpackRoomMessage(plaintext, event);
}

/** How long this page's difficulty takes at the measured ~60k hashes/s, said plainly. */
function estimateWork(bits) {
  const seconds = 2 ** bits / 60000;
  if (seconds < 1) return 'under a second';
  if (seconds < 90) return '~' + Math.round(seconds) + 's of work';
  return '~' + Math.round(seconds / 60) + ' min of work';
}

const MAX_MESSAGES = 300;
const FETCH_LIMIT = 200;
const RELAY_TIMEOUT_MS = 6000;

/** A vote must not cost a visitor the page's full mining time: 256 hashes is instant even on a phone.
 *  Votes are kind 7 (NIP-25) and are accepted without proof of work, because other clients' votes
 *  carry none — the room's gate is on what can be *said*, not on what can be scored. */
const REACTION_BITS = 8;

/** The relays this page talks to: the creator's `r=` list, or the site's usual public ones. */
function relaysFor(search) {
  const fromUrl = (new URLSearchParams(search).get('r') || '')
    .split(',').map((url) => url.trim()).filter(Boolean);
  const valid = fromUrl.filter((url) => /^wss?:\/\/[^\s]+$/i.test(url));
  return valid.length ? valid : DEFAULT_RELAYS;
}

/** The shareable form of an event id: `note1…`, or plain hex if the page's bech32 library is missing. */
function noteBech32(id) {
  try {
    const lib = typeof bech32 !== 'undefined' ? bech32 : null;
    if (lib && typeof lib.encode === 'function' && typeof lib.toWords === 'function') {
      return lib.encode('note', lib.toWords(fromHex(id)), 1000);
    }
  } catch { /* fall back to hex */ }
  return id;
}

function shortNote(id) {
  return '#' + String(id).slice(0, 8);
}

/** Clipboard, with the old execCommand path for pages served without a secure context. */
async function copyToClipboard(text) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch { /* fall through */ }
  try {
    const area = document.createElement('textarea');
    area.value = text;
    area.setAttribute('readonly', '');
    area.style.position = 'fixed';
    area.style.top = '0';
    area.style.opacity = '0';
    document.body.append(area);
    area.select();
    const ok = document.execCommand('copy');
    area.remove();
    return ok;
  } catch {
    return false;
  }
}

function shortAuthor(pubkey, encodeNpub) {
  if (typeof encodeNpub === 'function') {
    try {
      const npub = encodeNpub(pubkey);
      if (npub) return npub.slice(0, 10) + '…' + npub.slice(-4);
    } catch { /* fall through to hex */ }
  }
  return pubkey.slice(0, 8) + '…' + pubkey.slice(-4);
}

/** The page's own title: the room is named after the page it sits under. */
function pageTitle(search) {
  try {
    const params = new URLSearchParams(search);
    const fromQuery = params.get('t');
    if (fromQuery) {
      const text = decodeURIComponent(fromQuery.replace(/\+/g, ' ')).trim();
      if (text) return text.slice(0, 60);
    }
  } catch { /* an encrypted page carries no readable title in the query */ }

  // an encrypted page (`data=`) only has a title once it has been decrypted into the heading
  const heading = document.querySelector('#mainTitle');
  const rendered = heading && heading.textContent ? heading.textContent.trim() : '';
  return rendered && rendered.toLowerCase() !== 'snofl' ? rendered.slice(0, 60) : '';
}

function timeAgo(seconds) {
  const delta = Math.max(0, Math.floor(Date.now() / 1000) - seconds);
  if (delta < 60) return `${delta}s ago`;
  if (delta < 3600) return `${Math.floor(delta / 60)}m ago`;
  if (delta < 86400) return `${Math.floor(delta / 3600)}h ago`;
  return `${Math.floor(delta / 86400)}d ago`;
}

/**
 * Ask every relay for the page's messages and votes, and resolve when they have all answered or timed
 * out. Returns the raw events; decryption happens later, per message, so a relay that never answers
 * cannot hold the whole room hostage.
 */
function fetchRoomEvents(relays, roomId) {
  const subId = 'snoflroom-' + Math.random().toString(36).slice(2, 10);
  const seen = new Map();
  const sockets = [];

  return new Promise((resolve) => {
    let pending = relays.length;
    const finish = () => {
      sockets.forEach((socket) => {
        try { socket.close(); } catch { /* already closed */ }
      });
      resolve([...seen.values()]);
    };
    const done = () => {
      pending -= 1;
      if (pending <= 0) finish();
    };
    setTimeout(() => {
      // a relay that has not answered by now is not going to hold up the room
      if (pending > 0) finish();
    }, RELAY_TIMEOUT_MS);

    relays.forEach((url) => {
      let socket;
      try {
        socket = new WebSocket(url);
      } catch {
        done();
        return;
      }
      sockets.push(socket);
      const closeOnEose = (event) => {
        if (Array.isArray(event) && event[0] === 'EOSE') {
          try { socket.close(); } catch { /* fine */ }
          done();
        }
      };
      socket.onopen = () => {
        socket.send(JSON.stringify([
          'REQ', subId,
          { kinds: [1, 7], '#h': [roomId], limit: FETCH_LIMIT },
        ]));
      };
      socket.onmessage = (message) => {
        let payload;
        try { payload = JSON.parse(message.data); } catch { return; }
        if (payload[0] === 'EVENT' && payload[2] && payload[2].id) {
          const event = payload[2];
          if ((event.tags || []).some((tag) => tag[0] === 'h' && tag[1] === roomId)) {
            seen.set(event.id, event);
          }
        } else if (payload[0] === 'CLOSED' || payload[0] === 'NOTICE') {
          done();
        } else {
          closeOnEose(payload);
        }
      };
      socket.onerror = done;
      socket.onclose = done;
    });

    if (!relays.length) finish();
  });
}

function publishTo(relays, event) {
  const results = [];
  relays.forEach((url) => {
    results.push(new Promise((resolve) => {
      let settled = false;
      const settle = (ok, detail) => {
        if (settled) return;
        settled = true;
        resolve({ url, ok, detail });
      };
      let socket;
      try {
        socket = new WebSocket(url);
      } catch (error) {
        settle(false, String(error));
        return;
      }
      const timer = setTimeout(() => {
        try { socket.close(); } catch { /* fine */ }
        settle(false, 'timed out');
      }, RELAY_TIMEOUT_MS);
      socket.onopen = () => socket.send(JSON.stringify(['EVENT', event]));
      socket.onmessage = (message) => {
        let payload;
        try { payload = JSON.parse(message.data); } catch { return; }
        if (payload[0] === 'OK' && payload[1] === event.id) {
          clearTimeout(timer);
          try { socket.close(); } catch { /* fine */ }
          settle(payload[2] === true, payload[3] || '');
        }
      };
      socket.onerror = () => { clearTimeout(timer); settle(false, 'connection failed'); };
      socket.onclose = () => { clearTimeout(timer); settle(false, 'closed before OK'); };
    }));
  });
  return Promise.all(results);
}

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

/** The value of a NIP-25 vote, whatever form the client wrote it in. */
function voteValue(content) {
  const text = String(content || '').trim();
  if (text === '+' || text === '👍' || text === '❤️') return 1;
  if (text === '-' || text === '👎') return -1;
  return 0;
}

/**
 * Mount the room into #snofl-room. Called once, from the page.
 *
 * The globals it borrows from the page (pk, pub, schnorr, signEvent, npubEncode) are the site's own —
 * the room signs with the same identity that posts notes, so an author reads the same everywhere.
 */
export async function mount(options = {}) {
  const container = document.getElementById(options.containerId || 'snofl-room');
  if (!container) return null;

  const search = window.location.search || '';
  const identity = pageIdentity(search);

  // A page with no parameters is not a page: no title, no body, nothing to talk about. That is the
  // site's landing screen — and a room there would be a room for nothing, with an id, a composer and a
  // mining process nobody asked for.
  if (!identity) {
    container.textContent = '';
    container.hidden = true;
    return null;
  }

  const roomId = pageId(search);
  const roomName = pageTitle(search);
  const difficulty = roomDifficulty(search, options.difficulty ?? 20);
  const relays = options.relays?.length ? options.relays : relaysFor(search);

  container.hidden = false;
  container.textContent = '';

  const header = element('div', 'room__header');
  const sortNew = element('button', 'room__sort is-on', 'New');
  const sortTop = element('button', 'room__sort', 'Top');
  sortNew.type = 'button';
  sortTop.type = 'button';
  sortNew.title = 'Newest first';
  sortTop.title = 'Most upvoted first';
  const sorting = element('span', 'room__sorting');
  sorting.append(sortNew, sortTop);
  const count = element('span', 'room__count', '');
  header.append(
    element('span', 'room__title', roomName ? `Room · ${roomName}` : 'Room'),
    element('span', 'room__meta', `${roomId.slice(0, 10)} · ${difficulty} bits · ${relays.length} relay${relays.length === 1 ? '' : 's'}`),
    sorting,
    count,
  );

  const pollPanel = element('section', 'room__poll');
  pollPanel.hidden = true;
  const list = element('div', 'room__list');
  const composer = element('form', 'room__composer');
  const input = element('textarea', 'room__input');
  input.rows = 3;
  input.placeholder = 'Say something to whoever holds this link…';
  input.maxLength = 2000;
  const send = element('button', 'room__send', `Post · ${estimateWork(difficulty)}`);
  send.type = 'submit';
  const cancel = element('button', 'room__cancel', 'Cancel mining');
  cancel.type = 'button';
  cancel.hidden = true;
  const buttons = element('div', 'room__buttons');
  buttons.append(send, cancel);
  const status = element('p', 'room__status', '');
  status.setAttribute('role', 'status');
  const pollToggle = element('button', 'room__poll-open', 'Poll');
  pollToggle.type = 'button';
  pollToggle.title = 'Ask the room a question';
  composer.append(input, buttons, status, pollToggle);
  container.append(header, pollPanel, list, composer);
  list.append(element('p', 'room__empty', 'Reading the room from the relays…'));

  let key;
  try {
    key = conversationKeyFromSecret(pageSecret(search));
  } catch (error) {
    list.textContent = '';
    list.append(element('p', 'room__error', 'This browser cannot derive the room key: ' + error.message));
    composer.remove();
    return { roomId, conversationKey: null };
  }

  const messages = new Map();      // note id -> { id, pubkey, created_at, text, powBits }
  const reactions = new Map();     // note id -> Map(pubkey -> { value, created_at })
  const polls = new Map();         // poll id -> { id, pubkey, created_at, question, options, type, endsAt, noteId }
  // A poll written into the page's own content travels with the link, so every reader sees the same question
  // without anyone having to publish it first. It shares the room's payloads, mining and tallying; the
  // answers are the only thing that goes to a relay.
  const declaredPolls = Array.isArray(options.declaredPolls)
    ? options.declaredPolls
    : parseDeclaredPolls(Array.isArray(window.SNOFL_PAGE_POLLS) ? window.SNOFL_PAGE_POLLS.join('\n') : '');
  for (const poll of declaredPolls) {
    polls.set(poll.id, {...poll, source: 'page', pubkey: null, created_at: 0, powBits: 0});
  }
  const pollAnswers = new Map();   // poll id -> Map(pubkey -> { options, created_at })
  let sortMode = 'new';
  let activeMining = null;         // { cancelled } while a post or a vote is mining

  const scoreOf = (id) => {
    const votes = reactions.get(id);
    if (!votes) return 0;
    let total = 0;
    for (const vote of votes.values()) total += vote.value;
    return total;
  };

  const voteCounts = (id) => {
    const votes = reactions.get(id);
    let up = 0;
    let down = 0;
    let mine = 0;
    if (votes) {
      for (const [pubkey, vote] of votes) {
        if (vote.value > 0) up += 1; else down += 1;
        if (pubkey === window.pub) mine = vote.value;
      }
    }
    return { up, down, mine };
  };

  const ordered = () => {
    const rows = [...messages.values()];
    if (sortMode === 'top') {
      rows.sort((a, b) => (scoreOf(b.id) - scoreOf(a.id)) || (b.created_at - a.created_at));
    } else {
      rows.sort((a, b) => b.created_at - a.created_at);
    }
    return rows.slice(0, MAX_MESSAGES);
  };

  const copyButton = (makeText, label, title) => {
    const button = element('button', 'room__copy', label);
    button.type = 'button';
    button.title = title;
    button.addEventListener('click', async (clickEvent) => {
      clickEvent.preventDefault();
      const text = typeof makeText === 'function' ? makeText() : makeText;
      const ok = await copyToClipboard(text);
      button.textContent = ok ? 'copied' : 'failed';
      button.classList.toggle('is-done', ok);
      setTimeout(() => {
        button.textContent = label;
        button.classList.remove('is-done');
      }, 1400);
    });
    return button;
  };

  const render = () => {
    list.textContent = '';
    if (!messages.size) {
      list.append(element('p', 'room__empty', 'Nobody has said anything on this page yet.'));
    }
    ordered().forEach((message) => {
      const row = element('div', 'room__message');
      const head = element('div', 'room__message-head');

      const counts = voteCounts(message.id);
      const up = element('button', 'room__vote room__vote--up' + (counts.mine > 0 ? ' is-mine' : ''), `👍 ${counts.up}`);
      const down = element('button', 'room__vote room__vote--down' + (counts.mine < 0 ? ' is-mine' : ''), `👎 ${counts.down}`);
      up.type = 'button';
      down.type = 'button';
      up.title = 'Upvote this note';
      down.title = 'Downvote this note';
      up.addEventListener('click', () => react(message.id, 1));
      down.addEventListener('click', () => react(message.id, -1));
      const votes = element('span', 'room__votes');
      votes.append(up, down);

      const idChip = copyButton(() => noteBech32(message.id), shortNote(message.id), 'Copy this note\'s id (note1…)');
      idChip.classList.add('room__note-id');

      head.append(
        element('span', 'room__author', shortAuthor(message.pubkey, options.npubEncode || window.npubEncode)),
        element('span', 'room__time', timeAgo(message.created_at)),
        element('span', 'room__pow', `${message.powBits} bits`),
        votes,
        idChip,
        copyButton(() => message.text, 'copy text', 'Copy this note\'s text'),
      );

      const text = element('p', 'room__text', message.text);
      row.append(head, text);
      list.append(row);
    });
    count.textContent = messages.size ? `${messages.size} note${messages.size === 1 ? '' : 's'}` : '';
    renderPoll();
  };

  const setSort = (mode) => {
    sortMode = mode;
    sortNew.classList.toggle('is-on', mode === 'new');
    sortTop.classList.toggle('is-on', mode === 'top');
    render();
  };
  sortNew.addEventListener('click', () => setSort('new'));
  sortTop.addEventListener('click', () => setSort('top'));

  const seenEvents = new Set();     // every event already read, whatever it carried

  /** Verify and decrypt one event. Returns `{ payload, powBits }` or null; never stores anything. */
  const readEvent = (event) => {
    if (seenEvents.has(event.id)) return null;
    const verdict = verifyProofOfWork(event);
    if (!verdict.ok) return null;
    if (!looksLikePayload(event.content)) return null;
    let plaintext;
    try {
      plaintext = decryptPayload(event.content, key);
    } catch {
      // not this room's payload, or not a NIP-44 payload at all
      return null;
    }
    const payload = unpackMessage(plaintext, event);
    if (!payload) return null;
    return { payload, powBits: verdict.bits };
  };

  const storePoll = (event, payload, powBits) => {
    // a newer poll on the same id replaces the older one (a re-post or a relay replay)
    const known = polls.get(payload.poll.id);
    if (!known || known.created_at <= event.created_at) {
      polls.set(payload.poll.id, {
        ...payload.poll,
        pubkey: event.pubkey,
        created_at: event.created_at,
        powBits,
      });
    }
  };

  const storeAnswer = (event, payload) => {
    // an answer to a poll this room cannot read is noise — but on a first load the relay may hand the answer
    // over before the poll, so the load reads every poll before it reads any answer (see below)
    if (!polls.has(payload.vote.pollId)) return false;
    const answers = pollAnswers.get(payload.vote.pollId) || new Map();
    const previous = answers.get(event.pubkey);
    // NIP-88: one answer per pubkey and the newest wins, so a reader can change their mind
    if (previous && previous.created_at > event.created_at) return false;
    answers.set(event.pubkey, { options: payload.vote.options, created_at: event.created_at });
    pollAnswers.set(payload.vote.pollId, answers);
    return true;
  };

  const storeMessage = (event, payload, powBits) => {
    messages.set(event.id, {
      id: event.id, pubkey: event.pubkey, created_at: event.created_at,
      text: payload.text, powBits,
    });
  };

  /** One event from anywhere: a poll, an answer, or something someone said. */
  const accept = async (event) => {
    const read = readEvent(event);
    if (!read) return false;
    const { payload, powBits } = read;
    seenEvents.add(event.id);
    if (payload.poll) storePoll(event, payload, powBits);
    else if (payload.vote) storeAnswer(event, payload);
    else storeMessage(event, payload, powBits);
    return true;
  };

  const acceptReaction = (event) => {
    const target = (event.tags || []).find((tag) => tag[0] === 'e');
    if (!target || !target[1]) return false;
    const noteId = target[1];
    // a vote for a note this room cannot read is noise, not a vote
    if (!messages.has(noteId)) return false;
    const value = voteValue(event.content);
    if (!value) return false;
    const votes = reactions.get(noteId) || new Map();
    const previous = votes.get(event.pubkey);
    // one vote per key per note: the newest wins, so a reader can change their mind
    if (previous && previous.created_at > event.created_at) return false;
    votes.set(event.pubkey, { value, created_at: event.created_at });
    reactions.set(noteId, votes);
    return true;
  };

  const normalizeSigned = (signed) => ({
    id: signed.id,
    pubkey: signed.pubkey,
    created_at: signed.created_at,
    kind: signed.kind,
    tags: signed.tags,
    content: signed.content,
    // the page's signEvent() leaves sig as noble's raw bytes; JSON would serialise that as {"0":123,…}
    sig: typeof signed.sig === 'string' ? signed.sig : toHex(new Uint8Array(signed.sig)),
  });

  /** Mine, sign and publish. Cancelling is the caller's flag, checked between hashes. */
  const signAndPublish = async (draft, bits, mining) => {
    const privateKey = window.pk;
    if (!privateKey || typeof window.signEvent !== 'function') {
      throw new Error('this page has no key in this browser yet — post a public note first, then the room can sign for you');
    }
    const mined = await mineEvent(draft, bits, {
      shouldStop: mining ? () => mining.cancelled : undefined,
      onProgress: mining?.onProgress,
    });
    const signed = await window.signEvent(mined.event, privateKey);
    const publishable = normalizeSigned(signed);
    // a different id means the work is not this event's work
    if (publishable.id !== mined.id) {
      throw new Error('the signed event has a different id than the one that was mined');
    }
    const results = await publishTo(relays, publishable);
    // a message or a poll answer is a signed event from a custom page: one of the ways out of the ID hold
    if (results.some(result => result.ok) && window.snoflIdentity && window.snoflIdentity.markSignedAction) {
      window.snoflIdentity.markSignedAction(publishable.kind);
    }
    return { publishable, mined, results };
  };

  const react = async (noteId, value) => {
    const existing = reactions.get(noteId)?.get(window.pub);
    if (existing && existing.value === value) return;      // already counted, nothing to send
    if (activeMining) {
      status.textContent = 'Wait for the current post to finish or cancel it first.';
      return;
    }
    const mining = { cancelled: false };
    activeMining = mining;
    status.textContent = value > 0 ? 'Sending your 👍…' : 'Sending your 👎…';
    try {
      const draft = {
        pubkey: window.pub,
        created_at: Math.floor(Date.now() / 1000),
        kind: 7,
        tags: [['e', noteId], ['h', roomId], ['t', 'snofl-room']],
        content: value > 0 ? '+' : '-',
      };
      const { publishable, results } = await signAndPublish(draft, REACTION_BITS, mining);
      acceptReaction(publishable);
      render();
      const accepted = results.filter((entry) => entry.ok).length;
      status.textContent = accepted
        ? `Vote sent to ${accepted} of ${results.length} relays`
        : 'No relay accepted the vote: ' + (results.find((r) => r.detail)?.detail || 'all refused');
    } catch (error) {
      status.textContent = error?.cancelled ? 'Vote cancelled.' : 'Could not vote: ' + error.message;
    } finally {
      activeMining = null;
    }
  };


  /* ---------------------------------------------------------------- the poll
   *
   * NIP-88 carried inside the room's own envelope: the question, the options and every answer stay
   * encrypted, because a room whose question leaked to a relay would not be a room. The counting rule is
   * NIP-88's — one answer per pubkey, the newest wins — and the answers are mined at the vote difficulty so
   * answering costs a tap, not the page's full work.
   */

  const selectedPoll = () => {
    // the page declares at most one poll it means; a room poll is what happens when nobody wrote one
    const fromPage = [...polls.values()].filter(poll => poll.source === 'page').sort((a, b) => (
      declaredPolls.findIndex(entry => entry.id === a.id) - declaredPolls.findIndex(entry => entry.id === b.id)
    ));
    if (fromPage.length) return fromPage[0];
    let newest = null;
    for (const poll of polls.values()) {
      if (!newest || poll.created_at > newest.created_at) newest = poll;
    }
    return newest;
  };

  const myAnswer = (pollId) => pollAnswers.get(pollId)?.get(window.pub) || null;

  let pollDraft = new Set();          // what is ticked but not yet sent
  let pollDraftFor = null;            // which poll those ticks belong to

  const closesIn = (endsAt) => {
    if (!endsAt) return 'stays open';
    const left = endsAt - Math.floor(Date.now() / 1000);
    if (left <= 0) return 'closed';
    if (left < 3600) return `closes in ${Math.max(1, Math.round(left / 60))} min`;
    if (left < 86400) return `closes in ${Math.round(left / 3600)} h`;
    return `closes in ${Math.round(left / 86400)} d`;
  };

  /** Paint the newest poll, or hide the panel when the room has none. */
  function renderPoll() {
    const poll = selectedPoll();
    pollPanel.textContent = '';
    if (!poll) {
      pollPanel.hidden = true;
      pollToggle.textContent = 'Poll';
      return;
    }
    pollPanel.hidden = false;
    // A poll declared by the page is the room's poll: offering "New poll" beside it would post a room poll
    // that the panel never shows, because the page's one wins. Say so instead of hiding the reason.
    if (poll.source === 'page') {
      pollToggle.hidden = true;
      pollForm.hidden = true;
    } else {
      pollToggle.hidden = false;
      pollToggle.textContent = 'New poll';
    }

    if (pollDraftFor !== poll.id) {
      pollDraftFor = poll.id;
      pollDraft = new Set(myAnswer(poll.id)?.options || []);
    }

    const answers = pollAnswers.get(poll.id) || new Map();
    const { rows, voters } = tallyPoll(poll.options, answers);
    const closed = pollIsClosed(poll);
    const ceiling = pollMaxAnswers(poll);
    const mine = myAnswer(poll.id);
    const unchanged = mine
      && mine.options.length === pollDraft.size
      && mine.options.every((id) => pollDraft.has(id));

    const head = element('div', 'room__poll-head');
    head.append(
      element('span', 'room__poll-tag', 'Poll'),
      element('span', 'room__poll-meta',
        (poll.source === 'page'
          ? 'asked by this page'
          : `${shortAuthor(poll.pubkey, options.npubEncode || window.npubEncode)} · ${timeAgo(poll.created_at)}`) +
        ` · ${ceiling === 1 ? 'one answer each' : `up to ${ceiling} answers each`} · ${closesIn(poll.endsAt)}`),
    );

    const question = element('p', 'room__poll-question', poll.question);
    const list_ = element('div', 'room__poll-options');

    rows.forEach((row) => {
      const chosen = pollDraft.has(row.id);
      const button = element('button', 'room__poll-option' + (chosen ? ' is-chosen' : '') + (closed ? ' is-closed' : ''));
      button.type = 'button';
      if (closed) button.disabled = true;
      button.setAttribute('aria-pressed', chosen ? 'true' : 'false');
      const bar = element('span', 'room__poll-bar');
      bar.style.width = Math.round(row.share * 100) + '%';
      bar.setAttribute('aria-hidden', 'true');
      bar.classList.toggle('is-mine', !!mine && mine.options.includes(row.id));
      button.append(
        bar,
        element('span', 'room__poll-label', row.label),
        element('span', 'room__poll-count', `${row.count}`),
      );
      button.addEventListener('click', () => {
        if (closed) return;
        // this draft belongs to this poll now: without this, the next render would re-seed the ticks from
        // the last counted answer and the tap would undo itself
        pollDraftFor = poll.id;
        if (ceiling === 1) {
          pollDraft = new Set([row.id]);
        } else if (pollDraft.has(row.id)) {
          pollDraft.delete(row.id);
        } else if (pollDraft.size < ceiling) {
          pollDraft.add(row.id);
        } else {
          // at the ceiling: say so rather than silently dropping the tap
          status.textContent = `This poll takes ${ceiling} answers each — untick one to choose another.`;
          return;
        }
        renderPoll();
      });
      list_.append(button);
    });

    const actions = element('div', 'room__poll-actions');
    if (closed) {
      actions.append(element('span', 'room__poll-note', 'This poll has closed — the counts are final.'));
    } else if (unchanged) {
      actions.append(element('span', 'room__poll-note', 'Your answer is counted. Tick another to change it.'));
    } else {
      // the same control as Post, so it borrows that rule rather than inventing a second one
      const sendVote = element('button', 'room__poll-send room__send',
        ceiling > 1 ? `Send ${pollDraft.size || ''} answer${pollDraft.size === 1 ? '' : 's'}`.replace('  ', ' ') : 'Send answer');
      sendVote.type = 'button';
      sendVote.disabled = !pollDraft.size;
      sendVote.addEventListener('click', () => castPollAnswer(poll, [...pollDraft]));
      actions.append(sendVote);
    }
    // counted in people, not ticks: one person may hold two of the answers now, and "1 answer" read as a
    // tally of ticks next to three options
    actions.append(element('span', 'room__poll-voters', `${voters} ${voters === 1 ? 'voter' : 'voters'}`));

    pollPanel.append(head, question, list_, actions);
  }

  const castPollAnswer = async (poll, optionIds) => {
    if (activeMining) {
      status.textContent = 'Wait for the current post to finish or cancel it first.';
      return;
    }
    if (!optionIds.length) return;
    const mining = { cancelled: false };
    activeMining = mining;
    status.textContent = 'Sending your answer…';
    try {
      const createdAt = Math.floor(Date.now() / 1000);
      const content = encryptPayload(
        packPollVote(window.pub, createdAt, poll.id, optionIds, pollMaxAnswers(poll)), key);
      const draft = {
        pubkey: window.pub,
        created_at: createdAt,
        kind: 1,
        tags: [['h', roomId], ['t', 'snofl-room']],
        content,
      };
      const { publishable, results } = await signAndPublish(draft, REACTION_BITS, mining);
      accept(publishable);
      render();
      const accepted = results.filter((entry) => entry.ok).length;
      status.textContent = accepted
        ? `Answer sent to ${accepted} of ${results.length} relays`
        : 'No relay accepted the answer: ' + (results.find((r) => r.detail)?.detail || 'all refused');
    } catch (error) {
      status.textContent = error?.cancelled ? 'Answer cancelled.' : 'Could not answer: ' + error.message;
    } finally {
      activeMining = null;
    }
  };

  /* --- asking the room a question ------------------------------------------------ */

  const pollForm = element('form', 'room__poll-form');
  pollForm.hidden = true;
  const pollQuestion = element('input', 'room__poll-question-input');
  pollQuestion.type = 'text';
  pollQuestion.placeholder = 'Your question';
  pollQuestion.maxLength = 160;
  const pollFields = element('div', 'room__poll-fields');
  const pollType = element('select', 'room__poll-type');
  /**
   * How many answers one person may give. 1 is NIP-88's `singlechoice`, more is `multiplechoice` with a
   * ceiling; the list tracks how many options the poll actually has, so it can never offer 5 answers to a
   * poll with 3 options.
   */
  const rebuildAnswerCeiling = () => {
    const options = Math.max(POLL_MIN_OPTIONS, pollFields.children.length);
    const chosen = Number(pollType.value) || 1;
    pollType.textContent = '';
    for (let count = 1; count <= options; count += 1) {
      const option = element('option', '', count === 1 ? 'One answer each' : `Up to ${count} answers each`);
      option.value = String(count);
      pollType.append(option);
    }
    pollType.value = String(Math.min(Math.max(1, chosen), options));
  };
  const pollCloses = element('select', 'room__poll-closes');
  [['0', 'Stays open'], ['3600', 'Closes in an hour'], ['86400', 'Closes tomorrow'], ['604800', 'Closes in a week']]
    .forEach(([value, label]) => {
      const option = element('option', '', label);
      option.value = value;
      pollCloses.append(option);
    });

  const addOptionField = (value = '') => {
    if (pollFields.children.length >= POLL_MAX_OPTIONS) return;
    const field = element('input', 'room__poll-option-input');
    field.type = 'text';
    field.placeholder = `Option ${pollFields.children.length + 1}`;
    field.maxLength = 90;
    field.value = value;
    pollFields.append(field);
    rebuildAnswerCeiling();
  };
  addOptionField();
  addOptionField();

  // The + sits with the option fields, because that is the list it extends.
  const addOption = element('button', 'room__poll-add', '+');
  addOption.type = 'button';
  addOption.title = `Add another option (up to ${POLL_MAX_OPTIONS})`;
  addOption.setAttribute('aria-label', 'Add another option');
  pollFields.after(addOption);
  const syncAddOption = () => {
    const atCeiling = pollFields.children.length >= POLL_MAX_OPTIONS;
    addOption.disabled = atCeiling;
    addOption.title = atCeiling
      ? `A poll takes at most ${POLL_MAX_OPTIONS} options`
      : `Add another option (up to ${POLL_MAX_OPTIONS})`;
  };
  addOption.addEventListener('click', () => {
    if (pollFields.children.length >= POLL_MAX_OPTIONS) return;
    addOptionField();
    // a fresh field takes the focus, and the + goes quiet at the ceiling
    const fields = [...pollFields.children];
    fields[fields.length - 1].focus();
    syncAddOption();
  });
  syncAddOption();

  const postPoll = element('button', 'room__send', `Post poll · ${estimateWork(difficulty)}`);
  postPoll.type = 'submit';
  const closePollForm = element('button', 'room__poll-cancel', 'Cancel');
  closePollForm.type = 'button';
  closePollForm.addEventListener('click', () => {
    pollForm.hidden = true;
    pollToggle.hidden = false;
    pollQuestion.value = '';
    [...pollFields.children].forEach((field) => { field.value = ''; });
  });

  const rowsWrap = element('div', 'room__poll-selects');
  rowsWrap.append(pollType, pollCloses);
  const pollFormButtons = element('div', 'room__poll-form-buttons');
  pollFormButtons.append(postPoll, addOption, closePollForm);
  pollForm.append(pollQuestion, pollFields, rowsWrap, pollFormButtons);

  pollToggle.addEventListener('click', () => {
    pollForm.hidden = false;
    pollToggle.hidden = true;
    [...pollFields.children].forEach((field) => { if (!field.value) field.value = ''; });
    rebuildAnswerCeiling();
    syncAddOption();
    pollQuestion.focus();
  });

  pollForm.addEventListener('submit', async (submitEvent) => {
    submitEvent.preventDefault();
    if (activeMining) return;
    const question = pollQuestion.value.trim();
    const labels = [...pollFields.children].map((field) => field.value.trim()).filter(Boolean);
    if (!question || labels.length < POLL_MIN_OPTIONS) {
      status.textContent = 'A poll needs a question and at least two options.';
      return;
    }
    const mining = {
      cancelled: false,
      onProgress: ({ attempts, ms }) => {
        const rate = attempts / Math.max(1, ms / 1000);
        const left = Math.max(0, (2 ** difficulty - attempts) / Math.max(1, rate));
        status.textContent = `Mining ${difficulty} bits: ${attempts.toLocaleString()} hashes · ~${Math.ceil(left)}s left · Cancel stops it`;
      },
    };
    activeMining = mining;
    setBusy(true);
    pollForm.hidden = true;
    status.textContent = `Mining the poll at ${difficulty} bits… ${estimateWork(difficulty)}`;
    try {
      const createdAt = Math.floor(Date.now() / 1000);
      const seconds = Number(pollCloses.value) || 0;
      const pollId = newPollId();
      const options = labels.map((label, index) => [String.fromCharCode(97 + index), label]);
      const payload = packPoll(window.pub, createdAt, {
        id: pollId,
        question,
        options,
        max: Number(pollType.value) || 1,
        endsAt: seconds ? createdAt + seconds : 0,
      });
      const draft = {
        pubkey: window.pub,
        created_at: createdAt,
        kind: 1,
        tags: [['h', roomId], ['t', 'snofl-room']],
        content: encryptPayload(payload, key),
      };
      const { publishable, results } = await signAndPublish(draft, difficulty, mining);
      const accepted = results.filter((entry) => entry.ok).length;
      if (!accepted) {
        status.textContent = 'No relay accepted the poll: ' + (results.find((r) => r.detail)?.detail || 'all refused');
        return;
      }
      accept(publishable);
      pollDraftFor = null;
      render();
      status.textContent = `Poll sent to ${accepted} of ${results.length} relays`;
      pollQuestion.value = '';
      [...pollFields.children].forEach((field) => { field.value = ''; });
      syncAddOption();
    } catch (error) {
      status.textContent = error?.cancelled
        ? 'Mining cancelled — the poll was not sent.'
        : 'Could not post the poll: ' + error.message;
    } finally {
      activeMining = null;
      setBusy(false);
      pollToggle.hidden = false;
    }
  });

  container.insertBefore(pollForm, composer);

  const events = await fetchRoomEvents(relays, roomId);
  // Read in three passes, because relays answer in whatever order they like and each kind needs the one
  // before it: the polls first (an answer cannot attach to a poll that has not been read yet), then the
  // answers, then the chat. Then the reactions, which need the notes they point at.
  const read = [];
  for (const event of events) {
    if (event.kind === 7) continue;
    const row = readEvent(event);
    if (row) read.push({ event, ...row });
  }
  for (const row of read) if (row.payload.poll) { seenEvents.add(row.event.id); storePoll(row.event, row.payload, row.powBits); }
  for (const row of read) if (row.payload.vote) { seenEvents.add(row.event.id); storeAnswer(row.event, row.payload); }
  for (const row of read) if (!row.payload.poll && !row.payload.vote) { seenEvents.add(row.event.id); storeMessage(row.event, row.payload, row.powBits); }
  for (const event of events) if (event.kind === 7) acceptReaction(event);
  render();

  const setBusy = (busy) => {
    send.hidden = busy;
    cancel.hidden = !busy;
    cancel.disabled = false;
    input.readOnly = busy;
  };

  composer.addEventListener('submit', async (submitEvent) => {
    submitEvent.preventDefault();
    if (activeMining) return;
    const text = input.value.trim();
    if (!text) return;
    const mining = {
      cancelled: false,
      onProgress: ({ attempts, ms }) => {
        const rate = attempts / Math.max(1, ms / 1000);
        const left = Math.max(0, (2 ** difficulty - attempts) / Math.max(1, rate));
        status.textContent = `Mining ${difficulty} bits: ${attempts.toLocaleString()} hashes · ~${Math.ceil(left)}s left · Cancel stops it`;
      },
    };
    activeMining = mining;
    setBusy(true);
    status.textContent = `Mining ${difficulty} bits… ${estimateWork(difficulty)}`;
    try {
      const createdAt = Math.floor(Date.now() / 1000);
      // a NIP-44 v2 payload: version, nonce, ChaCha20 over padded plaintext, HMAC — the protocol's own
      // format, so any implementation handed the room key could read this message
      const content = encryptPayload(packMessage(window.pub, createdAt, text), key);
      const draft = {
        pubkey: window.pub,
        created_at: createdAt,
        kind: 1,
        tags: [['h', roomId], ['t', 'snofl-room']],
        content,
      };
      const { publishable, mined, results } = await signAndPublish(draft, difficulty, mining);
      const accepted = results.filter((entry) => entry.ok).length;
      if (!accepted) {
        status.textContent = 'No relay accepted the message: ' + (results.find((r) => r.detail)?.detail || 'all refused');
        return;
      }
      await accept(publishable);
      input.value = '';
      render();
      status.textContent = `Sent to ${accepted} of ${results.length} relays · ${mined.attempts.toLocaleString()} hashes · ${noteBech32(publishable.id)}`;
    } catch (error) {
      status.textContent = error?.cancelled
        ? 'Mining cancelled — nothing was sent.'
        : 'Could not post: ' + error.message;
    } finally {
      activeMining = null;
      setBusy(false);
    }
  });

  cancel.addEventListener('click', () => {
    if (!activeMining) return;
    activeMining.cancelled = true;
    cancel.disabled = true;
    status.textContent = 'Stopping the mining…';
  });

  return {
    roomId, difficulty, relays, conversationKey: key, messages, reactions, setSort,
    polls, pollAnswers, castPollAnswer, renderPoll,
  };
}

if (typeof window !== 'undefined') {
  window.SnoflRoom = { mount };
  const start = () => {
    // The page's own scripts run before a module does, but the room must not depend on their state.
    mount().catch((error) => console.error('room failed to mount:', error));
  };
  if (document.readyState === 'complete' || document.readyState === 'interactive') {
    setTimeout(start, 0);
  } else {
    document.addEventListener('DOMContentLoaded', start);
  }
}
