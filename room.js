// The room under a page: one encrypted thread per link, on the relays the page's creator chose.
//
// Everything a reader sees is derived from the URL — the room id, the key, the difficulty — so there is
// no account, no membership, and nothing to sign up for. The relays store ciphertext; the people holding
// the link read it. Anyone with the link can post, which is the point of the product and also its price:
// a leaked link leaks the room.

import {
  pageIdentity, pageId, pageSecret, roomDifficulty,
  mineEvent, verifyProofOfWork, toHex, fromHex,
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

function unpackMessage(plaintext, event) {
  let body;
  try {
    body = JSON.parse(plaintext);
  } catch {
    return null;
  }
  if (!body || body.v !== 1 || typeof body.m !== 'string') return null;
  if (String(body.p).toLowerCase() !== String(event.pubkey).toLowerCase()) return null;
  if (Number(body.c) !== Number(event.created_at)) return null;
  return body.m;
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
    element('span', 'room__title', 'Room'),
    element('span', 'room__meta', `${roomId.slice(0, 10)} · ${difficulty} bits · ${relays.length} relay${relays.length === 1 ? '' : 's'}`),
    sorting,
    count,
  );

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
  composer.append(input, buttons, status);
  container.append(header, list, composer);
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
  };

  const setSort = (mode) => {
    sortMode = mode;
    sortNew.classList.toggle('is-on', mode === 'new');
    sortTop.classList.toggle('is-on', mode === 'top');
    render();
  };
  sortNew.addEventListener('click', () => setSort('new'));
  sortTop.addEventListener('click', () => setSort('top'));

  const accept = async (event) => {
    if (messages.has(event.id)) return false;
    const verdict = verifyProofOfWork(event);
    if (!verdict.ok) return false;
    if (!looksLikePayload(event.content)) return false;
    let plaintext;
    try {
      plaintext = decryptPayload(event.content, key);
    } catch {
      // not this room's payload, or not a NIP-44 payload at all
      return false;
    }
    const text = unpackMessage(plaintext, event);
    if (text === null) return false;
    messages.set(event.id, {
      id: event.id, pubkey: event.pubkey, created_at: event.created_at,
      text, powBits: verdict.bits,
    });
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

  const events = await fetchRoomEvents(relays, roomId);
  // notes first: a vote can only be counted against a note that is already readable
  for (const event of events) if (event.kind !== 7) await accept(event);
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

  return { roomId, difficulty, relays, conversationKey: key, messages, reactions, setSort };
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
