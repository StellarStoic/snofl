// The room under a page: one encrypted thread per link, on the relays the page's creator chose.
//
// Everything a reader sees is derived from the URL — the room id, the key, the difficulty — so there is
// no account, no membership, and nothing to sign up for. The relays store ciphertext; the people holding
// the link read it. Anyone with the link can post, which is the point of the product and also its price:
// a leaked link leaks the room.

import {
  pageIdentity, pageId, roomDifficulty, roomKey,
  encryptMessage, decryptMessage, mineEvent, verifyProofOfWork, toHex, messageAad,
} from './roomlib.js';

const DEFAULT_RELAYS = [
  'wss://relay.nostr.band',
  'wss://relay.damus.io',
  'wss://njump.me',
  'wss://relay.snort.social',
  'wss://nos.lol',
];

const MAX_MESSAGES = 300;
const FETCH_LIMIT = 200;
const RELAY_TIMEOUT_MS = 6000;

/** The relays this page talks to: the creator's `r=` list, or the site's usual public ones. */
function relaysFor(search) {
  const fromUrl = (new URLSearchParams(search).get('r') || '')
    .split(',').map((url) => url.trim()).filter(Boolean);
  const valid = fromUrl.filter((url) => /^wss?:\/\/[^\s]+$/i.test(url));
  return valid.length ? valid : DEFAULT_RELAYS;
}

function shortAuthor(pubkey, bech32) {
  if (typeof bech32 === 'function') {
    try {
      const npub = bech32(pubkey);
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
 * Ask every relay for the page's messages and resolve when they have all answered or timed out.
 * Returns the raw events; decryption happens later, per message, so a relay that never answers cannot
 * hold the whole room hostage.
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
          { kinds: [1], '#h': [roomId], limit: FETCH_LIMIT },
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
  const roomId = pageId(search);
  const difficulty = roomDifficulty(search, options.difficulty ?? 20);
  const relays = options.relays?.length ? options.relays : relaysFor(search);

  container.textContent = '';
  const header = element('div', 'room__header');
  header.append(
    element('span', 'room__title', 'Room'),
    element('span', 'room__meta', `${roomId.slice(0, 10)} · ${difficulty} bits · ${relays.length} relay${relays.length === 1 ? '' : 's'}`),
  );
  const list = element('div', 'room__list');
  const composer = element('form', 'room__composer');
  const input = element('textarea', 'room__input');
  input.rows = 3;
  input.placeholder = 'Say something to whoever holds this link…';
  input.maxLength = 2000;
  const send = element('button', 'room__send', `Post · ~${Math.round(2 ** difficulty / 60000)}s of work`);
  send.type = 'submit';
  const status = element('p', 'room__status', '');
  composer.append(input, send, status);
  container.append(header, list, composer);

  const count = element('span', 'room__count', '');
  header.append(count);
  list.append(element('p', 'room__empty', 'Reading the room from the relays…'));

  let key;
  try {
    key = await roomKey(identity);
  } catch (error) {
    list.textContent = '';
    list.append(element('p', 'room__error', 'This browser cannot derive the room key: ' + error.message));
    composer.remove();
    return { roomId, roomKey: null };
  }

  const messages = [];
  const render = () => {
    list.textContent = '';
    if (!messages.length) {
      list.append(element('p', 'room__empty', 'Nobody has said anything on this page yet.'));
    }
    messages
      .sort((a, b) => b.created_at - a.created_at)
      .slice(0, MAX_MESSAGES)
      .forEach((message) => {
        const row = element('div', 'room__message');
        const head = element('div', 'room__message-head');
        head.append(
          element('span', 'room__author', shortAuthor(message.pubkey, options.npubEncode || window.npubEncode)),
          element('span', 'room__time', timeAgo(message.created_at)),
          element('span', 'room__pow', `${message.powBits} bits`),
        );
        row.append(head, element('p', 'room__text', message.text));
        list.append(row);
      });
    count.textContent = messages.length ? `${messages.length} message${messages.length === 1 ? '' : 's'}` : '';
  };

  const accept = async (event) => {
    if (messages.some((entry) => entry.id === event.id)) return false;
    const verdict = verifyProofOfWork(event);
    if (!verdict.ok) return false;
    const text = await decryptMessage(key, event.content, {
      aad: messageAad(roomId, event.pubkey, event.created_at),
    });
    if (text === null) return false;
    messages.push({
      id: event.id, pubkey: event.pubkey, created_at: event.created_at,
      text, powBits: verdict.bits,
    });
    return true;
  };

  const events = await fetchRoomEvents(relays, roomId);
  for (const event of events) await accept(event);
  render();

  composer.addEventListener('submit', async (submitEvent) => {
    submitEvent.preventDefault();
    const text = input.value.trim();
    if (!text) return;
    const privateKey = window.pk;
    if (!privateKey || typeof window.signEvent !== 'function') {
      status.textContent = 'This page has no key in this browser yet — post a note first, then the room can sign for you.';
      return;
    }
    send.disabled = true;
    input.readOnly = true;
    status.textContent = `Working… (~${Math.round(2 ** difficulty / 60000)}s)`;
    try {
      const createdAt = Math.floor(Date.now() / 1000);
      const content = await encryptMessage(key, text, {
        aad: messageAad(roomId, window.pub, createdAt),
      });
      const draft = {
        pubkey: window.pub,
        created_at: createdAt,
        kind: 1,
        tags: [['h', roomId], ['t', 'snofl-room']],
        content,
      };
      const mined = await mineEvent(draft, difficulty, {
        onProgress: ({ attempts, ms }) => {
          const rate = attempts / Math.max(1, ms / 1000);
          const remaining = Math.max(0, (2 ** difficulty - attempts) / Math.max(1, rate));
          status.textContent = `Mining ${difficulty} bits: ${attempts.toLocaleString()} hashes, ~${Math.ceil(remaining)}s left`;
        },
      });
      const signed = await window.signEvent(mined.event, privateKey);

      // The page's signEvent() leaves sig as the raw 64 bytes from noble. JSON would serialise that as
      // {"0":123,…} and every relay would refuse the event, so it is normalised to hex here — and the id
      // is checked against the one that was mined, because a different id means the work is not this
      // event's work.
      const publishable = {
        id: signed.id,
        pubkey: signed.pubkey,
        created_at: signed.created_at,
        kind: signed.kind,
        tags: signed.tags,
        content: signed.content,
        sig: typeof signed.sig === 'string' ? signed.sig : toHex(new Uint8Array(signed.sig)),
      };
      if (publishable.id !== mined.id) {
        throw new Error('the signed event has a different id than the one that was mined');
      }
      const results = await publishTo(relays, publishable);
      const accepted = results.filter((entry) => entry.ok).length;
      if (!accepted) {
        status.textContent = 'No relay accepted the message: ' + (results.find((r) => r.detail)?.detail || 'all refused');
      } else {
        status.textContent = `Sent to ${accepted} of ${results.length} relays · ${mined.attempts.toLocaleString()} hashes`;
        input.value = '';
        await accept(publishable);
        render();
      }
    } catch (error) {
      status.textContent = 'Could not post: ' + error.message;
    } finally {
      send.disabled = false;
      input.readOnly = false;
    }
  });

  return { roomId, difficulty, relays, roomKey: key, messages };
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
