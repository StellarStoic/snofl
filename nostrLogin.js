// Signing options for a snofl page.
//
// A page used to mint a random key the moment it opened, which is fine for a stranger and wrong for anyone who
// already has an identity: their notes went out under a throwaway name, and the page cheerfully published its own
// kind-0 profile for it. This module puts a door in front of that: a browser extension (NIP-07), a remote signer
// over NIP-46 (pair with a QR code, which is the only route that works well on a phone), or the same anonymous
// random key as before. Nothing here ever writes a profile for a real identity — that is *their* metadata.
//
// Pasting an nsec is deliberately not offered: a web page cannot keep it safe, so the UI says so instead of
// providing a box to type it into.

(function () {
  'use strict';

  const MODE_KEY = 'snofl_auth_mode';
  const REMOTE_SIGNER_KEY = 'snofl_remote_signer';
  const CLIENT_KEY_KEY = 'snofl_nip46_client';
  const REMOTE_RELAY_KEY = 'snofl_nip46_relay';
  // Measured from this box: relay.nsec.app does not answer at all, the three below do. A signer listens on whatever
  // relay the URI names, so the list is only about what both sides can reach.
  // Measured from this box: relay.nsec.app does not answer at all, and damus closes a second socket from the same
  // client with 1006 — which is exactly the pattern a pairing produces (page and signer side by side). Ditto and
  // primal took both. A signer listens on whatever relay the URI names, so this list is only about reachability.
  const SIGNER_RELAYS = ['wss://relay.ditto.pub', 'wss://relay.primal.net', 'wss://relay.damus.io', 'wss://relay.nsec.app'];

  const listeners = [];
  let pairing = null;   // active nostrconnect session: {secret, clientPriv, clientPub, relay, signer, socket, pending, ready}

  // ------------------------------------------------------------------ small helpers

  const hex = value => (typeof value === 'string' ? value : Array.from(value, x => x.toString(16).padStart(2, '0')).join(''));
  const bytes = hexString => Uint8Array.from(hexString.match(/.{1,2}/g) || [], b => parseInt(b, 16));
  const randomHex = length => hex(crypto.getRandomValues(new Uint8Array(length)));

  function api() {
    return window.nobleSecp256k1 || null;
  }

  async function sha256Hex(text) {
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
    return hex(new Uint8Array(digest));
  }

  async function eventId(event) {
    return sha256Hex(JSON.stringify([0, event.pubkey, event.created_at, event.kind, event.tags, event.content]));
  }

  function emit() {
    listeners.forEach(fn => { try { fn(snapshot()); } catch (error) { console.warn('identity listener failed', error); } });
  }

  // ------------------------------------------------------------------ NIP-04, for NIP-46's envelopes

  /** The x coordinate of the ECDH point: what both NIP-04 and NIP-44 use as shared material. */
  function sharedX(privateHex, publicHex) {
    const cryptoApi = api();
    const point = cryptoApi.getSharedSecret(privateHex, '02' + publicHex, true);
    return hex(point.slice(1, 33));
  }

  function nip04Encrypt(privateHex, publicHex, plaintext) {
    const key = sharedX(privateHex, publicHex);
    const iv = randomHex(16);
    const encrypted = window.CryptoJS.AES.encrypt(plaintext, window.CryptoJS.enc.Hex.parse(key), {
      iv: window.CryptoJS.enc.Hex.parse(iv),
    });
    return window.CryptoJS.enc.Base64.stringify(encrypted.ciphertext) + '?iv=' + window.CryptoJS.enc.Base64.stringify(window.CryptoJS.enc.Hex.parse(iv));
  }

  function nip04Decrypt(privateHex, publicHex, payload) {
    const [data, iv] = String(payload).split('?iv=');
    if (!data || !iv) throw new Error('not a NIP-04 payload');
    const key = sharedX(privateHex, publicHex);
    const decrypted = window.CryptoJS.AES.decrypt(
      window.CryptoJS.enc.Base64.parse(data).toString(window.CryptoJS.enc.Base64),
      window.CryptoJS.enc.Hex.parse(key),
      {iv: window.CryptoJS.enc.Hex.parse(window.CryptoJS.enc.Base64.parse(iv).toString())}
    );
    return decrypted.toString(window.CryptoJS.enc.Utf8);
  }

  // ------------------------------------------------------------------ state

  function mode() {
    return localStorage.getItem(MODE_KEY) || null;
  }

  function localPrivateKey() {
    return localStorage.getItem('nostr_pk') || null;
  }

  function pubkey() {
    const current = mode();
    if (current === 'nip07' || current === 'nip46') return localStorage.getItem('nostr_pub') || null;
    return localStorage.getItem('nostr_pub') || null;
  }

  function isRemote() {
    const current = mode();
    return current === 'nip07' || current === 'nip46';
  }

  function hasIdentity() {
    if (mode() === 'nip07') return !!localStorage.getItem('nostr_pub');
    if (mode() === 'nip46') return !!localStorage.getItem('nostr_pub') && !!localStorage.getItem(REMOTE_SIGNER_KEY);
    return !!(localPrivateKey() && localStorage.getItem('nostr_pub'));
  }

  function snapshot() {
    return {
      mode: mode(),
      pubkey: pubkey(),
      remote: isRemote(),
      profile: readCachedProfile(),
    };
  }

  // ------------------------------------------------------------------ the profile of a real identity
  //
  // Nothing here is ever *written*: a page may show a visitor's own name and picture, never publish one for them.

  const PROFILE_KEY = 'snofl_remote_profile';

  function readCachedProfile() {
    try {
      return JSON.parse(localStorage.getItem(PROFILE_KEY) || 'null');
    } catch (error) {
      return null;
    }
  }

  async function fetchProfile(pub, relays) {
    const targets = (relays && relays.length ? relays : SIGNER_RELAYS).slice(0, 6);
    return new Promise((resolve) => {
      let settled = 0;
      let done = false;
      const finish = (profile) => {
        settled += 1;
        if (done) return;
        if (profile) {
          done = true;
          try { localStorage.setItem(PROFILE_KEY, JSON.stringify(profile)); } catch (error) { /* quota */ }
          resolve(profile);
        } else if (settled >= targets.length) {
          done = true;
          resolve(null);
        }
      };
      targets.forEach((relay) => {
        let socket;
        try {
          socket = new WebSocket(relay);
        } catch { return finish(null); }
        const stop = () => { try { socket.close(); } catch { /* gone */ } };
        const timer = setTimeout(() => { stop(); finish(null); }, 6000);
        socket.onopen = () => {
          try { socket.send(JSON.stringify(['REQ', 'identity-profile', {kinds: [0], authors: [pub], limit: 1}])); }
          catch { clearTimeout(timer); stop(); finish(null); }
        };
        socket.onmessage = (message) => {
          try {
            const data = JSON.parse(message.data);
            if (data[0] === 'EOSE') { clearTimeout(timer); stop(); return finish(null); }
            if (data[0] !== 'EVENT' || !data[2]) return;
            let meta = {};
            try { meta = JSON.parse(data[2].content || '{}'); } catch { meta = {}; }
            clearTimeout(timer);
            stop();
            finish({
              name: meta.display_name || meta.name || null,
              picture: meta.picture || null,
              nip05: meta.nip05 || null,
              lud16: meta.lud16 || null,
            });
          } catch { /* not ours */ }
        };
        socket.onerror = () => { clearTimeout(timer); stop(); finish(null); };
        socket.onclose = () => { clearTimeout(timer); finish(null); };
      });
    });
  }

  // ------------------------------------------------------------------ signing

  async function signWithLocalKey(template) {
    const pk = localPrivateKey();
    if (!pk) throw new Error('no local key');
    const cryptoApi = api();
    const event = {
      kind: template.kind,
      content: template.content || '',
      created_at: template.created_at || Math.floor(Date.now() / 1000),
      tags: template.tags || [],
      pubkey: template.pubkey || hex(cryptoApi.schnorr.getPublicKey(pk)),
    };
    event.id = await eventId(event);
    const signature = await cryptoApi.schnorr.sign(event.id, pk);
    event.sig = typeof signature === 'string' ? signature : hex(signature);
    return event;
  }

  async function signWithExtension(template) {
    if (!window.nostr || typeof window.nostr.signEvent !== 'function') {
      throw new Error('the extension is not answering');
    }
    return window.nostr.signEvent({
      kind: template.kind,
      content: template.content || '',
      created_at: template.created_at || Math.floor(Date.now() / 1000),
      tags: template.tags || [],
      pubkey: localStorage.getItem('nostr_pub') || undefined,
    });
  }

  /** One request over the pairing relay, answered by the signer with the same request id. */
  async function remoteRequest(method, params) {
    // a reload forgets the socket, not the pairing: re-attach once before giving up
    if (!pairing && mode() === 'nip46') {
      await resumeRemote().catch(() => {});
    }
    if (!pairing || !pairing.ready) {
      throw new Error('not connected to the signer any more — pair it again from the badge');
    }
    const id = randomHex(8);
    const payload = JSON.stringify({id, method, params});
    const envelope = nip04Encrypt(pairing.clientPriv, pairing.signer, payload);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        pairing.pending.delete(id);
        reject(new Error('the signer did not answer in time'));
      }, 60000);
      pairing.pending.set(id, {resolve, reject, timer});
      const event = {
        kind: 24133,
        content: envelope,
        created_at: Math.floor(Date.now() / 1000),
        tags: [['p', pairing.signer]],
        pubkey: pairing.clientPub,
      };
      signWithLocalKeyForClient(event)
        .then(signed => {
          if (pairing.socket && pairing.socket.readyState === WebSocket.OPEN) {
            pairing.socket.send(JSON.stringify(['EVENT', signed]));
          } else {
            throw new Error('the pairing relay dropped');
          }
        })
        .catch(error => {
          clearTimeout(timer);
          pairing.pending.delete(id);
          reject(error);
        });
    });
  }

  /** NIP-46 envelopes are signed by the throwaway client key, not by the user's identity. */
  async function signWithLocalKeyForClient(event) {
    const cryptoApi = api();
    event.id = await eventId(event);
    const signature = await cryptoApi.schnorr.sign(event.id, pairing.clientPriv);
    event.sig = typeof signature === 'string' ? signature : hex(signature);
    return event;
  }

  async function sign(template) {
    const current = mode();
    if (current === 'nip07') return signWithExtension(template);
    if (current === 'nip46') {
      const result = await remoteRequest('sign_event', [JSON.stringify({
        kind: template.kind,
        content: template.content || '',
        created_at: template.created_at || Math.floor(Date.now() / 1000),
        tags: template.tags || [],
        pubkey: pairing.signer,
      })]);
      const signed = typeof result === 'string' ? JSON.parse(result) : result;
      if (!signed || !signed.sig) throw new Error('the signer returned no signature');
      return signed;
    }
    return signWithLocalKey(template);
  }

  // ------------------------------------------------------------------ what counts as using an ID
  //
  // The 24-hour hold on a random ID exists to stop a farm minting identities. Waiting is one way out; the other is
  // doing something with the ID on a custom page, which is exactly what a farm will not do. This counter is that
  // evidence: any signed event published from a page — a public note, a room message, a poll answer, an RSVP —
  // increments it.

  const ACTIONS_KEY = 'snofl_signed_actions_v1';

  function markSignedAction(kind) {
    let record = {count: 0, lastKind: null, lastAt: 0};
    try { record = JSON.parse(localStorage.getItem(ACTIONS_KEY) || 'null') || record; } catch (error) { record = {count: 0}; }
    record.count = (record.count || 0) + 1;
    record.lastKind = kind == null ? null : Number(kind);
    record.lastAt = Math.floor(Date.now() / 1000);
    try { localStorage.setItem(ACTIONS_KEY, JSON.stringify(record)); } catch (error) { /* quota */ }
    return record.count;
  }

  function signedActions() {
    try { return (JSON.parse(localStorage.getItem(ACTIONS_KEY) || 'null') || {}).count || 0; } catch (error) { return 0; }
  }

  // ------------------------------------------------------------------ NIP-46 pairing (nostrconnect://)

  function connectUri(session) {
    const params = new URLSearchParams({
      relay: session.relay,
      secret: session.secret,
      name: 'snofl',
      url: location.origin,
      perms: 'sign_event:1,sign_event:31922,sign_event:31923,sign_event:31925',
    });
    return 'nostrconnect://' + session.clientPub + '?' + params.toString();
  }

  /**
   * Pair with a remote signer. The client key only signs the NIP-46 envelopes; the signature on anything the page
   * publishes comes from the signer. Resolves with the signer's pubkey once it answers.
   */
  function pairRemoteSigner({onStatus, relay, relayIndex = 0} = {}) {
    const cryptoApi = api();
    const clientPriv = hex(cryptoApi.utils.randomPrivateKey());
    const clientPub = hex(cryptoApi.schnorr.getPublicKey(clientPriv));
    const session = {
      secret: randomHex(16),
      clientPriv,
      clientPub,
      relay: relay || SIGNER_RELAYS[relayIndex % SIGNER_RELAYS.length],
      signer: null,
      socket: null,
      pending: new Map(),
      ready: false,
    };
    pairing = session;
    const uri = connectUri(session);
    const status = text => { if (typeof onStatus === 'function') onStatus(text); };

    const openSocket = (relayUrl) => new Promise((resolve, reject) => {
      let socket;
      try {
        socket = new WebSocket(relayUrl);
      } catch (error) {
        return reject(error);
      }
      const ask = () => {
        try {
          socket.send(JSON.stringify(['REQ', 'nip46', {kinds: [24133], '#p': [clientPub], limit: 20}]));
        } catch { /* the socket went away; onclose deals with it */ }
      };
      socket.onopen = () => {
        session.socket = socket;
        ask();
        status('Waiting for the signer to scan…');
        // A signer that answers in the second before this REQ was registered would be missed for good: the relay
        // only sends stored events to a subscription that already exists. So keep asking until it answers — the
        // pairing is a person picking up a phone, which takes longer than a socket handshake.
        session.reask = setInterval(() => {
          if (session.ready) { clearInterval(session.reask); return; }
          ask();
        }, 5000);
        resolve();
      };
      socket.onmessage = (message) => {
        let data;
        try {
          data = JSON.parse(message.data);
        } catch { return; }
        if (data[0] === 'EOSE') { status('Pairing code seen by the relay. Scan it if you have not yet.'); return; }
        if (data[0] !== 'EVENT' || !data[2] || data[2].kind !== 24133) return;
        handleEnvelope(data[2]);
      };
      socket.onerror = () => reject(new Error('could not reach ' + relayUrl));
      socket.onclose = () => { if (!session.ready) status('The relay closed the connection. Try another relay.'); };
    });

    function handleEnvelope(event) {
      if (!session.signer && event.pubkey) session.signer = event.pubkey;
      let payload;
      try {
        payload = JSON.parse(nip04Decrypt(session.clientPriv, event.pubkey, event.content));
      } catch (error) {
        status('Could not read the signer’s answer: ' + error.message);
        return;
      }
      if (!payload) return;

      // the signer may answer the pairing itself: nsec.app echoes the secret, Amber answers "ack"
      if (!session.ready && (payload.result === session.secret || payload.result === 'ack' || payload.error === null && !payload.id)) {
        finishPairing(event.pubkey);
        return;
      }
      if (payload.result === session.secret) {
        finishPairing(event.pubkey);
        return;
      }
      const waiting = payload.id && session.pending.get(payload.id);
      if (waiting) {
        clearTimeout(waiting.timer);
        session.pending.delete(payload.id);
        if (payload.error) waiting.reject(new Error(payload.error));
        else waiting.resolve(payload.result);
        return;
      }
      if (!session.ready) finishPairing(event.pubkey);
    }

    async function finishPairing(signerPubkey) {
      if (session.ready) return;
      session.ready = true;
      if (session.reask) clearInterval(session.reask);
      session.signer = signerPubkey;
      localStorage.setItem(MODE_KEY, 'nip46');
      localStorage.setItem('nostr_pub', signerPubkey);
      localStorage.setItem(REMOTE_SIGNER_KEY, signerPubkey);
      localStorage.setItem(CLIENT_KEY_KEY, clientPriv);
      localStorage.setItem(REMOTE_RELAY_KEY, session.relay);
      status('Paired. Your signer signs, the page only sends the request.');
      const profile = await fetchProfile(signerPubkey, [session.relay]);
      if (profile) localStorage.setItem(PROFILE_KEY, JSON.stringify(profile));
      emit();
    }

    // The code is shown before the socket is attempted: a QR that appears only once a relay answers is a QR that
    // never appears when the relay is down, which is exactly when you need to be told.
    const connected = openSocket(session.relay).catch((error) => {
      status('Could not reach ' + session.relay + ' — try another relay.');
      throw error;
    });
    return {uri, session, connected};
  }

  /** Re-attach to a signer this browser already paired with, after a reload. */
  async function resumeRemote() {
    if (mode() !== 'nip46') return false;
    const clientPriv = localStorage.getItem(CLIENT_KEY_KEY);
    const signer = localStorage.getItem(REMOTE_SIGNER_KEY);
    const relay = localStorage.getItem(REMOTE_RELAY_KEY) || SIGNER_RELAYS[0];
    if (!clientPriv || !signer) return false;
    const clientPub = hex(api().schnorr.getPublicKey(clientPriv));
    pairing = {secret: null, clientPriv, clientPub, relay, signer, socket: null, pending: new Map(), ready: true};
    return new Promise((resolve) => {
      let socket;
      try {
        socket = new WebSocket(relay);
      } catch { return resolve(false); }
      const timer = setTimeout(() => resolve(false), 6000);
      socket.onopen = () => {
        clearTimeout(timer);
        pairing.socket = socket;
        socket.send(JSON.stringify(['REQ', 'nip46', {kinds: [24133], '#p': [clientPub], limit: 20}]));
        resolve(true);
      };
      socket.onmessage = (message) => {
        let data;
        try { data = JSON.parse(message.data); } catch { return; }
        if (data[0] !== 'EVENT' || !data[2] || data[2].kind !== 24133) return;
        let payload;
        try { payload = JSON.parse(nip04Decrypt(clientPriv, data[2].pubkey, data[2].content)); } catch { return; }
        const waiting = payload.id && pairing.pending.get(payload.id);
        if (waiting) {
          clearTimeout(waiting.timer);
          pairing.pending.delete(payload.id);
          if (payload.error) waiting.reject(new Error(payload.error));
          else waiting.resolve(payload.result);
        }
      };
      socket.onerror = () => { clearTimeout(timer); resolve(false); };
    });
  }

  // ------------------------------------------------------------------ choosing a mode

  async function useExtension() {
    if (!window.nostr || typeof window.nostr.getPublicKey !== 'function') {
      throw new Error('No browser extension answered. Install one (Alby, nos2x) or use a remote signer.');
    }
    const pub = await window.nostr.getPublicKey();
    if (!pub) throw new Error('The extension did not hand over a public key.');
    localStorage.setItem(MODE_KEY, 'nip07');
    localStorage.setItem('nostr_pub', pub);
    try { localStorage.removeItem('nostr_pk'); } catch (error) { /* nothing to remove */ }
    await fetchProfile(pub, null);
    emit();
    return pub;
  }

  function useAnonymous() {
    localStorage.setItem(MODE_KEY, 'anon');
    emit();
  }

  function signOut() {
    ['snofl_auth_mode', 'snofl_remote_signer', 'snofl_nip46_client', 'snofl_nip46_relay', 'snofl_remote_profile']
      .forEach(key => { try { localStorage.removeItem(key); } catch (error) { /* fine */ } });
    pairing = null;
    emit();
  }

  function onChange(fn) {
    listeners.push(fn);
  }

  // ------------------------------------------------------------------ the door itself

  let overlay = null;

  function buildPrompt() {
    if (overlay) return overlay;
    overlay = document.createElement('div');
    overlay.className = 'snofl-login';
    overlay.innerHTML = [
      '<div class="snofl-login__card" role="dialog" aria-modal="true" aria-labelledby="snoflLoginTitle">',
      '  <button type="button" class="snofl-login__close" aria-label="Close">×</button>',
      '  <h2 id="snoflLoginTitle" class="snofl-login__title">Post as yourself, or stay anonymous</h2>',
      '  <p class="snofl-login__lede">A note you post is public and signed. Choose how to sign it — you can change this later from the badge.</p>',
      '  <div class="snofl-login__options">',
      '    <button type="button" class="snofl-login__option" data-choice="extension">',
      '      <span class="snofl-login__option-name">Browser extension</span>',
      '      <span class="snofl-login__option-note">Alby, nos2x and similar (NIP-07). Nothing leaves your browser.</span>',
      '    </button>',
      '    <button type="button" class="snofl-login__option" data-choice="remote">',
      '      <span class="snofl-login__option-name">Remote signer — show a QR</span>',
      '      <span class="snofl-login__option-note">Scan it with Amber, nsec.app or any NIP-46 signer. Best on a phone.</span>',
      '    </button>',
      '    <button type="button" class="snofl-login__option" data-choice="anon">',
      '      <span class="snofl-login__option-name">Stay anonymous</span>',
      '      <span class="snofl-login__option-note">This page makes a random ID that lives in this browser, as it always has.</span>',
      '    </button>',
      '  </div>',
      '  <div class="snofl-login__pairing" hidden>',
      '    <p class="snofl-login__pairing-status">Starting…</p>',
      '    <div class="snofl-login__qr" id="snofl_login_qr"></div>',
      '    <label class="snofl-login__uri-label" for="snofl_login_uri">…or open this in your signer</label>',
      '    <textarea class="snofl-login__uri" id="snofl_login_uri" readonly rows="4"></textarea>',
      '    <div class="snofl-login__pairing-actions">',
      '      <a class="snofl-login__open-signer" id="snofl_login_open" href="#">Open in Amber</a>',
      '      <button type="button" class="snofl-login__retry" id="snofl_login_retry" hidden>Try another relay</button>',
      '      <button type="button" class="snofl-login__back">Back</button>',
      '    </div>',
      '  </div>',
      '  <p class="snofl-login__warning">Never paste an <code>nsec</code> into a web page — including this one. A page cannot keep it safe; that is exactly what a signer is for.</p>',
      '</div>',
    ].join('');
    document.body.appendChild(overlay);

    overlay.addEventListener('click', async (event) => {
      const choice = event.target.closest('[data-choice]');
      if (choice) {
        const picked = choice.dataset.choice;
        if (picked === 'extension') await tryExtension(choice);
        if (picked === 'remote') startPairing();
        if (picked === 'anon') {
          useAnonymous();
          if (typeof window.snoflBeginAnonymous === 'function') window.snoflBeginAnonymous();
          close();
        }
        return;
      }
      if (event.target === overlay || event.target.closest('.snofl-login__close')) close();
      if (event.target.closest('.snofl-login__back')) {
        overlay.querySelector('.snofl-login__pairing').hidden = true;
        overlay.querySelector('.snofl-login__options').hidden = false;
      }
    });
    return overlay;
  }

  async function tryExtension(button) {
    const note = button.querySelector('.snofl-login__option-note');
    const original = note.textContent;
    try {
      note.textContent = 'Asking the extension…';
      await useExtension();
      close();
    } catch (error) {
      note.textContent = error.message;
      setTimeout(() => { note.textContent = original; }, 6000);
    }
  }

  let relayAttempt = 0;

  function startPairing(relayIndex = relayAttempt) {
    relayAttempt = relayIndex;
    const card = overlay;
    const options = card.querySelector('.snofl-login__options');
    const pairingBox = card.querySelector('.snofl-login__pairing');
    const statusLine = card.querySelector('.snofl-login__pairing-status');
    const qrBox = card.querySelector('#snofl_login_qr');
    const uriField = card.querySelector('#snofl_login_uri');
    const openLink = card.querySelector('#snofl_login_open');

    options.hidden = true;
    pairingBox.hidden = false;
    qrBox.innerHTML = '';
    uriField.value = '';
    statusLine.textContent = 'Show this to your signer, or open the link on this phone.';

    const started = pairRemoteSigner({
      relayIndex,
      onStatus: text => { statusLine.textContent = text; },
    });

    // the code first, the connection afterwards
    uriField.value = started.uri;
    openLink.href = started.uri;
    if (typeof window.QRCode === 'function') {
      new window.QRCode(qrBox, {
        text: started.uri,
        width: 220,
        height: 220,
        colorDark: '#000000',
        colorLight: '#ffffff',
        correctLevel: window.QRCode.CorrectLevel?.M,
      });
    } else {
      statusLine.textContent = 'The QR library did not load — copy the link into your signer instead.';
    }

    const retry = card.querySelector('#snofl_login_retry');
    if (retry) {
      retry.textContent = 'Try ' + SIGNER_RELAYS[(relayIndex + 1) % SIGNER_RELAYS.length].replace('wss://', '');
      retry.hidden = false;
      retry.onclick = () => startPairing(relayIndex + 1);
    }

    started.connected.catch(() => { /* the status line already says it */ });

    const session = started.session;
    const watch = setInterval(() => {
      if (session.ready) {
        clearInterval(watch);
        close();
      }
    }, 700);
    setTimeout(() => clearInterval(watch), 300000);
  }

  function openPrompt() {
    buildPrompt();
    overlay.hidden = false;
    overlay.classList.add('is-open');
  }

  function close() {
    if (!overlay) return;
    overlay.classList.remove('is-open');
    overlay.hidden = true;
    // a pairing left half-finished must not keep a socket open
    if (pairing && !pairing.ready) {
      try { pairing.socket && pairing.socket.close(); } catch (error) { /* gone */ }
    }
  }

  // ------------------------------------------------------------------ exports

  window.snoflIdentity = {
    mode, pubkey, isRemote, hasIdentity, sign, onChange, snapshot,
    useExtension, useAnonymous, pairRemoteSigner, resumeRemote, fetchProfile,
    openPrompt, close,
    markSignedAction, signedActions,
    signOut,
    // for probes and for the page's own legacy key paths
    localPrivateKey,
  };
})();
