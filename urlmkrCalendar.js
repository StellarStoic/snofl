// Authoring a NIP-52 calendar event from the maker.
//
// The Calendar button used to insert `nostr:naddr1` and leave the writer to find an event that already existed
// somewhere. This is the other half: title, time, place, summary, signed by whichever identity the maker has
// (extension, remote signer or the anonymous key), published to relays, and only then inserted into the content as
// a reference — because the page resolves references, it does not carry events.
//
// Two kinds, as NIP-52 defines them:
//   31923  a time   — `start`/`end` in unix seconds, optional `start_tzid`/`end_tzid`
//   31922  whole days — `start`/`end` as YYYY-MM-DD, and `end` is EXCLUSIVE
//
// Both are addressable, so the event carries a `d` identifier and the reference is an naddr (kind + author + `d`),
// not an id: the author may replace the event later and the reference keeps working.

(function () {
  'use strict';

  const RELAYS = [
    'wss://relay.ditto.pub',
    'wss://relay.primal.net',
    'wss://relay.damus.io',
    'wss://nos.lol',
  ];

  let dialog = null;

  const el = (tag, className, text) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = text;
    return node;
  };

  function hexToBytes(hexString) {
    return Uint8Array.from((hexString.match(/.{1,2}/g) || []), byte => parseInt(byte, 16));
  }

  function localZone() {
    try {
      return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
    } catch (error) {
      return 'UTC';
    }
  }

  /** The naddr for a published event: TLV of identifier, relays, author and kind, as NIP-19 defines. */
  function naddrFor(event, relays) {
    // bech32.js declares a script-scope const, not a window property: the bare name is what the rest of the site uses
    const bech = (typeof bech32 !== 'undefined' && bech32) || window.bech32;
    if (!bech) throw new Error('bech32 is not loaded');
    const kindBytes = [];
    let kind = Number(event.kind);
    while (kind > 0) {
      kindBytes.unshift(kind & 0xff);
      kind >>= 8;
    }
    const identifier = (event.tags.find(tag => tag[0] === 'd') || [])[1] || '';
    const encoder = new TextEncoder();

    const parts = [];
    const push = (type, bytes) => parts.push(type, bytes.length, ...bytes);

    push(0, encoder.encode(identifier));
    relays.slice(0, 1).forEach(relay => push(1, encoder.encode(relay)));
    push(2, hexToBytes(event.pubkey));
    push(3, new Uint8Array(kindBytes));

    return bech.encode('naddr', bech.toWords(new Uint8Array(parts)), 2000);
  }

  /** Publish to the relays; resolve with how many accepted and what the rest said. */
  function publish(event, relays) {
    return new Promise((resolve) => {
      let accepted = 0;
      const reasons = [];
      let settled = 0;
      const done = () => {
        settled += 1;
        if (settled === relays.length) resolve({accepted, reasons});
      };
      relays.forEach((relay) => {
        let socket;
        try {
          socket = new WebSocket(relay);
        } catch { return done(); }
        let closed = false;
        const finish = () => {
          if (closed) return;
          closed = true;
          clearTimeout(timer);
          try { socket.close(); } catch { /* gone */ }
          done();
        };
        const timer = setTimeout(finish, 7000);
        socket.onopen = () => {
          try { socket.send(JSON.stringify(['EVENT', event])); } catch { finish(); }
        };
        socket.onmessage = (message) => {
          try {
            const data = JSON.parse(message.data);
            if (data[0] === 'OK' && data[2] === true) { accepted += 1; finish(); }
            else if (data[0] === 'OK') { reasons.push(relay + ': ' + (data[3] || 'refused')); finish(); }
            else if (data[0] === 'NOTICE') { reasons.push(relay + ': ' + data[1]); finish(); }
          } catch { /* not ours */ }
        };
        socket.onerror = finish;
        socket.onclose = finish;
      });
      if (!relays.length) resolve({accepted: 0, reasons: ['no relays']});
    });
  }

  /** Where the reference should land: the caret in #p_input, with the content switch on. */
  function insertReference(reference) {
    const field = document.getElementById('p_input');
    const toggle = document.getElementById('include_p');
    if (!field) return false;
    if (toggle && !toggle.checked) {
      toggle.checked = true;
      toggle.dispatchEvent(new Event('change', {bubbles: true}));
    }
    field.disabled = false;
    const start = field.selectionStart ?? field.value.length;
    const end = field.selectionEnd ?? start;
    const lead = field.value.slice(0, start).trim() ? '\n' : '';
    const text = lead + 'nostr:' + reference + '\n';
    field.value = field.value.slice(0, start) + text + field.value.slice(end);
    const caret = start + text.length;
    field.selectionStart = caret;
    field.selectionEnd = caret;
    field.focus();
    field.dispatchEvent(new Event('input', {bubbles: true}));
    field.dispatchEvent(new Event('change', {bubbles: true}));
    const hint = document.getElementById('content_console_hint');
    if (hint) hint.textContent = 'Calendar — the event is in the content as a reference; the page draws the card, and readers can answer it.';
    if (typeof window.syncStripOverflow === 'function') window.syncStripOverflow();
    return true;
  }

  function buildDialog() {
    if (dialog) return dialog;
    dialog = el('div', 'mk-cal');
    dialog.innerHTML = [
      '<div class="mk-cal__card" role="dialog" aria-modal="true" aria-labelledby="mkCalTitle">',
      '  <button type="button" class="mk-cal__close" aria-label="Close">×</button>',
      '  <h2 class="mk-cal__title" id="mkCalTitle">New calendar event</h2>',
      '  <p class="mk-cal__lede">Published to Nostr under your identity, then inserted into the content as a reference. Readers see the card and can answer it.</p>',
      '  <div class="mk-cal__fields">',
      '    <label class="mk-cal__field"><span>Kind</span>',
      '      <select id="mkCalKind"><option value="31923">A time (date, hours)</option><option value="31922">Whole days</option></select>',
      '    </label>',
      '    <label class="mk-cal__field"><span>Title</span><input type="text" id="mkCalTitleInput" placeholder="Sunset ridge walk" maxlength="140"></label>',
      '    <div class="mk-cal__pair">',
      '      <label class="mk-cal__field"><span id="mkCalStartLabel">Starts</span><input type="datetime-local" id="mkCalStart"></label>',
      '      <label class="mk-cal__field"><span id="mkCalEndLabel">Ends</span><input type="datetime-local" id="mkCalEnd"></label>',
      '    </div>',
      '    <label class="mk-cal__field" id="mkCalZoneField"><span>Timezone</span><input type="text" id="mkCalZone" placeholder="Europe/Ljubljana"></label>',
      '    <label class="mk-cal__field"><span>Place</span><input type="text" id="mkCalWhere" placeholder="Krvavec, SI" maxlength="120"></label>',
      '    <label class="mk-cal__field"><span>Summary</span><textarea id="mkCalSummary" rows="3" placeholder="What happens, what to bring." maxlength="600"></textarea></label>',
      '  </div>',
      '  <p class="mk-cal__status" id="mkCalStatus" role="status"></p>',
      '  <div class="mk-cal__actions">',
      '    <button type="button" class="mk-cal__publish" id="mkCalPublish">Publish and insert</button>',
      '    <button type="button" class="mk-cal__plain" id="mkCalPlain">Insert a plain reference</button>',
      '  </div>',
      '</div>',
    ].join('');
    document.body.appendChild(dialog);

    const kind = dialog.querySelector('#mkCalKind');
    const start = dialog.querySelector('#mkCalStart');
    const end = dialog.querySelector('#mkCalEnd');
    const zoneField = dialog.querySelector('#mkCalZoneField');
    const zone = dialog.querySelector('#mkCalZone');
    zone.value = localZone();

    // A timed event asks for hours, a whole-day event asks for days, and the labels say which
    const syncKind = () => {
      const timed = kind.value === '31923';
      start.type = timed ? 'datetime-local' : 'date';
      end.type = timed ? 'datetime-local' : 'date';
      zoneField.hidden = !timed;
      dialog.querySelector('#mkCalStartLabel').textContent = timed ? 'Starts' : 'First day';
      dialog.querySelector('#mkCalEndLabel').textContent = timed ? 'Ends' : 'Last day';
      if (!start.value) {
        const now = new Date();
        now.setMinutes(0, 0, 0);
        start.value = timed
          ? new Date(now.getTime() + 3600000 - now.getTimezoneOffset() * 60000).toISOString().slice(0, 16)
          : new Date(now.getTime() - now.getTimezoneOffset() * 60000).toISOString().slice(0, 10);
      }
    };
    kind.addEventListener('change', syncKind);
    syncKind();

    dialog.addEventListener('click', (event) => {
      if (event.target === dialog || event.target.closest('.mk-cal__close')) close();
    });
    dialog.querySelector('#mkCalPlain').addEventListener('click', () => {
      // not a fake reference: the caret, with `nostr:` ready, so a writer can paste one they already have
      close();
      const field = document.getElementById('p_input');
      const toggle = document.getElementById('include_p');
      if (!field) return;
      if (toggle && !toggle.checked) {
        toggle.checked = true;
        toggle.dispatchEvent(new Event('change', {bubbles: true}));
      }
      field.disabled = false;
      const at = field.selectionStart ?? field.value.length;
      field.value = field.value.slice(0, at) + 'nostr:' + field.value.slice(at);
      field.selectionStart = field.selectionEnd = at + 6;
      field.focus();
      field.dispatchEvent(new Event('input', {bubbles: true}));
    });
    dialog.querySelector('#mkCalPublish').addEventListener('click', submit);
    return dialog;
  }

  function open() {
    buildDialog();
    dialog.hidden = false;
    dialog.classList.add('is-open');
    const status = dialog.querySelector('#mkCalStatus');
    status.textContent = window.snoflIdentity && window.snoflIdentity.hasIdentity()
      ? ''
      : 'This needs an identity to sign with. Press Publish and you will be asked how.';
    setTimeout(() => dialog.querySelector('#mkCalTitleInput').focus(), 60);
  }

  function close() {
    if (!dialog) return;
    dialog.classList.remove('is-open');
    dialog.hidden = true;
  }

  async function ensureIdentity() {
    if (!window.snoflIdentity) throw new Error('the identity module is not loaded');
    if (window.snoflIdentity.hasIdentity()) return true;
    window.snoflIdentity.openPrompt();
    throw new Error('choose how to sign in (or stay anonymous), then press Publish again');
  }

  async function submit() {
    const status = dialog.querySelector('#mkCalStatus');
    const publishButton = dialog.querySelector('#mkCalPublish');
    const kind = Number(dialog.querySelector('#mkCalKind').value);
    const title = dialog.querySelector('#mkCalTitleInput').value.trim();
    const where = dialog.querySelector('#mkCalWhere').value.trim();
    const summary = dialog.querySelector('#mkCalSummary').value.trim();
    const startValue = dialog.querySelector('#mkCalStart').value;
    const endValue = dialog.querySelector('#mkCalEnd').value;
    const zone = dialog.querySelector('#mkCalZone').value.trim();

    if (!title) { status.textContent = 'An event needs a title.'; return; }
    if (!startValue) { status.textContent = 'An event needs a start.'; return; }

    publishButton.disabled = true;
    try {
      status.textContent = 'Checking identity…';
      await ensureIdentity();

      const identity = window.snoflIdentity.pubkey();
      const tags = [['d', 'snofl-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 7)], ['title', title]];
      if (summary) tags.push(['summary', summary]);
      if (where) tags.push(['location', where]);

      if (kind === 31923) {
        tags.push(['start', String(Math.floor(new Date(startValue).getTime() / 1000))]);
        if (endValue) tags.push(['end', String(Math.floor(new Date(endValue).getTime() / 1000))]);
        if (zone) {
          tags.push(['start_tzid', zone]);
          if (endValue) tags.push(['end_tzid', zone]);
        }
      } else {
        tags.push(['start', startValue]);
        if (endValue) {
          // NIP-52's `end` is the day after the last day, so "same day" still needs the next morning
          const included = new Date(endValue + 'T00:00:00Z');
          included.setUTCDate(included.getUTCDate() + 1);
          tags.push(['end', included.toISOString().slice(0, 10)]);
        } else {
          const nextDay = new Date(startValue + 'T00:00:00Z');
          nextDay.setUTCDate(nextDay.getUTCDate() + 1);
          tags.push(['end', nextDay.toISOString().slice(0, 10)]);
        }
      }

      status.textContent = 'Signing…';
      const signed = await window.snoflIdentity.sign({kind, content: '', tags, pubkey: identity});

      status.textContent = 'Publishing…';
      const targets = customRelays().length ? customRelays() : RELAYS;
      const {accepted, reasons} = await publish(signed, targets);
      if (accepted === 0) {
        // a bare "no relay took it" leaves a writer with nowhere to go; the relays' own words say what happened
        status.textContent = 'No relay accepted the event' +
          (reasons.length ? ' — ' + reasons.slice(0, 2).join(' · ') : ' (none answered)') +
          '. Try again, or use another relay in the maker.';
        return;
      }

      const reference = naddrFor(signed, targets);
      if (!insertReference(reference)) {
        status.textContent = 'Published, but the content field was not found. The reference is ' + reference;
        return;
      }
      status.textContent = 'Published to ' + accepted + ' of ' + targets.length + ' relays and inserted in the content.';
      setTimeout(close, 1400);
    } catch (error) {
      // keep the stack in the console: the form only has room for the sentence, and this is where a real fault
      // (a relay that refuses, a signer that misbehaves) is worth more than the sentence alone
      console.error('calendar composer:', error);
      status.textContent = error && error.message ? error.message : String(error);
    } finally {
      publishButton.disabled = false;
    }
  }

  /** Relays the writer typed in the maker, so the event lands where their page already looks. */
  function customRelays() {
    const toggle = document.getElementById('include_relays');
    if (!toggle || !toggle.checked) return [];
    return [1, 2, 3]
      .map(index => (document.getElementById('relay' + index) || {}).value || '')
      .map(value => value.trim())
      .filter(value => /^wss?:\/\//i.test(value));
  }

  window.snoflCalendarComposer = { open, close };
})();
