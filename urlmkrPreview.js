// Preview the page before publishing it.
//
// The link the maker shows in #url_output is the authority: if it is a real URL, the preview loads exactly
// what someone receiving it would get, encryption included. Only when there is no link yet (no card type
// chosen) does this file read the controls itself, and it says so rather than pretending.

(function () {
  'use strict';

  const BASE = 'index.html';

  function open() {
    const button = document.getElementById('preview_button');
    const dialog = document.getElementById('mk-preview');
    const frame = document.getElementById('mk-preview-frame');
    const link = document.getElementById('mk-preview-open');
    const close = document.getElementById('mk-preview-close');
    if (!button || !dialog || !frame) return;

    const readValue = (id) => {
      const node = document.getElementById(id);
      return node ? String(node.value || '').trim() : '';
    };
    const isOn = (id) => {
      const node = document.getElementById(id);
      return !!(node && node.checked);
    };

    /** The link exactly as it appears in the panel, if the panel holds one. */
    const publishedUrl = () => {
      const out = document.getElementById('url_output');
      const text = out ? String(out.textContent || '').trim() : '';
      return /^https?:\/\/\S+\?\S+/i.test(text) ? text : '';
    };

    /** Fallback: read the controls. Mirrors the maker's own parameter mapping for preview only. */
    const fromControls = () => {
      const hashtags = [1, 2, 3].map((n) => readValue('hashtag' + n)).filter(Boolean);
      const relays = [1, 2, 3, 4, 5].map((n) => readValue('relay' + n)).filter(Boolean);
      const stored = (key) => localStorage.getItem(key) || '';
      const params = new URLSearchParams();

      const put = (key, value) => {
        if (value !== '' && value !== null && value !== undefined) params.set(key, value);
      };

      if (isOn('include_h1')) put('t', readValue('h1_input'));
      if (isOn('include_h3')) put('s', readValue('h3_input'));
      if (isOn('include_p')) put('p', readValue('p_input'));
      if (isOn('include_message')) put('m', readValue('message_input'));
      if (isOn('include_font')) put('f', stored('selectedFontIndex'));
      if (isOn('include_background')) put('b', stored('selectedBackgroundIndex'));
      if (isOn('include_avatar')) put('a', stored('selectedAvatarIndex'));
      if (isOn('include_ln')) {
        const address = readValue('ln_input');
        // the maker stores the lightning address reversed; reverse it back for a readable preview
        if (address) put('ln', address.split('').reverse().join(''));
      }
      if (hashtags.length) put('h', hashtags.join(','));
      if (isOn('include_relays') && relays.length) put('r', relays.join(','));
      if (isOn('custom_characters')) put('l', readValue('characters_input'));
      if (!isOn('allow_notes')) put('n', '0');
      if (isOn('enable_hint')) put('c', readValue('password_hint'));

      const query = params.toString();
      return location.origin + '/' + BASE + (query ? '?' + query : '');
    };

    const show = () => {
      const url = publishedUrl() || fromControls();
      frame.src = url;
      if (link) link.href = url;
      if (typeof dialog.showModal === 'function') {
        if (!dialog.open) dialog.showModal();
      } else {
        dialog.setAttribute('open', '');
      }
    };

    button.addEventListener('click', show);
    if (close) {
      close.addEventListener('click', () => {
        if (typeof dialog.close === 'function') dialog.close();
        else dialog.removeAttribute('open');
        frame.src = 'about:blank';
      });
    }
    // Esc closes a <dialog> on its own; clear the frame so a closed preview is not still loading
    dialog.addEventListener('close', () => { frame.src = 'about:blank'; });
    dialog.addEventListener('click', (event) => {
      if (event.target === dialog) {
        if (typeof dialog.close === 'function') dialog.close();
      }
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', open);
  } else {
    open();
  }
})();
