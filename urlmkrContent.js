// The content editor, and the draft that survives a reload.
//
// Two problems used to live here.
//
// 1. The editor's open state WAS the content switch. The only way out of nearly-fullscreen was to switch the
//    content off — which also takes `p` out of the link, so the page you had just written stopped existing the
//    moment you wanted your screen back. The panel now has its own state: a Done button, Escape and a click on
//    the dimmed background all close it and leave the content switched on, in the field and in the link. A small
//    "Write in full view" button reopens it without touching the switch.
//
// 2. Nothing was remembered. A reload, a stray back button or a crash lost the writing. The maker's text now
//    goes to sessionStorage — it survives a reload and dies with the browser session, which is what was asked
//    for — and a "Clear draft" button throws it away on purpose.
//
// The switch itself still opens the editor when a person flips it (event.isTrusted), because that reads as "I am
// about to write". A console button flipping the switch behind the scenes does not, or every press would throw
// the writer into fullscreen.

(function () {
  'use strict';

  const toggle = document.getElementById('include_p');
  const field = document.getElementById('p_input');
  if (!toggle || !field) return;

  const row = field.closest('.mk__row') || field.parentElement;
  const DRAFT_KEY = 'snofl_maker_draft_v1';

  // ------------------------------------------------------------------ the editor's own state

  let open = false;

  const closeButton = document.createElement('button');
  closeButton.type = 'button';
  closeButton.className = 'mk__editor-close';
  closeButton.textContent = 'Done';
  closeButton.title = 'Close the editor — the content stays on the page and in the link';

  const openButton = document.createElement('button');
  openButton.type = 'button';
  openButton.className = 'mk__editor-open';
  openButton.textContent = 'Write in full view';
  openButton.title = 'Open the content editor to nearly the whole screen';

  const clearButton = document.createElement('button');
  clearButton.type = 'button';
  clearButton.className = 'mk__editor-clear';
  clearButton.textContent = 'Clear draft';
  clearButton.title = 'Throw away everything saved in this browser session';

  row.appendChild(openButton);
  row.appendChild(clearButton);
  row.appendChild(closeButton);

  function sync() {
    row.classList.toggle('is-expanded', open);
    row.classList.toggle('is-content-on', toggle.checked);
    document.body.style.overflow = open ? 'hidden' : '';
    closeButton.hidden = !open;
    openButton.hidden = open || !toggle.checked;
    clearButton.hidden = !hasDraft();
  }

  function openEditor() {
    if (!toggle.checked) return;
    open = true;
    // while expanded the stylesheet owns the height; an inline height from the grow listener would fight it
    field.style.height = '';
    sync();
    field.focus();
    const end = field.value.length;
    try { field.setSelectionRange(end, end); } catch { /* not all inputs allow it */ }
  }

  function closeEditor() {
    open = false;
    sync();
  }

  closeButton.addEventListener('click', closeEditor);
  openButton.addEventListener('click', openEditor);

  toggle.addEventListener('change', (event) => {
    if (!toggle.checked) {
      closeEditor();
      saveDraft();
      return;
    }
    // only a person flipping the switch opens the editor: a console button enables the field invisibly
    if (event.isTrusted) openEditor();
    else sync();
    saveDraft();
  });

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && open) closeEditor();
  });

  // a click on the dimmed background, not on the row itself
  document.addEventListener('mousedown', (event) => {
    if (!open) return;
    if (row.contains(event.target)) return;
    closeEditor();
  });

  // ------------------------------------------------------------------ the draft

  const FIELDS = [
    ['allow_notes', null],
    ['include_p', 'p_input'],
    ['include_h1', 'h1_input'],
    ['include_h3', 'h3_input'],
    ['include_message', 'message_input'],
    ['message_editable', null],
    ['include_relays', 'relay1'],
    ['include_relays', 'relay2'],
    ['include_relays', 'relay3'],
    [null, 'hashtag1'],
    [null, 'hashtag2'],
    [null, 'hashtag3'],
  ];

  function collect() {
    const draft = {};
    const flags = new Set();
    FIELDS.forEach(([flag, id]) => {
      const node = document.getElementById(id);
      if (node) draft[id] = node.value;
      if (flag && !flags.has(flag)) {
        flags.add(flag);
        const box = document.getElementById(flag);
        if (box) draft[flag] = box.checked;
      }
    });
    return draft;
  }

  function hasDraft() {
    try {
      const raw = sessionStorage.getItem(DRAFT_KEY);
      if (!raw) return false;
      const draft = JSON.parse(raw);
      return Object.values(draft).some(value => typeof value === 'string' ? value.trim() !== '' : value === true);
    } catch (error) {
      return false;
    }
  }

  let saveTimer = null;
  function saveDraft() {
    clearTimeout(saveTimer);
    saveTimer = setTimeout(() => {
      try {
        sessionStorage.setItem(DRAFT_KEY, JSON.stringify(collect()));
      } catch (error) {
        /* private mode or a full quota: the maker still works, it just forgets */
      }
      clearButton.hidden = !hasDraft();
    }, 250);
  }

  function restoreDraft() {
    let draft = null;
    try {
      draft = JSON.parse(sessionStorage.getItem(DRAFT_KEY) || 'null');
    } catch (error) {
      draft = null;
    }
    if (!draft) return;

    // every switch first, then every value: a value must never land in a field its own switch has not enabled yet
    const switches = [];
    const values = [];
    Object.keys(draft).forEach(key => {
      const node = document.getElementById(key);
      if (!node) return;
      const isSwitch = node.type === 'checkbox';
      (isSwitch ? switches : values).push([key, node]);
    });
    switches.forEach(([key, box]) => {
      box.checked = Boolean(draft[key]);
      box.dispatchEvent(new Event('change', {bubbles: true}));
    });
    values.forEach(([key, node]) => {
      if (typeof draft[key] !== 'string') return;
      node.value = draft[key];
      node.dispatchEvent(new Event('input', {bubbles: true}));
    });
    // gates that depend on another switch are applied last, after both sides have their restored state
    if (typeof window.syncSuggestedMessage === 'function') window.syncSuggestedMessage();
    if (typeof window.syncMessageLimit === 'function') window.syncMessageLimit();
    if (typeof window.updateURL === 'function') window.updateURL();
  }

  function clearDraft() {
    try { sessionStorage.removeItem(DRAFT_KEY); } catch (error) { /* nothing to clear */ }
    FIELDS.forEach(([flag, id]) => {
      const node = document.getElementById(id);
      if (node) {
        node.value = '';
        node.dispatchEvent(new Event('input', {bubbles: true}));
      }
      if (flag) {
        const box = document.getElementById(flag);
        if (box) {
          box.checked = false;
          box.dispatchEvent(new Event('change', {bubbles: true}));
        }
      }
    });
    closeEditor();
    clearButton.hidden = true;
    if (typeof window.syncSuggestedMessage === 'function') window.syncSuggestedMessage();
    if (typeof window.syncMessageLimit === 'function') window.syncMessageLimit();
    if (typeof window.updateURL === 'function') window.updateURL();
  }

  clearButton.addEventListener('click', clearDraft);

  document.addEventListener('input', saveDraft);
  document.addEventListener('change', saveDraft);

  // ------------------------------------------------------------------ start

  restoreDraft();
  // a reload never lands in fullscreen: the draft is restored, the screen is not taken
  open = false;
  sync();
})();
