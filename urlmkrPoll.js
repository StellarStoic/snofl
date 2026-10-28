// Authoring a poll from the maker, as a form rather than as bracket syntax.
//
// The Poll button used to insert `[poll:Your question here|First choice|Second choice]` and leave the writer to type
// over the placeholders. This is the form: a question, two to six options, and how many answers one person may give.
// It writes the same token the page already reads (`[poll:…]`, `[pollN:…]`), through buildPollDeclaration in
// roomlib.js, so the dialog and the parser cannot disagree about the syntax.
//
// What this is NOT: nothing is signed and nothing is published. The declaration travels inside the link — that is what
// makes it visible to every reader without anyone posting it — and only the answers go to the room, as NIP-88-shaped
// payloads inside the room's own NIP-44 envelope. NIP-88 itself (kind 1068/1018) is a public poll; the shape here is
// its shape, the transport is the room's.
//
// The shell is the calendar composer's (`.mk-cal` in urlmkr.css): same overlay, card, fields and sticky actions, because
// two dialogs that look like two different sites is worse than two dialogs sharing a stylesheet.

(function () {
  'use strict';

  const MIN_OPTIONS = 2;
  const MAX_OPTIONS = 6;

  let dialog = null;
  let rowsHost = null;
  let questionInput = null;
  let ceilingSelect = null;
  let previewNode = null;
  let insertButton = null;
  let hintNode = null;

  const el = (tag, className, text) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = text;
    return node;
  };

  /** The builder lives in roomlib.js; this dialog only knows how to drive it. */
  function builder() {
    return typeof window.snoflBuildPollDeclaration === 'function' ? window.snoflBuildPollDeclaration : null;
  }

  function optionValues() {
    return [...rowsHost.querySelectorAll('input')].map((input) => input.value);
  }

  function ceiling() {
    return Number(ceilingSelect.value) || 1;
  }

  /** What the link will carry, and how much of a tag it costs. */
  function currentToken() {
    const build = builder();
    if (!build) return '';
    return build({question: questionInput.value, options: optionValues(), max: ceiling()});
  }

  function syncCeilingOptions() {
    const count = optionValues().filter((value) => value.trim()).length;
    const wanted = Math.max(1, Math.min(count || 1, MAX_OPTIONS));
    const previous = ceilingSelect.value;
    ceilingSelect.textContent = '';
    for (let n = 1; n <= wanted; n += 1) {
      const option = el('option', null, n === 1 ? 'One answer each' : `${n} answers each`);
      option.value = String(n);
      ceilingSelect.append(option);
    }
    ceilingSelect.value = String(Math.min(Number(previous) || 1, wanted));
  }

  function syncState() {
    // the select is rebuilt from the number of filled options, so it has to settle BEFORE the token is built —
    // otherwise the preview and the inserted token show the ceiling from the previous keystroke
    syncCeilingOptions();
    const token = currentToken();
    const filled = optionValues().filter((value) => value.trim()).length;
    const valid = Boolean(token);
    insertButton.disabled = !valid;
    // a control that cannot act says why, and the count is the reason
    if (!questionInput.value.trim()) {
      hintNode.textContent = 'Type the question first.';
    } else if (filled < MIN_OPTIONS) {
      hintNode.textContent = `A poll needs at least ${MIN_OPTIONS} answers to choose between — ${filled} so far.`;
    } else {
      hintNode.textContent = '';
    }
    previewNode.textContent = token || '—';
    const bytes = token ? encodeURIComponent(token).length : 0;
    const cost = previewNode.nextElementSibling;
    if (cost) cost.textContent = token ? `${token.length} characters · ${bytes} bytes of the link` : '';
    const addButton = dialog.querySelector('#mkPollAdd');
    // the ceiling of option fields: quiet at the limit, not gone
    addButton.disabled = filled >= MAX_OPTIONS;
    addButton.title = addButton.disabled ? `A poll has at most ${MAX_OPTIONS} options` : 'Add another option';
  }

  function addRow(value = '') {
    const row = el('div', 'mk-poll__row');
    const input = el('input');
    input.type = 'text';
    input.placeholder = rowsHost.children.length ? 'Another choice' : 'A choice';
    input.value = value;
    input.maxLength = 90;
    input.addEventListener('input', syncState);
    const remove = el('button', 'mk-poll__remove', '×');
    remove.type = 'button';
    remove.setAttribute('aria-label', 'Remove this option');
    remove.addEventListener('click', () => {
      if (rowsHost.querySelectorAll('.mk-poll__row').length <= MIN_OPTIONS) {
        // keep the two the syntax requires; clearing the text is how a writer drops an option
        input.value = '';
        syncState();
        return;
      }
      row.remove();
      syncState();
    });
    row.append(input, remove);
    rowsHost.append(row);
    syncState();
    return input;
  }

  function buildDialog() {
    if (dialog) return dialog;
    dialog = el('div', 'mk-cal mk-poll');
    dialog.innerHTML = [
      '<div class="mk-cal__card" role="dialog" aria-modal="true" aria-labelledby="mkPollTitle">',
      '  <button type="button" class="mk-cal__close" aria-label="Close">×</button>',
      '  <h2 class="mk-cal__title" id="mkPollTitle">New poll</h2>',
      '  <p class="mk-cal__lede">The question is written into the link, so every reader sees it without anyone posting it.',
      '     Only the answers go to the room, and they are counted one per person. Nothing is published when you press',
      '     Insert — the poll lives in the page itself.</p>',
      '  <div class="mk-cal__fields">',
      '    <label class="mk-cal__field" for="mkPollQuestion"><span>Question</span>',
      '      <input type="text" id="mkPollQuestion" placeholder="Pineapple on pizza?" maxlength="160"></label>',
      '  </div>',
      '  <fieldset class="mk-poll__options"><legend>Answers to choose from</legend>',
      '    <div class="mk-poll__rows" id="mkPollRows"></div>',
      '    <button type="button" class="mk-poll__add" id="mkPollAdd">+ Add an option</button>',
      '    <label class="mk-cal__field mk-poll__ceiling" for="mkPollCeiling"><span>Each person may give</span>',
      '      <select id="mkPollCeiling"></select></label>',
      '  </fieldset>',
      '  <p class="mk-poll__hint" id="mkPollHint" role="status"></p>',
      '  <p class="mk-poll__previewwrap"><code class="mk-poll__preview" id="mkPollPreview">—</code><span class="mk-poll__cost"></span></p>',
      '  <div class="mk-cal__actions">',
      '    <button type="button" class="mk-cal__publish" id="mkPollInsert">Insert into the content</button>',
      '    <button type="button" class="mk-cal__plain" id="mkPollCancel">Cancel</button>',
      '  </div>',
      '</div>',
    ].join('\n');
    document.body.appendChild(dialog);

    rowsHost = dialog.querySelector('#mkPollRows');
    questionInput = dialog.querySelector('#mkPollQuestion');
    ceilingSelect = dialog.querySelector('#mkPollCeiling');
    previewNode = dialog.querySelector('#mkPollPreview');
    insertButton = dialog.querySelector('#mkPollInsert');
    hintNode = dialog.querySelector('#mkPollHint');

    questionInput.addEventListener('input', syncState);
    // without this the preview keeps showing the ceiling from before the select moved, while Insert (which rebuilds
    // the token) writes the new one — the form contradicting itself
    ceilingSelect.addEventListener('change', syncState);
    ceilingSelect.addEventListener('input', syncState);
    dialog.querySelector('#mkPollAdd').addEventListener('click', () => addRow().focus());
    insertButton.addEventListener('click', insert);
    dialog.querySelector('#mkPollCancel').addEventListener('click', close);
    dialog.querySelector('.mk-cal__close').addEventListener('click', close);
    dialog.addEventListener('click', (event) => {
      if (event.target === dialog) close();
    });
    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape' && isOpen()) close();
    });
    return dialog;
  }

  /** The token goes on its own line at the caret, and the link is rebuilt behind it. */
  function insert() {
    const token = currentToken();
    if (!token) return;
    const field = document.getElementById('p_input');
    const toggle = document.getElementById('include_p');
    if (!field) return;
    if (toggle && !toggle.checked) {
      toggle.checked = true;
      toggle.dispatchEvent(new Event('change', {bubbles: true}));
    }
    field.disabled = false;
    const start = field.selectionStart == null ? field.value.length : field.selectionStart;
    const end = field.selectionEnd == null ? start : field.selectionEnd;
    const before = field.value.slice(0, start);
    const lead = before && !/\n$/.test(before) ? '\n' : '';
    const text = lead + token + '\n';
    field.value = before + text + field.value.slice(end);
    const caret = start + text.length;
    field.selectionStart = caret;
    field.selectionEnd = caret;
    field.focus();
    field.dispatchEvent(new Event('input', {bubbles: true}));
    field.dispatchEvent(new Event('change', {bubbles: true}));
    const consoleHint = document.getElementById('content_console_hint');
    if (consoleHint) consoleHint.textContent = 'Poll — the question is in the content now; readers answer it under the page.';
    if (typeof window.syncStripOverflow === 'function') window.syncStripOverflow();
    close();
  }

  function isOpen() {
    return Boolean(dialog && dialog.classList.contains('is-open'));
  }

  function open() {
    buildDialog();
    // a fresh question each time this is opened from a page that has no poll yet
    if (!rowsHost.querySelector('.mk-poll__row')) {
      addRow();
      addRow();
    }
    syncState();
    // the shared shell hides with `display: none` and shows with `.is-open`; the hidden attribute loses to both
    dialog.hidden = false;
    dialog.classList.add('is-open');
    document.body.style.overflow = 'hidden';
    questionInput.focus();
  }

  function close() {
    if (!dialog) return;
    dialog.classList.remove('is-open');
    dialog.hidden = true;
    document.body.style.overflow = '';
  }

  /** Open on a declaration that is already in the content, so the form is a viewer as well as a writer. */
  function openWith(token) {
    open();
    const match = String(token || '').match(/^\[poll(\d?):(.+)\]$/s);
    if (!match) return;
    const parts = match[2].split('|').map((part) => part.trim());
    questionInput.value = parts.shift() || '';
    rowsHost.textContent = '';
    parts.filter(Boolean).forEach((label) => addRow(label));
    syncState();
    if (match[1]) ceilingSelect.value = match[1];
    syncState();
  }

  window.snoflPollComposer = {open, openWith, close};
})();
