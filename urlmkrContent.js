// The content field opens to nearly the whole screen, and the switch that opened it stays in reach.
//
// "Your content" is where an actual page gets written, so a 96px box is the wrong place to do it. The row
// itself becomes the editor — nothing is moved, duplicated or re-parented, so every id and handler the page
// already uses keeps working — and because the row carries its own switch, closing is the same control.

(function () {
  'use strict';

  const toggle = document.getElementById('include_p');
  const field = document.getElementById('p_input');
  if (!toggle || !field) return;

  const row = field.closest('.mk__row') || field.parentElement;

  const apply = () => {
    const open = toggle.checked;
    row.classList.toggle('is-expanded', open);
    document.body.style.overflow = open ? 'hidden' : '';
    if (!open) return;
    // while expanded the stylesheet owns the height; an inline height from the grow listener would fight it
    field.style.height = '';
    field.focus();
    const end = field.value.length;
    try { field.setSelectionRange(end, end); } catch { /* not all inputs allow it */ }
  };

  toggle.addEventListener('change', apply);

  document.addEventListener('keydown', (event) => {
    if (event.key !== 'Escape') return;
    if (!row.classList.contains('is-expanded')) return;
    toggle.checked = false;
    apply();
  });

  apply();
})();
