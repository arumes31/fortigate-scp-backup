(() => {
  'use strict';
  const search = document.querySelector('[data-report-search]');
  if (!search) return;
  const rows = Array.from(document.querySelectorAll('[data-report-row]'));
  const text = rows.map(row => row.textContent.toLocaleLowerCase());
  search.addEventListener('input', () => {
    const query = search.value.trim().toLocaleLowerCase();
    rows.forEach((row, index) => { row.hidden = !text[index].includes(query); });
  });
})();
