(() => {
  'use strict';
  const search = document.querySelector('[data-report-search]');
  if (search) {
    const rows = Array.from(document.querySelectorAll('[data-report-row]'));
    const text = rows.map(row => row.textContent.toLocaleLowerCase());
    search.addEventListener('input', () => {
      const query = search.value.trim().toLocaleLowerCase();
      rows.forEach((row, index) => { row.hidden = !text[index].includes(query); });
    });
  }

  const profile = document.querySelector('[data-report-profile]');
  if (profile) {
    profile.querySelectorAll('[data-report-order-list]').forEach(list => {
      const updateOrderButtons = () => {
        const items = Array.from(list.querySelectorAll('[data-report-order-item]'));
        items.forEach((item, index) => {
          item.querySelector('[data-report-move="earlier"]').disabled = index === 0;
          item.querySelector('[data-report-move="later"]').disabled = index === items.length - 1;
        });
      };
      list.querySelectorAll('[data-report-order-controls]').forEach(controls => { controls.hidden = false; });
      list.addEventListener('click', event => {
        const button = event.target.closest('[data-report-move]');
        if (!button) return;
        const item = button.closest('[data-report-order-item]');
        const earlier = button.dataset.reportMove === 'earlier';
        const neighbor = earlier ? item.previousElementSibling : item.nextElementSibling;
        if (!neighbor) return;
        if (earlier) list.insertBefore(item, neighbor);
        else list.insertBefore(neighbor, item);
        updateOrderButtons();
        if (button.disabled) {
          item.querySelector(earlier ? '[data-report-move="later"]' : '[data-report-move="earlier"]').focus();
        } else button.focus();
        const status = list.parentElement.querySelector('[data-report-order-status]');
        if (status) status.textContent = list.dataset.reportOrderChanged;
      });
      updateOrderButtons();
    });
    const frequency = profile.querySelector('[data-report-frequency]');
    const scheduledFields = Array.from(profile.querySelectorAll('[data-report-schedule-field]'));
    if (frequency) {
      const updateSchedule = () => {
        scheduledFields.forEach(field => {
          // Preserve values while a frequency is inactive. The server validates
          // all submitted settings; these controls only affect presentation.
          field.hidden = !field.dataset.reportScheduleField.split(' ').includes(frequency.value);
        });
      };
      frequency.addEventListener('change', updateSchedule);
      updateSchedule();
      profile.addEventListener('invalid', event => {
        // A value edited before changing frequency can still be invalid. Keep
        // that field reachable when native browser validation focuses it.
        const field = event.target.closest('[data-report-schedule-field]');
        if (field) field.hidden = false;
      }, true);
    }
  }
})();
