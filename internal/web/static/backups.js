(function () {
    'use strict';

    var form = document.querySelector('[data-backup-compare-form]');
    if (!form) return;
    var choices = Array.from(form.querySelectorAll('[data-backup-select]'));
    var submit = form.querySelector('[data-backup-compare]');
    var status = document.getElementById('backup-compare-status');

    function update() {
        var selected = choices.filter(function (choice) { return choice.checked; });
        choices.forEach(function (choice) {
            choice.disabled = selected.length === 2 && !choice.checked;
        });
        submit.disabled = selected.length !== 2;
        status.textContent = selected.length + ' of 2 selected';
    }

    choices.forEach(function (choice) { choice.addEventListener('change', update); });
    update();
}());
