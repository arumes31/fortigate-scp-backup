(function () {
    'use strict';

    function onReady(callback) {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', callback, { once: true });
        } else {
            callback();
        }
    }

    onReady(function () {
        var form = document.querySelector('[data-password-policy]');
        if (!form) return;

        var current = document.getElementById('old_password');
        var next = document.getElementById('new_password');
        var confirmation = document.getElementById('confirm_password');
        var byteCount = document.getElementById('passwordByteCount');
        var capsWarning = document.getElementById('capsLockWarning');
        var minBytes = Number(form.dataset.minBytes);
        var maxBytes = Number(form.dataset.maxBytes);
        var encoder = new TextEncoder();

        function setRule(name, valid) {
            var rule = form.querySelector('[data-password-rule="' + name + '"]');
            if (rule) rule.dataset.valid = valid ? 'true' : 'false';
        }

        function updatePolicy(showResults) {
            var bytes = encoder.encode(next.value).length;
            byteCount.textContent = bytes + ' UTF-8 ' + (bytes === 1 ? 'byte' : 'bytes');
            if (!showResults) return;
            setRule('length', bytes >= minBytes && bytes <= maxBytes);
            setRule('different', next.value !== '' && next.value !== current.value);
            setRule('match', next.value !== '' && confirmation.value !== '' && next.value === confirmation.value);
        }

        function updateCapsLock(event) {
            capsWarning.hidden = !(event.getModifierState && event.getModifierState('CapsLock'));
        }

        [current, next, confirmation].forEach(function (input) {
            input.addEventListener('input', function () { updatePolicy(true); });
            input.addEventListener('keydown', updateCapsLock);
            input.addEventListener('keyup', updateCapsLock);
            input.addEventListener('blur', function () { capsWarning.hidden = true; });
        });
        updatePolicy(false);
    });
})();
