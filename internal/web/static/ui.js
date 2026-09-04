// Shared browser helpers for FortiSafe pages. Loaded before any page script
// that builds DOM from strings, so there is exactly one HTML-escaping
// primitive and one i18n lookup in the app.

// esc HTML-escapes a value for safe interpolation into innerHTML strings.
function esc(s) {
    return String(s ?? "").replace(/[&<>"']/g, c => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    })[c]);
}

// tt looks up a UI string injected by the page as window.I18N (the catalog's
// own fallback is English, so a missing key rendering as its raw name is a
// bug, not a translation gap).
var fortiSafeI18nMeta = document.querySelector('meta[name="fortisafe-i18n"]');
if (fortiSafeI18nMeta) {
    try { window.I18N = JSON.parse(fortiSafeI18nMeta.content || '{}'); } catch (error) { window.I18N = {}; }
}
function tt(key) { return (window.I18N && window.I18N[key]) || key; }

// One shared live connection per authenticated page. Consumers such as the
// dashboard subscribe to the custom events instead of opening a second SSE
// stream. Public pages do not render data-live-status, so they never connect.
(function () {
    function startLiveStatus() {
        var status = document.querySelector('[data-live-status]');
        if (!status) return;
        var dot = document.getElementById('sseDot');
        var label = document.getElementById('sseLabel');
        function update(state, text) {
            if (dot) dot.className = 'sse-dot ' + state;
            if (label) label.textContent = text;
            window.dispatchEvent(new CustomEvent('fortisafe:connection', { detail: { state: state } }));
        }
        if (!window.EventSource) {
            update('offline', status.dataset.unavailable || 'Unavailable');
            return;
        }
        var events = new EventSource('/events');
        events.onopen = function () {
            update('online', status.dataset.connected || 'Connected');
        };
        events.onerror = function () {
            update('offline', status.dataset.reconnecting || 'Connection interrupted');
        };
        events.onmessage = function (event) {
            window.dispatchEvent(new CustomEvent('fortisafe:message', { detail: { data: event.data } }));
        };
        window.addEventListener('pagehide', function () { events.close(); }, { once: true });
    }
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', startLiveStatus, { once: true });
    } else {
        startLiveStatus();
    }
})();

// Shared keyboard, feedback, clipboard, password, and time primitives. Pages
// opt in through data attributes; no page-specific inline handlers are needed.
(function () {
    'use strict';

    var timePreferenceKey = 'fortisafe.ui.v1.timeMode';
    var allowedTimeModes = { utc: true, local: true };

    function onReady(callback) {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', callback, { once: true });
        } else {
            callback();
        }
    }

    function focusableElements(container) {
        return Array.from(container.querySelectorAll(
            'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), ' +
            'textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
        )).filter(function (element) { return !element.hidden && element.getClientRects().length > 0; });
    }

    function initDialogs() {
        document.querySelectorAll('dialog[data-ui-dialog]').forEach(function (dialog) {
            var opener = null;
            var confirmation = dialog.querySelector('[data-confirm-input]');
            var action = dialog.querySelector('[data-confirm-action]');

            function updateConfirmation() {
                var expected = dialog.dataset.confirmText || '';
                if (confirmation && action) action.disabled = !expected || confirmation.value !== expected;
            }
            if (confirmation) confirmation.addEventListener('input', updateConfirmation);
            updateConfirmation();

            dialog.addEventListener('keydown', function (event) {
                if (event.key !== 'Tab') return;
                var elements = focusableElements(dialog);
                if (!elements.length) return;
                var first = elements[0];
                var last = elements[elements.length - 1];
                if (event.shiftKey && document.activeElement === first) {
                    event.preventDefault();
                    last.focus();
                } else if (!event.shiftKey && document.activeElement === last) {
                    event.preventDefault();
                    first.focus();
                }
            });
            dialog.addEventListener('close', function () {
                if (opener && opener.isConnected) opener.focus();
            });
            dialog.querySelectorAll('[data-dialog-close]').forEach(function (button) {
                button.addEventListener('click', function () { dialog.close(); });
            });
            document.querySelectorAll('[data-dialog-open="' + CSS.escape(dialog.id) + '"]').forEach(function (button) {
                button.addEventListener('click', function () {
                    opener = button;
                    if (confirmation) confirmation.value = '';
                    updateConfirmation();
                    dialog.showModal();
                    var initial = dialog.querySelector('[data-dialog-initial]');
                    if (initial) initial.focus();
                });
            });
        });
    }

    function initTabs() {
        document.querySelectorAll('[data-tabs]').forEach(function (tabs) {
            var tabList = tabs.querySelector('[role="tablist"]');
            if (!tabList) return;
            var tabButtons = Array.from(tabList.querySelectorAll('[role="tab"]'));

            function activate(tab, moveFocus) {
                tabButtons.forEach(function (candidate) {
                    var selected = candidate === tab;
                    candidate.setAttribute('aria-selected', String(selected));
                    candidate.tabIndex = selected ? 0 : -1;
                    var panel = document.getElementById(candidate.getAttribute('aria-controls'));
                    if (panel) panel.hidden = !selected;
                });
                if (moveFocus) tab.focus();
            }
            tabButtons.forEach(function (tab, index) {
                tab.addEventListener('click', function () { activate(tab, false); });
                tab.addEventListener('keydown', function (event) {
                    var next = index;
                    if (event.key === 'ArrowRight') next = (index + 1) % tabButtons.length;
                    else if (event.key === 'ArrowLeft') next = (index - 1 + tabButtons.length) % tabButtons.length;
                    else if (event.key === 'Home') next = 0;
                    else if (event.key === 'End') next = tabButtons.length - 1;
                    else return;
                    event.preventDefault();
                    activate(tabButtons[next], true);
                });
            });
        });
    }

    function copyFallback(value) {
        var field = document.createElement('textarea');
        field.value = value;
        field.setAttribute('readonly', '');
        field.style.position = 'fixed';
        field.style.opacity = '0';
        document.body.appendChild(field);
        field.select();
        var copied = false;
        try {
            copied = document.execCommand('copy');
        } catch (_) {
            copied = false;
        } finally {
            field.remove();
        }
        return copied ? Promise.resolve() : Promise.reject(new Error('copy failed'));
    }

    function initCopyButtons() {
        document.querySelectorAll('[data-copy-target]').forEach(function (button) {
            button.addEventListener('click', function () {
                var source = document.getElementById(button.dataset.copyTarget);
                var feedback = document.getElementById(button.dataset.copyFeedback || '');
                if (!source) return;
                var value = source.value !== undefined ? source.value : source.textContent;
                var operation = navigator.clipboard && navigator.clipboard.writeText
                    ? navigator.clipboard.writeText(value).catch(function () { return copyFallback(value); })
                    : copyFallback(value);
                operation.then(function () {
                    announceFeedback(feedback, 'success', button.dataset.copySuccess || 'Copied');
                }).catch(function () {
                    announceFeedback(feedback, 'error', button.dataset.copyError || 'Copy failed');
                });
            });
        });
    }

    function configureFeedback(feedback) {
        var urgent = feedback.dataset.feedback === 'error';
        feedback.setAttribute('role', urgent ? 'alert' : 'status');
        feedback.setAttribute('aria-live', urgent ? 'assertive' : 'polite');
        feedback.setAttribute('aria-atomic', 'true');
    }

    function announceFeedback(feedback, kind, message) {
        if (!feedback) return;
        feedback.dataset.feedback = kind;
        configureFeedback(feedback);
        feedback.textContent = message;
    }

    function initFeedback() {
        document.querySelectorAll('[data-feedback]').forEach(function (feedback) {
            configureFeedback(feedback);
        });
    }

    function initPasswordToggles() {
        document.querySelectorAll('[data-password-toggle]').forEach(function (button) {
            button.addEventListener('click', function () {
                var input = document.getElementById(button.dataset.passwordToggle);
                if (!input) return;
                var reveal = input.type === 'password';
                input.type = reveal ? 'text' : 'password';
                button.setAttribute('aria-pressed', String(reveal));
                if (button.dataset.showLabel && button.dataset.hideLabel) {
                    button.textContent = reveal ? button.dataset.hideLabel : button.dataset.showLabel;
                }
                if (button.dataset.showAriaLabel && button.dataset.hideAriaLabel) {
                    button.setAttribute('aria-label', reveal ? button.dataset.hideAriaLabel : button.dataset.showAriaLabel);
                }
            });
        });
    }

    function readTimeMode() {
        try {
            var stored = localStorage.getItem(timePreferenceKey);
            return allowedTimeModes[stored] ? stored : 'utc';
        } catch (_) {
            return 'utc';
        }
    }

    function twoDigits(value) { return String(value).padStart(2, '0'); }

    function formatTime(date, mode, timeOnly) {
        var year = mode === 'utc' ? date.getUTCFullYear() : date.getFullYear();
        var month = mode === 'utc' ? date.getUTCMonth() + 1 : date.getMonth() + 1;
        var day = mode === 'utc' ? date.getUTCDate() : date.getDate();
        var hour = mode === 'utc' ? date.getUTCHours() : date.getHours();
        var minute = mode === 'utc' ? date.getUTCMinutes() : date.getMinutes();
        var second = mode === 'utc' ? date.getUTCSeconds() : date.getSeconds();
        var clock = twoDigits(hour) + ':' + twoDigits(minute) + ':' + twoDigits(second);
        if (timeOnly) return clock + (mode === 'utc' ? ' UTC' : '');
        return year + '-' + twoDigits(month) + '-' + twoDigits(day) + ' ' + clock + (mode === 'utc' ? ' UTC' : '');
    }

    function formatTimestamp(value, timeOnly) {
        var date = value instanceof Date ? value : new Date(value);
        if (Number.isNaN(date.getTime())) return '';
        return formatTime(date, readTimeMode(), Boolean(timeOnly));
    }

    function refreshTimes(root) {
        var scope = root || document;
        var mode = readTimeMode();
        scope.querySelectorAll('time[datetime]').forEach(function (element) {
            var value = new Date(element.dateTime);
            if (!Number.isNaN(value.getTime())) {
                element.textContent = formatTime(value, mode, element.dataset.timeFormat === 'time');
            }
        });
        document.querySelectorAll('[data-time-mode]').forEach(function (button) {
            button.setAttribute('aria-pressed', String(button.dataset.timeMode === mode));
        });
    }

    function initTimeControls() {
        document.querySelectorAll('[data-time-mode]').forEach(function (button) {
            button.addEventListener('click', function () {
                var mode = button.dataset.timeMode;
                if (!allowedTimeModes[mode]) return;
                try { localStorage.setItem(timePreferenceKey, mode); } catch (_) { /* private mode */ }
                refreshTimes(document);
            });
        });
        refreshTimes(document);
    }

    window.FortiSafeUI = Object.freeze({
        refreshTimes: refreshTimes,
        formatTimestamp: formatTimestamp,
        announce: announceFeedback
    });
    onReady(function () {
        initDialogs();
        initTabs();
        initFeedback();
        initCopyButtons();
        initPasswordToggles();
        initTimeControls();
    });
})();
