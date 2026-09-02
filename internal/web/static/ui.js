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
