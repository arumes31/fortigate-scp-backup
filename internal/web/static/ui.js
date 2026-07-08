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
