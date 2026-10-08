(function () {
    var input = document.getElementById('licSearch');
    var count = document.getElementById('licSearchCount');
    if (!input) { return; }
    var activePreset = 'all';
    var detailText = {};
    document.querySelectorAll('.lic-detail').forEach(function (d) {
        detailText[d.dataset.detailFor] = d.textContent.toLowerCase();
    });
    var rows = Array.prototype.slice.call(
        document.querySelectorAll('#licTable > tbody > tr[data-fw]'));

    function closeDetails(row) {
        var detail = document.getElementById('license-detail-' + row.dataset.fw);
        var toggle = row.querySelector('.lic-toggle');
        if (detail) { detail.hidden = true; }
        if (toggle) { toggle.setAttribute('aria-expanded', 'false'); }
    }

    function presetMatches(level) {
        if (activePreset === 'all') { return true; }
        if (activePreset === 'expiring') { return level === 'warn' || level === 'crit'; }
        return level === activePreset;
    }

    function applyFilters() {
        var terms = input.value.toLowerCase().split(/\s+/).filter(Boolean);
        var visible = 0;
        rows.forEach(function (row) {
            var text = row.textContent.toLowerCase() + ' ' + (detailText[row.dataset.fw] || '');
            var match = presetMatches(row.dataset.level) && terms.every(function (t) { return text.indexOf(t) !== -1; });
            row.hidden = !match;
            closeDetails(row);
            if (match) { visible++; }
        });
        count.textContent = visible + ' ' + count.dataset.of + ' ' + rows.length + ' ' + count.dataset.deviceLabel;
    }

    document.querySelectorAll('[data-license-preset]').forEach(function (button) {
        button.addEventListener('click', function () {
            activePreset = button.dataset.licensePreset;
            document.querySelectorAll('[data-license-preset]').forEach(function (candidate) {
                candidate.setAttribute('aria-pressed', String(candidate === button));
            });
            applyFilters();
        });
    });
    document.querySelectorAll('.lic-toggle').forEach(function (button) {
        button.addEventListener('click', function () {
            var detail = document.getElementById(button.getAttribute('aria-controls'));
            if (!detail) { return; }
            var expanded = button.getAttribute('aria-expanded') === 'true';
            var tableWrap = detail.closest('.table-wrap');
            if (!expanded && tableWrap) { tableWrap.scrollLeft = 0; }
            detail.hidden = expanded;
            button.setAttribute('aria-expanded', String(!expanded));
        });
    });
    input.addEventListener('input', applyFilters);
    applyFilters();
})();

// Sweep progress: while a fleet refresh runs (manual or the daily job), show
// its progress; when a sweep we observed finishes, reload so the new data
// appears without a manual refresh.
(function () {
    var el = document.getElementById('licProgress');
    var wasRunning = false;
    var retryDelay = 2000;
    var POLL_RETRY_MAX_MS = 30000;
    var IDLE_POLL_MS = 30000;
    function poll() {
        fetch('/licenses/status').then(function (r) {
            if (!r.ok) { throw new Error('http ' + r.status); }
            return r.json();
        }).then(function (d) {
            retryDelay = 2000;
            if (d.running) {
                wasRunning = true;
                el.className = 'license-refresh-state is-running';
                el.textContent = el.dataset.refreshing + ' ' + d.done + ' ' + el.dataset.of + ' ' + d.total + (d.current ? ': ' + d.current : '');
                setTimeout(poll, 2000);
            } else if (wasRunning) {
                location.reload();
            } else {
                setTimeout(poll, IDLE_POLL_MS);
            }
        }).catch(function () {
            el.className = 'license-refresh-state is-error';
            el.textContent = el.dataset.unavailable;
            setTimeout(poll, wasRunning ? retryDelay : IDLE_POLL_MS);
            if (wasRunning) {
                retryDelay = Math.min(POLL_RETRY_MAX_MS, retryDelay * 2);
            }
        });
    }
    poll();
})();
