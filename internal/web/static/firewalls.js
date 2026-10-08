    (function () {
        var toggle = document.getElementById('addToggle');
        var body = document.getElementById('addBody');
        var btn = document.getElementById('addToggleBtn');
        if (toggle && body) {
            toggle.addEventListener('click', function () {
                if (body.hasAttribute('hidden')) {
                    body.removeAttribute('hidden');
                    if (btn) { btn.textContent = (document.documentElement.lang === 'de' ? 'Ausblenden' : 'Hide'); }
                } else {
                    body.setAttribute('hidden', '');
                    if (btn) { btn.textContent = (document.documentElement.lang === 'de' ? 'Anzeigen' : 'Show'); }
                }
            });
        }
        // FQDN/status filter, persisted across reloads.
        var filter = document.getElementById('fwFilter');
        var table = document.getElementById('fwTable');
        function applyFilter() {
            if (!filter || !table) { return; }
            var q = filter.value.toLowerCase();
            try { localStorage.setItem('fwFilter', filter.value); } catch (e) {}
            var rows = table.tBodies[0].rows;
            for (var i = 0; i < rows.length; i++) {
                var fqdnCell = rows[i].querySelector('.fw-fqdn');
                var statusCell = rows[i].querySelector('.fw-status');
                var hay = ((fqdnCell ? fqdnCell.textContent : '') + ' ' + (statusCell ? statusCell.textContent : '')).toLowerCase();
                rows[i].style.display = hay.indexOf(q) !== -1 ? '' : 'none';
            }
        }
        if (filter) {
            // A ?q= param (e.g. from a clicked dashboard tile) takes precedence and
            // is persisted, so deep-links like /?q=Failed pre-filter the list.
            var urlQ = new URLSearchParams(window.location.search).get('q');
            if (urlQ !== null) {
                filter.value = urlQ;
                try { localStorage.setItem('fwFilter', urlQ); } catch (e) {}
            } else {
                try { filter.value = localStorage.getItem('fwFilter') || ''; } catch (e) {}
            }
            filter.addEventListener('input', applyFilter);
            applyFilter();
        }
        // Status pill markup, mirrored from the server for live updates.
        function escapeHTML(value) {
            return String(value || '').replace(/[&<>"']/g, function (char) {
                return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[char];
            });
        }
        function pill(status) {
            if (status === 'Success') { return '<span class="pill pill-success">Success</span>'; }
            if (status === 'New') { return '<span class="pill pill-new">New</span>'; }
            if (status === 'In Progress') { return '<span class="pill pill-info">In Progress</span>'; }
            if (status.indexOf('Failed') === 0) { return '<span class="pill pill-failed" title="' + escapeHTML(status) + '">Failed</span>'; }
            return '<span class="pill pill-muted">' + escapeHTML(status) + '</span>';
        }
        // Live status updates via SSE (#70).
        window.addEventListener('fortisafe:message', function (event) {
            try {
                var d = JSON.parse(event.detail.data);
                // Only backup status changes drive the status pills; the
                // operation lifecycle events (analysis, sshdiag, …) would
                // otherwise overwrite a firewall's status with "started".
                if (d.kind && d.kind !== 'backup') { return; }
                var row = table && table.querySelector('tr[data-fw="' + d.fw_id + '"]');
                if (row) {
                    var cell = row.querySelector('.fw-status');
                    if (cell) { cell.innerHTML = pill(d.status); }
                }
            } catch (err) {}
        });
        // Test connection buttons (#34).
        document.querySelectorAll('.test-conn').forEach(function (b) {
            b.addEventListener('click', function () {
                var id = b.getAttribute('data-fw');
                var orig = b.textContent;
                b.textContent = '…'; b.disabled = true;
                fetch('/test_connection/' + id, {method: 'POST'}).then(function (r) { return r.json(); }).then(function (j) {
                    alert(j.message || (j.ok ? 'OK' : 'Failed'));
                }).catch(function () { alert((document.documentElement.lang === 'de' ? 'Test fehlgeschlagen' : 'Test failed')); }).finally(function () {
                    b.textContent = orig; b.disabled = false;
                });
            });
        });
    })();
