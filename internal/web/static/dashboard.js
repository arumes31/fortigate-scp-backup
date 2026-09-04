(function () {
    document.querySelectorAll('[data-confirm-submit]').forEach(function (form) {
        form.addEventListener('submit', function (event) {
            if (!window.confirm(form.dataset.confirmSubmit || '')) { event.preventDefault(); }
        });
    });
    function tt(key) { return (window.I18N && window.I18N[key]) || key; }
    function setText(k, v) {
        var el = document.querySelector('[data-k="' + k + '"]');
        if (el && v !== undefined && v !== null) { el.textContent = v; }
    }
    function esc(s) {
        return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
        });
    }
    function fmtBytes(n) {
        if (n < 1024) { return n + ' B'; }
        var u = ['KB', 'MB', 'GB', 'TB', 'PB']; var i = -1;
        do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
        return n.toFixed(1) + ' ' + u[i];
    }

    var attentionBody = document.getElementById('attentionBody');
    var attentionCount = document.getElementById('attentionCount');
    function renderAttention(d) {
        if (!attentionBody) { return; }
        var list = Array.isArray(d.attention) ? d.attention : [];
        var total = Number(d.attentionAll || 0);
        if (attentionCount) {
            attentionCount.textContent = total + ' open';
            attentionCount.classList.toggle('pill-failed', total > 0);
        }
        if (d.loadError) {
            attentionBody.innerHTML = '<div class="alert alert-error" role="alert">' +
                'Issue data could not be loaded completely; no healthy state is inferred.</div>';
            return;
        }
        if (!list.length) {
            attentionBody.innerHTML = '<div class="empty">No actionable issues.</div>';
            return;
        }
        attentionBody.innerHTML = '<ol class="attention-list">' + list.map(function (item) {
            var severity = item.severity === 'Critical' ? 'Critical' : 'Warning';
            var href = String(item.href || '/');
            if (href.charAt(0) !== '/') { href = '/'; }
            return '<li class="attention-item"><span class="attention-severity severity-' + severity + '">' +
                esc(severity) + '</span><div class="attention-copy"><span class="attention-source">' +
                esc(item.source) + '</span><strong>' + esc(item.title) + '</strong><span class="muted">' +
                esc(item.detail) + '</span></div><span class="attention-age" aria-label="Age ' + esc(item.age) + '">' +
                esc(item.age) + '</span><a class="btn btn-sm" href="' + esc(href) + '">' + esc(item.action) + '</a></li>';
        }).join('') + '</ol>' + (d.attentionMore ? '<p class="attention-more">+' +
            Number(d.attentionMore) + ' more in detailed issue data</p>' : '');
    }

    var running = document.getElementById('runningList');
    var runningCard = document.getElementById('runningCard');
    // fmtElapsed renders a running duration compactly ("42s", "3m 07s", "1h 4m").
    function fmtElapsed(ms) {
        var s = Math.max(0, Math.round(ms / 1000));
        var h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
        if (h > 0) { return h + 'h ' + m + 'm'; }
        if (m > 0) { return m + 'm ' + String(sec).padStart(2, '0') + 's'; }
        return sec + 's';
    }
    function renderRunning(list) {
        if (!running || !runningCard) { return; }
        if (!list || !list.length) { runningCard.hidden = true; running.innerHTML = ''; return; }
        runningCard.hidden = false;
        running.innerHTML = list.map(function (r) {
            var name = esc(r.fqdn || ('fw #' + r.fw_id));
            // Every kind gets a labeled pill (backup, analysis, devicedata,
            // sshdiag, audit — see the dashboard.running_* keys).
            var pill = r.kind ? ' <span class="pill">' + tt('dashboard.running_' + r.kind) +
                (r.label ? ' · ' + esc(r.label) : '') + '</span>' : '';
            var detail = r.detail ? ' <span class="muted">' + esc(r.detail) + '</span>' : '';
            // Numeric progress (Graylog stages, per-switch diag, analysis steps)
            // gets a thin bar; text-only stages (backups) just show the detail.
            var bar = '';
            if (r.total > 0) {
                var pct = Math.max(0, Math.min(100, Math.round(100 * r.step / r.total)));
                bar = ' <span class="muted">' + r.step + '/' + r.total + '</span>' +
                    '<div class="running-bar"><div class="running-bar-fill" style="width:' + pct + '%"></div></div>';
            }
            return '<div class="running-row"><span class="spinner"></span><b>' + name + '</b>' +
                pill + detail +
                ' <span class="muted running-elapsed" data-since="' + esc(r.since) + '" title="' +
                tt('dashboard.running_since') + ' ' + window.FortiSafeUI.formatTimestamp(r.since, true) + '"></span>' +
                bar + '</div>';
        }).join('');
        tickRunningElapsed();
    }

    // Live elapsed tick: updates each row's duration every second without a
    // full re-render (which only happens on the ~5s poll).
    function tickRunningElapsed() {
        if (!running) { return; }
        var now = Date.now();
        running.querySelectorAll('.running-elapsed').forEach(function (el) {
            var since = el.getAttribute('data-since');
            if (since) { el.textContent = fmtElapsed(now - new Date(since).getTime()); }
        });
    }
    setInterval(tickRunningElapsed, 1000);

    // Stale-backups card: kept in sync on every poll so a backup that clears
    // (or newly slips overdue) shows/hides without a full page reload, the
    // same way the running card and tiles already refresh live.
    var staleCard = document.getElementById('staleCard');
    var staleList = document.getElementById('staleList');
    var staleCount = document.getElementById('staleCount');
    function renderStale(list) {
        if (!staleCard || !staleList) { return; }
        if (!list || !list.length) {
            staleCard.hidden = true; staleList.innerHTML = '';
            if (staleCount) { staleCount.textContent = '0'; }
            return;
        }
        staleCard.hidden = false;
        if (staleCount) { staleCount.textContent = list.length; }
        staleList.innerHTML = list.map(function (r) {
            var name = esc(r.fqdn || ('fw #' + r.fw_id));
            var id = encodeURIComponent(r.fw_id);
            return '<tr><td>' + esc(r.fw_id) + '</td><td>' + name + '</td>' +
                '<td class="muted"><time datetime="' + esc(r.last_success) + '"></time></td>' +
                '<td><span class="pill" style="background: rgba(245,158,11,0.15); color: #fbbf24; border-color: rgba(245,158,11,0.4);">' +
                esc(r.age_hours) + 'h ' + tt('dashboard.stale_ago') + '</span></td>' +
                '<td class="muted">' + tt('dashboard.stale_every') + ' ' + esc(r.cadence) + '</td>' +
                '<td><div class="actions">' +
                '<form method="post" action="/backup_now/' + id + '" style="display:inline">' +
                '<button type="submit" class="btn btn-sm">' + tt('dashboard.backup_now') + '</button></form> ' +
                '<a class="btn btn-sm" href="/backups/' + id + '">' + tt('dashboard.backups') + '</a>' +
                '</div></td></tr>';
        }).join('');
        if (window.FortiSafeUI) { window.FortiSafeUI.refreshTimes(staleList); }
    }

    // While anything is running, poll faster than the configured auto-refresh:
    // a polsplit analysis or manual topology fetch often finishes inside one
    // 30s tick and would otherwise never appear on the card.
    var runningPollTimer = null;
    function scheduleRunningPoll(active) {
        clearTimeout(runningPollTimer); runningPollTimer = null;
        if (active) { runningPollTimer = setTimeout(refreshStats, 5000); }
    }

    function refreshStats() {
        var refreshStatus = document.getElementById('dashboardRefreshStatus');
        if (refreshStatus) {
            refreshStatus.className = 'dashboard-refresh-status is-loading';
            refreshStatus.textContent = 'Refreshing dashboard data…';
        }
        fetch('/dashboard/stats', { headers: { 'Accept': 'application/json' } })
            .then(function (r) { if (!r.ok) { throw new Error('bad'); } return r.json(); })
            .then(function (d) {
                setText('total', d.total); setText('healthy', d.healthy);
                setText('failed', d.failed); setText('new', d.new);
                setText('backups24h', d.backups24h); setText('totalBackups', d.totalBackups);
                setText('storage', fmtBytes(d.storageBytes));
                setText('storageWeek', '(+' + fmtBytes(d.storageWeek) + '/7d)');
                setText('avg', d.avgDuration); setText('runs', '(' + d.backupsRun + ' runs)');
                setText('largest', fmtBytes(d.largestBytes)); setText('smallest', fmtBytes(d.smallestBytes));
                setText('pruned', d.prunedTotal);
                var nb = document.getElementById('nextBackup'); if (nb) { nb.dataset.next = d.nextBackup || ''; }
                var ca = document.getElementById('clusterAlert'); if (ca) { ca.hidden = !d.clusterAlert; }
                renderRunning(d.running);
                renderStale(d.stale);
                renderAttention(d);
                scheduleRunningPoll(d.running && d.running.length > 0);
                if (refreshStatus) {
                    refreshStatus.className = 'dashboard-refresh-status' + (d.loadError ? ' is-error' : '');
                    refreshStatus.textContent = d.loadError ?
                        'Dashboard data is incomplete. Check the application log.' : 'Dashboard data is current.';
                }
            })
            .catch(function () {
                if (refreshStatus) {
                    refreshStatus.className = 'dashboard-refresh-status is-error';
                    refreshStatus.textContent = 'Dashboard refresh failed. Existing values may be stale.';
                }
            });
    }

    // Coming back to the tab refreshes immediately — the card may be minutes
    // stale after a background stay, whatever the auto-refresh setting.
    document.addEventListener('visibilitychange', function () {
        if (document.visibilityState === 'visible') { refreshStats(); }
    });

    // "Next Backup" live countdown.
    function fmtCountdown(ms) {
        if (ms <= 0) { return 'due'; }
        var s = Math.round(ms / 1000);
        var h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
        if (h > 0) { return h + 'h ' + m + 'm'; }
        if (m > 0) { return m + 'm ' + String(sec).padStart(2, '0') + 's'; }
        return sec + 's';
    }
    function tickCountdown() {
        var nb = document.getElementById('nextBackup');
        if (!nb) { return; }
        var iso = nb.dataset.next;
        if (!iso) { nb.textContent = '—'; return; }
        nb.textContent = fmtCountdown(new Date(iso).getTime() - Date.now());
    }
    setInterval(tickCountdown, 1000); tickCountdown();

    // Toasts.
    var toastWrap = document.getElementById('toastWrap');
    function toast(msg, kind) {
        if (!toastWrap) { return; }
        var t = document.createElement('div');
        t.className = 'toast ' + (kind || '');
        t.textContent = msg;
        toastWrap.appendChild(t);
        setTimeout(function () { t.classList.add('show'); }, 10);
        setTimeout(function () { t.classList.remove('show'); setTimeout(function () { t.remove(); }, 300); }, 6000);
    }

    // Live SYS_STDOUT feed.
    var stdoutLog = document.getElementById('stdoutLog');
    function logLine(text) {
        if (!stdoutLog) { return; }
        var p = document.createElement('p');
        var instant = new Date().toISOString();
        p.innerHTML = '<span class="ts">[<time data-time-format="time" datetime="' + instant + '"></time>]</span> ' +
            esc(text);
        stdoutLog.insertBefore(p, stdoutLog.firstChild);
        if (window.FortiSafeUI) { window.FortiSafeUI.refreshTimes(p); }
        while (stdoutLog.childElementCount > 200) { stdoutLog.removeChild(stdoutLog.lastChild); }
    }

    // Shared shell SSE.
    var debounce = null;
    function scheduleRefresh() { clearTimeout(debounce); debounce = setTimeout(refreshStats, 400); }
    var sseWasDown = false;
    window.addEventListener('fortisafe:connection', function (event) {
        if (event.detail.state === 'online') {
            // On reconnect, pull fresh stats immediately: events that fired
            // while the stream was down may have been missed.
            if (sseWasDown) { refreshStats(); }
            sseWasDown = false;
        } else if (event.detail.state === 'offline') {
            sseWasDown = true;
        }
    });
    window.addEventListener('fortisafe:message', function (event) {
        try {
            var d = JSON.parse(event.detail.data);
            var kind = d.kind || 'backup';
            logLine(tt('dashboard.running_' + kind) + ' fw #' + d.fw_id + ' → ' + d.status);
            if (kind === 'backup' && typeof d.status === 'string' && d.status.indexOf('Failed') === 0) {
                toast('Backup fehlgeschlagen: fw #' + d.fw_id, 'error');
            }
            scheduleRefresh();
        } catch (err) {}
    });

    // Test-connection buttons.
    document.querySelectorAll('.test-conn').forEach(function (b) {
        b.addEventListener('click', function () {
            var id = b.getAttribute('data-fw'), orig = b.textContent;
            b.textContent = '…'; b.disabled = true;
            fetch('/test_connection/' + id, {method: 'POST'}).then(function (r) { return r.json(); }).then(function (j) {
                toast(j.message || (j.ok ? 'OK' : 'Failed'), j.ok ? 'ok' : 'error');
            }).catch(function () { toast('Test fehlgeschlagen', 'error'); }).finally(function () {
                b.textContent = orig; b.disabled = false;
            });
        });
    });

    // Auto-refresh interval.
    var sel = document.getElementById('refreshInterval'), timer = null;
    function applyInterval() {
        if (timer) { clearInterval(timer); timer = null; }
        var v = parseInt(sel ? sel.value : '0', 10);
        if (v > 0) { timer = setInterval(refreshStats, v * 1000); }
        try { localStorage.setItem('dashRefresh', String(v)); } catch (e) {}
    }
    if (sel) {
        try { var saved = localStorage.getItem('dashRefresh'); if (saved !== null) { sel.value = saved; } } catch (e) {}
        sel.addEventListener('change', applyInterval);
        applyInterval();
    }

    // Initial async load: replaces the running-list skeleton.
    refreshStats();

    /* ---------------- blocked switch ports: live re-check ---------------- */
    var blockedTable = document.getElementById('blockedPortTable');
    if (blockedTable) {
        function updateBlockedCount() {
            var n = blockedTable.querySelectorAll('tbody tr').length;
            var el = document.getElementById('blockedPortCount');
            if (el) { el.textContent = n + ' ' + tt('dashboard.blocked_unit'); }
            if (n === 0) {
                var card = blockedTable.closest('.card');
                if (card) { card.hidden = true; }
            }
        }
        // checkOnePort runs one port's live re-check and returns a promise so
        // checkAllPorts can serialize the ports on the same firewall (they
        // share one SSH session) while different firewalls run concurrently.
        function checkOnePort(row) {
            var fw = row.getAttribute('data-fw'), sw = row.getAttribute('data-switch'), port = row.getAttribute('data-port');
            var btn = row.querySelector('.blocked-check-btn');
            var out = row.querySelector('.blocked-check-result');
            btn.disabled = true;
            out.textContent = tt('dashboard.checking');
            var url = '/graylog-devices/check-blocked-port/' + encodeURIComponent(fw) +
                '?switch=' + encodeURIComponent(sw) + '&port=' + encodeURIComponent(port);
            return fetch(url, { method: 'POST' }).then(function (r) {
                if (r.status === 429) { out.textContent = tt('dashboard.check_busy'); btn.disabled = false; return; }
                if (!r.ok) { out.textContent = tt('dashboard.check_failed'); btn.disabled = false; return; }
                return r.json().then(function (j) {
                    if (!j.stillBlocked) {
                        out.textContent = tt('dashboard.check_recovered');
                        setTimeout(function () { row.remove(); updateBlockedCount(); }, 900);
                    } else {
                        out.textContent = tt('dashboard.check_still_blocked');
                        btn.disabled = false;
                    }
                });
            }).catch(function () {
                out.textContent = tt('dashboard.check_failed');
                btn.disabled = false;
            });
        }
        blockedTable.querySelectorAll('.blocked-check-btn').forEach(function (btn) {
            btn.addEventListener('click', function () { checkOnePort(btn.closest('tr')); });
        });
        var checkAllBtn = document.getElementById('blockedCheckAll');
        if (checkAllBtn) {
            checkAllBtn.addEventListener('click', function () {
                checkAllBtn.disabled = true;
                var rows = Array.prototype.slice.call(blockedTable.querySelectorAll('tbody tr'));
                var byFw = {};
                rows.forEach(function (row) {
                    var fw = row.getAttribute('data-fw');
                    (byFw[fw] = byFw[fw] || []).push(row);
                });
                var groups = Object.keys(byFw).map(function (fw) {
                    return byFw[fw].reduce(function (chain, row) {
                        return chain.then(function () { return checkOnePort(row); });
                    }, Promise.resolve());
                });
                Promise.all(groups).finally(function () { checkAllBtn.disabled = false; });
            });
        }
    }
})();
