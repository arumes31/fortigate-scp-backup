/* Policy Split Advisor front-end: load the target policy from the latest
 * backup, run the Graylog traffic analysis, render tuples + strategies. */
'use strict';

const psState = { rangeSec: 86400, policyLoaded: false, vdom: '', abortCtrl: null, analyzeCtrl: null };

function $(id) { return document.getElementById(id); }

function esc(s) {
    return String(s ?? '').replace(/[&<>"']/g, c => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));
}

async function fetchJSON(url, opts) {
    const resp = await fetch(url, opts);
    let body = null;
    try { body = await resp.json(); } catch { /* non-JSON error page */ }
    if (!resp.ok) {
        throw new Error((body && body.error) || ('HTTP ' + resp.status));
    }
    return body;
}

/* ---------------- target policy ---------------- */

async function loadPolicy() {
    const fwID = $('ps-firewall').value;
    const polID = $('ps-policy-id').value;
    if (!fwID || polID === '') { alert('Select a firewall and enter a policy ID'); return; }
    if (psState.abortCtrl) psState.abortCtrl.abort();
    psState.abortCtrl = new AbortController();
    const signal = psState.abortCtrl.signal;
    const btn = $('ps-load-btn');
    btn.disabled = true;
    try {
        let url = `/fgt-polsplit/policy_info?fw_id=${encodeURIComponent(fwID)}&policy_id=${encodeURIComponent(polID)}`;
        if (psState.vdom) {
            url += `&vdom=${encodeURIComponent(psState.vdom)}`;
        }
        const resp = await fetch(url, { signal });
        let body = null;
        try { body = await resp.json(); } catch { }
        if (!resp.ok) {
            if (body && body.ambiguous && body.vdoms) {
                const choice = prompt(`Policy ID ${polID} is ambiguous. Please select a VDOM from the following options:\n${body.vdoms.join(', ')}`);
                if (choice) {
                    const matchedVdom = body.vdoms.find(v => v.toLowerCase() === choice.trim().toLowerCase());
                    if (matchedVdom) {
                        psState.vdom = matchedVdom;
                        setTimeout(loadPolicy, 0);
                        return;
                    } else {
                        alert('Invalid VDOM selected');
                    }
                }
            }
            throw new Error((body && body.error) || ('HTTP ' + resp.status));
        }

        renderPolicy(body);
        psState.policyLoaded = true;
        $('ps-options-card').hidden = false;
        $('ps-prefix').placeholder = 'PS' + polID;
        $('ps-results').hidden = true;
    } catch (err) {
        if (err.name === 'AbortError') return;
        psState.policyLoaded = false;
        psState.vdom = '';
        $('ps-policy-card').hidden = true;
        $('ps-options-card').hidden = true;
        alert('Failed to load policy: ' + err.message);
    } finally {
        btn.disabled = false;
    }
}

function kv(label, value) {
    return `<div class="ps-kv-row"><span class="ps-kv-key">${esc(label)}</span><span class="ps-kv-val">${value}</span></div>`;
}

function renderPolicy(data) {
    const p = data.policy;
    const list = a => (a && a.length) ? a.map(esc).join(', ') : '—';
    let html = '';
    html += kv('Name', esc(p.name || '(unnamed)') + (p.vdom ? ` <span class="ps-muted">[vdom ${esc(p.vdom)}]</span>` : ''));
    html += kv('Src Interface', list(p.srcintf));
    html += kv('Dst Interface', list(p.dstintf));
    html += kv('Src Address', list(p.srcaddr));
    html += kv('Dst Address', list(p.dstaddr));
    html += kv('Service', list(p.services));
    html += kv('Action', esc(data.action_display));
    html += kv('Schedule', esc(p.schedule || '—'));
    html += kv('NAT', esc(p.nat || 'disable'));
    if (p.comments) html += kv('Comments', esc(p.comments));
    $('ps-policy-summary').innerHTML = html;
    $('ps-backup-time').textContent = `(backup from ${data.backup_time})`;
    $('ps-policy-card').hidden = false;
    if (data.warnings && data.warnings.length) {
        alert(data.warnings.join('\n'));
    }
}

/* ---------------- analysis ---------------- */

function selectedRange() {
    if (psState.rangeSec > 0) return { range_seconds: psState.rangeSec };
    const from = $('ps-from').value, to = $('ps-to').value;
    if (!from || !to) throw new Error('Set both custom range fields');
    return {
        range_seconds: 0,
        from: new Date(from).toISOString(),
        to: new Date(to).toISOString(),
    };
}

/* ---------------- progress display ----------------
 * The server publishes step/total (stage), plus a detail line and optional
 * sub-progress (chunked Graylog loading). The client adds a spinner, live
 * elapsed time, an interpolated bar and a per-stage timing log. */

const PS_SPIN = ['|', '/', '-', '\\'];

function newProgressId() {
    return (window.crypto && crypto.randomUUID)
        ? crypto.randomUUID()
        : 'p' + Date.now().toString(36) + Math.random().toString(36).slice(2, 10);
}

// progressPct interpolates within the running stage using the sub-progress:
// completed stages count fully, the current stage by its sub-fraction.
function progressPct(p) {
    if (!p || !(p.total > 0)) return 0;
    const frac = p.sub_total > 0 ? Math.min(p.sub / p.sub_total, 1) : 0;
    const pct = Math.round(100 * (Math.max(p.step - 1, 0) + frac) / p.total);
    return Math.max(0, Math.min(100, pct));
}

function renderProgress(prog) {
    const p = prog.state;
    $('ps-progress').hidden = false;
    $('ps-progress-bar').style.width = progressPct(p) + '%';
    let text = p.message || '';
    if (p.detail) text += ' — ' + p.detail;
    if (p.total > 0) text += ` (${p.step}/${p.total})`;
    const t = $('ps-progress-text');
    if (t.textContent !== text) t.textContent = text; // aria-live fires on real changes only
    renderProgressMeta(prog);
}

function renderProgressMeta(prog) {
    const secs = ((Date.now() - prog.startedAt) / 1000).toFixed(1);
    $('ps-progress-meta').textContent = `[${PS_SPIN[prog.spin]}] ${progressPct(prog.state)}% · ${secs}s`;
}

// updateProgress folds a poll result in; a message change closes the previous
// stage into the timing log.
function updateProgress(prog, p) {
    if (p.message !== prog.state.message && prog.state.message) {
        logStage(prog, prog.state.message);
    }
    prog.state = p;
    renderProgress(prog);
}

function logStage(prog, msg) {
    const secs = ((Date.now() - prog.stageStart) / 1000).toFixed(1);
    const line = document.createElement('div');
    line.textContent = `✓ ${msg} (${secs}s)`;
    $('ps-progress-log').appendChild(line);
    prog.stageStart = Date.now();
}

function hideProgress() {
    $('ps-progress').hidden = true;
    $('ps-progress-bar').style.width = '0%';
}

function clearResults() {
    $('ps-results').hidden = true;
}

async function analyze() {
    if (!psState.policyLoaded) { alert('Load a policy first'); return; }
    let range;
    try { range = selectedRange(); } catch (err) { alert(err.message); return; }

    if (psState.abortCtrl) psState.abortCtrl.abort();
    const ctrl = new AbortController();
    psState.abortCtrl = ctrl;
    // Progress-display ownership: only a NEWER analyze() run takes it over.
    // Cancellation from elsewhere (loadPolicy, invalidatePolicy) must still
    // let this run's teardown hide the bar and re-enable the button.
    psState.analyzeCtrl = ctrl;
    const signal = ctrl.signal;

    const progressId = newProgressId();
    const req = Object.assign({
        fw_id: parseInt($('ps-firewall').value, 10),
        policy_id: parseInt($('ps-policy-id').value, 10),
        vdom: psState.vdom || '',
        rollup_src: $('ps-rollup-src').checked,
        rollup_dst: $('ps-rollup-dst').checked,
        rollup_threshold: parseInt($('ps-rollup-threshold').value, 10) || 5,
        rollup_mask: parseInt($('ps-rollup-mask').value, 10) || 24,
        prefix: $('ps-prefix').value.trim(),
        compare_seconds: parseInt($('ps-compare').value, 10) || 0,
        resolve_dns: $('ps-resolve-dns').checked,
        ticket: $('ps-ticket').value.trim(),
        wan_mode: $('ps-wan-mode').value,
        emit_deny: $('ps-emit-deny').checked,
        progress_id: progressId,
    }, range);

    const btn = $('ps-analyze-btn');
    btn.disabled = true;
    const prog = {
        startedAt: Date.now(), stageStart: Date.now(), spin: 0,
        state: { message: 'Starting analysis', detail: '', step: 0, total: 0, sub: 0, sub_total: 0 },
    };
    const logEl = $('ps-progress-log');
    logEl.innerHTML = '';
    logEl.hidden = false;
    renderProgress(prog);
    // Clear any previous results so stale recommendations cannot persist if
    // this analysis fails or is cancelled.
    clearResults();
    // Spinner + elapsed tick between polls (skipped for reduced-motion users;
    // the meta line still refreshes with every poll).
    const reduceMotion = window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches;
    const anim = reduceMotion ? 0 : setInterval(() => {
        prog.spin = (prog.spin + 1) % PS_SPIN.length;
        renderProgressMeta(prog);
    }, 200);
    // Poll the server-side stage while the analyze request runs; overlapping
    // polls are prevented and errors ignored (the bar is best-effort).
    let polling = false;
    const poll = setInterval(async () => {
        if (polling) return;
        polling = true;
        try {
            const resp = await fetch(`/fgt-polsplit/progress?id=${encodeURIComponent(progressId)}`, { signal });
            if (resp.ok) {
                const p = await resp.json();
                if (p.active) updateProgress(prog, p);
            }
        } catch { /* best-effort */ } finally {
            polling = false;
        }
    }, 400);
    try {
        const data = await fetchJSON('/fgt-polsplit/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(req),
            signal,
        });
        if (prog.state.message) logStage(prog, prog.state.message);
        const doneLine = document.createElement('div');
        doneLine.className = 'ps-progress-done';
        doneLine.textContent = `Analysis complete in ${((Date.now() - prog.startedAt) / 1000).toFixed(1)}s`;
        logEl.appendChild(doneLine);
        renderResults(data);
    } catch (err) {
        if (err.name === 'AbortError') return;
        alert('Analysis failed: ' + err.message);
    } finally {
        clearInterval(poll);
        if (anim) clearInterval(anim);
        // A superseding analyze() run owns the progress display now — only
        // the run that still owns it may tear it down. Aborts from other
        // controls (loadPolicy, invalidatePolicy) leave ownership with this
        // run, so the bar is hidden and the button re-enabled either way.
        if (psState.analyzeCtrl === ctrl) {
            psState.analyzeCtrl = null;
            hideProgress();
            btn.disabled = false;
        }
    }
}

function renderResults(data) {
    // warnings
    const warn = data.warnings || [];
    $('ps-warnings-card').hidden = warn.length === 0;
    $('ps-warnings').innerHTML = warn.map(w => `<li>${esc(w)}</li>`).join('');

    // stats
    const tuples = data.tuples || [];
    const srcs = data.src_count !== undefined ? data.src_count : new Set(tuples.map(t => t.srcip)).size;
    const dsts = data.dst_count !== undefined ? data.dst_count : new Set(tuples.map(t => t.dstip)).size;
    const svcs = data.svc_count !== undefined ? data.svc_count : new Set(tuples.map(t => t.proto + '/' + t.port)).size;
    $('ps-stats').innerHTML = [
        ['Log messages', data.total_messages],
        ['Traffic tuples', data.tuple_count],
        ['Distinct sources', srcs],
        ['Distinct destinations', dsts],
        ['Distinct services', svcs],
    ].map(([k, v]) => `<div class="ps-stat"><div class="ps-stat-val">${esc(v)}</div><div class="ps-stat-key">${esc(k)}</div></div>`).join('');

    // tuple table
    const tbody = $('ps-tuples-table').querySelector('tbody');
    tbody.innerHTML = tuples.map(t => `<tr>
        <td>${esc(t.srcip)}</td><td>${esc(t.dstip)}</td>
        <td>${esc(t.proto)}</td><td>${t.port || '—'}</td>
        <td>${esc(t.service || '—')}</td><td class="ps-num">${esc(t.hits)}</td>
        <td>${esc(fmtTime(t.last_seen))}</td>
        <td>${t.flow === 'new' ? '<span class="ps-badge-new">NEW</span>' : ''}</td></tr>`).join('');
    $('ps-tuples-note').textContent = data.tuple_count > tuples.length
        ? `Showing top ${tuples.length} of ${data.tuple_count} tuples by hits.` : '';

    // baseline-only (stale) flows
    const stale = data.stale_tuples || [];
    $('ps-stale-wrap').hidden = stale.length === 0;
    $('ps-stale-count').textContent = stale.length;
    $('ps-stale-table').querySelector('tbody').innerHTML = stale.map(t => `<tr>
        <td>${esc(t.srcip)}</td><td>${esc(t.dstip)}</td>
        <td>${esc(t.proto)}</td><td>${t.port || '—'}</td>
        <td class="ps-num">${esc(t.hits)}</td><td>${esc(fmtTime(t.last_seen))}</td></tr>`).join('');

    // FQDN suggestions
    const dns = data.dns_suggestions || [];
    $('ps-dns-wrap').hidden = dns.length === 0;
    $('ps-dns-count').textContent = dns.length;
    $('ps-dns-table').querySelector('tbody').innerHTML = dns.map(d => `<tr>
        <td>${esc(d.ip)}</td><td>${esc(d.name)}</td><td class="ps-num">${esc(d.hits)}</td></tr>`).join('');

    // Internet-Service (ISDB) suggestions
    const isdb = data.isdb_suggestions || [];
    $('ps-isdb-wrap').hidden = isdb.length === 0;
    $('ps-isdb-count').textContent = isdb.length;
    $('ps-isdb-table').querySelector('tbody').innerHTML = isdb.map(s => `<tr>
        <td>${esc(s.vendor)}</td><td class="ps-num">${esc(s.ips)}</td><td class="ps-num">${esc(s.hits)}</td>
        <td>${(s.names && s.names.length) ? s.names.map(esc).join(', ') : '<span class="ps-muted">none parsed from backup</span>'}</td></tr>`).join('');

    // Authenticated identities (user/group fields)
    const users = data.user_activity || [];
    $('ps-users-wrap').hidden = users.length === 0;
    $('ps-users-count').textContent = users.length;
    $('ps-users-table').querySelector('tbody').innerHTML = users.map(u => `<tr>
        <td>${esc(u.user)}</td><td>${esc(u.group || '—')}</td><td class="ps-num">${esc(u.hits)}</td></tr>`).join('');

    // Application-control usage with ISDB object matches
    const apps = data.app_usage || [];
    $('ps-apps-wrap').hidden = apps.length === 0;
    $('ps-apps-count').textContent = apps.length;
    $('ps-apps-table').querySelector('tbody').innerHTML = apps.map(a => `<tr>
        <td>${esc(a.app)}</td><td>${esc(a.category || '—')}</td><td class="ps-num">${esc(a.hits)}</td>
        <td>${(a.isdb && a.isdb.length) ? a.isdb.map(esc).join(', ') : '<span class="ps-muted">—</span>'}</td></tr>`).join('');

    // UTM-blocked destinations
    const utm = data.utm_blocked || [];
    $('ps-utm-wrap').hidden = utm.length === 0;
    $('ps-utm-count').textContent = utm.length;
    $('ps-utm-table').querySelector('tbody').innerHTML = utm.map(u => `<tr>
        <td>${esc(u.ip)}</td><td class="ps-num">${esc(u.hits)}</td></tr>`).join('');

    renderStrategies(data.strategies || []);
    $('ps-results').hidden = false;
    $('ps-results').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// copyText copies to the clipboard, falling back to a hidden textarea when the
// Clipboard API is unavailable (plain-HTTP deployments have no
// navigator.clipboard). Resolves to true on success.
async function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
        try { await navigator.clipboard.writeText(text); return true; } catch { /* fall through */ }
    }
    try {
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        const ok = document.execCommand('copy');
        ta.remove();
        return ok;
    } catch {
        return false;
    }
}

function fmtTime(ts) {
    if (!ts) return '—';
    const d = new Date(ts);
    return isNaN(d) ? ts : d.toLocaleString();
}

/* ---------------- strategies ---------------- */

function entityList(ents) {
    return ents.map(e => esc(e.value) + (e.is_net ? ` <span class="ps-muted">(${e.hosts} hosts)</span>` : '')).join(', ');
}

function svcList(svcs) {
    return svcs.map(s => esc(s.log_name || s.key)).join(', ');
}

function renderStrategies(strategies) {
    const tabs = $('ps-strategy-tabs');
    const panels = $('ps-strategy-panels');
    tabs.innerHTML = '';
    panels.innerHTML = '';
    strategies.forEach((s, i) => {
        const tab = document.createElement('button');
        tab.className = 'btn btn-sm ps-tab' + (i === 0 ? ' active' : '');
        tab.innerHTML = esc(s.label)
            + ` <span class="ps-count">${(s.policies || []).length}</span>`
            + (s.recommended ? ' <span class="ps-badge">RECOMMENDED</span>' : '');
        tab.addEventListener('click', () => {
            tabs.querySelectorAll('.ps-tab').forEach(t => t.classList.remove('active'));
            panels.querySelectorAll('.ps-panel').forEach(p => p.hidden = true);
            tab.classList.add('active');
            $('ps-panel-' + i).hidden = false;
        });
        tabs.appendChild(tab);

        const panel = document.createElement('div');
        panel.className = 'ps-panel';
        panel.id = 'ps-panel-' + i;
        panel.hidden = i !== 0;
        panel.innerHTML = strategyPanel(s, i);
        panels.appendChild(panel);
    });
    panels.querySelectorAll('.ps-copy').forEach(btn => {
        btn.addEventListener('click', () => {
            const pre = document.getElementById(btn.dataset.target);
            copyText(pre.textContent).then(ok => {
                btn.textContent = ok ? 'Copied!' : 'Copy failed — select & copy manually';
                setTimeout(() => { btn.textContent = 'Copy Config'; }, 2000);
            });
        });
    });
}

function strategyPanel(s, i) {
    const pols = s.policies || [];
    if (pols.length === 0) {
        return '<p class="ps-muted">No traffic observed — nothing to split.</p>';
    }
    let html = `<div class="ps-table-wrap"><table class="ps-table">
        <thead><tr><th>ID</th><th>Name</th><th>Sources</th><th>Destinations</th><th>Services</th><th>Hits</th></tr></thead><tbody>`;
    html += pols.map(p => `<tr>
        <td>${esc(p.id)}</td><td>${esc(p.name)}${(p.tags || []).map(t => ` <span class="ps-tag">${esc(t)}</span>`).join('')}</td>
        <td>${entityList(p.src)}</td><td>${entityList(p.dst)}</td>
        <td>${svcList(p.services)}</td><td class="ps-num">${esc(p.hits)}</td></tr>`).join('');
    html += '</tbody></table></div>';

    const objs = s.new_objects || [];
    html += `<h3>Missing objects to create <span class="ps-count">${objs.length}</span></h3>`;
    if (objs.length === 0) {
        html += '<p class="ps-muted">All referenced objects already exist in the current config.</p>';
    } else {
        html += `<div class="ps-table-wrap"><table class="ps-table">
            <thead><tr><th>Type</th><th>Name</th><th>Definition</th></tr></thead><tbody>`;
        html += objs.map(o => `<tr><td>${esc(o.kind)}</td><td>${esc(o.name)}</td><td>${esc(o.value)}</td></tr>`).join('');
        html += '</tbody></table></div>';
    }

    html += `<h3>FortiGate configuration</h3>
        <p class="ps-muted">New policy IDs assume the latest backup reflects the live device. Verify the splits pass traffic before the final block disables the original policy.</p>
        <button class="btn btn-sm ps-copy" data-target="ps-config-${i}">Copy Config</button>
        <pre class="ps-config" id="ps-config-${i}">${esc(s.config)}</pre>`;
    return html;
}

/* ---------------- wiring ---------------- */

document.addEventListener('DOMContentLoaded', () => {
    $('ps-load-btn').addEventListener('click', loadPolicy);
    $('ps-analyze-btn').addEventListener('click', analyze);
    $('ps-policy-id').addEventListener('keydown', e => { if (e.key === 'Enter') loadPolicy(); });
    const invalidatePolicy = () => {
        if (psState.abortCtrl) { psState.abortCtrl.abort(); psState.abortCtrl = null; }
        psState.policyLoaded = false;
        psState.vdom = '';
        $('ps-policy-card').hidden = true;
        $('ps-options-card').hidden = true;
        $('ps-results').hidden = true;
    };
    $('ps-firewall').addEventListener('change', invalidatePolicy);
    $('ps-policy-id').addEventListener('input', invalidatePolicy);
    $('ps-policy-id').addEventListener('change', invalidatePolicy);
    $('ps-range-row').querySelectorAll('.ps-range').forEach(btn => {
        btn.addEventListener('click', () => {
            $('ps-range-row').querySelectorAll('.ps-range').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            psState.rangeSec = parseInt(btn.dataset.sec, 10);
            $('ps-custom-range').hidden = psState.rangeSec !== 0;
        });
    });
});
