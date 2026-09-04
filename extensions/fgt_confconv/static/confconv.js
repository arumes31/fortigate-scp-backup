/* Configuration Conversions front-end: load the parsed config summary for a
 * firewall, let the operator pick recipes + options, run the chained
 * pipeline, and render the resulting CLI sections + warnings. */
(function () {
'use strict';

const ccRoot = document.getElementById('confconv-page');
if (!ccRoot) return;

const ccState = {
    summary: null,
    vlanMoveRowCount: 0,
    combined: '',
    fortilinkPorts: [],
    portDialogReturnFocus: null,
};

const recipeOrder = [
    { key: 'iface-to-fortilink', enable: 'cc-fl-enable', label: 'Interface(s) → FortiLink' },
    { key: 'wan-to-sdwan', enable: 'cc-sw-enable', label: 'WAN interface(s) → SD-WAN' },
    { key: 'iface-to-zone', enable: 'cc-zn-enable', label: 'Interface-based → zone-based policies' },
    { key: 'sdwan-routes-to-rules', enable: 'cc-sr-enable', label: 'SD-WAN static routes → SD-WAN rules' },
];

function $(id) { return ccRoot.querySelector('#' + CSS.escape(id)); }

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

function sortedInterfaces() {
    return ((ccState.summary && ccState.summary.interfaces) || []).slice()
        .sort((a, b) => a.name.localeCompare(b.name));
}

/* ---------------- config summary ---------------- */

async function loadSummary() {
    const fwID = $('cc-firewall').value;
    resetOptionsUI();
    $('cc-results').hidden = true;
    ccState.summary = null;
    if (!fwID) {
        $('cc-backup-info').hidden = true;
        $('cc-version-warning').hidden = true;
        updateGenerateEnabled();
        return;
    }
    try {
        const data = await fetchJSON(`/fgt-confconv/config_summary?fw_id=${encodeURIComponent(fwID)}`);
        ccState.summary = data;
        $('cc-backup-info').hidden = false;
        $('cc-backup-info').textContent = `Backup from ${data.backupTime} — FortiOS ${data.version}`;
        applySDWANGate(data.versionOK, data.version);
        renderChecklist('cc-sw-members', 'sw-mem');
        renderChecklist('cc-zn-members', 'zn-mem');
        renderVLANParents();
        refreshVLANMoveOptions();
    } catch (err) {
        $('cc-backup-info').hidden = false;
        $('cc-backup-info').textContent = 'Failed to load config: ' + err.message;
    }
    updateGenerateEnabled();
}

function resetOptionsUI() {
    ['cc-sw-members', 'cc-zn-members', 'cc-fl-bulkvlan'].forEach(id => { $(id).innerHTML = ''; });
    $('cc-fl-vlanmoves').innerHTML = '';
    ccState.vlanMoveRowCount = 0;
    ccState.fortilinkPorts = [];
    renderFortilinkPorts();
    renderPipelinePreview();
}

function renderChecklist(containerId, prefix) {
    const container = $(containerId);
    const ifaces = sortedInterfaces();
    if (!ifaces.length) {
        container.innerHTML = '<p class="cc-muted">No interfaces found in this backup.</p>';
        return;
    }
    container.innerHTML = ifaces.map(iface => {
        const id = `cc-${prefix}-${iface.name}`;
        const roleTag = iface.role ? ` <span class="cc-muted">(${esc(iface.role)})</span>` : '';
        return `<label class="cc-check-item" for="${esc(id)}">
            <input type="checkbox" value="${esc(iface.name)}" id="${esc(id)}">${esc(iface.name)}${roleTag}
        </label>`;
    }).join('');
}

function checkedValues(containerId) {
    return Array.from($(containerId).querySelectorAll('input[type=checkbox]:checked')).map(cb => cb.value);
}

/* ---------------- FortiLink member ports (popup picker) ---------------- */

// Physical ports are the only valid FortiLink members: exclude aggregates,
// VLANs, and interfaces that already carry members.
function physicalPortCandidates() {
    return sortedInterfaces().filter(i =>
        (!i.type || i.type === 'physical') && !i.vlanId && !(i.members && i.members.length));
}

function renderFortilinkPorts() {
    const box = $('cc-fl-members-chips');
    if (!box) return;
    if (!ccState.fortilinkPorts.length) {
        box.innerHTML = '<span class="cc-muted">No ports selected yet.</span>';
        return;
    }
    box.innerHTML = ccState.fortilinkPorts.map(p =>
        `<button type="button" class="chip cc-port-chip" data-port="${esc(p)}" aria-label="Remove ${esc(p)} from FortiLink selection">${esc(p)} <span class="cc-chip-x" aria-hidden="true">×</span></button>`
    ).join('');
    box.querySelectorAll('.cc-port-chip').forEach(chip => {
        chip.addEventListener('click', () => {
            ccState.fortilinkPorts = ccState.fortilinkPorts.filter(x => x !== chip.dataset.port);
            renderFortilinkPorts();
            updateGenerateEnabled();
            renderPipelinePreview();
        });
    });
}

function openPortDialog() {
    const list = $('cc-fl-port-list');
    const cands = physicalPortCandidates();
    if (!cands.length) {
        list.innerHTML = '<p class="cc-muted">No physical ports found — load a firewall first.</p>';
    } else {
        const selected = new Set(ccState.fortilinkPorts);
        list.innerHTML = cands.map(i => {
            const roleTag = i.role ? ` <span class="cc-muted">(${esc(i.role)})</span>` : '';
            return `<label class="cc-check-item">
                <input type="checkbox" value="${esc(i.name)}"${selected.has(i.name) ? ' checked' : ''}>${esc(i.name)}${roleTag}
            </label>`;
        }).join('');
    }
    $('cc-port-search').value = '';
    filterPortList();
    ccState.portDialogReturnFocus = document.activeElement;
    $('cc-port-dialog').showModal();
    $('cc-port-search').focus();
}

function closePortDialog() {
    const dialog = $('cc-port-dialog');
    if (dialog.open) dialog.close('cancel');
}

function commitPortDialog() {
    ccState.fortilinkPorts = checkedValues('cc-fl-port-list');
    renderFortilinkPorts();
    $('cc-port-dialog').close('apply');
    updateGenerateEnabled();
    renderPipelinePreview();
}

function filterPortList() {
    const q = ($('cc-port-search').value || '').toLowerCase();
    let visible = 0;
    $('cc-fl-port-list').querySelectorAll('.cc-check-item').forEach(item => {
        item.hidden = !item.textContent.toLowerCase().includes(q);
        if (!item.hidden) visible++;
    });
    $('cc-port-empty').hidden = visible !== 0 || !physicalPortCandidates().length;
}

/* ---------------- VLAN moves (FortiLink recipe) ---------------- */

function vlanMoveIfaceOptions(selected) {
    const opts = sortedInterfaces().map(i =>
        `<option value="${esc(i.name)}"${i.name === selected ? ' selected' : ''}>${esc(i.name)}</option>`).join('');
    return `<option value="">Select interface</option>${opts}`;
}

function addVLANMoveRow() {
    const idx = ccState.vlanMoveRowCount++;
    const row = document.createElement('div');
    row.className = 'cc-vlanmove-row';
    row.dataset.idx = String(idx);
    row.innerHTML = `
        <select class="form-control cc-vlanmove-iface">${vlanMoveIfaceOptions('')}</select>
        <input type="number" class="form-control cc-vlanmove-vlanid" placeholder="VLAN ID" min="1" max="4094">
        <button type="button" class="btn btn-sm cc-vlanmove-remove">Remove</button>
    `;
    row.querySelector('.cc-vlanmove-remove').addEventListener('click', () => {
        row.remove();
        renderPipelinePreview();
    });
    $('cc-fl-vlanmoves').appendChild(row);
    renderPipelinePreview();
}

function refreshVLANMoveOptions() {
    ccRoot.querySelectorAll('#cc-fl-vlanmoves .cc-vlanmove-iface').forEach(sel => {
        const current = sel.value;
        sel.innerHTML = vlanMoveIfaceOptions(current);
    });
}

function collectVLANMoves() {
    return Array.from(ccRoot.querySelectorAll('#cc-fl-vlanmoves .cc-vlanmove-row')).map(row => ({
        interface: row.querySelector('.cc-vlanmove-iface').value,
        vlan_id: parseInt(row.querySelector('.cc-vlanmove-vlanid').value, 10) || 0,
    })).filter(m => m.interface && m.vlan_id);
}

/* Interfaces that carry stacked VLANs, each check moving every child VLAN
 * (name + tag preserved) onto the FortiLink in one shot. */
function renderVLANParents() {
    const container = $('cc-fl-bulkvlan');
    if (!container) return;
    const counts = {};
    ((ccState.summary && ccState.summary.interfaces) || []).forEach(i => {
        if (i.type === 'vlan' && i.parent) counts[i.parent] = (counts[i.parent] || 0) + 1;
    });
    const parents = Object.keys(counts).sort((a, b) => a.localeCompare(b));
    if (!parents.length) {
        container.innerHTML = '<p class="cc-muted">No interface in this backup has VLANs stacked on it.</p>';
        return;
    }
    container.innerHTML = parents.map(p => {
        const id = `cc-fl-bulk-${p}`;
        const n = counts[p];
        return `<label class="cc-check-item" for="${esc(id)}">
            <input type="checkbox" value="${esc(p)}" id="${esc(id)}">${esc(p)} <span class="cc-muted">(${n} VLAN${n === 1 ? '' : 's'})</span>
        </label>`;
    }).join('');
}

/* ---------------- recipe selection / options ---------------- */

function updateGenerateEnabled() {
    const anyEnabled = $('cc-fl-enable').checked || $('cc-sw-enable').checked ||
        $('cc-zn-enable').checked || $('cc-sr-enable').checked;
    const fwPicked = !!$('cc-firewall').value;
    // No global version gate: the SD-WAN recipes self-disable below 7.4 (see
    // applySDWANGate), while FortiLink/zone stay available on older trains.
    $('cc-generate-btn').disabled = !(anyEnabled && fwPicked);
}

function selectionSummary(key) {
    switch (key) {
    case 'iface-to-fortilink': {
        const vlanCount = collectVLANMoves().length + checkedValues('cc-fl-bulkvlan').length;
        const ports = ccState.fortilinkPorts.length;
        return `${ports} member port${ports === 1 ? '' : 's'}; ${vlanCount} VLAN move${vlanCount === 1 ? '' : 's'}`;
    }
    case 'wan-to-sdwan': {
        const members = checkedValues('cc-sw-members').length;
        const zone = $('cc-sw-zone').value.trim() || 'default zone name';
        return `${members} WAN member${members === 1 ? '' : 's'}; ${zone}`;
    }
    case 'iface-to-zone': {
        const members = checkedValues('cc-zn-members').length;
        const zone = $('cc-zn-zone').value.trim() || 'new zone';
        return `${members} interface${members === 1 ? '' : 's'}; ${zone}`;
    }
    case 'sdwan-routes-to-rules':
        return $('cc-sr-strategy').selectedOptions[0]?.textContent || 'manual strategy';
    default:
        return '';
    }
}

function renderPipelinePreview() {
    const selected = recipeOrder.filter(recipe => $(recipe.enable).checked);
    const preview = $('cc-pipeline-preview');
    if (!selected.length) {
        preview.innerHTML = '<li class="cc-muted">Select a recipe to build the preview.</li>';
        return;
    }
    preview.innerHTML = selected.map(recipe => `
        <li data-recipe-key="${recipe.key}">
            <strong>${esc(recipe.label)}</strong>
            <span class="cc-muted">${esc(selectionSummary(recipe.key))}</span>
        </li>
    `).join('');
}

/* Below FortiOS 7.4 only the SD-WAN recipes are unavailable (they emit 7.4+
 * `config system sdwan` syntax); FortiLink and zone conversions still run. */
function applySDWANGate(ok, version) {
    [['cc-sw-enable', 'cc-sw-options'], ['cc-sr-enable', 'cc-sr-options']].forEach(([enableId, optId]) => {
        const cb = $(enableId);
        cb.disabled = !ok;
        if (!ok) {
            cb.checked = false;
            $(optId).hidden = true;
        }
    });
    const note = $('cc-version-warning');
    note.hidden = ok;
    if (!ok) {
        note.textContent =
            `FortiOS ${version}: SD-WAN recipes need 7.4+ and are disabled here — FortiLink and zone recipes are available.`;
    }
    updateGenerateEnabled();
    renderPipelinePreview();
}

function wireRecipeToggle(enableId, optionsId) {
    $(enableId).addEventListener('change', () => {
        $(optionsId).hidden = !$(enableId).checked;
        updateGenerateEnabled();
        renderPipelinePreview();
    });
}

function buildSelections() {
    const recipes = [];
    if ($('cc-fl-enable').checked) {
        recipes.push({
            key: 'iface-to-fortilink',
            options: {
                member_ports: ccState.fortilinkPorts,
                fortilink_name: $('cc-fl-name').value.trim(),
                use_existing: $('cc-fl-existing').checked,
                vlan_moves: collectVLANMoves(),
                bulk_vlan_parents: checkedValues('cc-fl-bulkvlan'),
                fortilink_ip: $('cc-fl-ip').value.trim(),
                dual_homed: $('cc-fl-dualhomed').checked,
            },
        });
    }
    if ($('cc-sw-enable').checked) {
        recipes.push({
            key: 'wan-to-sdwan',
            options: {
                members: checkedValues('cc-sw-members'),
                zone_name: $('cc-sw-zone').value.trim(),
                use_existing: $('cc-sw-existing').checked,
            },
        });
    }
    if ($('cc-zn-enable').checked) {
        recipes.push({
            key: 'iface-to-zone',
            options: {
                interfaces: checkedValues('cc-zn-members'),
                zone_name: $('cc-zn-zone').value.trim(),
                use_existing: $('cc-zn-existing').checked,
                intrazone_deny: !$('cc-zn-intrazone').checked,
            },
        });
    }
    if ($('cc-sr-enable').checked) {
        recipes.push({
            key: 'sdwan-routes-to-rules',
            options: { strategy: $('cc-sr-strategy').value },
        });
    }
    return recipes;
}

/* ---------------- generate ---------------- */

async function generate() {
    const fwID = $('cc-firewall').value;
    const recipes = buildSelections();
    if (!fwID || !recipes.length) return;
    const btn = $('cc-generate-btn');
    const feedback = $('cc-action-feedback');
    btn.disabled = true;
    feedback.dataset.state = 'loading';
    feedback.textContent = 'Generating preview…';
    try {
        const result = await fetchJSON('/fgt-confconv/convert', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ fw_id: parseInt(fwID, 10), recipes }),
        });
        renderResults(result);
        feedback.dataset.state = 'success';
        feedback.textContent = 'Conversion preview generated. Review every warning and CLI section before use.';
    } catch (err) {
        feedback.dataset.state = 'error';
        feedback.textContent = 'Conversion failed: ' + err.message;
    } finally {
        updateGenerateEnabled();
    }
}

function renderResults(result) {
    $('cc-results').hidden = false;
    const warningsEl = $('cc-warnings');
    if (result.warnings && result.warnings.length) {
        warningsEl.hidden = false;
        warningsEl.innerHTML = '<h3>Needs manual review</h3><ul class="cc-warning-list">' +
            result.warnings.map(w =>
                `<li><strong>${esc(w.recipe)}:</strong> ${esc(w.detail)}${w.line ? ` <code>${esc(w.line)}</code>` : ''}</li>`
            ).join('') + '</ul>';
    } else {
        warningsEl.hidden = true;
        warningsEl.innerHTML = '';
    }

    const sectionsEl = $('cc-sections');
    sectionsEl.innerHTML = (result.sections || []).map((s, i) => `
        <h3>${esc(s.label)}</h3>
        <button type="button" class="btn btn-sm cc-copy" data-target="cc-section-${i}">Copy</button>
        <pre class="cc-config" id="cc-section-${i}">${esc(s.lines.join('\n'))}</pre>
    `).join('');

    sectionsEl.querySelectorAll('.cc-copy').forEach(btn => {
        btn.addEventListener('click', () => {
            const pre = $(btn.dataset.target);
            if (navigator.clipboard) navigator.clipboard.writeText(pre.textContent);
        });
    });

    ccState.combined = result.combined || '';
}

/* ---------------- wiring ---------------- */

document.addEventListener('DOMContentLoaded', () => {
    if (typeof initSearchableSelect === 'function') {
        initSearchableSelect($('cc-firewall'), { placeholder: 'Select Firewall' });
    }
    $('cc-firewall').addEventListener('change', loadSummary);

    wireRecipeToggle('cc-fl-enable', 'cc-fl-options');
    wireRecipeToggle('cc-sw-enable', 'cc-sw-options');
    wireRecipeToggle('cc-zn-enable', 'cc-zn-options');
    wireRecipeToggle('cc-sr-enable', 'cc-sr-options');

    $('cc-fl-add-vlanmove').addEventListener('click', addVLANMoveRow);

    $('cc-fl-add-port').addEventListener('click', openPortDialog);
    $('cc-port-dialog-cancel').addEventListener('click', closePortDialog);
    $('cc-port-dialog-apply').addEventListener('click', commitPortDialog);
    $('cc-port-search').addEventListener('input', filterPortList);
    $('cc-port-dialog').addEventListener('close', () => {
        const returnFocus = ccState.portDialogReturnFocus;
        ccState.portDialogReturnFocus = null;
        if (returnFocus instanceof HTMLElement && returnFocus.isConnected) returnFocus.focus();
    });
    $('cc-port-dialog').addEventListener('keydown', event => {
        if (event.key !== 'Escape') return;
        event.preventDefault();
        closePortDialog();
    });
    renderFortilinkPorts();
    renderPipelinePreview();

    ccRoot.addEventListener('input', event => {
        if (event.target.closest('.cc-options')) renderPipelinePreview();
    });
    ccRoot.addEventListener('change', event => {
        if (event.target.closest('.cc-options')) renderPipelinePreview();
    });

    $('cc-generate-btn').addEventListener('click', generate);
    $('cc-copy-all').addEventListener('click', () => {
        if (navigator.clipboard) navigator.clipboard.writeText(ccState.combined || '');
    });
});

})();
