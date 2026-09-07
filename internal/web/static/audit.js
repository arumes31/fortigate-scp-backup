// ---------------------------------------------------------------------------
// Async audit loading: the page shell renders instantly; per-firewall results
// are fetched from /audit/results/{id} with limited concurrency and rendered
// as they arrive. esc()/tt() come from ui.js.
// ---------------------------------------------------------------------------
const auditRows = Array.from(document.querySelectorAll("tr.audit-row-item"));
const auditState = {};        // fwid -> result JSON
const searchCache = {};       // fwid -> uppercase searchable text of the result
const failedRows = new Set(); // fwids whose fetch failed (excluded from totals)
let totals = { critical: 0, warning: 0, loaded: 0 };

function sevColor(sev) {
    return isCriticalSeverity(sev) ? "#ef4444" : sev === "warning" ? "#f59e0b" : "#3b82f6";
}

function isCriticalSeverity(severity) { return severity === "critical" || severity === "high"; }

function scoreBar(label, score) {
    const color = score < 50 ? "#ef4444" : score < 80 ? "#f59e0b" : "#10b981";
    return `<div style="margin-bottom: 8px;">
        <div style="display: flex; justify-content: space-between; font-size: 0.8em; margin-bottom: 2px;">
            <span>${label}</span><strong>${score}%</strong>
        </div>
        <div style="height: 6px; background: rgba(255,255,255,0.05); border-radius: 3px; overflow: hidden;">
            <div style="height: 100%; width: ${score}%; background: ${color};"></div>
        </div>
    </div>`;
}

// Renders the config context snippet with a line-number gutter and the
// detected line highlighted.
function contextView(f) {
    if (!f.context) return "";
    const lines = f.context.split("\n");
    let num = f.context_start || 1;
    let afterGap = false; // past the "..." the true line numbers are unknown
    let html = "";
    for (const line of lines) {
        const isEllipsis = line.trim() === "...";
        if (isEllipsis) afterGap = true;
        const isMatch = !isEllipsis && !afterGap && num === f.line;
        html += `<div style="display: flex; ${isMatch ? "background: rgba(239, 68, 68, 0.12); border-left: 2px solid " + sevColor(f.severity) + ";" : "border-left: 2px solid transparent;"}">
            <span style="width: 48px; text-align: right; padding-right: 10px; color: rgba(255,255,255,0.25); user-select: none; flex-shrink: 0;">${isEllipsis || afterGap ? "" : num}</span>
            <span style="white-space: pre; color: ${isMatch ? "#fecaca" : "#9ca3af"};">${esc(line)}</span>
        </div>`;
        if (!isEllipsis) num++;
    }
    return `<details style="margin-top: 6px; background: rgba(0,0,0,0.25); border-radius: 4px; border: 1px solid rgba(255,255,255,0.04);">
        <summary style="font-size: 0.8em; cursor: pointer; color: rgba(255,255,255,0.4); padding: 4px 8px;">${tt("audit.show_context").replace("%d", f.line)}</summary>
        <div style="padding: 8px 0; font-family: monospace; font-size: 0.82em; overflow-x: auto;">${html}</div>
    </details>`;
}

function findingCard(f, fwid) {
    return `<div class="finding finding-${esc(f.severity)}" style="padding: 10px; margin-bottom: 8px; border-radius: 4px; background: rgba(255,255,255,0.02); border-left: 4px solid ${sevColor(f.severity)};">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; gap: 10px;">
            <strong style="color: #fff;">${esc(f.text)}</strong>
            <form method="post" action="/audit/exemption" style="margin: 0; display: flex; gap: 4px; flex-shrink: 0;">
                ${csrfInput()}
                <input type="hidden" name="fw_id" value="${fwid}">
                <input type="hidden" name="finding_key" value="${esc(f.key || "")}">
                <input type="hidden" name="finding_text" value="${esc(f.text)}">
                <label class="audit-inline-field"><span>${tt("audit.exemption_reason_label")}</span><input type="text" name="reason" placeholder="${tt("audit.exempt_reason")}" required autocomplete="off" data-bwignore data-lpignore="true" data-1p-ignore></label>
                <button type="submit" class="btn btn-small" style="font-size: 0.8em; padding: 2px 6px;">${tt("audit.exempt")}</button>
            </form>
        </div>
        ${f.remediation ? `<details style="margin-top: 8px; background: rgba(0,0,0,0.2); border-radius: 4px; border: 1px solid rgba(255,255,255,0.03);">
            <summary style="font-size: 0.8em; cursor: pointer; color: rgba(255,255,255,0.4); padding: 4px 8px;">${tt("audit.show_cli")}</summary>
            <pre style="margin: 0; padding: 8px; font-family: monospace; font-size: 0.85em; color: #34d399; white-space: pre-wrap; border-top: 1px solid rgba(255,255,255,0.03);">${esc(f.remediation)}</pre>
        </details>` : ""}
        ${contextView(f)}
    </div>`;
}

function renderRow(tr, res) {
    // Coerce the id to a number at the DOM boundary: data-fwid is a
    // server-rendered integer, and a numeric value can never be reinterpreted
    // as HTML when later interpolated into innerHTML strings.
    const fwid = Number(tr.getAttribute("data-fwid"));
    const sysCell = tr.querySelector(".cell-sys");
    const scoreCell = tr.querySelector(".cell-scores");
    const ticketCell = tr.querySelector(".cell-ticket");
    const actionCell = tr.querySelector(".cell-actions");

    if (!res.has_config) {
        sysCell.innerHTML = `<span class="muted">${tt("audit.no_backup")}</span>`;
        scoreCell.innerHTML = '<span class="muted">—</span>';
        ticketCell.innerHTML = '<span class="muted">—</span>';
        actionCell.innerHTML = '<span class="muted">—</span>';
        return;
    }

    sysCell.innerHTML = `
        <div>${tt("audit.model")} <strong style="color: #fff;">${res.model ? esc(res.model) : "—"}</strong></div>
        <div style="margin-top: 3px;">FortiOS: <code>${esc(res.version)}</code></div>
        <div class="muted" style="margin-top: 3px; font-size: 0.85em;" title="${tt("audit.computed")} ${esc(res.computed_at || "")}">${tt("audit.backup")} ${esc(res.backup_filename || "")}</div>`;

    scoreCell.innerHTML = scoreBar("PCI-DSS", res.pci_score) + scoreBar("CIS Benchmark", res.cis_score) + scoreBar("HIPAA", res.hipaa_score);

    ticketCell.innerHTML = `
        <form method="post" action="/audit/ticket" class="audit-ticket-form">
            ${csrfInput()}
            <input type="hidden" name="backup_filename" value="${esc(res.backup_filename)}">
            <label>${tt("audit.ticket_id_label")}<input type="text" name="ticket_id" value="${esc(res.ticket_id || "")}" placeholder="${tt("audit.ticket_id")}" autocomplete="off" data-bwignore data-lpignore="true" data-1p-ignore></label>
            <label>${tt("audit.ticket_comment_label")}<input type="text" name="details" value="${esc(res.ticket_detail || "")}" placeholder="${tt("audit.ticket_comment")}" autocomplete="off" data-bwignore data-lpignore="true" data-1p-ignore></label>
            <button type="submit" class="btn btn-small" style="padding: 2px; font-size: 0.8em; width: 60px;">Link</button>
        </form>`;

    const nCrit = (res.findings || []).filter(f => isCriticalSeverity(f.severity)).length;
    const nWarn = (res.findings || []).filter(f => f.severity === "warning").length;
    actionCell.innerHTML = `
        <button type="button" class="btn btn-small audit-detail-toggle" data-audit-detail="${fwid}" id="btn-${fwid}" aria-expanded="false" aria-controls="detail-${fwid}" style="background: rgba(255,255,255,0.05); color: #fff; border: 1px solid rgba(255,255,255,0.1); padding: 4px 10px;">${tt("audit.details_show")}</button>
        <div style="margin-top: 6px; font-size: 0.82em;">
            ${nCrit ? `<span style="color: #ef4444;">● ${nCrit} ${tt("audit.n_critical")}</span> ` : ""}
            ${nWarn ? `<span style="color: #f59e0b;">● ${nWarn} ${tt("audit.n_warnings")}</span>` : ""}
            ${!nCrit && !nWarn ? `<span style="color: #10b981;">● ${tt("audit.clean")}</span>` : ""}
        </div>
        <button type="button" class="btn btn-small audit-recheck" data-audit-recheck="${fwid}" title="${tt("audit.recheck_title")}">${tt("audit.recheck")}</button>`;

    // The heavy details DOM (finding cards with per-finding exemption forms)
    // is built lazily on first expand: building it for every firewall up
    // front made the whole page unresponsive — hundreds of hidden forms and
    // inputs, re-scanned by password-manager extensions on every row update.
    const detailRow = document.getElementById("detail-" + fwid);
    detailRow.firstElementChild.dataset.built = "";
    if (detailRow.style.display !== "none") {
        buildDetail(fwid);
        document.getElementById("btn-" + fwid).textContent = tt("audit.details_hide");
        document.getElementById("btn-" + fwid).setAttribute("aria-expanded", "true");
    }
}

// buildDetail renders the findings/upgrade panel for one firewall into its
// detail row (no-op when already built for the current result).
function buildDetail(fwid) {
    const detail = document.getElementById("detail-" + fwid).firstElementChild;
    if (detail.dataset.built === "1") return;
    const res = auditState[fwid];
    if (!res) return;

    let findingsHtml;
    if (res.findings && res.findings.length) {
        findingsHtml = res.findings.map(f => findingCard(f, fwid)).join("");
    } else {
        findingsHtml = `<div class="alert alert-success" style="padding: 10px;">${tt("audit.findings_none")}</div>`;
    }
    let exemptedHtml = "";
    if (res.exempted && res.exempted.length) {
        exemptedHtml = `<h4 style="margin-top: 15px; margin-bottom: 5px; color: #f59e0b;">${tt("audit.exempted_title")}</h4>` +
            res.exempted.map(f => `<div style="font-size: 0.85em; padding: 6px; background: rgba(245, 158, 11, 0.05); margin-bottom: 4px; border-radius: 4px; border-left: 3px solid #f59e0b;">${esc(f.text)} <span class="muted">${tt("audit.exempted_note")}</span></div>`).join("");
    }
    const upgradeHtml = (res.upgrade_path || []).map((step, i) => `
        <div style="display: flex; align-items: center; gap: 8px; font-size: 0.9em;">
            <span style="background: rgba(255,255,255,0.1); border-radius: 50%; width: 20px; height: 20px; display: flex; align-items: center; justify-content: center; font-size: 0.8em; font-weight: bold; color: var(--accent); flex-shrink: 0;">${i + 1}</span>
            <code>${esc(step)}</code>
        </div>`).join("");

    detail.innerHTML = `
        <div class="grid-2" style="display: grid; grid-template-columns: 2fr 1fr; gap: 20px;">
            <div>
                <h3 class="mt-0">${tt("audit.findings_title")}</h3>
                ${findingsHtml}
                ${exemptedHtml}
            </div>
            <div style="border-left: 1px solid rgba(255,255,255,0.05); padding-left: 20px;">
                <h3 class="mt-0">${tt("audit.upgrade_title")}</h3>
                <p class="muted" style="font-size: 0.85em;">${tt("audit.upgrade_note")}</p>
                <div style="display: flex; flex-direction: column; gap: 8px; margin-top: 10px;">${upgradeHtml}</div>
            </div>
        </div>`;
    detail.dataset.built = "1";
}

function renderError(tr, fwid) {
    tr.querySelector(".cell-sys").innerHTML = `<span style="color: #ef4444;">${tt("audit.load_error")}</span>`;
    tr.querySelector(".cell-actions").innerHTML = `<button type="button" class="btn btn-small audit-retry" data-audit-retry="${fwid}" style="background: rgba(239,68,68,0.15); color: #f87171; border: 1px solid rgba(239,68,68,0.3); padding: 4px 10px;">${tt("audit.retry")}</button>`;
}

function reorderAuditRows() {
    const body = document.getElementById("auditBody");
    if (!body) return;
    const ordered = auditRows.slice().sort((a, b) => {
        function priority(tr) {
            const id = String(tr.getAttribute("data-fwid"));
            if (failedRows.has(id)) return [0, 0, 0, tr.dataset.fqdn || ""];
            const res = auditState[id];
            if (!res) return [4, 0, 100, tr.dataset.fqdn || ""];
            const findings = res.findings || [];
            const critical = findings.filter(f => isCriticalSeverity(f.severity)).length;
            const warnings = findings.filter(f => f.severity === "warning").length;
            const score = Math.min(res.pci_score ?? 100, res.cis_score ?? 100, res.hipaa_score ?? 100);
            return [critical ? 1 : warnings ? 2 : 3, -(critical || warnings), score, tr.dataset.fqdn || ""];
        }
        const ap = priority(a), bp = priority(b);
        for (let i = 0; i < 3; i++) if (ap[i] !== bp[i]) return ap[i] - bp[i];
        return String(ap[3]).localeCompare(String(bp[3]));
    });
    for (const tr of ordered) {
        body.appendChild(tr);
        const detail = document.getElementById("detail-" + tr.getAttribute("data-fwid"));
        if (detail) body.appendChild(detail);
    }
}

function updateTotals() {
    totals.critical = 0; totals.warning = 0;
    for (const res of Object.values(auditState)) {
        for (const f of (res.findings || [])) {
            if (isCriticalSeverity(f.severity)) totals.critical++;
            else if (f.severity === "warning") totals.warning++;
        }
    }
    // Rows that failed to load are NOT counted: mark the tiles so a partial
    // failure can never read as a fleet-wide all-clear.
    const failMark = failedRows.size ? " ⚠" : "";
    document.getElementById("statCritical").textContent = totals.critical + failMark;
    document.getElementById("statWarnings").textContent = totals.warning + failMark;
    document.getElementById("statLoaded").textContent =
        totals.loaded + "/" + auditRows.length + (failedRows.size ? " ⚠" + failedRows.size : "");
    const loadStatus = document.getElementById("auditLoadStatus");
    if (loadStatus) {
        if (failedRows.size) {
            loadStatus.className = "audit-load-status is-error";
            loadStatus.textContent = totals.loaded + "/" + auditRows.length + " loaded · " + failedRows.size + " failed. Results are incomplete.";
        } else if (totals.loaded < auditRows.length) {
            loadStatus.className = "audit-load-status is-loading";
            loadStatus.textContent = "Loading audit results: " + totals.loaded + "/" + auditRows.length;
        } else {
            loadStatus.className = "audit-load-status";
            loadStatus.textContent = "All " + auditRows.length + " audit results loaded.";
        }
    }
    reorderAuditRows();
}

async function loadRow(fwid, recompute) {
    const tr = document.querySelector(`tr.audit-row-item[data-fwid="${fwid}"]`);
    if (!tr) return;
    try {
        const url = "/audit/results/" + fwid + (recompute ? "?recompute=1" : "");
        const resp = await fetch(url, { headers: { "Accept": "application/json" } });
        if (!resp.ok) throw new Error("HTTP " + resp.status);
        const res = await resp.json();
        auditState[fwid] = res;
        // Search matches result content (findings, model, backup, …) without
        // requiring the detail DOM to exist.
        searchCache[fwid] = JSON.stringify(res).toUpperCase();
        failedRows.delete(String(fwid));
        renderRow(tr, res);
    } catch (e) {
        failedRows.add(String(fwid));
        renderError(tr, fwid);
    } finally {
        totals.loaded = Object.keys(auditState).length;
        updateTotals();
    }
}

function recompute(fwid) {
    const tr = document.querySelector(`tr.audit-row-item[data-fwid="${fwid}"]`);
    if (tr) tr.querySelector(".cell-sys").innerHTML = '<span class="spinner"></span>';
    loadRow(fwid, true);
}

// Fetch all rows with limited concurrency (4 at a time).
async function loadAll() {
    const ids = auditRows.map(tr => Number(tr.getAttribute("data-fwid")));
    let idx = 0;
    async function worker() {
        while (idx < ids.length) {
            const id = ids[idx++];
            await loadRow(id);
        }
    }
    await Promise.all(Array.from({ length: Math.min(4, ids.length) }, worker));
    updateTotals();
}

function filterAuditTable() {
    const input = document.getElementById("auditSearch").value.toUpperCase();
    for (const tr of auditRows) {
        const fwid = Number(tr.getAttribute("data-fwid"));
        const detailsRow = document.getElementById("detail-" + fwid);
        const text = tr.textContent.toUpperCase() + " " + (searchCache[fwid] || "");
        if (text.indexOf(input) > -1) {
            tr.style.display = "";
        } else {
            tr.style.display = "none";
            if (detailsRow) {
                detailsRow.style.display = "none";
                const btn = document.getElementById("btn-" + fwid);
                if (btn) { btn.textContent = tt("audit.details_show"); btn.setAttribute("aria-expanded", "false"); }
            }
        }
    }
}

function toggleDetails(fwID) {
    const row = document.getElementById("detail-" + fwID);
    const btn = document.getElementById("btn-" + fwID);
    if (row.style.display === "none") {
        buildDetail(fwID);
        row.style.display = "table-row";
        btn.textContent = tt("audit.details_hide");
        btn.setAttribute("aria-expanded", "true");
    } else {
        row.style.display = "none";
        btn.textContent = tt("audit.details_show");
        btn.setAttribute("aria-expanded", "false");
    }
}

document.addEventListener("click", function (event) {
    const detailToggle = event.target.closest("[data-audit-detail]");
    if (detailToggle) toggleDetails(Number(detailToggle.dataset.auditDetail));
    const retry = event.target.closest("[data-audit-retry]");
    if (retry) loadRow(Number(retry.dataset.auditRetry));
    const recheck = event.target.closest("[data-audit-recheck]");
    if (recheck) recompute(Number(recheck.dataset.auditRecheck));
});
document.addEventListener("DOMContentLoaded", function () {
    const filter = document.getElementById("auditSearch");
    if (filter) filter.addEventListener("input", filterAuditTable);
    loadAll();
});
