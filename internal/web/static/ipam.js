(function () {
  "use strict";

  var workspace = document.getElementById("ipamWorkspace");
  if (!workspace) return;

  var ENTRY_RENDER_CAP = 1000;
  var OVERLAP_RENDER_CAP = 500;
  var allEntries = [];
  var allOverlaps = [];
  var filteredEntries = [];
  var mode = "text";
  var source = "all";
  var body = document.getElementById("ipamBody");
  var overlapBody = document.getElementById("ipamOverlapBody");
  var search = document.getElementById("ipamSearch");
  var firewallFilter = document.getElementById("ipamFirewallFilter");
  var vdomFilter = document.getElementById("ipamVDOMFilter");
  var loadState = document.getElementById("ipamLoadState");
  var exportButton = document.getElementById("ipamExportCSV");
  var numberFormat = new Intl.NumberFormat(document.documentElement.lang || "en");
  var sourceLabels = {
    interface: workspace.dataset.sourceInterface,
    secondary: workspace.dataset.sourceSecondary,
    route: workspace.dataset.sourceRoute,
    dhcp: workspace.dataset.sourceDhcp,
    address: workspace.dataset.sourceAddress,
  };

  function text(value) {
    return String(value == null ? "" : value);
  }

  function ip4ToInt(value) {
    var match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(value);
    if (!match) return null;
    var result = 0;
    for (var index = 1; index <= 4; index++) {
      var octet = Number(match[index]);
      if (octet > 255) return null;
      result = result * 256 + octet;
    }
    return result >>> 0;
  }

  function prefixParts(value) {
    var match = /^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/.exec(value || "");
    if (!match) return null;
    var base = ip4ToInt(match[1]);
    var bits = Number(match[2]);
    return base === null || bits > 32 ? null : { base: base, bits: bits };
  }

  function ipInPrefix(ip, prefix) {
    if (!prefix) return false;
    if (prefix.bits === 0) return true;
    return ((ip ^ prefix.base) >>> (32 - prefix.bits)) === 0;
  }

  function entrySearchText(entry) {
    return [entry.prefix, entry.fqdn, entry.vdom, sourceLabels[entry.source] || entry.source, entry.name]
      .map(text).join(" ").toLowerCase();
  }

  function sourceMatches(entry) {
    if (source === "all") return true;
    if (source === "interfaces") return entry.source === "interface" || entry.source === "secondary";
    return entry.source === source;
  }

  function structuralMatches(entry) {
    return (firewallFilter.value === "all" || entry.fqdn === firewallFilter.value) &&
      (vdomFilter.value === "all" || entry.vdom === vdomFilter.value) && sourceMatches(entry);
  }

  function queryState() {
    var value = search.value.trim().toLowerCase();
    if (!value) return { value: "", ip: null, valid: true, terms: [] };
    if (mode === "ip") {
      var ip = ip4ToInt(value);
      return { value: value, ip: ip, valid: ip !== null, terms: [] };
    }
    return { value: value, ip: null, valid: true, terms: value.split(/\s+/).filter(Boolean) };
  }

  function queryMatchesEntry(entry, query) {
    if (!query.value) return true;
    if (mode === "ip") return query.valid && ipInPrefix(query.ip, entry._prefix);
    return query.terms.every(function (term) { return entry._search.indexOf(term) !== -1; });
  }

  function element(name, className, value) {
    var node = document.createElement(name);
    if (className) node.className = className;
    if (value != null) node.textContent = text(value);
    return node;
  }

  function emptyRow(columns, message) {
    var row = document.createElement("tr");
    var cell = element("td", "empty", message);
    cell.colSpan = columns;
    row.appendChild(cell);
    return row;
  }

  function option(value) {
    var node = document.createElement("option");
    node.value = value;
    node.textContent = value;
    return node;
  }

  function populateSelect(select, values) {
    while (select.options.length > 1) select.remove(1);
    Array.from(new Set(values.filter(Boolean))).sort().forEach(function (value) {
      select.appendChild(option(value));
    });
  }

  function entryRow(entry) {
    var row = document.createElement("tr");
    var prefixCell = document.createElement("td");
    prefixCell.appendChild(element("code", "", entry.prefix));
    row.appendChild(prefixCell);
    row.appendChild(element("td", "", entry.fqdn));
    row.appendChild(element("td", "ipam-vdom", entry.vdom || "root"));
    row.appendChild(element("td", "muted", sourceLabels[entry.source] || entry.source));
    row.appendChild(element("td", "muted", entry.name));
    return row;
  }

  function renderActiveFilters(query) {
    var container = document.getElementById("ipamActiveFilters");
    container.replaceChildren();
    var filters = [];
    if (query.value) filters.push({ key: "query", label: search.labels[0].textContent.trim() + ": " + query.value });
    if (firewallFilter.value !== "all") filters.push({ key: "firewall", label: "Firewall: " + firewallFilter.value });
    if (vdomFilter.value !== "all") filters.push({ key: "vdom", label: "VDOM: " + vdomFilter.value });
    if (source !== "all") {
      var button = document.querySelector('[data-ipam-source="' + source + '"]');
      filters.push({ key: "source", label: workspace.dataset.colSource + ": " + button.textContent });
    }
    filters.forEach(function (filter) {
      var button = element("button", "btn btn-sm ipam-filter-chip", filter.label);
      button.type = "button";
      button.dataset.removeFilter = filter.key;
      button.setAttribute("aria-label", workspace.dataset.removeFilter + " " + filter.label);
      container.appendChild(button);
    });
  }

  function renderEntries() {
    var query = queryState();
    filteredEntries = query.valid ? allEntries.filter(function (entry) {
      return structuralMatches(entry) && queryMatchesEntry(entry, query);
    }) : [];
    var shown = filteredEntries.slice(0, ENTRY_RENDER_CAP);
    var fragment = document.createDocumentFragment();
    shown.forEach(function (entry) { fragment.appendChild(entryRow(entry)); });
    if (!shown.length) fragment.appendChild(emptyRow(5, query.valid ? workspace.dataset.empty : workspace.dataset.invalidIp));
    if (filteredEntries.length > shown.length) {
      fragment.appendChild(emptyRow(5, "… " + numberFormat.format(filteredEntries.length - shown.length) + " " + workspace.dataset.moreRows));
    }
    body.replaceChildren(fragment);
    document.getElementById("ipamSearchCount").textContent =
      numberFormat.format(shown.length) + " " + workspace.dataset.of + " " + numberFormat.format(allEntries.length) + " " + workspace.dataset.matches;
    loadState.textContent = query.valid ? (allEntries.length ? "" : workspace.dataset.empty) : workspace.dataset.invalidIp;
    exportButton.disabled = filteredEntries.length === 0;
    renderActiveFilters(query);
    renderOverlaps(query);
  }

  function overlapRelatedEntries(overlap) {
    return allEntries.filter(function (entry) {
      return entry.prefix === overlap.prefix || (overlap.inner && entry.prefix === overlap.inner);
    });
  }

  function overlapMatches(overlap, query, related) {
    var structuralActive = firewallFilter.value !== "all" || vdomFilter.value !== "all" || source !== "all";
    if (structuralActive && !related.length) return false;
    if (!query.value) return true;
    if (mode === "ip") {
      return query.valid && (ipInPrefix(query.ip, overlap._prefix) || ipInPrefix(query.ip, overlap._inner));
    }
    return query.terms.every(function (term) {
      return overlap._search.indexOf(term) !== -1 || related.some(function (entry) {
        return entry._search.indexOf(term) !== -1;
      });
    });
  }

  function overlapRow(overlap, related) {
    var row = document.createElement("tr");
    var kindCell = document.createElement("td");
    kindCell.appendChild(element("span", overlap.kind === "duplicate" ? "pill pill-failed" : "pill pill-new",
      overlap.kind === "duplicate" ? workspace.dataset.kindDuplicate : workspace.dataset.kindContainment));
    row.appendChild(kindCell);
    [overlap.prefix, overlap.inner || "—"].forEach(function (value) {
      var cell = document.createElement("td");
      if (value === "—") cell.appendChild(element("span", "muted", value));
      else cell.appendChild(element("code", "", value));
      row.appendChild(cell);
    });
    var firewalls = (overlap.firewalls || []).join(", ");
    if (overlap.count > (overlap.firewalls || []).length) firewalls += " +" + (overlap.count - overlap.firewalls.length);
    row.appendChild(element("td", "muted", overlap.count + " — " + firewalls));
    var contextCell = document.createElement("td");
    var context = element("div", "ipam-overlap-context");
    related.slice(0, 3).forEach(function (entry) {
      context.appendChild(element("span", "", entry.fqdn + " · " + (entry.vdom || "root") + " · " +
        (sourceLabels[entry.source] || entry.source) + " · " + entry.name));
    });
    if (!related.length) context.appendChild(element("span", "", "—"));
    contextCell.appendChild(context);
    row.appendChild(contextCell);
    return row;
  }

  function renderOverlaps(query) {
    var matched = [];
    allOverlaps.forEach(function (overlap) {
      var related = overlapRelatedEntries(overlap).filter(structuralMatches);
      if (overlapMatches(overlap, query, related)) matched.push({ overlap: overlap, related: related });
    });
    var shown = matched.slice(0, OVERLAP_RENDER_CAP);
    var fragment = document.createDocumentFragment();
    shown.forEach(function (item) { fragment.appendChild(overlapRow(item.overlap, item.related)); });
    if (!shown.length) fragment.appendChild(emptyRow(5, workspace.dataset.noFilteredOverlaps));
    if (matched.length > shown.length) {
      fragment.appendChild(emptyRow(5, "… " + numberFormat.format(matched.length - shown.length) + " " + workspace.dataset.moreRows));
    }
    overlapBody.replaceChildren(fragment);
    var card = document.getElementById("ipamOverlapCard");
    card.hidden = allOverlaps.length === 0;
    document.getElementById("ipamOverlapDesc").textContent =
      numberFormat.format(shown.length) + " " + workspace.dataset.of + " " + numberFormat.format(matched.length) + " " + workspace.dataset.matches;
  }

  function renderSnapshot(snapshot) {
    document.getElementById("ipamFwCount").textContent = text(snapshot.scanned || 0) + " / " + text(snapshot.firewalls || 0);
    document.getElementById("ipamPrefixCount").textContent = text(snapshot.prefixes || 0);
    document.getElementById("ipamOverlapCount").textContent = text((snapshot.overlaps || []).length);
    allEntries = snapshot.entries || [];
    allEntries.forEach(function (entry) {
      entry.vdom = entry.vdom || "root";
      entry._search = entrySearchText(entry);
      entry._prefix = prefixParts(entry.prefix);
    });
    allOverlaps = snapshot.overlaps || [];
    allOverlaps.forEach(function (overlap) {
      overlap._search = [overlap.kind, overlap.prefix, overlap.inner, (overlap.firewalls || []).join(" ")].join(" ").toLowerCase();
      overlap._prefix = prefixParts(overlap.prefix);
      overlap._inner = prefixParts(overlap.inner);
    });
    populateSelect(firewallFilter, allEntries.map(function (entry) { return entry.fqdn; }));
    populateSelect(vdomFilter, allEntries.map(function (entry) { return entry.vdom; }));
    renderEntries();
  }

  function sanitizeCSVCell(value) {
    var safe = text(value);
    if (/^\s*[=+\-@]/.test(safe)) safe = "'" + safe;
    return '"' + safe.replace(/"/g, '""') + '"';
  }

  function exportFilteredCSV() {
    var rows = [[workspace.dataset.colPrefix, workspace.dataset.colFirewall, workspace.dataset.colVdom,
      workspace.dataset.colSource, workspace.dataset.colName]];
    filteredEntries.forEach(function (entry) {
      rows.push([entry.prefix, entry.fqdn, entry.vdom || "root", sourceLabels[entry.source] || entry.source, entry.name]);
    });
    var csv = rows.map(function (row) { return row.map(sanitizeCSVCell).join(","); }).join("\r\n") + "\r\n";
    var url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
    var link = document.createElement("a");
    link.href = url;
    link.download = "fortisafe-ipam-filtered.csv";
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 0);
  }

  function setMode(nextMode, button) {
    mode = nextMode;
    document.querySelectorAll("[data-ipam-mode]").forEach(function (candidate) {
      candidate.setAttribute("aria-pressed", text(candidate === button));
    });
    document.getElementById("ipamSearchMode").textContent = button.textContent;
    renderEntries();
  }

  function setSource(nextSource, button) {
    source = nextSource;
    document.querySelectorAll("[data-ipam-source]").forEach(function (candidate) {
      candidate.setAttribute("aria-pressed", text(candidate === button));
    });
    renderEntries();
  }

  var pollTimer = null;
  var pollFailures = 0;
  var POLL_RETRY_MAX_MS = 30000;
  function poll() {
    if (pollTimer) { clearTimeout(pollTimer); pollTimer = null; }
    fetch("/ipam/data" + window.location.search).then(function (response) {
      if (!response.ok) throw new Error("http " + response.status);
      return response.json();
    }).then(function (data) {
      pollFailures = 0;
      if (data.snapshot) renderSnapshot(data.snapshot);
      document.getElementById("ipamUpdated").textContent = data.computed_at
        ? workspace.dataset.lastUpdated + ": " + data.computed_at.replace("T", " ").replace(/:\d\dZ?$/, "")
        : workspace.dataset.never;
      var progress = document.getElementById("ipamProgressWrap");
      var refresh = document.getElementById("ipamRefreshBtn");
      progress.hidden = !data.running;
      refresh.disabled = Boolean(data.running);
      if (data.running) {
        var percent = data.total ? Math.round(100 * data.done / data.total) : 0;
        var meter = progress.querySelector("[role=progressbar]");
        meter.setAttribute("aria-valuenow", text(percent));
        document.getElementById("ipamProgressBar").style.width = percent + "%";
        document.getElementById("ipamProgressText").textContent = data.total && data.done >= data.total
          ? workspace.dataset.finalizing
          : workspace.dataset.updating + " " + data.done + " / " + data.total + (data.current ? " — " + data.current : "");
        pollTimer = setTimeout(poll, 2000);
      } else if (!data.snapshot) {
        loadState.textContent = workspace.dataset.empty;
      }
    }).catch(function (error) {
      loadState.textContent = workspace.dataset.error + " (" + error.message + ")";
      pollFailures++;
      var retryDelay = Math.min(POLL_RETRY_MAX_MS, 2000 * Math.pow(2, pollFailures - 1));
      pollTimer = setTimeout(poll, retryDelay);
    });
  }

  search.addEventListener("input", renderEntries);
  firewallFilter.addEventListener("change", renderEntries);
  vdomFilter.addEventListener("change", renderEntries);
  document.querySelectorAll("[data-ipam-mode]").forEach(function (button) {
    button.addEventListener("click", function () { setMode(button.dataset.ipamMode, button); });
  });
  document.querySelectorAll("[data-ipam-source]").forEach(function (button) {
    button.addEventListener("click", function () { setSource(button.dataset.ipamSource, button); });
  });
  document.getElementById("ipamActiveFilters").addEventListener("click", function (event) {
    var button = event.target.closest("[data-remove-filter]");
    if (!button) return;
    if (button.dataset.removeFilter === "query") search.value = "";
    if (button.dataset.removeFilter === "firewall") firewallFilter.value = "all";
    if (button.dataset.removeFilter === "vdom") vdomFilter.value = "all";
    if (button.dataset.removeFilter === "source") {
      var allSource = document.querySelector('[data-ipam-source="all"]');
      setSource("all", allSource);
      return;
    }
    renderEntries();
  });
  exportButton.addEventListener("click", exportFilteredCSV);
  document.getElementById("ipamRefreshBtn").addEventListener("click", function () {
    fetch("/ipam/refresh", { method: "POST" }).then(poll).catch(function () {
      loadState.textContent = workspace.dataset.error;
    });
  });

  poll();
})();
