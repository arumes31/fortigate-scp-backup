// ---------------------------------------------------------------------------
// Interactive network topology renderer: D3 tree, Internet → FortiGate →
// interfaces → VLANs / FortiSwitches → ports. Clicking the firewall or a
// switch opens an auto-generated faceplate.
//
// Used by both the authenticated /topology page and the public shared view.
// Configure via window.TOPO_CONFIG before loading:
//   { dataBase: "/topology/data/" }        — id appended from #topoSelect
//   { staticUrl: "/topology/shared/x/data" } — fixed endpoint, no selector
// ---------------------------------------------------------------------------
let topo = null;        // current topology JSON
let topoDevices = null; // device inventory from the graylog_device_data extension (null = unavailable)
let svg, gRoot, zoomBehavior;

// esc() and tt() come from ui.js, which every topology page loads first.

const NODE_STYLE = {
    internet:  { fill: "#0f172a", stroke: "#94a3b8", icon: "☁", label: "#e2e8f0" },
    firewall:  { fill: "#1e293b", stroke: "#f87171", icon: "▣", label: "#fff" },
    intf:      { fill: "#0f172a", stroke: "#3b82f6", icon: "▤", label: "#dbeafe" },
    wan:       { fill: "#1c1917", stroke: "#f59e0b", icon: "☁", label: "#fde68a" },
    vlan:      { fill: "#1e1b4b", stroke: "#8b5cf6", icon: "⌗", label: "#ddd6fe" },
    switch:    { fill: "#064e3b", stroke: "#10b981", icon: "≣", label: "#d1fae5" },
    port:      { fill: "#0f172a", stroke: "#34d399", icon: "•", label: "#a7f3d0" },
    route:     { fill: "#1e293b", stroke: "#38bdf8", icon: "→", label: "#bae6fd" },
    device:    { fill: "#082f36", stroke: "#22d3ee", icon: "◇", label: "#a5f3fc" },
    lan:       { fill: "#111827", stroke: "#6b7280", icon: "▦", label: "#e5e7eb" }
};

// deviceNode maps one Graylog inventory entry to a tree node. Devices whose
// MAC/IP is shared are highlighted (red dashed border) so address conflicts
// and multi-homed devices stand out.
function deviceNode(d) {
    let info = `${tt("topo.device")}\nMAC: ${d.mac}\nIP: ${d.ip || "—"}\nVLAN: ${d.vlan || "—"}\nPort: ${d.port || "—"}`;
    if (d.hostname) info += `\nHost: ${d.hostname}`;
    if (d.switch_id) info += `\nSwitch: ${d.switch_id}`;
    if (d.last_seen) info += `\n${tt("topo.seen")}: ${d.last_seen}`;
    if (d.shared_mac) info += `\n⚠ ${tt("topo.shared_mac")}`;
    if (d.shared_ip) info += `\n⚠ ${tt("topo.shared_ip")}`;
    return {
        name: d.hostname || d.ip || d.mac,
        kind: "device", data: d, info: info,
        badge: d.vlan ? "VLAN " + d.vlan + (d.ip ? " · " + d.ip : "") : (d.ip || d.mac),
        highlight: !!(d.shared_mac || d.shared_ip)
    };
}

// wanSet returns the interface names facing the internet: role wan or device
// of a default route. Single source of truth for the tree and the faceplate.
function wanSet(interfaces, routes) {
    const wan = new Set();
    (interfaces || []).forEach(i => { if ((i.role || "") === "wan") wan.add(i.name); });
    (routes || []).forEach(r => {
        if (!r.device) return;
        if (!r.dst || r.dst.startsWith("0.0.0.0")) wan.add(r.device);
    });
    return wan;
}

// buildTree converts the parsed config into a d3.hierarchy-compatible tree.
function buildTree(data) {
    const interfaces = data.interfaces || [];
    const switches = data.switches || [];
    const routes = data.routes || [];
    const policies = data.policies || [];

    const wanDevices = wanSet(interfaces, routes);

    const policyCount = {};
    policies.forEach(p => {
        [...(p.srcintf || []), ...(p.dstintf || [])].forEach(n => {
            policyCount[n] = (policyCount[n] || 0) + 1;
        });
    });

    const vlansByParent = {};
    const physical = [];
    interfaces.forEach(i => {
        if (i.vlan_id > 0 && i.interface) {
            (vlansByParent[i.interface] = vlansByParent[i.interface] || []).push(i);
        } else {
            physical.push(i);
        }
    });

    const routesByDevice = {};
    routes.forEach(r => (routesByDevice[r.device] = routesByDevice[r.device] || []).push(r));

    const fortilinkHost = physical.find(i => i.name.toLowerCase().includes("fortilink"))?.name || null;

    // Graylog device inventory: assign each device to its switch / VLAN group.
    const devices = topoDevices || [];
    const singleSwitch = switches.length === 1;
    const assigned = new Set();

    function intfNode(i) {
        const isWan = wanDevices.has(i.name);
        const children = [];
        (vlansByParent[i.name] || []).forEach(v => {
            children.push({
                name: v.name, kind: "vlan", data: v,
                info: `VLAN-ID: ${v.vlan_id}\nIP: ${v.ip ? v.ip + "/" + v.mask : "—"}\n${tt("topo.parent")}: ${v.interface}`,
                badge: "VLAN " + v.vlan_id
            });
        });
        if (i.name === fortilinkHost) {
            switches.forEach(sw => children.push(switchNode(sw)));
        }
        (routesByDevice[i.name] || []).forEach(r => {
            children.push({
                name: r.dst && !r.dst.startsWith("0.0.0.0") ? r.dst : "default",
                kind: "route", data: r,
                info: `${tt("topo.route")}\n${tt("topo.route_dst")}: ${r.dst || "0.0.0.0/0 (default)"}\n${tt("topo.gateway")}: ${r.gateway || tt("topo.direct")}\nInterface: ${r.device}`
            });
        });
        return {
            name: i.name, kind: isWan ? "wan" : "intf", data: i,
            info: `${isWan ? "WAN-" : ""}Interface\nIP: ${i.ip ? i.ip + "/" + i.mask : "—"}${i.alias ? "\nAlias: " + i.alias : ""}\nMgmt: ${(i.allowaccess || []).join(", ") || "—"}\nPolicies: ${policyCount[i.name] || 0}`,
            badge: i.alias || null,
            children: children
        };
    }

    function switchNode(sw) {
        const ports = sw.ports || [];
        // Devices seen behind this switch (unattributed devices match when
        // there is only one switch).
        const swDevs = devices.filter(dv => {
            if (assigned.has(dv)) return false;
            if (!dv.switch_id) return singleSwitch;
            return dv.switch_id === sw.switch_id || (sw.name && dv.switch_id === sw.name) || singleSwitch;
        });

        const byVlan = {};
        ports.forEach(p => (byVlan[p.vlan || "—"] = byVlan[p.vlan || "—"] || []).push(p));
        const children = Object.entries(byVlan).map(([vlan, ps]) => {
            const portNames = new Set(ps.map(p => p.name));
            const groupDevs = swDevs.filter(dv => !assigned.has(dv) && (
                (dv.port && portNames.has(dv.port)) ||
                (dv.vlan && (String(dv.vlan) === vlan || vlan === "vlan" + dv.vlan || vlan.endsWith("." + dv.vlan) || vlan.endsWith("_" + dv.vlan)))
            ));
            groupDevs.forEach(dv => assigned.add(dv));
            return {
                name: vlan === "—" ? tt("topo.no_vlan") : "VLAN " + vlan,
                kind: "port", data: { vlan, ports: ps },
                info: `${ps.length} ${tt("topo.ports")}\n${ps.map(p => p.name).join(", ")}` +
                    (groupDevs.length ? `\n${groupDevs.length} ${tt("topo.devices")}` : ""),
                badge: ps.length + " " + tt("topo.ports") + (groupDevs.length ? " · " + groupDevs.length + " " + tt("topo.devices") : ""),
                children: groupDevs.map(deviceNode)
            };
        });
        // Devices that matched the switch but no VLAN/port group.
        const rest = swDevs.filter(dv => !assigned.has(dv));
        rest.forEach(dv => assigned.add(dv));
        children.push(...rest.map(deviceNode));

        const devCount = swDevs.length;
        return {
            name: sw.name || sw.switch_id, kind: "switch", data: sw,
            info: `FortiSwitch\n${tt("topo.serial")}: ${sw.switch_id}\n${tt("topo.ports")}: ${ports.length}` +
                (devCount ? `\n${tt("topo.devices")}: ${devCount}` : ""),
            children: children
        };
    }

    // Sort: WAN interfaces first, then those with children, then the rest.
    const sorted = [...physical].sort((a, b) => {
        const aw = wanDevices.has(a.name) ? 0 : 1, bw = wanDevices.has(b.name) ? 0 : 1;
        if (aw !== bw) return aw - bw;
        const ac = (vlansByParent[a.name] || []).length, bc = (vlansByParent[b.name] || []).length;
        return bc - ac;
    });

    const fwChildren = sorted.map(intfNode);

    // Devices that could not be attributed to any switch get their own group
    // under the firewall so they never disappear.
    const unassigned = devices.filter(dv => !assigned.has(dv));
    if (unassigned.length) {
        fwChildren.push({
            name: tt("topo.devices"), kind: "lan",
            info: `${unassigned.length} ${tt("topo.devices")}`,
            badge: String(unassigned.length),
            children: unassigned.map(deviceNode)
        });
    }

    return {
        name: tt("topo.internet"), kind: "internet", info: tt("topo.external"),
        children: [{
            name: data.fqdn || "FortiGate",
            kind: "firewall", data: data,
            info: `${data.model || "FortiGate"} · FortiOS ${data.version || "?"}\nInterfaces: ${interfaces.length}\nSwitches: ${switches.length}\nPolicies: ${policies.length}` +
                (devices.length ? `\n${tt("topo.devices")}: ${devices.length}` : ""),
            badge: data.model || null,
            children: fwChildren
        }]
    };
}

function renderTree(data) {
    svg = d3.select("#topoSvg");
    svg.selectAll("*").remove();

    const height = 640;

    const root = d3.hierarchy(buildTree(data));
    root.descendants().forEach(d => {
        d._children = d.children;
        // Collapse port/route groups by default to keep the initial view tidy
        // (their devices/details expand on click).
        if (d.data.kind === "port" || d.data.kind === "route") d.children = null;
    });

    gRoot = svg.append("g");
    zoomBehavior = d3.zoom().scaleExtent([0.25, 3]).on("zoom", ev => gRoot.attr("transform", ev.transform));
    svg.call(zoomBehavior);

    const gLinks = gRoot.append("g");
    const gNodes = gRoot.append("g");

    const tree = d3.tree().nodeSize([44, 210]);
    const diagonal = d3.linkHorizontal().x(d => d.y).y(d => d.x);

    let i = 0;
    function update(source) {
        tree(root);
        const nodes = root.descendants();
        const links = root.links();

        nodes.forEach(d => { d.y += 60; });

        const node = gNodes.selectAll("g.node").data(nodes, d => d.id || (d.id = ++i));

        const nodeEnter = node.enter().append("g")
            .attr("class", "node")
            .attr("transform", `translate(${source.y0 || 60},${source.x0 || 0})`)
            .style("cursor", "pointer")
            .on("click", (ev, d) => {
                if (d.data.kind === "firewall" || d.data.kind === "switch") {
                    showFaceplate(d.data);
                    return;
                }
                d.children = d.children ? null : d._children;
                update(d);
            })
            .on("mousemove", (ev, d) => showTip(ev, d.data.name, d.data.info || ""))
            .on("mouseleave", hideTip);

        nodeEnter.each(function(d) {
            const st = NODE_STYLE[d.data.kind] || NODE_STYLE.lan;
            const g = d3.select(this);
            const isMajor = d.data.kind === "firewall" || d.data.kind === "internet" || d.data.kind === "switch";
            const w = isMajor ? 150 : 120, h = isMajor ? 40 : 30;

            // Shared MAC/IP devices get a red dashed border so conflicts stand out.
            const stroke = d.data.highlight ? "#ef4444" : st.stroke;
            const rect = g.append("rect")
                .attr("x", -w / 2).attr("y", -h / 2).attr("width", w).attr("height", h)
                .attr("rx", 7)
                .attr("fill", st.fill)
                .attr("stroke", stroke)
                .attr("stroke-width", d.data.highlight ? 2.4 : (isMajor ? 2.4 : 1.4));
            if (d.data.highlight) rect.attr("stroke-dasharray", "5,3");

            g.append("text")
                .attr("x", -w / 2 + 10).attr("y", 4)
                .attr("fill", st.stroke).attr("font-size", isMajor ? "15px" : "12px")
                .text(st.icon);

            g.append("text")
                .attr("x", -w / 2 + 28).attr("y", d.data.badge ? -1 : 4)
                .attr("fill", st.label)
                .attr("font-size", isMajor ? "11px" : "10px")
                .attr("font-weight", isMajor ? "bold" : "normal")
                .text(d.data.name.length > 16 ? d.data.name.slice(0, 15) + "…" : d.data.name);

            if (d.data.badge) {
                g.append("text")
                    .attr("x", -w / 2 + 28).attr("y", 11)
                    .attr("fill", "rgba(255,255,255,0.45)").attr("font-size", "8.5px")
                    .text(String(d.data.badge).length > 20 ? String(d.data.badge).slice(0, 19) + "…" : d.data.badge);
            }

            if (d._children && d._children.length) {
                g.append("text")
                    .attr("class", "chevron")
                    .attr("x", w / 2 - 14).attr("y", 4)
                    .attr("fill", "rgba(255,255,255,0.5)").attr("font-size", "10px")
                    .text(d.children ? "▾" : "▸");
            }
        });

        const nodeUpdate = nodeEnter.merge(node);
        nodeUpdate.transition().duration(220).attr("transform", d => `translate(${d.y},${d.x})`);
        nodeUpdate.select("text.chevron").text(d => d.children ? "▾" : "▸");

        node.exit().transition().duration(180)
            .attr("transform", `translate(${source.y},${source.x})`)
            .style("opacity", 0).remove();

        const link = gLinks.selectAll("path.link").data(links, d => d.target.id);
        link.enter().append("path")
            .attr("class", "link")
            .attr("fill", "none")
            .attr("stroke", d => (NODE_STYLE[d.target.data.kind] || NODE_STYLE.lan).stroke)
            .attr("stroke-opacity", 0.35)
            .attr("stroke-width", d => d.target.data.kind === "firewall" ? 2.2 : 1.3)
            .attr("d", diagonal)
          .merge(link)
            .transition().duration(220).attr("d", diagonal);
        link.exit().remove();

        nodes.forEach(d => { d.x0 = d.x; d.y0 = d.y; });
    }

    root.x0 = height / 2;
    root.y0 = 60;
    update(root);

    svg.call(zoomBehavior.transform, d3.zoomIdentity.translate(20, height / 2));
}

function resetZoom() {
    if (!svg || !zoomBehavior) return;
    svg.transition().duration(300).call(zoomBehavior.transform, d3.zoomIdentity.translate(20, 320));
}

// ---------------------------------------------------------------------------
// Tooltip
// ---------------------------------------------------------------------------
function showTip(ev, title, body) {
    const tip = document.getElementById("topoTip");
    document.getElementById("topoTipTitle").textContent = title;
    document.getElementById("topoTipBody").textContent = body;
    tip.style.display = "block";
    const card = document.getElementById("topoSvg").parentElement.getBoundingClientRect();
    let x = ev.clientX - card.left + 16, y = ev.clientY - card.top + 12;
    if (x + 330 > card.width) x -= 350;
    tip.style.left = x + "px";
    tip.style.top = y + "px";
}
function hideTip() { document.getElementById("topoTip").style.display = "none"; }

// ---------------------------------------------------------------------------
// Faceplate: auto-generated schematic front panel for firewall / switch.
// ---------------------------------------------------------------------------
function portColor(p) {
    if (p.isWan) return "#f59e0b";
    if (p.isFortilink) return "#10b981";
    if (p.vlans > 0) return "#8b5cf6";
    if (p.hasIP) return "#3b82f6";
    return "#374151";
}

function faceplateSVG(ports, title) {
    const perRow = Math.min(Math.max(Math.ceil(ports.length / 2), 4), 12);
    const cell = 34, gap = 8, padX = 18, padY = 30;
    const rows = Math.ceil(ports.length / perRow);
    const w = padX * 2 + perRow * (cell + gap) - gap;
    const h = padY + rows * (cell + 22) + 14;

    let cells = "";
    ports.forEach((p, idx) => {
        const r = Math.floor(idx / perRow), c = idx % perRow;
        const x = padX + c * (cell + gap), y = padY + r * (cell + 22);
        const col = portColor(p);
        cells += `
        <g class="fp-port" data-idx="${idx}" style="cursor: pointer;">
            <rect x="${x}" y="${y}" width="${cell}" height="${cell}" rx="4" fill="rgba(0,0,0,0.55)" stroke="${col}" stroke-width="1.6"/>
            <rect x="${x + 8}" y="${y + cell - 11}" width="${cell - 16}" height="6" rx="1.5" fill="${col}" opacity="0.85"/>
            <circle cx="${x + 7}" cy="${y + 7}" r="2.4" fill="${p.hasIP || p.vlans > 0 || p.isWan || p.isFortilink ? "#22c55e" : "#4b5563"}"/>
            <text x="${x + cell / 2}" y="${y + cell + 13}" text-anchor="middle" fill="#9ca3af" font-size="8.2" font-family="monospace">${esc(p.label.length > 7 ? p.label.slice(0, 6) + "…" : p.label)}</text>
        </g>`;
    });

    return `<svg viewBox="0 0 ${w} ${h}" style="width: 100%; background: linear-gradient(180deg, #171b22, #0c0f14); border: 1px solid rgba(255,255,255,0.1); border-radius: 8px;">
        <text x="${padX}" y="19" fill="rgba(255,255,255,0.6)" font-size="10.5" font-family="monospace" font-weight="bold">${esc(title)}</text>
        <circle cx="${w - 22}" cy="15" r="3.2" fill="#22c55e"><animate attributeName="opacity" values="1;0.4;1" dur="2.2s" repeatCount="indefinite"/></circle>
        ${cells}
    </svg>`;
}

function faceplateLegend() {
    const items = [["#f59e0b", tt("topo.legend_wan")], ["#10b981", "FortiLink"], ["#8b5cf6", tt("topo.legend_vlan")], ["#3b82f6", tt("topo.legend_ip")], ["#374151", tt("topo.legend_none")]];
    return `<div style="display: flex; flex-wrap: wrap; gap: 12px; margin-top: 12px; font-size: 0.78em;">
        ${items.map(([c, t]) => `<span><span style="display: inline-block; width: 10px; height: 10px; border-radius: 2px; background: ${c}; margin-right: 5px; vertical-align: -1px;"></span>${t}</span>`).join("")}
    </div>`;
}

function portDetailHTML(p) {
    return `<div style="margin-top: 14px; padding: 10px; background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.07); border-radius: 6px; font-size: 0.85em;">
        <strong style="color: #fff;">${esc(p.label)}</strong>
        <pre class="muted" style="margin: 6px 0 0; white-space: pre-wrap; font-size: 0.95em;">${esc(p.detail)}</pre>
    </div>`;
}

function showFaceplate(nodeData) {
    const panel = document.getElementById("facePanel");
    const body = document.getElementById("faceBody");
    let ports = [], title = "", sub = "";

    if (nodeData.kind === "firewall") {
        const d = nodeData.data;
        title = d.fqdn || "FortiGate";
        sub = `${d.model || "FortiGate"} · FortiOS ${d.version || "?"}`;
        const wan = wanSet(d.interfaces, d.routes);
        const vlanCount = {};
        (d.interfaces || []).forEach(i => { if (i.vlan_id > 0 && i.interface) vlanCount[i.interface] = (vlanCount[i.interface] || 0) + 1; });

        ports = (d.interfaces || []).filter(i => !(i.vlan_id > 0)).map(i => ({
            label: i.name,
            hasIP: !!i.ip,
            isWan: wan.has(i.name),
            isFortilink: i.name.toLowerCase().includes("fortilink"),
            vlans: vlanCount[i.name] || 0,
            detail: `IP: ${i.ip ? i.ip + "/" + i.mask : "—"}${i.alias ? "\n" + tt("topo.alias") + ": " + i.alias : ""}\n${tt("topo.role")}: ${i.role || "—"}\nVLANs: ${vlanCount[i.name] || 0}\n${tt("topo.mgmt_access")}: ${(i.allowaccess || []).join(", ") || "—"}`
        }));
    } else if (nodeData.kind === "switch") {
        const sw = nodeData.data;
        title = sw.name || sw.switch_id;
        sub = `FortiSwitch · ${sw.switch_id}`;
        ports = (sw.ports || []).map(p => ({
            label: p.name,
            hasIP: false,
            isWan: false,
            isFortilink: false,
            vlans: p.vlan ? 1 : 0,
            detail: `VLAN: ${p.vlan || "—"}`
        }));
    }

    document.getElementById("faceTitle").textContent = title;
    document.getElementById("faceSub").textContent = sub;
    body.innerHTML = ports.length
        ? faceplateSVG(ports, title) + faceplateLegend() + '<div id="facePortDetail"></div>'
        : `<p class="muted">${tt("topo.no_ports")}</p>`;

    body.querySelectorAll(".fp-port").forEach(el => {
        const p = ports[Number(el.getAttribute("data-idx"))];
        el.addEventListener("click", () => {
            document.getElementById("facePortDetail").innerHTML = portDetailHTML(p);
        });
        el.addEventListener("mouseenter", () => el.style.opacity = "0.75");
        el.addEventListener("mouseleave", () => el.style.opacity = "1");
    });

    panel.style.right = "0";
}
function closeFaceplate() { document.getElementById("facePanel").style.right = "-480px"; }

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------
function topoDataURL() {
    const cfg = window.TOPO_CONFIG || {};
    if (cfg.staticUrl) return cfg.staticUrl;
    const sel = document.getElementById("topoSelect");
    if (!sel || !sel.value) return null;
    return (cfg.dataBase || "/topology/data/") + sel.value;
}

function selectedFwID() {
    const sel = document.getElementById("topoSelect");
    return sel && sel.value ? sel.value : null;
}

// loadDeviceData fetches the Graylog device inventory (extension). Returns
// the device list or null when the extension is disabled/unreachable — the
// topology renders fine without it.
async function loadDeviceData() {
    const cfg = window.TOPO_CONFIG || {};
    const fwid = selectedFwID();
    if (!cfg.devicesBase || !fwid) return null;
    try {
        const resp = await fetch(cfg.devicesBase + "/data/" + fwid, { headers: { "Accept": "application/json" } });
        if (!resp.ok) return null;
        const data = await resp.json();
        const btn = document.getElementById("fetchDevBtn");
        if (btn) btn.style.display = "";
        return data.devices || [];
    } catch (e) {
        return null;
    }
}

// fetchDevicesNow triggers an immediate Graylog fetch for the viewed firewall
// ("fetch device data now" button) and re-renders the tree.
async function fetchDevicesNow() {
    const cfg = window.TOPO_CONFIG || {};
    const fwid = selectedFwID();
    if (!cfg.devicesBase || !fwid) return;
    const meta = document.getElementById("topoMeta");
    const btn = document.getElementById("fetchDevBtn");
    if (btn) btn.disabled = true;
    if (meta) meta.textContent = tt("topo.fetching");
    try {
        const resp = await fetch(cfg.devicesBase + "/refresh/" + fwid, { method: "POST" });
        if (!resp.ok) throw new Error("HTTP " + resp.status);
        const data = await resp.json();
        topoDevices = data.devices || [];
        if (topo && topo.has_config) renderTree(topo);
        if (meta) meta.textContent = topoMetaText() + " · " + tt("topo.dev_updated");
    } catch (e) {
        console.error("device fetch failed", e);
        if (meta) meta.textContent = tt("topo.fetch_failed");
    } finally {
        if (btn) btn.disabled = false;
    }
}

function topoMetaText() {
    if (!topo) return "";
    let text = `${topo.model || ""} · FortiOS ${topo.version || "?"} · ${(topo.interfaces || []).length} Interfaces · ${(topo.switches || []).length} Switches`;
    if (topoDevices && topoDevices.length) {
        text += ` · ${topoDevices.length} ${tt("topo.devices")}`;
    }
    return text;
}

async function loadTopology() {
    const url = topoDataURL();
    if (!url) return;
    closeFaceplate();
    const meta = document.getElementById("topoMeta");
    if (meta) meta.textContent = tt("topo.loading");
    try {
        const [resp, devices] = await Promise.all([
            fetch(url, { headers: { "Accept": "application/json" } }),
            loadDeviceData()
        ]);
        if (!resp.ok) throw new Error("HTTP " + resp.status);
        topo = await resp.json();
        topoDevices = devices;
        if (!topo.has_config) {
            if (meta) meta.textContent = tt("topo.no_backup");
            d3.select("#topoSvg").selectAll("*").remove();
            return;
        }
        if (meta) meta.textContent = topoMetaText();
        renderTree(topo);
    } catch (e) {
        console.error("topology load failed", e);
        if (meta) meta.textContent = tt("topo.load_error");
    }
}

document.addEventListener("DOMContentLoaded", loadTopology);
