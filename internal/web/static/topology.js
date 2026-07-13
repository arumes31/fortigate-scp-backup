// ---------------------------------------------------------------------------
// Interactive network topology renderer: D3 tree, Internet → FortiGate →
// interfaces → VLANs / FortiSwitches → ports. Switch interlinks (MC-LAG ICL,
// persisted ISL trunks, MAC-detected links) are drawn as a dashed overlay
// between switch nodes. Clicking the firewall or a switch opens an
// auto-generated faceplate.
//
// Used by both the authenticated /topology page and the public shared view.
// Configure via window.TOPO_CONFIG before loading:
//   { dataBase: "/topology/data/" }        — id appended from #topoSelect
//   { staticUrl: "/topology/shared/x/data" } — fixed endpoint, no selector
// ---------------------------------------------------------------------------
let topo = null;        // current topology JSON
let topoDevices = null; // device inventory from the graylog_device_data extension (null = unavailable)
let topoStp = [];       // STP/guard/link port states from the extension (switch-controller event logs)
let topoStpIdx = {};    // "switchDisplayName|port" → { role, state, guard, link, last, blocked }
let topoStpEvents = []; // raw port event history (48h) from the extension
let topoStpEventsIdx = {}; // "switchDisplayName|port" → [events, newest first]
let topoMultiMac = [];  // ports with several MACs behind them (extension-computed)
let topoEdges = [];     // switch-edge observations (STP trunk names + LAG legs) from the extension
let topoFaceData = null;      // nodeData of the open faceplate (re-render on filter change)
let topoFaceVlanFilter = null;// active VLAN highlight filter on the faceplate (legend click)
let topoMultiMacIdx = {};  // "switchDisplayName|port" → mac count
let topoVpn = [];       // VPN tunnel up/down states from the extension
let topoVpnIdx = {};    // tunnel name → { status, remip, type }
let topoHaDetail = "";  // newest HA event summary from the extension
let topoFwHealth = "";  // live CPU/mem/sessions/uptime + HA roles (SSH diagnostics)
let topoSwitchHealth = []; // per-switch fan/congestion/tcn/poe health (SSH)
let topoLiveRoutes = [];   // live routing egress summary: device → {routes, default} (SSH)
let topoSdwan = [];        // per-member SD-WAN SLA: {member, state, loss, latency, jitter} (SSH)
let topoThroughput = [];   // per-interface live throughput {iface, rx_mbps, tx_mbps} (SSH)
let topoDiagStatus = null; // last SSH collection status {last_run, switches, duration_ms, static}
let topoLoadSeq = 0;    // increases per loadTopology() call; stale responses are discarded
let topoInterlinks = [];// switch interlinks of the current tree (config-derived + MAC-detected)
let topoRootNode = null;// d3 hierarchy root of the current render (search/locate)
let topoUpdate = null;  // update(source) closure of the current render
let svg, gRoot, zoomBehavior;

// View filters (toolbar checkboxes); toggling re-renders the tree.
let topoFilters = { devices: true, routes: true, vlans: true, edge: true };
function setTopoFilter(key, val) {
    topoFilters[key] = val;
    if (topo && topo.has_config) renderTree(topo);
}

// esc() and tt() come from ui.js, which every topology page loads first.

const NODE_STYLE = {
    internet:  { fill: "#0f172a", stroke: "#94a3b8", icon: "☁", label: "#e2e8f0" },
    firewall:  { fill: "#1e293b", stroke: "#f87171", icon: "▣", label: "#fff" },
    intf:      { fill: "#0f172a", stroke: "#3b82f6", icon: "▤", label: "#dbeafe" },
    wan:       { fill: "#1c1917", stroke: "#f59e0b", icon: "☁", label: "#fde68a" },
    vlan:      { fill: "#1e1b4b", stroke: "#8b5cf6", icon: "⌗", label: "#ddd6fe" },
    switch:    { fill: "#064e3b", stroke: "#10b981", icon: "≣", label: "#d1fae5" },
    mclag:     { fill: "#042f2e", stroke: "#14b8a6", icon: "⇄", label: "#ccfbf1" },
    vlangroup: { fill: "#1e1b4b", stroke: "#8b5cf6", icon: "⌗", label: "#ddd6fe" },
    zone:      { fill: "#111827", stroke: "#94a3b8", icon: "▣", label: "#e5e7eb" },
    vpn:       { fill: "#2a1215", stroke: "#fb7185", icon: "⚿", label: "#fecdd3" },
    vpngroup:  { fill: "#2a1215", stroke: "#fb7185", icon: "⚿", label: "#fecdd3" },
    apgroup:   { fill: "#082436", stroke: "#38bdf8", icon: "❊", label: "#bae6fd" },
    ap:        { fill: "#082436", stroke: "#38bdf8", icon: "❊", label: "#bae6fd" },
    ssid:      { fill: "#1e1b4b", stroke: "#a78bfa", icon: "≋", label: "#ddd6fe" },
    port:      { fill: "#0f172a", stroke: "#34d399", icon: "•", label: "#a7f3d0" },
    route:     { fill: "#1e293b", stroke: "#38bdf8", icon: "→", label: "#bae6fd" },
    device:    { fill: "#082f36", stroke: "#22d3ee", icon: "◇", label: "#a5f3fc" },
    lan:       { fill: "#111827", stroke: "#6b7280", icon: "▦", label: "#e5e7eb" }
};

// isStaleDevice reports whether a device's last_seen is older than 24h
// (unparsable timestamps count as fresh).
function isStaleDevice(d) {
    if (!d.last_seen) return false;
    const t = Date.parse(String(d.last_seen).replace(" ", "T"));
    return !isNaN(t) && (Date.now() - t) > 24 * 3600 * 1000;
}

// deviceNode maps one Graylog inventory entry to a tree node. Devices whose
// MAC/IP is shared are highlighted (red dashed border) so address conflicts
// and multi-homed devices stand out; stale devices (not seen for >24h) are
// faded.
function deviceNode(d) {
    const stale = isStaleDevice(d);
    let info = `${tt("topo.device")}\nMAC: ${d.mac}\nIP: ${d.ip || "—"}\nVLAN: ${d.vlan || "—"}\nPort: ${d.port || "—"}`;
    if (d.hostname) info += `\nHost: ${d.hostname}`;
    if (d.switch_id) info += `\nSwitch: ${d.switch_id}`;
    // Endpoint fingerprint (device-identification) and wireless association.
    const fp = [d.devtype, d.osname && (d.osname + (d.osversion ? " " + d.osversion : "")), d.vendor].filter(Boolean).join(" · ");
    if (fp) info += `\n${fp}`;
    if (d.ap) info += `\n${tt("topo.ap")}: ${d.ap}${d.ssid ? " · " + d.ssid : ""}${d.signal ? " · " + d.signal + " dBm" : ""}`;
    if (d.first_seen) info += `\n${tt("topo.first_seen")}: ${d.first_seen}`;
    if (d.last_seen) info += `\n${tt("topo.seen")}: ${d.last_seen}`;
    if (stale) info += `\n⏱ ${tt("topo.stale")}`;
    if (d.shared_mac) info += `\n⚠ ${tt("topo.shared_mac")}`;
    if (d.shared_ip) info += `\n⚠ ${tt("topo.shared_ip")}`;
    return {
        name: d.hostname || d.ip || d.mac,
        kind: "device", data: d, info: info,
        badge: d.vlan ? "VLAN " + d.vlan + (d.ip ? " · " + d.ip : "") : (d.ip || d.mac),
        highlight: !!(d.shared_mac || d.shared_ip),
        faded: stale
    };
}

// fwLabel renders "model · FortiOS version", omitting whatever is unknown —
// the public shared endpoint redacts the firmware version on purpose, so it
// must not render as "FortiOS ?".
function fwLabel(d) {
    let s = d.model || "FortiGate";
    if (d.version) s += " · FortiOS " + d.version;
    return s;
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

// swName is the display/node name of a switch (matches the Go side's
// switchDisplayName so server-derived interlinks resolve to tree nodes).
function swName(sw) { return sw.name || sw.switch_id; }

// switchIdMatch reports whether a device/log switch reference identifies this
// switch. A log source may key a switch by its serial, its config switch-id or
// its friendly name, and casing can differ between the config backup and the
// Graylog fields, so the exact comparison is case-insensitive. When no identity
// matches exactly, a shared serial suffix (≥8 chars) still links a bare serial
// to a switch the config keyed/named differently — the same tolerance the
// trunk-peer resolver (switchByRef) uses. Without this a device carrying a
// serial never attaches to a switch keyed by name (or vice versa).
function switchIdMatch(sw, ref) {
    if (!ref || !sw) return false;
    const r = String(ref).trim().toUpperCase();
    if (!r) return false;
    for (const id of [sw.switch_id, sw.name, sw.serial]) {
        if (id && String(id).trim().toUpperCase() === r) return true;
    }
    // Serial-suffix fallback: require BOTH strings to be ≥8 chars so a short
    // reference (e.g. a bare port or a 3-char tail) cannot false-match a
    // serial's ending. This mirrors the ≥8-char fragment guard the trunk-peer
    // resolver uses.
    const ser = String(sw.serial || sw.switch_id || "").trim().toUpperCase();
    return ser.length >= 8 && r.length >= 8 && (ser.endsWith(r) || r.endsWith(ser));
}

// resolveSwitchName maps an inventory switch reference (name, switch-id or
// serial, depending on the log source) to the tree node name.
function resolveSwitchName(switches, id) {
    if (!id) return null;
    const sw = switches.find(s => switchIdMatch(s, id));
    return sw ? swName(sw) : null;
}

// addInterlink merges a link into the list: one edge per switch pair, port
// lists unioned (an ICL detected from config AND via MAC stays one edge).
function addInterlink(links, l) {
    const ex = links.find(e => (e.from === l.from && e.to === l.to) || (e.from === l.to && e.to === l.from));
    if (!ex) { links.push(l); return; }
    if (l.parent && !ex.parent) ex.parent = l.parent; // uplink direction survives merging
    if (l.blocked) ex.blocked = true;                 // a block on either end blocks the redundant link
    if (l.note && !ex.note) ex.note = l.note;          // ICL split-brain / health note survives merging
    const merge = (arr, add) => { (add || []).forEach(p => { if (!arr.includes(p)) arr.push(p); }); };
    ex.from_ports = ex.from_ports || [];
    ex.to_ports = ex.to_ports || [];
    if (ex.from === l.from) {
        merge(ex.from_ports, l.from_ports);
        merge(ex.to_ports, l.to_ports);
    } else {
        merge(ex.from_ports, l.to_ports);
        merge(ex.to_ports, l.from_ports);
    }
}

// Live SSH lookups by interface/member/tunnel name.
function sdwanOf(name) { return name ? topoSdwan.find(s => s.member === name) : null; }
function throughputOf(name) { return name ? topoThroughput.find(t => t.iface === name) : null; }
// sdwanLabel renders a member's SLA compactly, flagging loss/dead.
function sdwanLabel(s) {
    if (!s) return "";
    const parts = [s.state === "dead" ? "⚠ dead" : "alive"];
    if (s.loss) parts.push("loss " + s.loss + "%");
    if (s.latency) parts.push(Math.round(s.latency) + "ms");
    return parts.join(" · ");
}

function interlinkKindLabel(kind) {
    if (kind === "mclag-icl") return tt("topo.mclag_icl");
    if (kind === "isl") return tt("topo.isl");
    return tt("topo.link_detected");
}

// taggedVlans renders a port's tagged-VLAN set ("" when the port carries
// none): the explicit allowed-vlans list, or "all" for allowed-vlans-all.
function taggedVlans(p) {
    if (p.allowed_vlans_all) return tt("topo.all_vlans");
    return (p.allowed_vlans || []).join(", ");
}

// vlanColor hashes a VLAN name to a stable hue so the same VLAN gets the
// same color on every switch faceplate and tree node.
function vlanColor(vlan) {
    if (!vlan) return "#8b5cf6";
    let h = 0;
    for (let i = 0; i < vlan.length; i++) h = (h * 31 + vlan.charCodeAt(i)) >>> 0;
    return `hsl(${(h * 137.508) % 360}, 55%, 58%)`;
}

// groupColor hashes a switch-group name to a stable colour, deeper and more
// saturated than the VLAN palette so the switch-group overlay reads as a
// separate dimension from the VLAN link colours.
function groupColor(name) {
    if (!name) return null;
    let h = 0;
    for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) >>> 0;
    return `hsl(${(h * 47) % 360}, 68%, 47%)`;
}

// stpLabel renders one port's STP/guard status ("designated · forwarding",
// "⃠ bpdu-guard", …).
function stpLabel(st) {
    if (!st) return "";
    const parts = [st.role, st.state].filter(Boolean);
    if (st.guard) parts.push(st.guard);
    return (st.blocked ? "⃠ " : "") + parts.join(" · ");
}

// stpBlockedPorts lists an interlink's endpoint ports currently blocked
// (STP discarding/alternate, BPDU/loop/root guard).
function stpBlockedPorts(l) {
    const out = [];
    const scan = (sw, ports) => (ports || []).forEach(p => {
        const st = topoStpIdx[sw + "|" + p];
        if (st && st.blocked) out.push(`${sw} ${p}: ${st.guard || st.state || st.role}`);
    });
    scan(l.from, l.from_ports);
    scan(l.to, l.to_ports);
    return out;
}

function interlinkTip(l) {
    let s = `${tt("topo.interlink")} · ${interlinkKindLabel(l.kind)}\n` +
        `${l.from}: ${(l.from_ports || []).join(", ") || "—"}\n` +
        `${l.to}: ${(l.to_ports || []).join(", ") || "—"}`;
    const blocked = stpBlockedPorts(l);
    if (blocked.length) s += `\n⃠ ${tt("topo.stp_blocked")}: ${blocked.join("; ")}`;
    if (l.note) s += `\n${l.note}`; // MC-LAG ICL health (split-brain / keepalive drops)
    return s;
}

// buildTree converts the parsed config into a d3.hierarchy-compatible tree.
function buildTree(data) {
    const interfaces = data.interfaces || [];
    const switches = data.switches || [];
    const routes = data.routes || [];
    const policies = data.policies || [];

    const wanDevices = wanSet(interfaces, routes);

    // Zones: interface → zone name.
    const zoneOf = {};
    (data.zones || []).forEach(z => (z.interfaces || []).forEach(n => { zoneOf[n] = z.name; }));

    // DHCP servers: interface → server.
    const dhcpByIntf = {};
    (data.dhcp_servers || []).forEach(d => { dhcpByIntf[d.interface] = d; });

    // SD-WAN: interface → membership (zone, gateway, health checks).
    const sdwanByIntf = {};
    if (data.sdwan) {
        (data.sdwan.members || []).forEach(m => {
            sdwanByIntf[m.interface] = { seq: m.seq, zone: m.zone || "virtual-wan-link", gateway: m.gateway, checks: [] };
        });
        (data.sdwan.health_checks || []).forEach(hc => (hc.members || []).forEach(seq => {
            Object.values(sdwanByIntf).forEach(e => { if (e.seq === seq) e.checks.push(hc.name); });
        }));
        // Underlay SD-WAN members (with a gateway) face the internet.
        Object.entries(sdwanByIntf).forEach(([n, e]) => { if (e.gateway) wanDevices.add(n); });
    }

    // IPsec tunnels: by tunnel name (tunnel interfaces carry the same name).
    const vpnByName = {};
    (data.vpns || []).forEach(v => { vpnByName[v.name] = v; });

    const ssidByName = {};
    (data.ssids || []).forEach(s => { ssidByName[s.name] = s; });

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

    // FortiLink host: prefer the interface the config itself declares (managed-
    // switch `fsw-wan1-peer` / switch-group `fortilink`) — on many models the
    // FortiLink interface is a plain port name like "a" or "flink", so the
    // name heuristic alone misses it and the whole switch stack vanishes.
    const fortilinkNames = new Set();
    switches.forEach(sw => { if (sw.fortilink) fortilinkNames.add(sw.fortilink); });
    (data.switch_groups || []).forEach(g => { if (g.fortilink) fortilinkNames.add(g.fortilink); });
    const fortilinkHost =
        physical.find(i => fortilinkNames.has(i.name))?.name ||
        physical.find(i => i.name.toLowerCase().includes("fortilink"))?.name ||
        null;
    let switchesHosted = false; // set when an interface node adopts the stack

    // Graylog device inventory: assign each device to its switch / VLAN group.
    const devices = topoFilters.devices ? (topoDevices || []) : [];
    const singleSwitch = switches.length === 1;
    const assigned = new Set();

    // Switch interlinks: config-derived (MC-LAG ICL, persisted ISL trunks)
    // plus links detected by matching inventory MACs against the switch-port
    // MACs from the config — a "device" whose MAC belongs to another switch's
    // port is that switch, wired to the port it was seen on. Port MACs are
    // sequential per switch, so MACs falling into a switch's port-MAC range
    // (± a small margin for the base/mgmt MAC) also count as that switch.
    const interlinks = (data.switch_links || []).map(l => ({ ...l }));
    const macNum = m => {
        const hex = String(m || "").toLowerCase().replace(/[^0-9a-f]/g, "");
        return hex.length === 12 ? parseInt(hex, 16) : NaN;
    };
    const portMacOwner = {};
    const macRanges = []; // { sw, min, max }
    switches.forEach(sw => {
        let min = Infinity, max = -Infinity;
        (sw.ports || []).forEach(p => {
            if (!p.mac) return;
            portMacOwner[p.mac.toLowerCase()] = { sw: swName(sw), port: p.name };
            const n = macNum(p.mac);
            if (!isNaN(n)) { min = Math.min(min, n); max = Math.max(max, n); }
        });
        if (min <= max) macRanges.push({ sw: swName(sw), min: min - 8, max: max + 8 });
    });
    const macOwner = mac => {
        const exact = portMacOwner[mac];
        if (exact) return exact;
        const n = macNum(mac);
        if (isNaN(n)) return null;
        const r = macRanges.find(r => n >= r.min && n <= r.max);
        return r ? { sw: r.sw, port: null } : null;
    };
    devices.forEach(dv => {
        const own = macOwner((dv.mac || "").toLowerCase());
        if (!own) return;
        const from = resolveSwitchName(switches, dv.switch_id);
        if (from === own.sw) {
            assigned.add(dv); // a switch's own MAC, not a client device
            return;
        }
        if (from && dv.port) {
            addInterlink(interlinks, {
                from: from, from_ports: [dv.port],
                to: own.sw, to_ports: own.port ? [own.port] : [],
                kind: "detected"
            });
            assigned.add(dv); // interlink endpoint, not a client device
        }
        // Otherwise the record is unattributable — leave it unassigned so it
        // still renders as a device instead of silently disappearing.
    });
    // Graylog switch-edge observations (STP/link events): FortiSwitch names
    // auto-ISL trunks after the PEER's serial fragment, so the trunk name
    // resolves the neighbor, and an STP root role marks the trunk as the
    // owner's UPLINK — orienting the tree even between same-tier switches.
    const trunkPeer = ref => {
        if (!ref || /^port\d+$/i.test(ref) || /^_FlInK/i.test(ref)) return null; // FortiLink LAG/ICL: peer not encoded
        const frag = ref.replace(/-\d+$/, "").toUpperCase();
        if (frag.length < 8) return null;
        const sw = switches.find(x => (x.serial || x.switch_id || "").toUpperCase().endsWith(frag));
        return sw ? swName(sw) : null;
    };
    // Auto-ISL trunk member ports aren't available over SSH (the `trunk` command
    // is blocked for a read-only admin), but the config backup parses them: the
    // FortiSwitch persists the auto-ISL/MLAG trunk under the same name shown in
    // the STP output, so join by trunk name to fill the exact cabled member ports.
    const trunkMembers = (swDisp, trunkName) => {
        const sw = switches.find(s => swName(s) === swDisp);
        const tp = sw && (sw.ports || []).find(p => p.name === trunkName && (p.members || []).length);
        return tp ? tp.members : [];
    };
    const iclOwners = {}; // ICL trunk name → owners; exactly two = MC-LAG peer pair
    (topoEdges || []).forEach(g => {
        const from = resolveSwitchName(switches, g.switch_sn) || resolveSwitchName(switches, g.switch_name);
        if (!from) return;
        if (/_ICL\d*_?$/i.test(g.trunk)) {
            const iclPorts = (g.ports && g.ports.length) ? g.ports : trunkMembers(from, g.trunk);
            (iclOwners[g.trunk] = iclOwners[g.trunk] || []).push({ from: from, ports: iclPorts, note: g.note || "" });
            return;
        }
        const to = trunkPeer(g.trunk);
        if (!to || to === from) return;
        const members = (g.ports && g.ports.length) ? g.ports : trunkMembers(from, g.trunk);
        addInterlink(interlinks, {
            from: from, from_ports: members.length ? members : [g.trunk],
            to: to, to_ports: [],
            kind: "stp",
            parent: g.role === "root" ? to : null, // my root port points AT the upstream switch
            // A trunk discarding/alternate on either end is a redundant path STP
            // blocks — render it as blocked, and never orient the tree from it
            // (parent stays null since a blocked edge is never the root port).
            blocked: (g.state || "").toLowerCase() === "discarding" || g.role === "alternate" || g.role === "backup"
        });
    });
    Object.values(iclOwners).forEach(owners => {
        if (owners.length !== 2 || owners[0].from === owners[1].from) return;
        const iclNote = owners[0].note || owners[1].note || "";
        addInterlink(interlinks, {
            from: owners[0].from, from_ports: owners[0].ports,
            to: owners[1].from, to_ports: owners[1].ports,
            kind: "mclag-icl", note: iclNote,
            blocked: /split-brain/i.test(iclNote) // split-brain = degraded MC-LAG, flag red
        });
    });
    topoInterlinks = interlinks;

    // Ports that carry a switch↔switch link (interlink endpoints + trunk-type
    // ports). Any other port is an edge/access port facing hosts, where a
    // transient STP discarding/blocking state is normal port-transition noise
    // rather than a loop being broken (see blocked below).
    const interSwitchPorts = new Set();
    (interlinks || []).forEach(l => {
        (l.from_ports || []).forEach(p => interSwitchPorts.add(l.from + "|" + p));
        (l.to_ports || []).forEach(p => interSwitchPorts.add(l.to + "|" + p));
    });
    switches.forEach(sw => (sw.ports || []).forEach(p => {
        if (p.type === "trunk") interSwitchPorts.add(swName(sw) + "|" + p.name);
    }));

    // STP/guard/link overlay: latest status per port, keyed by the switch's
    // tree node name. A port counts as blocked when a BPDU/loop/root guard
    // triggered, or STP put an inter-switch link out of forwarding
    // (alternate/backup/disabled role, or discarding/blocking state). The
    // discarding/blocking STATE is ignored on edge (access) ports, where it is
    // not a loop event worth flagging.
    const dispName = ref => resolveSwitchName(switches, ref) || ref;
    topoStpIdx = {};
    (topoStp || []).forEach(s => {
        const disp = resolveSwitchName(switches, s.switch_name) ||
            resolveSwitchName(switches, s.serial) || s.switch_name;
        const state = (s.state || "").toLowerCase();
        const role = (s.role || "").toLowerCase();
        const isEdge = !interSwitchPorts.has(disp + "|" + s.port);
        topoStpIdx[disp + "|" + s.port] = {
            role: s.role, state: s.state, guard: s.guard, link: s.link, last: s.last_change,
            // Live SSH-diagnostics enrichment (empty when only Graylog is the source).
            dot1x: s.dot1x, media: s.media, speed: s.speed, admin: s.admin,
            poe: s.poe, optic: s.optic, health: s.health, neighbor: s.neighbor,
            blocked: !!s.guard || role === "alternate" || role === "backup" || role === "disabled" ||
                (!isEdge && (state === "discarding" || state === "blocking"))
        };
    });
    // Port event history (48h), newest first per port.
    topoStpEventsIdx = {};
    (topoStpEvents || []).forEach(ev => {
        const key = dispName(ev.switch_name) + "|" + ev.port;
        (topoStpEventsIdx[key] = topoStpEventsIdx[key] || []).push(ev);
    });
    // Multi-MAC ports (mini-switch/AP suspected), by display name and raw id.
    topoMultiMacIdx = {};
    (topoMultiMac || []).forEach(m => {
        topoMultiMacIdx[dispName(m.switch_id) + "|" + m.port] = m.mac_count;
    });
    // VPN tunnel up/down states, keyed by tunnel name for vpnNode() lookup.
    topoVpnIdx = {};
    (topoVpn || []).forEach(v => { topoVpnIdx[v.name] = v; });

    const mclagNames = new Set();
    interlinks.filter(l => l.kind === "mclag-icl").forEach(l => { mclagNames.add(l.from); mclagNames.add(l.to); });

    // Switch-group membership (config switch-controller switch-group).
    // Switch-group membership (config switch-controller switch-group). Members
    // are managed-switch identifiers (serial or config key depending on the
    // backup), so resolve each to the switch's display name — otherwise a
    // serial-keyed member never matches the friendly-named tree node.
    const swGroupOf = {};
    (data.switch_groups || []).forEach(g => (g.members || []).forEach(m => {
        swGroupOf[resolveSwitchName(switches, m) || m] = g.name;
    }));

    // Tier rank from the serial prefix digit (S5xx aggregation → S4/2xx access
    // → S1xx edge) so the stack reads top-down like the physical layout.
    function switchTierRank(sw) {
        const m = /^S(\d)/i.exec(sw.serial || sw.switch_id || "");
        return m ? -Number(m[1]) : 0;
    }
    function isEdgeSwitch(sw) { return switchTierRank(sw) === -1; }

    // Uplink nesting: a detected/persisted interlink between different tiers
    // makes the lower-tier switch a child of the higher-tier one, so the
    // stack becomes real tree depth (core → access → edge). Strict tier
    // ordering keeps the relation acyclic; ICL peers stay siblings.
    const swByName = {};
    switches.forEach(sw => { swByName[swName(sw)] = sw; });
    const swKidsOf = {};   // parent name → [child switch]
    const nestedSw = new Set();
    interlinks.forEach(l => {
        if (l.kind === "mclag-icl") return;
        const a = swByName[l.from], b = swByName[l.to];
        if (!a || !b) return;
        let parent, child;
        if (l.parent === l.from || l.parent === l.to) {
            // STP root role told us the uplink direction — trust it, even
            // between same-tier switches (access→access chains).
            parent = l.parent;
            child = l.parent === l.from ? l.to : l.from;
        } else {
            const ra = switchTierRank(a), rb = switchTierRank(b);
            if (ra === rb) return;
            parent = ra < rb ? l.from : l.to;
            child = ra < rb ? l.to : l.from;
        }
        if (nestedSw.has(child)) return; // first uplink wins
        nestedSw.add(child);
        (swKidsOf[parent] = swKidsOf[parent] || []).push(swByName[child]);
    });

    const sortSwitches = list => [...list].sort((a, b) =>
        switchTierRank(a) - switchTierRank(b) ||
        (swGroupOf[swName(a)] || "").localeCompare(swGroupOf[swName(b)] || "") ||
        swName(a).localeCompare(swName(b)));

    // pushSwitchNodes appends the FortiLink stack: the MC-LAG peer group
    // first (as one group node), then the remaining top-level switches by
    // tier; switches with a detected uplink nest under their upstream switch.
    function pushSwitchNodes(children) {
        const roots = sortSwitches(switches.filter(sw => !nestedSw.has(swName(sw))));
        const visible = roots.filter(sw => topoFilters.edge || !isEdgeSwitch(sw));
        const mclag = visible.filter(sw => mclagNames.has(swName(sw)));
        const rest = visible.filter(sw => !mclagNames.has(swName(sw)));
        if (mclag.length) {
            children.push({
                name: tt("topo.mclag_group"), kind: "mclag",
                info: `${tt("topo.mclag_info")}\n${mclag.map(swName).join(", ")}`,
                badge: mclag.map(swName).join(" · "),
                children: mclag.map(switchNode)
            });
        }
        rest.forEach(sw => children.push(switchNode(sw)));
    }

    // dhcpLine renders an interface's DHCP server as one info line ("" when
    // none is bound to it).
    function dhcpLine(name) {
        const dh = dhcpByIntf[name];
        if (!dh) return "";
        let s = `\nDHCP: ${(dh.ranges || []).join(", ") || "—"}`;
        if (dh.gateway) s += ` (GW ${dh.gateway})`;
        return s;
    }
    const nacFeature = f => f === "nac" || f === "nac-segment";

    // apGroupNode renders the managed FortiAPs with their SSIDs.
    function apGroupNode() {
        const aps = data.aps || [];
        if (!aps.length) return null;
        return {
            name: tt("topo.aps"), kind: "apgroup",
            info: `${aps.length} FortiAP`,
            badge: String(aps.length),
            children: aps.map(ap => ({
                name: ap.name || ap.wtp_id, kind: "ap", data: ap,
                info: `FortiAP${ap.platform ? " " + ap.platform : ""}\n${tt("topo.serial")}: ${ap.wtp_id}` +
                    (ap.profile ? `\n${tt("topo.profile")}: ${ap.profile}` : ""),
                badge: ap.platform ? "FAP-" + ap.platform : null,
                children: (ap.ssids || []).map(name => {
                    const s = ssidByName[name] || { name: name, ssid: name };
                    return {
                        name: s.ssid || s.name, kind: "ssid", data: s,
                        info: `SSID\n${tt("topo.ssid_name")}: ${s.ssid || s.name}` +
                            (s.vlan_id ? `\nVLAN-ID: ${s.vlan_id}` : "") +
                            (s.security ? `\n${tt("topo.security")}: ${s.security}` : ""),
                        badge: s.vlan_id ? "VLAN " + s.vlan_id : null
                    };
                })
            }))
        };
    }

    function intfNode(i) {
        const isWan = wanDevices.has(i.name);
        const sdw = sdwanByIntf[i.name];
        const isDown = i.status === "down";
        const children = [];
        if (i.name === fortilinkHost) {
            switchesHosted = true;
            pushSwitchNodes(children);
            const apg = apGroupNode();
            if (apg) children.push(apg);
        }
        const vlanKids = !topoFilters.vlans ? [] : (vlansByParent[i.name] || []).map(v => ({
            name: v.name, kind: "vlan", data: v,
            info: `VLAN-ID: ${v.vlan_id}\nIP: ${v.ip ? v.ip + "/" + v.mask : "—"}\n${tt("topo.parent")}: ${v.interface}` +
                dhcpLine(v.name) +
                (nacFeature(v.switch_feature) ? `\n☑ ${tt("topo.nac")}` : ""),
            badge: "VLAN " + v.vlan_id + (nacFeature(v.switch_feature) ? " · NAC" : ""),
            strokeColor: vlanColor(v.name),
            faded: v.status === "down"
        }));
        // Many VLANs (typical on the FortiLink interface) collapse into one
        // group node so the switch stack stays readable.
        if (vlanKids.length > 8) {
            children.push({
                name: "VLANs", kind: "vlangroup",
                info: vlanKids.length + " VLANs",
                badge: String(vlanKids.length),
                children: vlanKids
            });
        } else {
            children.push(...vlanKids);
        }
        if (topoFilters.routes) {
            (routesByDevice[i.name] || []).forEach(r => {
                children.push({
                    name: r.dst && !r.dst.startsWith("0.0.0.0") ? r.dst : "default",
                    kind: "route", data: r,
                    info: `${tt("topo.route")}\n${tt("topo.route_dst")}: ${r.dst || "0.0.0.0/0 (default)"}\n${tt("topo.gateway")}: ${r.gateway || tt("topo.direct")}\nInterface: ${r.device}`
                });
            });
        }
        let info = `${isWan ? "WAN-" : ""}Interface\nIP: ${i.ip ? i.ip + "/" + i.mask : "—"}` +
            `${i.alias ? "\nAlias: " + i.alias : ""}` +
            (isDown ? `\n⏻ ${tt("topo.status_down")}` : "") +
            ((i.members || []).length ? `\nPorts: ${i.members.join(", ")}` : "") +
            (sdw ? `\nSD-WAN: ${sdw.zone}${sdw.gateway ? " · GW " + sdw.gateway : ""}` : "") +
            (sdw && sdw.checks.length ? `\n${tt("topo.checks")}: ${sdw.checks.join(", ")}` : "") +
            (nacFeature(i.switch_feature) ? `\n☑ ${tt("topo.nac")}` : "") +
            dhcpLine(i.name) +
            `\nMgmt: ${(i.allowaccess || []).join(", ") || "—"}\nPolicies: ${policyCount[i.name] || 0}`;
        return {
            name: i.name, kind: isWan ? "wan" : "intf", data: i,
            info: info,
            badge: sdw ? "SD-WAN " + sdw.zone : (i.alias || null),
            faded: isDown,
            children: children
        };
    }

    // vpnNode renders an IPsec tunnel; ctx carries the tunnel's interface
    // entry and children when the tunnel exists as an interface.
    function vpnNode(t, ctx) {
        const i = ctx && ctx.intf;
        // Live tunnel state from the extension's VPN logs (up/down), matched by
        // tunnel name; falls back to no annotation when nothing was logged.
        const vs = topoVpnIdx[t.name];
        const up = vs && vs.status === "up", down = vs && vs.status === "down";
        // Live routing (SSH): how many installed routes actually egress this tunnel.
        const lr = topoLiveRoutes.find(r => r.device === t.name);
        // Live SD-WAN SLA + throughput (SSH), matched by the tunnel/member name.
        const sla = sdwanOf(t.name) || sdwanOf(t.interface);
        const tp = throughputOf(t.name) || throughputOf(t.interface);
        return {
            name: t.name, kind: "vpn", data: i ? { ...t, ...i } : t,
            info: `IPsec VPN\n${tt("topo.remote_gw")}: ${t.remote_gw || "—"}` +
                (t.ike_version ? `\nIKE v${t.ike_version}` : "") +
                `\n${tt("topo.egress")}: ${t.interface || "—"}` +
                (i && i.ip ? `\nIP: ${i.ip}/${i.mask}` : "") +
                (vs ? `\nStatus: ${vs.status}${vs.remip ? " · " + vs.remip : ""}` : "") +
                (sla ? `\n${tt("topo.sdwan_sla")}: ${sdwanLabel(sla)}` : "") +
                (tp ? `\n${tt("topo.throughput")}: ↓${tp.rx_mbps.toFixed(1)} ↑${tp.tx_mbps.toFixed(1)} Mbps` : "") +
                (lr ? `\n${tt("topo.live_routes")}: ${lr.routes}` : "") +
                `\nPolicies: ${policyCount[t.name] || 0}`,
            badge: (up ? "▲ " : down ? "▼ " : "") + ((sla && (sla.state === "dead" || sla.loss >= 5)) ? "⚠ " : "") + (lr ? lr.routes + "R " : "") + (t.remote_gw || (vs && vs.remip) || "VPN"),
            strokeColor: up ? "#10b981" : down ? "#ef4444" : null,
            faded: down,
            children: (ctx && ctx.children) || []
        };
    }

    // vpnBranches builds the Internet-side VPN limbs: tunnels terminate at
    // remote peers across the internet, so they hang off the Internet node —
    // grouped by their zone when zoned, one "IPsec VPN" group otherwise.
    function vpnBranches() {
        const vpns = data.vpns || [];
        if (!vpns.length) return [];
        const mkVpn = t => {
            const i = interfaces.find(x => x.name === t.name) || null;
            const kids = [];
            if (topoFilters.routes) {
                (routesByDevice[t.name] || []).forEach(r => {
                    kids.push({
                        name: r.dst && !r.dst.startsWith("0.0.0.0") ? r.dst : "default",
                        kind: "route", data: r,
                        info: `${tt("topo.route")}\n${tt("topo.route_dst")}: ${r.dst || "0.0.0.0/0 (default)"}\n${tt("topo.gateway")}: ${r.gateway || tt("topo.direct")}\nInterface: ${r.device}`
                    });
                });
            }
            return vpnNode(t, { intf: i, children: kids });
        };
        const byZone = {};
        const unzoned = [];
        vpns.forEach(t => {
            const zn = zoneOf[t.name];
            if (zn) (byZone[zn] = byZone[zn] || []).push(t);
            else unzoned.push(t);
        });
        const branches = Object.entries(byZone).map(([zn, list]) => ({
            name: zn, kind: "vpngroup",
            info: `${tt("topo.zone")} · IPsec VPN\n${list.length} Tunnel`,
            badge: list.length + " VPN",
            children: list.map(mkVpn)
        }));
        if (unzoned.length > 3) {
            branches.push({
                name: "IPsec VPN", kind: "vpngroup",
                info: `${unzoned.length} IPsec VPN`,
                badge: String(unzoned.length),
                children: unzoned.map(mkVpn)
            });
        } else {
            branches.push(...unzoned.map(mkVpn));
        }
        return branches;
    }

    function switchNode(sw) {
        const ports = sw.ports || [];
        // Downstream switches detected via uplink interlinks nest first.
        const nested = sortSwitches(swKidsOf[swName(sw)] || [])
            .filter(k => topoFilters.edge || !isEdgeSwitch(k));
        // Devices seen behind this switch (unattributed devices match when
        // there is only one switch).
        const swDevs = devices.filter(dv => {
            if (assigned.has(dv)) return false;
            if (!dv.switch_id) return singleSwitch;
            return switchIdMatch(sw, dv.switch_id) || singleSwitch;
        });

        // Group this switch's devices by the physical port they were seen on:
        // switch → portN → device(s). The port's assigned (native) VLAN colors
        // the port node's border and the tree links to/under it (see linkColor
        // honoured in the link renderer). Devices seen without a port fall back
        // to a direct child so they are never dropped.
        const portCfg = {};
        ports.forEach(p => { portCfg[p.name] = p; });
        const byPort = {};
        const rest = [];
        swDevs.forEach(dv => {
            if (assigned.has(dv)) return;
            assigned.add(dv);
            if (dv.port) (byPort[dv.port] = byPort[dv.port] || []).push(dv);
            else rest.push(dv);
        });
        const portNum = name => { const m = /(\d+)/.exec(name || ""); return m ? Number(m[1]) : 1e9; };
        const children = Object.entries(byPort)
            .sort((a, b) => portNum(a[0]) - portNum(b[0]) || (a[0] < b[0] ? -1 : 1))
            .map(([port, devs]) => {
                const p = portCfg[port];
                const nativeVlan = p && p.vlan ? String(p.vlan) : "";
                // An 802.1x port holds clients on its native (onboarding) VLAN
                // until they authenticate, then dynamically moves them to their
                // assigned VLAN. Label/colour the port by the client's effective
                // VLAN (from the device record), falling back to the native VLAN.
                const devVlan = devs.map(d => (d.vlan == null ? "" : String(d.vlan))).find(v => v !== "") || "";
                const vlan = devVlan || nativeVlan;
                const col = vlan ? vlanColor(vlan) : null;
                const mm = topoMultiMacIdx[swName(sw) + "|" + port];
                const st = topoStpIdx[swName(sw) + "|" + port];
                return {
                    name: port, kind: "port", data: { port, vlan, nativeVlan, ports: p ? [p] : [] },
                    info: `Port ${port}` +
                        (vlan ? `\nVLAN: ${vlan}` : "") +
                        (nativeVlan && nativeVlan !== vlan ? `\nNative VLAN: ${nativeVlan}` : "") +
                        (p && taggedVlans(p) ? `\n${tt("topo.tagged")}: ${taggedVlans(p)}` : "") +
                        (mm ? `\n⚠ ${mm} MACs — ${tt("topo.multi_mac")}` : "") +
                        (st && st.blocked ? `\n⃠ ${tt("topo.stp_blocked")}` : "") +
                        `\n${devs.length} ${tt("topo.devices")}`,
                    badge: (vlan ? "VLAN " + vlan + " · " : "") + devs.length + " " + tt("topo.devices"),
                    strokeColor: col,
                    linkColor: col,
                    children: devs.map(dv => { const n = deviceNode(dv); n.linkColor = col; return n; })
                };
            });
        // Devices matched to the switch but with no port association.
        children.push(...rest.map(deviceNode));

        const devCount = swDevs.length;
        const group = swGroupOf[swName(sw)] || "";
        const blockedPorts = ports
            .filter(p => (topoStpIdx[swName(sw) + "|" + p.name] || {}).blocked)
            .map(p => {
                const st = topoStpIdx[swName(sw) + "|" + p.name];
                return `${p.name} (${st.guard || st.state || st.role})`;
            });
        // Live switch health (SSH): fan fault + a count of ports with error counters.
        const health = topoSwitchHealth.find(h => switchIdMatch(sw, h.switch_name)) || {};
        const fanFault = /fault/i.test(health.fan || "");
        const errPorts = ports.filter(p => (topoStpIdx[swName(sw) + "|" + p.name] || {}).health).length;
        return {
            name: swName(sw), kind: "switch", data: sw,
            info: `FortiSwitch${sw.model ? " " + sw.model : ""}\n${tt("topo.serial")}: ${sw.serial || sw.switch_id}` +
                (group ? `\n${tt("topo.group")}: ${group}` : "") +
                (sw.description ? `\n${sw.description}` : "") +
                `\n${tt("topo.ports")}: ${ports.length}` +
                (nested.length ? `\nDownstream: ${nested.map(swName).join(", ")}` : "") +
                (blockedPorts.length ? `\n⃠ ${tt("topo.stp_blocked")}: ${blockedPorts.join(", ")}` : "") +
                (health.fan ? `\n${fanFault ? "⚠ " : ""}${tt("topo.fan")}: ${health.fan}` : "") +
                (health.poe_total ? `\nPoE: ${Math.round(health.poe_used)}/${Math.round(health.poe_total)} W` : "") +
                (health.tcn ? `\n${tt("topo.tcn")}: ${health.tcn}` : "") +
                (errPorts ? `\n⚠ ${errPorts} ${tt("topo.err_ports")}` : "") +
                (devCount ? `\n${tt("topo.devices")}: ${devCount}` : ""),
            badge: [(fanFault || errPorts ? "⚠" : ""), sw.model, group].filter(Boolean).join(" · ") || null,
            hasBlocked: blockedPorts.length > 0,
            hasFault: fanFault || errPorts > 0,
            group: group,
            groupColor: groupColor(group),
            children: [...nested.map(switchNode), ...children]
        };
    }

    // Sort: WAN interfaces first, then those with children, then the rest.
    const sorted = [...physical].sort((a, b) => {
        const aw = wanDevices.has(a.name) ? 0 : 1, bw = wanDevices.has(b.name) ? 0 : 1;
        if (aw !== bw) return aw - bw;
        const ac = (vlansByParent[a.name] || []).length, bc = (vlansByParent[b.name] || []).length;
        return bc - ac;
    });

    // Zoned interfaces are grouped under one node per zone, placed where the
    // zone's first member would have appeared in the sort order. Tunnel
    // interfaces are excluded here — VPNs render on the Internet side — and
    // zones consisting only of tunnels move there with them.
    const fwChildren = [];
    const externalIntf = []; // WAN uplinks — rendered on the Internet side (left)
    const zoneEmitted = new Set();
    sorted.forEach(i => {
        if (vpnByName[i.name]) return;
        // WAN interfaces face the Internet: pull them out of the firewall subtree
        // so they render on the left alongside the VPN tunnels.
        if (wanDevices.has(i.name)) { externalIntf.push(intfNode(i)); return; }
        const zn = zoneOf[i.name];
        if (!zn) { fwChildren.push(intfNode(i)); return; }
        if (zoneEmitted.has(zn)) return;
        zoneEmitted.add(zn);
        const members = sorted.filter(m => zoneOf[m.name] === zn && !vpnByName[m.name] && !wanDevices.has(m.name));
        if (!members.length) return;
        fwChildren.push({
            name: zn, kind: "zone",
            info: `${tt("topo.zone")}\n${members.length} Interfaces`,
            badge: String(members.length),
            children: members.map(intfNode)
        });
    });

    // Safety net: when no interface adopted the FortiLink stack (unidentified
    // or WAN-classified fortilink interface), host the managed switches — and
    // the FortiAP group that rides with them — directly under the firewall
    // rather than silently dropping them from the tree.
    if (!switchesHosted) {
        if (switches.length) pushSwitchNodes(fwChildren);
        const apg = apGroupNode();
        if (apg) fwChildren.push(apg);
    }

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

    const rootChildren = [{
        name: data.fqdn || "FortiGate",
        kind: "firewall", data: data,
        info: `${fwLabel(data)}\nInterfaces: ${interfaces.length}\nSwitches: ${switches.length}\nPolicies: ${policies.length}` +
            (data.ha ? `\nHA: ${data.ha.mode}${data.ha.group_name ? " · " + data.ha.group_name : ""}` : "") +
            (devices.length ? `\n${tt("topo.devices")}: ${devices.length}` : "") +
            (topoFwHealth ? `\n${topoFwHealth}` : "") +
            (topoDiagStatus && topoDiagStatus.last_run ? `\n${tt("topo.ssh_collected")}: ${topoDiagStatus.switches} sw · ${(topoDiagStatus.duration_ms / 1000).toFixed(1)}s${topoDiagStatus.static ? " · full" : ""} @ ${(topoDiagStatus.last_run || "").slice(11, 16)}` : ""),
        badge: data.model || null,
        children: fwChildren
    }];

    // External / Internet-facing branches (WAN uplinks + IPsec VPN tunnels)
    // render to the LEFT of the Internet node (see the mirror step in update());
    // the firewall and its LAN stay on the right.
    const externalBranches = [...externalIntf, ...vpnBranches()];
    externalBranches.forEach(n => { n.side = "left"; });
    rootChildren.push(...externalBranches);

    // HA peer: the standby unit of an a-p / a-a cluster.
    if (data.ha) {
        const ha = data.ha;
        rootChildren.push({
            name: (data.fqdn || "FortiGate") + " ②", kind: "firewall", data: data,
            info: `${tt("topo.ha_standby")}\nHA: ${ha.mode}` +
                (ha.group_name ? `\n${tt("topo.group")}: ${ha.group_name}` : "") +
                ((ha.hbdev || []).length ? `\nHeartbeat: ${ha.hbdev.join(", ")}` : "") +
                ((ha.monitor || []).length ? `\nMonitor: ${ha.monitor.join(", ")}` : "") +
                (topoHaDetail ? `\n${topoHaDetail}` : ""),
            badge: "HA " + ha.mode,
            children: []
        });
    }

    return {
        name: tt("topo.internet"), kind: "internet", info: tt("topo.external"),
        children: rootChildren
    };
}

function renderTree(data) {
    svg = d3.select("#topoSvg");
    svg.selectAll("*").remove();

    const height = 640;

    const root = d3.hierarchy(buildTree(data));
    root.descendants().forEach(d => {
        d._children = d.children;
        // Collapse route/VLAN/VPN groups and the general (unattributed) device
        // list by default to keep the initial view tidy. Per-switch port nodes
        // stay expanded so each switch shows its clients as switch → port →
        // device with VLAN-coloured links.
        if (d.data.kind === "route" || d.data.kind === "vlangroup" || d.data.kind === "vpngroup" || d.data.kind === "lan") d.children = null;
    });

    gRoot = svg.append("g");
    zoomBehavior = d3.zoom().scaleExtent([0.25, 3]).on("zoom", ev => gRoot.attr("transform", ev.transform));
    svg.call(zoomBehavior);

    const gLinks = gRoot.append("g");
    const gInter = gRoot.append("g"); // switch interlink overlay (above tree links, below nodes)
    const gNodes = gRoot.append("g");

    const tree = d3.tree().nodeSize([44, 210]);
    const diagonal = d3.linkHorizontal().x(d => d.y).y(d => d.x);

    let i = 0;
    function update(source) {
        tree(root);
        const nodes = root.descendants();
        const links = root.links();

        nodes.forEach(d => { d.y += 60; });

        // Mirror the external branches (WAN uplinks + VPN tunnels, tagged
        // side:"left" on their depth-1 root) to the left of the Internet node,
        // so the map reads internet-in-the-middle: WAN/VPN left, LAN right.
        const rootY = root.y;
        nodes.forEach(d => {
            let a = d;
            while (a.depth > 1) a = a.parent;
            if (a.depth === 1 && a.data.side === "left") d.y = 2 * rootY - d.y;
        });

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
            .on("mouseleave", hideTip)
            .on("contextmenu", (ev, d) => showCtxMenu(ev, d));

        nodeEnter.each(function(d) {
            const st = NODE_STYLE[d.data.kind] || NODE_STYLE.lan;
            const g = d3.select(this);
            if (d.data.faded) g.attr("opacity", 0.55);
            const isMajor = d.data.kind === "firewall" || d.data.kind === "internet" || d.data.kind === "switch";
            const w = isMajor ? 150 : 120, h = isMajor ? 40 : 30;

            // Shared MAC/IP devices get a red dashed border so conflicts stand
            // out; VLAN nodes carry their hashed per-VLAN color.
            const stroke = d.data.highlight ? "#ef4444" : (d.data.strokeColor || st.stroke);
            const rect = g.append("rect")
                .attr("x", -w / 2).attr("y", -h / 2).attr("width", w).attr("height", h)
                .attr("rx", 7)
                .attr("fill", st.fill)
                .attr("stroke", stroke)
                .attr("stroke-width", d.data.highlight ? 2.4 : (isMajor ? 2.4 : 1.4));
            if (d.data.highlight) rect.attr("stroke-dasharray", "5,3");

            // Switch-group overlay: a colour stripe on the switch node's left
            // edge marks its config switch-controller switch-group membership
            // (colour matches the group legend). Uplink hierarchy is unchanged.
            if (d.data.kind === "switch" && d.data.groupColor) {
                g.append("rect")
                    .attr("x", -w / 2).attr("y", -h / 2).attr("width", 5).attr("height", h)
                    .attr("rx", 2)
                    .attr("fill", d.data.groupColor);
            }

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

            // Switches with STP/guard-blocked ports carry a blinking marker.
            if (d.data.hasBlocked) {
                const dot = g.append("circle")
                    .attr("cx", w / 2 - 4).attr("cy", -h / 2 + 4).attr("r", 4.5)
                    .attr("fill", "#f97316").attr("stroke", "#0c0f14").attr("stroke-width", 1.2);
                dot.append("animate")
                    .attr("attributeName", "opacity")
                    .attr("values", "1;0.15;1").attr("dur", "1s")
                    .attr("repeatCount", "indefinite");
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
            .attr("stroke", d => d.target.data.linkColor || (NODE_STYLE[d.target.data.kind] || NODE_STYLE.lan).stroke)
            .attr("stroke-opacity", d => d.target.data.linkColor ? 0.7 : 0.35)
            .attr("stroke-width", d => d.target.data.kind === "firewall" ? 2.2 : 1.3)
            .attr("d", diagonal)
          .merge(link)
            .transition().duration(220).attr("d", diagonal);
        link.exit().remove();

        // Switch interlinks: orthogonal edges anchored at per-port stubs on the
        // switch nodes' LEFT edges (the uplink-facing side) so they route
        // through the parent column instead of overlapping the port → device
        // subtree that now grows to the right. Each link gets its own vertical
        // lane so parallel links do not overlap.
        const swPos = {};
        nodes.forEach(d => { if (d.data.kind === "switch") swPos[d.data.name] = d; });
        // Skip pairs already connected by a tree edge (uplink-nested switches).
        const treePair = l => swPos[l.from].parent === swPos[l.to] || swPos[l.to].parent === swPos[l.from];
        const activeLinks = topoInterlinks.filter(l => swPos[l.from] && swPos[l.to] && !treePair(l));
        const linkKey = l => l.from + "|" + l.to + "|" + l.kind;

        // Port stubs: every port referenced by a visible link, stacked on the
        // switch node's right edge in numeric order.
        const stubList = []; // { sw, port, x, y }
        const stubPos = {};  // "sw|port" → {x, y}
        {
            const portsBySwitch = {};
            activeLinks.forEach(l => {
                (l.from_ports || []).forEach(p => (portsBySwitch[l.from] = portsBySwitch[l.from] || new Set()).add(p));
                (l.to_ports || []).forEach(p => (portsBySwitch[l.to] = portsBySwitch[l.to] || new Set()).add(p));
            });
            const portNum = p => Number((/\d+/.exec(p) || [0])[0]);
            Object.entries(portsBySwitch).forEach(([sw, set]) => {
                const d = swPos[sw];
                if (!d) return;
                const ports = [...set].sort((a, b) => portNum(a) - portNum(b));
                const step = Math.min(12, 30 / Math.max(1, ports.length - 1) || 12);
                ports.forEach((p, i) => {
                    const y = d.x - ((ports.length - 1) * step) / 2 + i * step;
                    const s = { sw, port: p, x: d.y - 75, y };
                    stubList.push(s);
                    stubPos[sw + "|" + p] = s;
                });
            });
        }
        // anchor: average stub position of a link endpoint's ports (node edge
        // when the ports are unknown).
        const anchor = (sw, ports) => {
            const d = swPos[sw];
            const pts = (ports || []).map(p => stubPos[sw + "|" + p]).filter(Boolean);
            if (!pts.length) return { x: d.y - 75, y: d.x };
            return { x: pts[0].x, y: pts.reduce((s, p) => s + p.y, 0) / pts.length };
        };
        // Orthogonal route: out of A's left edge to the link's lane, vertical,
        // then into B. Lanes sit left of the shallower node, one per link.
        const laneOf = {};
        activeLinks.forEach((l, i) => { laneOf[linkKey(l)] = i; });
        const laneX = l => {
            const a = swPos[l.from], b = swPos[l.to];
            return Math.min(a.y, b.y) - 75 - 26 - laneOf[linkKey(l)] * 12;
        };
        const interPath = l => {
            const p1 = anchor(l.from, l.from_ports), p2 = anchor(l.to, l.to_ports);
            const lx = laneX(l);
            return `M${p1.x},${p1.y} H${lx} V${p2.y} H${p2.x}`;
        };
        const interMid = l => {
            const p1 = anchor(l.from, l.from_ports), p2 = anchor(l.to, l.to_ports);
            return [laneX(l), (p1.y + p2.y) / 2];
        };

        // Stub chips (port numbers at the node edge).
        const stub = gInter.selectAll("g.interstub")
            .data(stubList, s => s.sw + "|" + s.port);
        const stubEnter = stub.enter().append("g")
            .attr("class", "interstub")
            .style("pointer-events", "none")
            .attr("transform", s => `translate(${s.x},${s.y})`);
        stubEnter.append("rect")
            .attr("x", -22).attr("y", -5).attr("width", 22).attr("height", 10)
            .attr("rx", 3)
            .attr("fill", "#1c1917").attr("stroke", "#f59e0b").attr("stroke-width", 1)
            .attr("stroke-opacity", 0.7);
        stubEnter.append("text")
            .attr("x", -11).attr("y", 3)
            .attr("text-anchor", "middle")
            .attr("fill", "#fde68a").attr("font-size", "7.5px").attr("font-family", "monospace")
            .text(s => String((/\d+/.exec(s.port) || [s.port])[0]));
        stubEnter.merge(stub)
            .transition().duration(220)
            .attr("transform", s => `translate(${s.x},${s.y})`);
        stub.exit().remove();

        const ilink = gInter.selectAll("path.interlink").data(activeLinks, linkKey);
        ilink.enter().append("path")
            .attr("class", "interlink")
            .attr("fill", "none")
            .attr("stroke", l => l.blocked ? "#ef4444" : "#f59e0b") // red = STP-blocked redundant path
            .attr("stroke-width", 1.7)
            .attr("stroke-dasharray", "6,4")
            .attr("stroke-opacity", l => l.blocked ? 0.4 : 0.65)
            .style("cursor", "pointer")
            .on("mousemove", (ev, l) => showTip(ev, `${l.from} ⇄ ${l.to}`, interlinkTip(l)))
            .on("mouseleave", hideTip)
            .attr("d", interPath)
          .merge(ilink)
            .transition().duration(220).attr("d", interPath);
        ilink.exit().remove();

        // Links with an STP/guard-blocked endpoint carry a blinking ⃠ marker
        // on the lane's vertical segment (like the FortiGate GUI).
        const bmark = gInter.selectAll("g.interlink-block")
            .data(activeLinks.filter(l => stpBlockedPorts(l).length), linkKey);
        const bmarkEnter = bmark.enter().append("g")
            .attr("class", "interlink-block")
            .style("pointer-events", "none");
        bmarkEnter.append("circle")
            .attr("r", 7.5).attr("fill", "#1c1917")
            .attr("stroke", "#f97316").attr("stroke-width", 1.8);
        bmarkEnter.append("line")
            .attr("x1", -4).attr("y1", 4).attr("x2", 4).attr("y2", -4)
            .attr("stroke", "#f97316").attr("stroke-width", 1.8);
        bmarkEnter.append("animate")
            .attr("attributeName", "opacity")
            .attr("values", "1;0.2;1").attr("dur", "0.9s")
            .attr("repeatCount", "indefinite");
        bmarkEnter.merge(bmark)
            .transition().duration(220)
            .attr("transform", l => { const [mx, my] = interMid(l); return `translate(${mx},${my})`; });
        bmark.exit().remove();

        nodes.forEach(d => { d.x0 = d.x; d.y0 = d.y; });
    }

    root.x0 = height / 2;
    root.y0 = 60;
    topoRootNode = root;
    topoUpdate = update;
    update(root);

    // Internet sits in the middle now (WAN/VPN mirror to its left), so anchor
    // the initial view further right than the old left-edge origin to keep the
    // left arm on-screen.
    const svgEl0 = svg.node();
    const originX = Math.round((svgEl0 && svgEl0.clientWidth ? svgEl0.clientWidth : 1000) * 0.42);
    svg.call(zoomBehavior.transform, d3.zoomIdentity.translate(originX, height / 2));

    // Switch-group legend: a fixed overlay (outside the zoom group) keying the
    // colour stripe drawn on each switch node to its switch-group.
    const groupNames = (data.switch_groups || []).map(g => g.name).filter(Boolean);
    if (groupNames.length) {
        const lg = svg.append("g").attr("class", "group-legend").attr("transform", "translate(14,14)");
        lg.append("rect")
            .attr("x", -8).attr("y", -8).attr("width", 176).attr("height", 20 + groupNames.length * 16)
            .attr("rx", 6).attr("fill", "rgba(12,15,20,0.82)").attr("stroke", "rgba(255,255,255,0.08)");
        lg.append("text").attr("x", 0).attr("y", 5)
            .attr("fill", "rgba(255,255,255,0.6)").attr("font-size", "10px")
            .text(tt("topo.switch_groups"));
        groupNames.forEach((name, idx) => {
            const row = lg.append("g").attr("transform", `translate(0,${20 + idx * 16})`);
            row.append("rect").attr("x", 0).attr("y", -8).attr("width", 10).attr("height", 10)
                .attr("rx", 2).attr("fill", groupColor(name));
            row.append("text").attr("x", 16).attr("y", 1)
                .attr("fill", "#d1d5db").attr("font-size", "10px")
                .text(name.length > 23 ? name.slice(0, 22) + "…" : name);
        });
    }
}

// ---------------------------------------------------------------------------
// Search & locate
// ---------------------------------------------------------------------------
function centerOnNode(d) {
    const svgEl = document.getElementById("topoSvg");
    svg.transition().duration(400).call(zoomBehavior.transform,
        d3.zoomIdentity.translate(svgEl.clientWidth / 2 - d.y, 320 - d.x));
    // Brief highlight pulse on the located node.
    d3.selectAll("g.node").filter(n => n === d).select("rect")
        .transition().duration(150).attr("stroke-width", 4)
        .transition().duration(900).attr("stroke-width", 2.4);
}

// searchTopo finds the first node matching the query (name, IP, MAC, alias,
// serial, hostname — case-insensitive substring), expands its ancestors and
// centers the view on it.
function searchTopo(q) {
    q = (q || "").trim().toLowerCase();
    const meta = document.getElementById("topoMeta");
    if (!topoRootNode || !topoUpdate || !q) return;
    const match = d => {
        if ((d.data.name || "").toLowerCase().includes(q)) return true;
        const raw = d.data.data || {};
        return ["ip", "mac", "alias", "serial", "switch_id", "hostname", "ssid", "remote_gw"]
            .some(k => String(raw[k] || "").toLowerCase().includes(q));
    };
    let found = null;
    (function walk(d) {
        if (found) return;
        if (d !== topoRootNode && match(d)) { found = d; return; }
        (d.children || d._children || []).forEach(walk);
    })(topoRootNode);
    if (!found) {
        if (meta) meta.textContent = topoMetaText() + " · " + tt("topo.no_match");
        return;
    }
    for (let a = found.parent; a; a = a.parent) {
        if (!a.children && a._children) a.children = a._children;
    }
    topoUpdate(topoRootNode);
    if (meta) meta.textContent = topoMetaText();
    // Positions are set by the layout run in topoUpdate.
    centerOnNode(found);
}

// locateDeviceByMac jumps from the device panel to the tree node.
function locateDeviceByMac(mac) { searchTopo(mac); }

// ---------------------------------------------------------------------------
// Context menu
// ---------------------------------------------------------------------------
function hideCtxMenu() {
    const el = document.getElementById("topoCtx");
    if (el) el.style.display = "none";
}
document.addEventListener("click", hideCtxMenu);

function showCtxMenu(ev, d) {
    const el = document.getElementById("topoCtx");
    if (!el) return;
    ev.preventDefault();
    ev.stopPropagation();
    const raw = d.data.data || {};
    const items = [];
    const add = (label, fn) => items.push({ label, fn });
    add(`⧉ ${tt("topo.ctx_copy")}: ${d.data.name}`, () => navigator.clipboard.writeText(d.data.name));
    if (raw.ip) add(`⧉ IP: ${raw.ip}`, () => navigator.clipboard.writeText(raw.ip));
    if (raw.mac) add(`⧉ MAC: ${raw.mac}`, () => navigator.clipboard.writeText(raw.mac));
    if (raw.serial) add(`⧉ ${tt("topo.serial")}: ${raw.serial}`, () => navigator.clipboard.writeText(raw.serial));
    if (d.data.kind === "firewall" || d.data.kind === "switch") {
        add(`▤ ${tt("topo.ctx_faceplate")}`, () => showFaceplate(d.data));
    }
    if (d._children && d._children.length) {
        add(d.children ? `▸ ${tt("topo.ctx_collapse")}` : `▾ ${tt("topo.ctx_expand")}`, () => {
            d.children = d.children ? null : d._children;
            if (topoUpdate) topoUpdate(d);
        });
    }
    el.innerHTML = items.map((it, i) =>
        `<div class="topo-ctx-item" data-i="${i}" style="padding: 6px 12px; cursor: pointer; white-space: nowrap;">${esc(it.label)}</div>`).join("");
    el.querySelectorAll(".topo-ctx-item").forEach(node => {
        node.addEventListener("click", () => { items[Number(node.getAttribute("data-i"))].fn(); hideCtxMenu(); });
        node.addEventListener("mouseenter", () => node.style.background = "rgba(255,255,255,0.08)");
        node.addEventListener("mouseleave", () => node.style.background = "");
    });
    const card = document.getElementById("topoSvg").parentElement.getBoundingClientRect();
    el.style.left = (ev.clientX - card.left + 4) + "px";
    el.style.top = (ev.clientY - card.top + 4) + "px";
    el.style.display = "block";
}

// ---------------------------------------------------------------------------
// Device panel (inventory list synchronized with the tree)
// ---------------------------------------------------------------------------
function renderDevicePanel() {
    const panel = document.getElementById("devPanel");
    const body = document.getElementById("devPanelBody");
    if (!panel || !body) return;
    const devices = topoDevices || [];
    if (!devices.length) { panel.style.display = "none"; return; }
    panel.style.display = "";
    const q = (document.getElementById("devFilter")?.value || "").trim().toLowerCase();
    const rows = devices.filter(d => !q ||
        [d.mac, d.ip, d.hostname, d.vlan, d.switch_id, d.port]
            .some(v => String(v || "").toLowerCase().includes(q)));
    document.getElementById("devPanelCount").textContent = `${rows.length} / ${devices.length}`;
    // The MAC travels via a data attribute, never interpolated into inline
    // JS: esc() is safe for attribute/text context but not for a script
    // string literal (the browser decodes entities before the JS parser).
    body.innerHTML = rows.slice(0, 500).map(d => {
        const stale = isStaleDevice(d);
        return `<div class="dev-row" data-mac="${esc(d.mac)}" style="display: flex; gap: 10px; padding: 4px 8px; cursor: pointer; border-radius: 4px; font-size: 0.8em; ${stale ? "opacity: 0.5;" : ""}">
            <span style="color: #a5f3fc; min-width: 130px; font-family: monospace;">${esc(d.mac)}</span>
            <span style="min-width: 110px;">${esc(d.ip || "—")}</span>
            <span style="flex: 1; overflow: hidden; text-overflow: ellipsis;">${esc(d.hostname || "—")}</span>
            <span class="muted">VLAN ${esc(String(d.vlan || "—"))}</span>
            <span class="muted">${esc(d.switch_id || "")}${d.port ? " · " + esc(d.port) : ""}</span>
            ${stale ? `<span style="color: #f59e0b;">⏱ ${tt("topo.stale")}</span>` : ""}
        </div>`;
    }).join("");
    body.querySelectorAll(".dev-row").forEach(el => {
        el.addEventListener("click", () => locateDeviceByMac(el.getAttribute("data-mac") || ""));
        el.addEventListener("mouseenter", () => el.style.background = "rgba(255,255,255,0.05)");
        el.addEventListener("mouseleave", () => el.style.background = "");
    });
}

function resetZoom() {
    if (!svg || !zoomBehavior) return;
    const el = svg.node();
    const originX = Math.round((el && el.clientWidth ? el.clientWidth : 1000) * 0.42);
    svg.transition().duration(300).call(zoomBehavior.transform, d3.zoomIdentity.translate(originX, 320));
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
    if (p.isDown) return "#4b5563";
    if (p.isInterlink) return "#f59e0b";
    if (p.isWan) return "#f59e0b";
    if (p.isFortilink) return "#10b981";
    if (p.vlans > 0) return p.vlanName ? vlanColor(p.vlanName) : "#8b5cf6";
    if (p.hasIP) return "#3b82f6";
    return "#374151";
}

// fmtPoe turns the stored PoE code ("deliver:6.4/30.0W:cls4" / "search" / "off"
// / "fault") into a readable string for the port detail pane.
function fmtPoe(s) {
    if (!s) return "";
    const m = /^deliver:([\d.]+)\/([\d.]+)W:cls(\d+)/.exec(s);
    if (m) return `${m[1]}/${m[2]} W · class ${m[3]}`;
    return { search: "searching", off: "off", fault: "⚠ fault" }[s] || s;
}

// portCellSVG renders one faceplate port cell. idx indexes the panel's port
// array (click handler lookup); the cyan corner square marks 802.1X ports.
// The corner LED reflects link state: green = confirmed up, red = down (admin
// or live), grey = unknown. Down ports render dimmed; STP/guard blocks blink
// orange.
function portCellSVG(p, idx, x, y, cell) {
    // A configured VLAN alone does NOT prove the link is up — an unused access
    // port has a VLAN but no cable. "Up" therefore needs a positive signal: a
    // live up event, a pinned client (proven traffic), or a structural
    // inter-switch/uplink port (up whenever the switch is). "Down" is admin
    // status or a live down event. Everything else is unknown (grey), never a
    // misleading green.
    const isDownPort = p.isDown || p.liveDown;
    const hasClients = !!(p.devices && p.devices.length);
    // confirmedUp is set directly for firewall interfaces (admin-up + in use),
    // which have no live link signal of their own; switch ports derive it below.
    const confirmedUp = p.confirmedUp || p.liveUp || hasClients || p.isInterlink || p.isIcl || p.isUplink;
    const col = p.stpBlocked ? "#f97316" : (isDownPort ? "#4b5563" : portColor(p));
    const led = p.stpBlocked ? "#f97316"
        : isDownPort ? "#ef4444"
            : confirmedUp ? "#22c55e"
                : "#4b5563";
    const blink = p.stpBlocked
        ? `<rect x="${x - 1.5}" y="${y - 1.5}" width="${cell + 3}" height="${cell + 3}" rx="5" fill="none" stroke="#f97316" stroke-width="2">
             <animate attributeName="opacity" values="1;0.1;1" dur="0.9s" repeatCount="indefinite"/>
           </rect>`
        : "";
    const multiMac = p.multiMac
        ? `<circle cx="${x + cell - 7}" cy="${y + cell - 7}" r="5.5" fill="#22d3ee"/>
           <text x="${x + cell - 7}" y="${y + cell - 4.5}" text-anchor="middle" fill="#083344" font-size="7.5" font-weight="bold" font-family="monospace">${p.multiMac > 9 ? "9+" : p.multiMac}</text>`
        : "";
    // Pinned-device count (violet) unless the multi-MAC badge already tells it.
    const devBadge = !p.multiMac && p.devices && p.devices.length
        ? `<circle cx="${x + 7}" cy="${y + cell - 7}" r="5.5" fill="#a78bfa"/>
           <text x="${x + 7}" y="${y + cell - 4.5}" text-anchor="middle" fill="#1e1b4b" font-size="7.5" font-weight="bold" font-family="monospace">${p.devices.length > 9 ? "9+" : p.devices.length}</text>`
        : "";
    // Guard glyph (BPDU / loop / root); AP ports show the WiFi client bubble.
    const guardGlyph = p.guardKind
        ? `<text x="${x + cell / 2}" y="${y + 13}" text-anchor="middle" font-size="9">${p.guardKind === "bpdu-guard" ? "⛔" : (p.guardKind === "loop-guard" ? "↻" : "🛡")}</text>`
        : (p.wifiCount ? `<text x="${x + cell / 2}" y="${y + 12}" text-anchor="middle" fill="#7dd3fc" font-size="8" font-family="monospace">📶${p.wifiCount > 9 ? "9+" : p.wifiCount}</text>` : "");
    // 802.1X: configured = cyan; live authorized = green; unauthorized = red.
    const dot1xCol = p.dot1xState === "authorized" ? "#22c55e" : (p.dot1xState === "unauthorized" ? "#ef4444" : "#38bdf8");
    // allowed-vlans-all: tri-color micro stripe above the native VLAN stripe.
    const seg = (cell - 16) / 3;
    const rainbow = p.allowedAll
        ? `<rect x="${x + 8}" y="${y + cell - 15}" width="${seg}" height="3" fill="#ef4444" opacity="0.5"/>
           <rect x="${x + 8 + seg}" y="${y + cell - 15}" width="${seg}" height="3" fill="#22c55e" opacity="0.5"/>
           <rect x="${x + 8 + 2 * seg}" y="${y + cell - 15}" width="${seg}" height="3" fill="#3b82f6" opacity="0.5"/>`
        : "";
    const uplink = p.isUplink ? `<text x="${x + cell / 2}" y="${y - 3}" text-anchor="middle" fill="#f59e0b" font-size="9" font-family="monospace">▲</text>` : "";
    const icl = p.isIcl ? `<text x="${x + cell - 6}" y="${y - 3}" text-anchor="middle" fill="#f59e0b" font-size="9" font-family="monospace">⫘</text>` : "";
    const quarantine = p.quarantine ? `<text x="${x + 6}" y="${y - 3}" text-anchor="middle" font-size="8">☣</text>` : "";
    // HA heartbeat interface (firewall faceplate): a rose heart over the cell.
    const haHb = p.haHeartbeat ? `<text x="${x + cell / 2}" y="${y - 3}" text-anchor="middle" fill="#fb7185" font-size="9">♥</text>` : "";
    // Live SSH health: a static red ring marks a port with nonzero error/collision
    // counters (distinct from the blinking orange STP-block ring).
    const healthRing = (p.health && !p.stpBlocked)
        ? `<rect x="${x - 1.5}" y="${y - 1.5}" width="${cell + 3}" height="${cell + 3}" rx="5" fill="none" stroke="#ef4444" stroke-width="1.5"/>`
        : "";
    // PoE: a green bolt over ports actively delivering power (phones/APs/cameras).
    const poeGlyph = /^deliver/.test(p.poe || "") ? `<text x="${x + cell - 6}" y="${y - 3}" text-anchor="middle" fill="#22c55e" font-size="9">⚡</text>` : "";
    const dim = p.filtered ? " opacity: 0.15;" : ((p.isDown || p.liveDown) && !p.stpBlocked ? " opacity: 0.45;" : "");
    return `
    <g class="fp-port" data-idx="${idx}" style="cursor: pointer;${dim}">
        <rect x="${x}" y="${y}" width="${cell}" height="${cell}" rx="4" fill="rgba(0,0,0,0.55)" stroke="${col}" stroke-width="1.6"/>
        ${blink}${healthRing}
        <rect x="${x + 8}" y="${y + cell - 11}" width="${cell - 16}" height="6" rx="1.5" fill="${col}" opacity="0.85"/>
        ${rainbow}
        <circle cx="${x + 7}" cy="${y + 7}" r="2.4" fill="${led}">${p.stpBlocked ? `<animate attributeName="opacity" values="1;0.15;1" dur="0.9s" repeatCount="indefinite"/>` : ""}</circle>
        ${p.dot1x || p.dot1xState ? `<rect x="${x + cell - 11}" y="${y + 4}" width="7" height="7" rx="1.5" fill="${dot1xCol}"/>` : ""}
        ${p.nac ? `<rect x="${x + cell - 21}" y="${y + 4}" width="7" height="7" rx="1.5" fill="#34d399"/><text x="${x + cell - 17.5}" y="${y + 10}" text-anchor="middle" fill="#022c22" font-size="6" font-weight="bold" font-family="monospace">N</text>` : ""}
        ${guardGlyph}
        ${multiMac}
        ${devBadge}
        ${uplink}${icl}${quarantine}${haHb}${poeGlyph}
        <text x="${x + cell / 2}" y="${y + cell + 13}" text-anchor="middle" fill="#9ca3af" font-size="8.2" font-family="monospace">${esc(p.label.length > 7 ? p.label.slice(0, 6) + "…" : p.label)}</text>
    </g>`;
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
        cells += portCellSVG(p, p._idx !== undefined ? p._idx : idx, padX + c * (cell + gap), padY + r * (cell + 22), cell);
    });

    return `<svg viewBox="0 0 ${w} ${h}" style="width: 100%; background: linear-gradient(180deg, #171b22, #0c0f14); border: 1px solid rgba(255,255,255,0.1); border-radius: 8px;">
        <text x="${padX}" y="19" fill="rgba(255,255,255,0.6)" font-size="10.5" font-family="monospace" font-weight="bold">${esc(title)}</text>
        <circle cx="${w - 22}" cy="15" r="3.2" fill="#22c55e"><animate attributeName="opacity" values="1;0.4;1" dur="2.2s" repeatCount="indefinite"/></circle>
        ${cells}
    </svg>`;
}

// switchFaceplateSVG renders a model-accurate front panel: copper ports in
// two rows (odd on top, even below — physical numbering), then the SFP block
// separated by a divider. Ports carry _idx into the panel's port array.
function switchFaceplateSVG(copper, sfp, title) {
    const cell = 30, gap = 6, padX = 18, padY = 30, groupGap = 20;
    const cols = Math.ceil(copper.length / 2), sfpCols = Math.ceil(sfp.length / 2);
    const copperW = cols ? cols * (cell + gap) - gap : 0;
    const sfpW = sfpCols ? sfpCols * (cell + gap) - gap : 0;
    const w = padX * 2 + copperW + (sfpCols ? groupGap + sfpW : 0);
    const h = padY + 2 * (cell + 22) + 14;

    let cells = "";
    copper.forEach((p, i) => {
        cells += portCellSVG(p, p._idx, padX + Math.floor(i / 2) * (cell + gap), padY + (i % 2) * (cell + 22), cell);
    });
    const sfpX = padX + copperW + groupGap;
    sfp.forEach((p, i) => {
        cells += portCellSVG(p, p._idx, sfpX + Math.floor(i / 2) * (cell + gap), padY + (i % 2) * (cell + 22), cell);
    });
    const divider = sfpCols
        ? `<line x1="${sfpX - groupGap / 2}" y1="${padY - 4}" x2="${sfpX - groupGap / 2}" y2="${h - 12}" stroke="rgba(255,255,255,0.15)" stroke-dasharray="3,3"/>
           <text x="${sfpX}" y="${padY - 8}" fill="rgba(255,255,255,0.4)" font-size="8.5" font-family="monospace">SFP</text>`
        : "";

    return `<svg viewBox="0 0 ${w} ${h}" style="width: 100%; background: linear-gradient(180deg, #171b22, #0c0f14); border: 1px solid rgba(255,255,255,0.1); border-radius: 8px;">
        <text x="${padX}" y="19" fill="rgba(255,255,255,0.6)" font-size="10.5" font-family="monospace" font-weight="bold">${esc(title)}</text>
        <circle cx="${w - 22}" cy="15" r="3.2" fill="#22c55e"><animate attributeName="opacity" values="1;0.4;1" dur="2.2s" repeatCount="indefinite"/></circle>
        ${divider}
        ${cells}
    </svg>`;
}

function faceplateLegend(kind) {
    const items = kind === "switch"
        ? [["#f97316", tt("topo.stp_blocked")], ["#f59e0b", tt("topo.interlink")], ["#8b5cf6", tt("topo.legend_vlan")], ["#38bdf8", "802.1X"], ["#4b5563", tt("topo.status_down")], ["#374151", tt("topo.legend_none")]]
        : [["#f59e0b", tt("topo.legend_wan")], ["#10b981", "FortiLink"], ["#8b5cf6", tt("topo.legend_vlan")], ["#3b82f6", tt("topo.legend_ip")], ["#374151", tt("topo.legend_none")]];
    const glyphs = kind === "switch"
        ? `<div class="muted" style="margin-top: 6px; font-size: 0.78em;">▲ ${tt("topo.uplink")} · ⫘ ${tt("topo.icl")} · N ${tt("topo.nac")} · ☣ ${tt("topo.quarantine")} · 🔒/🔓 802.1X · ⛔↻🛡 Guard</div>`
        : `<div class="muted" style="margin-top: 6px; font-size: 0.78em;"><span style="color:#22c55e;">●</span>/<span style="color:#ef4444;">●</span> ${tt("topo.led_admin")} · ♥ ${tt("topo.ha_heartbeat")}</div>`;
    return `<div style="display: flex; flex-wrap: wrap; gap: 12px; margin-top: 12px; font-size: 0.78em;">
        ${items.map(([c, t]) => `<span><span style="display: inline-block; width: 10px; height: 10px; border-radius: 2px; background: ${c}; margin-right: 5px; vertical-align: -1px;"></span>${t}</span>`).join("")}
    </div>` + glyphs;
}

// vlanColorLegend maps the hashed per-VLAN port colors on a switch faceplate
// back to VLAN names, so the colors the port cells use are readable. Returns
// "" when no port carries an (untagged) VLAN name.
function vlanColorLegend(ports) {
    const names = [...new Set((ports || []).map(p => p.vlanName).filter(Boolean))]
        .sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
    if (!names.length) return "";
    const vlanIdOf = n => ((topo && topo.interfaces) || []).find(i => i.name === n)?.vlan_id || 0;
    return `<div style="display: flex; flex-wrap: wrap; gap: 12px; margin-top: 8px; font-size: 0.78em; border-top: 1px solid rgba(255,255,255,0.06); padding-top: 8px;">
        <span class="muted">${tt("topo.vlan_colors")}:</span>
        ${names.map(n => `<span data-vlanchip="${esc(n)}" title="VLAN ${vlanIdOf(n) || "?"} · ${esc(n)}" style="cursor: pointer;${topoFaceVlanFilter === n ? " outline: 1px solid " + vlanColor(n) + "; outline-offset: 2px; border-radius: 2px;" : ""}"><span style="display: inline-block; width: 10px; height: 10px; border-radius: 2px; background: ${vlanColor(n)}; margin-right: 5px; vertical-align: -1px;"></span>${esc(n)}</span>`).join("")}
    </div>`;
}

// buildSwitchFacePorts assembles the faceplate port array for one switch:
// config attributes + live STP/link/802.1X state, interlink/uplink/ICL flags,
// pinned devices (with AP/WiFi enrichment) and quarantine/NAC markers.
function buildSwitchFacePorts(sw) {
    const swTitle = swName(sw);
    const allSw = (topo && topo.switches) || [];
    const vlanIdOf = n => ((topo && topo.interfaces) || []).find(i => i.name === n)?.vlan_id || 0;

    const inter = {}, interIcl = {};
    (topoInterlinks || []).forEach(l => {
        const mark = (pl, peer, peerPorts, iclFlag) => (pl || []).forEach((p2, i) => {
            inter[p2] = peer + ((peerPorts || [])[i] ? " " + peerPorts[i] : "");
            if (iclFlag) interIcl[p2] = true;
        });
        if (l.from === swTitle) mark(l.from_ports, l.to, l.to_ports, l.kind === "mclag-icl");
        if (l.to === swTitle) mark(l.to_ports, l.from, l.from_ports, l.kind === "mclag-icl");
    });
    // Uplink ports: STP root role, or member ports of an edge whose parent is the peer.
    const uplinkPorts = new Set();
    (topoInterlinks || []).forEach(l => {
        if (l.parent === l.to && l.from === swTitle) (l.from_ports || []).forEach(p2 => uplinkPorts.add(p2));
        if (l.parent === l.from && l.to === swTitle) (l.to_ports || []).forEach(p2 => uplinkPorts.add(p2));
    });
    // Pinned devices per port (server-side best-pin already applied).
    const devsByPort = {};
    (topoDevices || []).forEach(dv => {
        if (!dv.port) return;
        if (resolveSwitchName(allSw, dv.switch_id) === swTitle) {
            (devsByPort[dv.port] = devsByPort[dv.port] || []).push(dv);
        }
    });
    const apOf = dv => ((topo && topo.aps) || []).find(a =>
        (a.name && dv.hostname && a.name.toLowerCase() === dv.hostname.toLowerCase()) ||
        (a.wtp_id && dv.hostname === a.wtp_id));

    return (sw.ports || []).map(p => {
        const st = topoStpIdx[swTitle + "|" + p.name];
        const multiMac = topoMultiMacIdx[swTitle + "|" + p.name] || 0;
        const history = (topoStpEventsIdx[swTitle + "|" + p.name] || []).slice(0, 6)
            .map(ev => `  ${(ev.time || "").replace("T", " ").slice(5, 16)} ${ev.kind}: ${ev.from ? ev.from + " → " : ""}${ev.to}`);
        const devices = devsByPort[p.name] || [];
        let apName = "", wifiCount = 0;
        devices.forEach(dv => {
            const ap = apOf(dv);
            if (ap) {
                apName = ap.name || ap.wtp_id;
                wifiCount = (topoDevices || []).filter(d2 => d2.ap && (d2.ap === ap.name || d2.ap === ap.wtp_id)).length;
            }
        });
        const quarantine = /quarantine/i.test(p.vlan || "") || vlanIdOf(p.vlan) === 4093;
        const nac = p.access_mode === "nac" || p.access_mode === "dynamic";
        return {
            label: p.name,
            _sw: swTitle,
            hasIP: false, isWan: false, isFortilink: false,
            isInterlink: !!inter[p.name],
            isIcl: !!interIcl[p.name],
            isUplink: uplinkPorts.has(p.name) || !!(st && st.role === "root"),
            isDown: p.status === "down" || (st && st.admin === "down"),
            adminShut: (st && st.admin === "down") || p.status === "down",
            liveDown: !!(st && st.link === "down"),
            liveUp: !!(st && st.link === "up"),
            dot1x: !!p.security_policy,
            dot1xState: (st && st.dot1x) || "",
            nac: nac,
            quarantine: quarantine,
            guardKind: st && st.blocked ? (st.guard || "") : "",
            isTrunk: p.type === "trunk",
            stpBlocked: !!(st && st.blocked),
            liveMedia: (st && st.media) || "",
            liveSpeed: (st && st.speed) || "",
            poe: (st && st.poe) || "",
            optic: (st && st.optic) || "",
            health: (st && st.health) || "",
            multiMac: multiMac,
            devices: devices,
            apName: apName, wifiCount: wifiCount,
            vlanName: p.vlan || "",
            tagged: p.allowed_vlans || [],
            allowedAll: !!p.allowed_vlans_all,
            vlans: (p.vlan ? 1 : 0) + (p.allowed_vlans || []).length + (p.allowed_vlans_all ? 1 : 0),
            detail: `VLAN: ${p.vlan || "—"}` +
                (taggedVlans(p) ? `\n${tt("topo.tagged")}: ${taggedVlans(p)}` : "") +
                (quarantine ? `\n☣ ${tt("topo.quarantine")}` : "") +
                (inter[p.name] ? `\n${interIcl[p.name] ? "⫘ " + tt("topo.icl") : tt("topo.interlink")}: ${inter[p.name]}` : "") +
                (uplinkPorts.has(p.name) || (st && st.role === "root") ? `\n▲ ${tt("topo.uplink")}` : "") +
                (st && st.link ? `\nLink: ${st.link}${st.speed ? " · " + st.speed : ""}` : "") +
                (st && st.admin === "down" ? `\n⏻ ${tt("topo.admin_down")}` : "") +
                (st && st.media ? `\n${tt("topo.media")}: ${st.media}${st.optic && st.optic !== "empty" ? " · " + st.optic : ""}` : "") +
                (st && st.optic === "empty" ? `\n${tt("topo.optic")}: ${tt("topo.optic_empty")}` : "") +
                (st && st.neighbor ? `\n🔗 ${tt("topo.lldp_neighbor")}: ${st.neighbor}` : "") +
                (st && st.poe ? `\nPoE: ${fmtPoe(st.poe)}` : "") +
                (st && st.health ? `\n⚠ ${tt("topo.port_errors")}: ${st.health}` : "") +
                (st ? `\nSTP: ${stpLabel(st)}${st.last ? " (" + st.last + ")" : ""}` : "") +
                (st && st.dot1x ? `\n${st.dot1x === "authorized" ? "🔒 " + tt("topo.dot1x_auth") : "🔓 " + tt("topo.dot1x_unauth")}` : "") +
                (nac ? `\n☑ ${tt("topo.nac")} (${p.access_mode})` : "") +
                (multiMac ? `\n⚠ ${multiMac} MACs — ${tt("topo.multi_mac")}` : "") +
                (devices.length ? `\n${tt("topo.port_devices")}: ${devices.length}` : "") +
                (apName ? `\n📶 ${apName}${wifiCount ? " · " + wifiCount + " " + tt("topo.wifi_clients") : ""}` : "") +
                (p.status === "down" ? `\n⏻ ${tt("topo.status_down")}` : "") +
                (p.security_policy ? `\n802.1X: ${p.security_policy}` : "") +
                (p.type === "trunk" ? `\nLAG: ${(p.members || []).join(", ") || "—"}` : "") +
                (st && st.guard === "bpdu-guard" ? `\n⛔ ${tt("topo.bpdu_fix")}:\n  config switch-controller managed-switch\n  edit "${sw.serial || sw.switch_id}" > config ports > edit "${p.name}"\n  set status disable → set status enable` : "") +
                (p.description ? `\n${p.description}` : "") +
                (p.mac ? `\nMAC: ${p.mac}` : "") +
                (p.speed ? `\nSpeed: ${p.speed}` : "") +
                (history.length ? `\n${tt("topo.history")}:\n${history.join("\n")}` : "")
        };
    });
}

// buildSwitchPanelHTML draws one switch's model-accurate panel (copper rows +
// SFP block + LAG chips) from ports whose _idx is already assigned; falls
// back to the generic grid for unknown models.
function buildSwitchPanelHTML(sw, ports) {
    const title = swName(sw);
    const m = /^FS-(\d{3})/.exec(sw.model || "");
    const base = m ? Number(m[1]) % 100 : 0;
    // Live SSH-diagnostics connector type (RJ45/SFP+/QSFP) is authoritative when
    // present; it replaces the model%100 heuristic for the copper/SFP partition.
    const hasMedia = ports.some(p => p.liveMedia);
    const copper = [], sfp = [], lags = [];
    ports.forEach(p => {
        const pm = /^port(\d+)$/i.exec(p.label);
        if (p.isTrunk || !pm) { lags.push(p); return; }
        const media = (p.liveMedia || "").toUpperCase();
        if (media.includes("SFP") || media.includes("QSFP")) sfp.push(p);
        else if (media === "RJ45") copper.push(p);
        else if (base && Number(pm[1]) > base) sfp.push(p);
        else copper.push(p);
    });
    let html = "";
    if ((base || hasMedia) && copper.length) {
        const byNum = (a, b) => Number((/\d+/.exec(a.label) || [0])[0]) - Number((/\d+/.exec(b.label) || [0])[0]);
        copper.sort(byNum);
        sfp.sort(byNum);
        html = switchFaceplateSVG(copper, sfp, title);
        if (lags.length) {
            html += `<div style="display: flex; flex-wrap: wrap; gap: 6px; margin-top: 10px;">` +
                lags.map(p => `<span class="fp-port" data-idx="${p._idx}" style="cursor: pointer; padding: 3px 10px; border: 1px solid ${portColor(p)}; border-radius: 12px; font-size: 0.75em; font-family: monospace;">⇆ ${esc(p.label)}</span>`).join("") +
                `</div>`;
        }
    }
    if (!html && ports.length) html = faceplateSVG(ports, title);
    return html;
}

// fpPopover shows the pinned devices of a hovered port; rows locate the
// device in the tree on click. Stale devices (unseen > 24h) render faded.
function fpPopoverEl() {
    let el = document.getElementById("fpPopover");
    if (!el) {
        el = document.createElement("div");
        el.id = "fpPopover";
        el.style.cssText = "position:fixed;z-index:2000;display:none;max-width:340px;background:#12161d;border:1px solid rgba(255,255,255,0.15);border-radius:8px;padding:6px 8px;font-size:12px;box-shadow:0 8px 24px rgba(0,0,0,.6);color:#d1d5db;";
        el.addEventListener("mouseenter", () => clearTimeout(el._t));
        el.addEventListener("mouseleave", () => hideFpPopover());
        document.body.appendChild(el);
    }
    return el;
}
function hideFpPopover() {
    const el = document.getElementById("fpPopover");
    if (!el) return;
    clearTimeout(el._t);
    el._t = setTimeout(() => { el.style.display = "none"; }, 200);
}
function deviceIsStale(dv) {
    const t = Date.parse(String(dv.last_seen || "").replace(" ", "T"));
    return !isNaN(t) && Date.now() - t > 24 * 3600 * 1000;
}
function showFpPopover(anchor, p) {
    if (!p.devices || !p.devices.length) { hideFpPopover(); return; }
    const el = fpPopoverEl();
    clearTimeout(el._t);
    const rows = p.devices.slice(0, 12).map(dv => {
        const fp = [dv.osname, dv.devtype, dv.vendor].filter(Boolean).join(" · ");
        const stale = deviceIsStale(dv);
        // 802.1X identity (RADIUS user + group) from the live SSH mac_enrich join.
        const dot1x = dv.dot1x_user ? `<br><span style="color:#7dd3fc;">🔒 ${esc(dv.dot1x_user)}${dv.dot1x_group ? " · " + esc(dv.dot1x_group) : ""}</span>` : "";
        return `<div class="fp-devrow" data-mac="${esc(dv.mac)}" style="cursor:pointer;padding:4px 6px;border-radius:5px;${stale ? "opacity:.5;" : ""}" onmouseover="this.style.background='rgba(255,255,255,0.06)'" onmouseout="this.style.background=''">
            <span style="color:#fff;">${esc(dv.hostname || dv.ip || dv.mac)}</span>${stale ? ` <span style="color:#9ca3af;">· ${tt("topo.stale")}</span>` : ""}
            <div style="color:#9ca3af;font-family:monospace;font-size:11px;">${esc(dv.mac)}${dv.ip ? " · " + esc(dv.ip) : ""}${fp ? "<br>" + esc(fp) : ""}${dot1x}</div>
        </div>`;
    }).join("");
    el.innerHTML = `<div style="color:#9ca3af;margin:2px 4px 4px;">${tt("topo.port_devices")} — ${esc(p.label)} (${p.devices.length})</div>` + rows;
    el.querySelectorAll(".fp-devrow").forEach(r => r.addEventListener("click", () => {
        locateDeviceByMac(r.getAttribute("data-mac"));
    }));
    const rect = anchor.getBoundingClientRect();
    el.style.display = "block";
    el.style.left = Math.max(8, Math.min(window.innerWidth - 356, rect.left)) + "px";
    el.style.top = (rect.bottom + 8) + "px";
}

function portDetailHTML(p) {
    return `<div style="margin-top: 14px; padding: 10px; background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.07); border-radius: 6px; font-size: 0.85em;">
        <strong style="color: #fff;">${esc(p.label)}</strong>
        <pre class="muted" style="margin: 6px 0 0; white-space: pre-wrap; font-size: 0.95em;">${esc(p.detail)}</pre>
    </div>`;
}

// buildFirewallVpnPorts assembles the firewall's IPsec tunnels for the VPN
// panel: the config attributes (remote gateway, egress interface, IKE version)
// plus the live up/down state and remote peer IP from the Graylog VPN logs
// (topoVpnIdx), matched by tunnel name.
function buildFirewallVpnPorts(d) {
    return (d.vpns || []).map(t => {
        const vs = topoVpnIdx[t.name];
        const status = vs ? (vs.status || "") : "";
        return {
            label: t.name,
            status: status,
            remGw: t.remote_gw || (vs && vs.remip) || "",
            egress: t.interface || "",
            detail: "IPsec VPN" +
                `\n${tt("topo.remote_gw")}: ${t.remote_gw || "—"}` +
                (t.ike_version ? `\nIKE v${t.ike_version}` : "") +
                `\n${tt("topo.egress")}: ${t.interface || "—"}` +
                `\nStatus: ${status || tt("topo.vpn_unknown")}${vs && vs.remip ? " · " + vs.remip : ""}`
        };
    });
}

// vpnPanelHTML renders the firewall's IPsec tunnels as their own panel below the
// interface faceplate — one card per tunnel with an up/down LED, remote gateway
// and egress interface. Down tunnels fade; unknown (no logged state) stay grey.
// Cards carry _idx into the vpn port array for the click handler, which shows
// tunnel detail in the shared detail area.
function vpnPanelHTML(vpnPorts) {
    const ledOf = s => s === "up" ? "#22c55e" : (s === "down" ? "#ef4444" : "#4b5563");
    const up = vpnPorts.filter(p => p.status === "up").length;
    const down = vpnPorts.filter(p => p.status === "down").length;
    const header = `<div style="display: flex; align-items: center; gap: 8px; margin: 16px 0 8px;">
        <span style="color: #fecdd3; font-weight: bold; font-size: 0.9em;">⚿ ${tt("topo.vpn_tunnels")}</span>
        <span class="muted" style="font-size: 0.78em;">${vpnPorts.length}${up ? " · ▲" + up : ""}${down ? " · ▼" + down : ""}</span>
    </div>`;
    if (!vpnPorts.length) {
        return header + `<p class="muted" style="font-size: 0.82em;">${tt("topo.vpn_none")}</p>`;
    }
    const cards = vpnPorts.map((p, i) => {
        const led = ledOf(p.status);
        const statusTxt = p.status === "up" ? tt("topo.vpn_up") : (p.status === "down" ? tt("topo.vpn_down") : tt("topo.vpn_unknown"));
        return `<div class="fp-vpn" data-idx="${i}" style="cursor: pointer; background: linear-gradient(180deg, #2a1215, #160a0c); border: 1px solid rgba(251,113,133,0.25); border-left: 3px solid ${led}; border-radius: 6px; padding: 7px 9px;${p.status === "down" ? " opacity: 0.55;" : ""}">
            <div style="display: flex; align-items: center; gap: 6px;">
                <span style="width: 8px; height: 8px; border-radius: 50%; background: ${led}; display: inline-block; flex: 0 0 auto;"></span>
                <span style="color: #fff; font-size: 0.82em; font-family: monospace; font-weight: bold; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${esc(p.label)}</span>
            </div>
            <div class="muted" style="font-size: 0.74em; margin-top: 3px; font-family: monospace; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">→ ${esc(p.remGw || "—")}</div>
            <div class="muted" style="font-size: 0.74em;">${esc(p.egress || "—")} · ${statusTxt}</div>
        </div>`;
    }).join("");
    return header + `<div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 8px;">${cards}</div>`;
}

// fwIntfConfirmedUp decides the green "up" LED for a firewall interface from the
// config alone — no live link state is collected for firewall interfaces, so the
// cell LED reflects admin/config state: green when the interface is
// administratively up AND in use (has an IP, is a WAN uplink, a bundle member,
// an HA heartbeat, or carries a role), red when `set status down`, grey when
// defined but idle. This mirrors the switch faceplate's rule of never showing a
// misleading green.
function fwIntfConfirmedUp(i, isWan, isMember, isHb) {
    if ((i.status || "") === "down") return false;
    return !!(i.ip || isWan || isMember || isHb || i.role || (i.members && i.members.length));
}

// fwIntfDetail is the port-detail text for one firewall interface cell.
function fwIntfDetail(i, vlans, isHb, parent) {
    return `IP: ${i.ip ? i.ip + "/" + i.mask : "—"}` +
        (i.alias ? `\n${tt("topo.alias")}: ${i.alias}` : "") +
        `\n${tt("topo.role")}: ${i.role || "—"}` +
        (i.type ? `\n${tt("topo.iface_type")}: ${i.type}` : "") +
        `\nVLANs: ${vlans}` +
        `\n${tt("topo.mgmt_access")}: ${(i.allowaccess || []).join(", ") || "—"}` +
        (parent ? `\n${tt("topo.bundle_member")}: ${parent}` : "") +
        (isHb ? `\n♥ ${tt("topo.ha_heartbeat")}` : "") +
        ((i.status || "") === "down" ? `\n⏻ ${tt("topo.admin_down")}` : "");
}

// fwIntfPort builds one firewall interface cell object for portCellSVG, carrying
// the admin up/down LED (011/012) and the HA-heartbeat marker (072).
function fwIntfPort(i, wan, vlanCount, hbSet, parent) {
    const isHb = hbSet.has(i.name);
    const isMember = !!parent;
    const vlans = vlanCount[i.name] || 0;
    return {
        label: i.name,
        hasIP: !!i.ip,
        isWan: wan.has(i.name),
        isFortilink: !!i.fortilink || i.name.toLowerCase().includes("fortilink"),
        vlans: vlans,
        isDown: (i.status || "") === "down",
        confirmedUp: fwIntfConfirmedUp(i, wan.has(i.name), isMember, isHb),
        haHeartbeat: isHb,
        detail: fwIntfDetail(i, vlans, isHb, parent)
    };
}

// fwBundleKind classifies a member-carrying firewall interface into its bundle
// type — the FortiLink fabric (008), an LACP aggregate or redundant pair (007),
// or a hardware switch (006) — with the glyph and accent used in the panel.
function fwBundleKind(i) {
    const name = (i.name || "").toLowerCase();
    if (i.fortilink || name.includes("fortilink")) return { label: "FortiLink", glyph: "⇅", color: "#10b981" };
    switch (i.type || "") {
        case "aggregate": return { label: "LACP aggregate", glyph: "⇉", color: "#38bdf8" };
        case "redundant": return { label: "Redundant", glyph: "⇄", color: "#38bdf8" };
        case "hard-switch":
        case "switch": return { label: "Hardware switch", glyph: "▤", color: "#a78bfa" };
        default: return { label: "Bundle", glyph: "▦", color: "#94a3b8" };
    }
}

// buildFirewallBundles collects every member-carrying interface as a bundle with
// its member ports (each with an admin-down / HA-heartbeat marker).
function buildFirewallBundles(d, wan, hbSet) {
    const byName = {};
    (d.interfaces || []).forEach(i => { byName[i.name] = i; });
    return (d.interfaces || [])
        .filter(i => i.members && i.members.length)
        .map(i => {
            const kind = fwBundleKind(i);
            const members = i.members.map(mn => {
                const mi = byName[mn] || {};
                return { name: mn, isDown: (mi.status || "") === "down", isHb: hbSet.has(mn) };
            });
            return {
                label: i.name,
                kind: kind,
                ip: i.ip || "",
                isDown: (i.status || "") === "down",
                members: members,
                detail: kind.label +
                    (i.type ? `\n${tt("topo.iface_type")}: ${i.type}` : "") +
                    (i.ip ? `\nIP: ${i.ip}/${i.mask}` : "") +
                    `\n${tt("topo.role")}: ${i.role || "—"}` +
                    `\n${tt("topo.mgmt_access")}: ${(i.allowaccess || []).join(", ") || "—"}` +
                    `\n${tt("topo.members")} (${members.length}): ${i.members.join(", ")}` +
                    ((i.status || "") === "down" ? `\n⏻ ${tt("topo.admin_down")}` : "")
            };
        });
}

// bundlePanelHTML renders the aggregate / redundant / hardware-switch / FortiLink
// bundles as their own panel below the interface faceplate — one card per bundle
// with an admin LED and a chip per member port (006/007/008). Cards carry _idx
// for the click handler, which shows the bundle detail in the shared area.
function bundlePanelHTML(bundles) {
    if (!bundles.length) return "";
    const header = `<div style="display: flex; align-items: center; gap: 8px; margin: 16px 0 8px;">
        <span style="color: #cbd5e1; font-weight: bold; font-size: 0.9em;">▤ ${tt("topo.bundles")}</span>
        <span class="muted" style="font-size: 0.78em;">${bundles.length}</span>
    </div>`;
    const cards = bundles.map((b, i) => {
        const led = b.isDown ? "#ef4444" : "#22c55e";
        const chips = b.members.map(m => {
            const mled = m.isDown ? "#ef4444" : "#22c55e";
            return `<span style="display: inline-flex; align-items: center; gap: 4px; font-family: monospace; font-size: 0.72em; color: #cbd5e1; background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-left: 2px solid ${mled}; border-radius: 4px; padding: 2px 6px;${m.isDown ? " opacity: 0.55;" : ""}">${esc(m.name)}${m.isHb ? " ♥" : ""}</span>`;
        }).join("");
        return `<div class="fp-bundle" data-idx="${i}" style="cursor: pointer; background: linear-gradient(180deg, #131a24, #0d131b); border: 1px solid rgba(255,255,255,0.1); border-left: 3px solid ${b.kind.color}; border-radius: 6px; padding: 8px 10px;${b.isDown ? " opacity: 0.6;" : ""}">
            <div style="display: flex; align-items: center; gap: 6px;">
                <span style="width: 8px; height: 8px; border-radius: 50%; background: ${led}; display: inline-block; flex: 0 0 auto;"></span>
                <span style="color: #fff; font-size: 0.82em; font-family: monospace; font-weight: bold;">${b.kind.glyph} ${esc(b.label)}</span>
                <span class="muted" style="font-size: 0.72em; margin-left: auto;">${esc(b.kind.label)}${b.ip ? " · " + esc(b.ip) : ""}</span>
            </div>
            <div style="display: flex; flex-wrap: wrap; gap: 5px; margin-top: 7px;">${chips}</div>
        </div>`;
    }).join("");
    return header + `<div style="display: grid; gap: 8px;">${cards}</div>`;
}

function showFaceplate(nodeData) {
    const panel = document.getElementById("facePanel");
    const body = document.getElementById("faceBody");
    let ports = [], title = "", sub = "";

    if (nodeData.kind === "firewall") {
        const d = nodeData.data;
        title = d.fqdn || "FortiGate";
        sub = fwLabel(d);
        const wan = wanSet(d.interfaces, d.routes);
        const vlanCount = {};
        (d.interfaces || []).forEach(i => { if (i.vlan_id > 0 && i.interface) vlanCount[i.interface] = (vlanCount[i.interface] || 0) + 1; });

        // Bundle grouping (006/007/008): interfaces that carry member ports are
        // aggregates, redundant pairs, hardware switches or the FortiLink fabric.
        // Their members live in the bundle panel below, so keep both the members
        // and the bundle parent out of the flat interface grid.
        const memberOf = {}, parentSet = new Set();
        (d.interfaces || []).forEach(i => {
            if (i.members && i.members.length) {
                parentSet.add(i.name);
                i.members.forEach(m => { memberOf[m] = i.name; });
            }
        });
        // HA heartbeat interfaces (072), marked with a ♥ on their cell.
        const hbSet = new Set((d.ha && d.ha.hbdev) || []);

        ports = (d.interfaces || [])
            .filter(i => !(i.vlan_id > 0) && !parentSet.has(i.name) && !memberOf[i.name])
            .map(i => fwIntfPort(i, wan, vlanCount, hbSet, null));
        nodeData._fwBundles = buildFirewallBundles(d, wan, hbSet);
    } else if (nodeData.kind === "switch") {
        const sw = nodeData.data;
        title = swName(sw);
        sub = `FortiSwitch${sw.model ? " " + sw.model : ""} · ${sw.serial || sw.switch_id}`;
        ports = buildSwitchFacePorts(sw);
        // MC-LAG peer: stack the partner's faceplate in the same panel.
        const iclLink = (topoInterlinks || []).find(l => l.kind === "mclag-icl" && (l.from === title || l.to === title));
        if (iclLink) {
            const peerName = iclLink.from === title ? iclLink.to : iclLink.from;
            const peerSw = ((topo && topo.switches) || []).find(s2 => swName(s2) === peerName);
            if (peerSw) {
                ports = ports.concat(buildSwitchFacePorts(peerSw));
                nodeData._pairPeer = peerSw;
                sub += ` · ⫘ ${tt("topo.mclag_peer")}: ${peerName}`;
            }
        }
        // Dual-homed uplink: this switch links to BOTH members of the MC-LAG pair.
        const pair = (topoInterlinks || []).find(l => l.kind === "mclag-icl");
        if (pair && title !== pair.from && title !== pair.to) {
            const peers = new Set();
            (topoInterlinks || []).forEach(l => {
                if (l.from === title) peers.add(l.to);
                if (l.to === title) peers.add(l.from);
            });
            if (peers.has(pair.from) && peers.has(pair.to)) {
                sub += ` · ⇈ ${tt("topo.dual_homed")}: ${pair.from} + ${pair.to}`;
            }
        }
        // Legend VLAN filter: dim every port not carrying the selected VLAN.
        const f = topoFaceVlanFilter;
        if (f) ports.forEach(p => { p.filtered = !(p.vlanName === f || (p.tagged || []).includes(f) || p.allowedAll); });
    }

    document.getElementById("faceTitle").textContent = title;
    document.getElementById("faceSub").textContent = sub;

    // Switch panels are drawn model-accurately when the model is known; an
    // MC-LAG pair renders both members stacked, joined by an ICL divider.
    let panelHTML = "";
    ports.forEach((p, idx) => { p._idx = idx; });
    if (nodeData.kind === "switch" && ports.length) {
        const own = ports.filter(p => p._sw === title || !p._sw);
        panelHTML = buildSwitchPanelHTML(nodeData.data, own);
        if (nodeData._pairPeer) {
            const peerPorts = ports.filter(p => p._sw === swName(nodeData._pairPeer));
            panelHTML += `<div style="text-align: center; color: #f59e0b; font-size: 0.8em; margin: 6px 0;">⫘ ${tt("topo.icl")} ⇕</div>` +
                buildSwitchPanelHTML(nodeData._pairPeer, peerPorts);
        }
    }
    if (!panelHTML && ports.length) panelHTML = faceplateSVG(ports, title);

    // Firewall: aggregate/hardware-switch/FortiLink bundles and IPsec VPN tunnels
    // each render in their own panel below the interface faceplate (WAN
    // interfaces face outward; the tunnels ride them separately).
    let vpnPorts = [], vpnHTML = "", bundleHTML = "";
    if (nodeData.kind === "firewall") {
        vpnPorts = buildFirewallVpnPorts(nodeData.data);
        vpnHTML = vpnPanelHTML(vpnPorts);
        bundleHTML = bundlePanelHTML(nodeData._fwBundles || []);
    }

    const legend = faceplateLegend(nodeData.kind) +
        (nodeData.kind === "switch" ? vlanColorLegend(ports) : "");
    body.innerHTML = (panelHTML || vpnHTML || bundleHTML)
        ? (panelHTML || "") + legend + bundleHTML + vpnHTML + '<div id="facePortDetail"></div>'
        : `<p class="muted">${tt("topo.no_ports")}</p>`;

    body.querySelectorAll(".fp-port").forEach(el => {
        const p = ports[Number(el.getAttribute("data-idx"))];
        el.addEventListener("click", () => {
            document.getElementById("facePortDetail").innerHTML = portDetailHTML(p);
        });
        el.addEventListener("mouseenter", () => { el.style.opacity = "0.75"; showFpPopover(el, p); });
        el.addEventListener("mouseleave", () => { el.style.opacity = "1"; hideFpPopover(); });
    });
    // VPN tunnel cards: click shows the tunnel's detail in the shared area.
    body.querySelectorAll(".fp-vpn").forEach(el => {
        const p = vpnPorts[Number(el.getAttribute("data-idx"))];
        el.addEventListener("click", () => {
            document.getElementById("facePortDetail").innerHTML = portDetailHTML(p);
        });
    });
    // Interface-bundle cards: click shows the bundle detail (type + members).
    body.querySelectorAll(".fp-bundle").forEach(el => {
        const b = (nodeData._fwBundles || [])[Number(el.getAttribute("data-idx"))];
        el.addEventListener("click", () => {
            document.getElementById("facePortDetail").innerHTML = portDetailHTML({ label: b.label, detail: b.detail });
        });
    });
    // Legend VLAN chips filter the panel; a second click clears the filter.
    body.querySelectorAll("[data-vlanchip]").forEach(el => {
        el.addEventListener("click", () => {
            const v = el.getAttribute("data-vlanchip");
            topoFaceVlanFilter = topoFaceVlanFilter === v ? null : v;
            showFaceplate(topoFaceData);
        });
    });

    topoFaceData = nodeData;
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
        const live = document.getElementById("liveDevBtn");
        if (live) live.style.display = "";
        topoStp = data.stp || [];
        topoStpEvents = data.stp_events || [];
        topoMultiMac = data.multi_mac_ports || [];
        topoEdges = data.edges || [];
        topoVpn = data.vpn || [];
        topoHaDetail = data.ha_detail || "";
        topoFwHealth = data.fw_health || "";
        topoSwitchHealth = data.switch_health || [];
        topoLiveRoutes = data.live_routes || [];
        topoSdwan = data.sdwan_health || [];
        topoThroughput = data.throughput || [];
        topoDiagStatus = data.diag_status || null;
        return data.devices || [];
    } catch (e) {
        return null;
    }
}

// fetchDevicesNow triggers an immediate Graylog fetch for the viewed firewall
// ("fetch device data now" button) and re-renders the tree. rangeSec, when
// given (live mode), narrows the Graylog search window to recent logs only.
async function fetchDevicesNow(rangeSec) {
    const cfg = window.TOPO_CONFIG || {};
    const fwid = selectedFwID();
    if (!cfg.devicesBase || !fwid) return;
    const meta = document.getElementById("topoMeta");
    const btn = document.getElementById("fetchDevBtn");
    if (btn) btn.disabled = true;
    if (meta) meta.textContent = tt("topo.fetching");
    try {
        const url = cfg.devicesBase + "/refresh/" + fwid + (rangeSec ? "?range=" + rangeSec : "");
        const resp = await fetch(url, { method: "POST" });
        if (!resp.ok) throw new Error("HTTP " + resp.status);
        const data = await resp.json();
        if (fwid !== selectedFwID()) return; // firewall switched mid-refresh
        topoDevices = data.devices || [];
        topoStp = data.stp || [];
        topoStpEvents = data.stp_events || [];
        topoMultiMac = data.multi_mac_ports || [];
        topoEdges = data.edges || [];
        topoVpn = data.vpn || [];
        topoHaDetail = data.ha_detail || "";
        topoFwHealth = data.fw_health || "";
        topoSwitchHealth = data.switch_health || [];
        topoLiveRoutes = data.live_routes || [];
        topoSdwan = data.sdwan_health || [];
        topoThroughput = data.throughput || [];
        topoDiagStatus = data.diag_status || null;
        if (topo && topo.has_config) renderTree(topo);
        renderDevicePanel();
        if (meta) meta.textContent = topoDevices.length
            ? topoMetaText() + " · " + tt("topo.dev_updated")
            : tt("topo.no_devices");
    } catch (e) {
        console.error("device fetch failed", e);
        if (meta) meta.textContent = tt("topo.fetch_failed");
    } finally {
        if (btn) btn.disabled = false;
    }
}

// --- Live device-data mode -------------------------------------------------
// While enabled, re-runs the Graylog device fetch for the viewed firewall
// every LIVE_INTERVAL_MS so the topology tracks clients in near-real-time (the
// background worker only refreshes hourly). It auto-stops after LIVE_MAX_MS so
// a forgotten tab cannot poll Graylog forever; toggling off, or closing the
// tab, stops it too. Each tick targets whatever firewall is currently
// selected, so switching the selector keeps live mode following the view.
const LIVE_INTERVAL_MS = 60000;  // poll cadence (~1 min)
const LIVE_MAX_MS = 600000;      // safety cap: auto-stop after 10 min
const LIVE_RANGE_SEC = 300;      // live polls scan only the last 5 min of logs
                                 // (vs the full default window) — retention keeps
                                 // everything already fetched, so a short window
                                 // is enough and far cheaper on Graylog.
let liveTimer = null;            // setInterval handle for the poll
let liveCountdown = null;        // setInterval handle for the 1s button label
let liveDeadline = 0;            // epoch ms at which live mode auto-stops
let liveInFlight = false;        // prevents overlapping fetches on slow Graylog

function toggleLiveDevices() {
    if (liveTimer) stopLiveDevices();
    else startLiveDevices();
}

function startLiveDevices() {
    if (liveTimer) return;
    liveDeadline = Date.now() + LIVE_MAX_MS;
    liveTimer = setInterval(livePoll, LIVE_INTERVAL_MS);
    liveCountdown = setInterval(updateLiveBtn, 1000);
    updateLiveBtn();
    livePoll(); // fetch immediately so enabling gives instant feedback
}

function stopLiveDevices() {
    if (liveTimer) { clearInterval(liveTimer); liveTimer = null; }
    if (liveCountdown) { clearInterval(liveCountdown); liveCountdown = null; }
    updateLiveBtn();
}

async function livePoll() {
    if (Date.now() >= liveDeadline) { stopLiveDevices(); return; }
    if (liveInFlight) return; // a previous fetch is still running — skip this tick
    liveInFlight = true;
    try { await fetchDevicesNow(LIVE_RANGE_SEC); }
    finally { liveInFlight = false; }
}

// updateLiveBtn reflects live state on the button: an orange "⏸ Live m:ss"
// countdown while active, the cyan "⟳ Live" idle label otherwise. It also
// enforces the deadline between poll ticks.
function updateLiveBtn() {
    const btn = document.getElementById("liveDevBtn");
    if (!btn) return;
    if (liveTimer) {
        if (Date.now() >= liveDeadline) { stopLiveDevices(); return; }
        const secs = Math.max(0, Math.round((liveDeadline - Date.now()) / 1000));
        const mm = Math.floor(secs / 60), ss = String(secs % 60).padStart(2, "0");
        btn.textContent = `⏸ ${tt("topo.live")} ${mm}:${ss}`;
        btn.style.background = "rgba(239,68,68,0.15)";
        btn.style.color = "#fca5a5";
        btn.style.borderColor = "rgba(239,68,68,0.4)";
    } else {
        btn.textContent = `⟳ ${tt("topo.live")}`;
        btn.style.background = "rgba(34,211,238,0.12)";
        btn.style.color = "#67e8f9";
        btn.style.borderColor = "rgba(34,211,238,0.35)";
    }
}

function topoMetaText() {
    if (!topo) return "";
    const parts = [];
    if (topo.model) parts.push(topo.model);
    if (topo.version) parts.push("FortiOS " + topo.version);
    parts.push(`${(topo.interfaces || []).length} Interfaces`);
    parts.push(`${(topo.switches || []).length} Switches`);
    if (topoDevices && topoDevices.length) {
        parts.push(`${topoDevices.length} ${tt("topo.devices")}`);
    }
    return parts.join(" · ");
}

async function loadTopology() {
    const url = topoDataURL();
    if (!url) return;
    // Switching the firewall selector mid-flight starts a new load; any older
    // in-flight load must not overwrite the newer result.
    const seq = ++topoLoadSeq;
    closeFaceplate();
    const meta = document.getElementById("topoMeta");
    if (meta) meta.textContent = tt("topo.loading");
    try {
        const [resp, devices] = await Promise.all([
            fetch(url, { headers: { "Accept": "application/json" } }),
            loadDeviceData()
        ]);
        if (!resp.ok) throw new Error("HTTP " + resp.status);
        const data = await resp.json();
        if (seq !== topoLoadSeq) return; // superseded by a newer load
        topo = data;
        topoDevices = devices;
        if (!topo.has_config) {
            if (meta) meta.textContent = tt("topo.no_backup");
            d3.select("#topoSvg").selectAll("*").remove();
            return;
        }
        if (meta) meta.textContent = topoMetaText();
        renderTree(topo);
        renderDevicePanel();
    } catch (e) {
        if (seq !== topoLoadSeq) return; // stale failure: a newer load owns the UI
        console.error("topology load failed", e);
        if (meta) meta.textContent = tt("topo.load_error");
    }
}

// Embed mode (?embed=1) hides the page chrome for wall dashboards; ?fw=<id>
// preselects a firewall and ?refresh=<seconds> (min 5) reloads periodically.
document.addEventListener("DOMContentLoaded", () => {
    const params = new URLSearchParams(location.search);
    const sel = document.getElementById("topoSelect");
    if (sel && params.get("fw")) sel.value = params.get("fw");
    if (params.get("embed") === "1") {
        document.body.classList.add("topo-embed");
        // With the chrome gone, grow the canvas to fill the iframe/viewport.
        const el = document.getElementById("topoSvg");
        const fit = () => el && el.setAttribute("height", Math.max(300, window.innerHeight));
        fit();
        // Debounce: a resize drag fires continuously, but re-fit + reset only
        // needs to run once the size settles.
        let resizeT;
        window.addEventListener("resize", () => {
            clearTimeout(resizeT);
            resizeT = setTimeout(() => { fit(); resetZoom(); }, 150);
        });
    }
    const refresh = Number(params.get("refresh") || 0);
    if (refresh >= 5) setInterval(loadTopology, refresh * 1000);
    loadTopology();
});
