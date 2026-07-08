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

// resolveSwitchName maps an inventory switch reference (name, switch-id or
// serial, depending on the log source) to the tree node name.
function resolveSwitchName(switches, id) {
    if (!id) return null;
    const sw = switches.find(s => s.switch_id === id || s.name === id || s.serial === id);
    return sw ? swName(sw) : null;
}

// addInterlink merges a link into the list: one edge per switch pair, port
// lists unioned (an ICL detected from config AND via MAC stays one edge).
function addInterlink(links, l) {
    const ex = links.find(e => (e.from === l.from && e.to === l.to) || (e.from === l.to && e.to === l.from));
    if (!ex) { links.push(l); return; }
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

function interlinkTip(l) {
    return `${tt("topo.interlink")} · ${interlinkKindLabel(l.kind)}\n` +
        `${l.from}: ${(l.from_ports || []).join(", ") || "—"}\n` +
        `${l.to}: ${(l.to_ports || []).join(", ") || "—"}`;
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

    const interfaceNames = new Set(interfaces.map(i => i.name));
    const fortilinkHost = physical.find(i => i.name.toLowerCase().includes("fortilink"))?.name || null;

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
    topoInterlinks = interlinks;

    const mclagNames = new Set();
    interlinks.filter(l => l.kind === "mclag-icl").forEach(l => { mclagNames.add(l.from); mclagNames.add(l.to); });

    // Switch-group membership (config switch-controller switch-group).
    const swGroupOf = {};
    (data.switch_groups || []).forEach(g => (g.members || []).forEach(m => { swGroupOf[m] = g.name; }));

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
        const ra = switchTierRank(a), rb = switchTierRank(b);
        if (ra === rb) return;
        const parent = ra < rb ? l.from : l.to;
        const child = ra < rb ? l.to : l.from;
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
        const vpn = vpnByName[i.name];
        const sdw = sdwanByIntf[i.name];
        const isDown = i.status === "down";
        const children = [];
        if (i.name === fortilinkHost) {
            pushSwitchNodes(children);
            const apg = apGroupNode();
            if (apg) children.push(apg);
        }
        // IPsec tunnels egressing here that have no own interface entry.
        (data.vpns || []).forEach(t => {
            if (t.interface !== i.name || interfaceNames.has(t.name)) return;
            children.push(vpnNode(t, null));
        });
        const vlanKids = !topoFilters.vlans ? [] : (vlansByParent[i.name] || []).map(v => ({
            name: v.name, kind: "vlan", data: v,
            info: `VLAN-ID: ${v.vlan_id}\nIP: ${v.ip ? v.ip + "/" + v.mask : "—"}\n${tt("topo.parent")}: ${v.interface}` +
                dhcpLine(v.name) +
                (nacFeature(v.switch_feature) ? `\n☑ ${tt("topo.nac")}` : ""),
            badge: "VLAN " + v.vlan_id + (nacFeature(v.switch_feature) ? " · NAC" : ""),
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
        if (vpn) return vpnNode(vpn, { intf: i, children: children });

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
        return {
            name: t.name, kind: "vpn", data: i || t,
            info: `IPsec VPN\n${tt("topo.remote_gw")}: ${t.remote_gw || "—"}` +
                (t.ike_version ? `\nIKE v${t.ike_version}` : "") +
                `\n${tt("topo.egress")}: ${t.interface || "—"}` +
                (i && i.ip ? `\nIP: ${i.ip}/${i.mask}` : "") +
                `\nPolicies: ${policyCount[t.name] || 0}`,
            badge: t.remote_gw || null,
            children: (ctx && ctx.children) || []
        };
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
            return dv.switch_id === sw.switch_id || (sw.name && dv.switch_id === sw.name) ||
                (sw.serial && dv.switch_id === sw.serial) || singleSwitch;
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
            // Trunk-ish ports also carry tagged VLANs: list them per port.
            const taggedLines = ps.filter(taggedVlans)
                .map(p => `${p.name}: +${taggedVlans(p)}`);
            return {
                name: vlan === "—" ? tt("topo.no_vlan") : "VLAN " + vlan,
                kind: "port", data: { vlan, ports: ps },
                info: `${ps.length} ${tt("topo.ports")}\n${ps.map(p => p.name).join(", ")}` +
                    (taggedLines.length ? `\n${tt("topo.tagged")}:\n${taggedLines.join("\n")}` : "") +
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
        const group = swGroupOf[swName(sw)] || swGroupOf[sw.switch_id] || "";
        return {
            name: swName(sw), kind: "switch", data: sw,
            info: `FortiSwitch${sw.model ? " " + sw.model : ""}\n${tt("topo.serial")}: ${sw.serial || sw.switch_id}` +
                (group ? `\n${tt("topo.group")}: ${group}` : "") +
                (sw.description ? `\n${sw.description}` : "") +
                `\n${tt("topo.ports")}: ${ports.length}` +
                (nested.length ? `\nDownstream: ${nested.map(swName).join(", ")}` : "") +
                (devCount ? `\n${tt("topo.devices")}: ${devCount}` : ""),
            badge: [sw.model, group].filter(Boolean).join(" · ") || null,
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
    // zone's first member would have appeared in the sort order.
    const fwChildren = [];
    const zoneEmitted = new Set();
    sorted.forEach(i => {
        const zn = zoneOf[i.name];
        if (!zn) { fwChildren.push(intfNode(i)); return; }
        if (zoneEmitted.has(zn)) return;
        zoneEmitted.add(zn);
        const members = sorted.filter(m => zoneOf[m.name] === zn);
        fwChildren.push({
            name: zn, kind: "zone",
            info: `${tt("topo.zone")}\n${members.length} Interfaces`,
            badge: String(members.length),
            children: members.map(intfNode)
        });
    });

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
            (devices.length ? `\n${tt("topo.devices")}: ${devices.length}` : ""),
        badge: data.model || null,
        children: fwChildren
    }];

    // HA peer: the standby unit of an a-p / a-a cluster.
    if (data.ha) {
        const ha = data.ha;
        rootChildren.push({
            name: (data.fqdn || "FortiGate") + " ②", kind: "firewall", data: data,
            info: `${tt("topo.ha_standby")}\nHA: ${ha.mode}` +
                (ha.group_name ? `\n${tt("topo.group")}: ${ha.group_name}` : "") +
                ((ha.hbdev || []).length ? `\nHeartbeat: ${ha.hbdev.join(", ")}` : "") +
                ((ha.monitor || []).length ? `\nMonitor: ${ha.monitor.join(", ")}` : ""),
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
        // Collapse port/route/VLAN groups by default to keep the initial view
        // tidy (their devices/details expand on click).
        if (d.data.kind === "port" || d.data.kind === "route" || d.data.kind === "vlangroup") d.children = null;
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

        // Switch interlinks: dashed edges bowing right of the deeper switch,
        // drawn between the switch nodes currently visible.
        const swPos = {};
        nodes.forEach(d => { if (d.data.kind === "switch") swPos[d.data.name] = d; });
        const interPath = l => {
            const a = swPos[l.from], b = swPos[l.to];
            const x1 = a.y + 75, y1 = a.x, x2 = b.y + 75, y2 = b.x;
            const mx = Math.max(x1, x2) + 46 + Math.abs(y2 - y1) / 8;
            return `M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`;
        };
        // Skip pairs already connected by a tree edge (uplink-nested switches).
        const treePair = l => swPos[l.from].parent === swPos[l.to] || swPos[l.to].parent === swPos[l.from];
        const ilink = gInter.selectAll("path.interlink")
            .data(topoInterlinks.filter(l => swPos[l.from] && swPos[l.to] && !treePair(l)),
                l => l.from + "|" + l.to + "|" + l.kind);
        ilink.enter().append("path")
            .attr("class", "interlink")
            .attr("fill", "none")
            .attr("stroke", "#f59e0b")
            .attr("stroke-width", 1.7)
            .attr("stroke-dasharray", "6,4")
            .attr("stroke-opacity", 0.65)
            .style("cursor", "pointer")
            .on("mousemove", (ev, l) => showTip(ev, `${l.from} ⇄ ${l.to}`, interlinkTip(l)))
            .on("mouseleave", hideTip)
            .attr("d", interPath)
          .merge(ilink)
            .transition().duration(220).attr("d", interPath);
        ilink.exit().remove();

        nodes.forEach(d => { d.x0 = d.x; d.y0 = d.y; });
    }

    root.x0 = height / 2;
    root.y0 = 60;
    topoRootNode = root;
    topoUpdate = update;
    update(root);

    svg.call(zoomBehavior.transform, d3.zoomIdentity.translate(20, height / 2));
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
    body.innerHTML = rows.slice(0, 500).map(d => {
        const stale = isStaleDevice(d);
        return `<div onclick="locateDeviceByMac('${esc(d.mac)}')" style="display: flex; gap: 10px; padding: 4px 8px; cursor: pointer; border-radius: 4px; font-size: 0.8em; ${stale ? "opacity: 0.5;" : ""}" onmouseenter="this.style.background='rgba(255,255,255,0.05)'" onmouseleave="this.style.background=''">
            <span style="color: #a5f3fc; min-width: 130px; font-family: monospace;">${esc(d.mac)}</span>
            <span style="min-width: 110px;">${esc(d.ip || "—")}</span>
            <span style="flex: 1; overflow: hidden; text-overflow: ellipsis;">${esc(d.hostname || "—")}</span>
            <span class="muted">VLAN ${esc(String(d.vlan || "—"))}</span>
            <span class="muted">${esc(d.switch_id || "")}${d.port ? " · " + esc(d.port) : ""}</span>
            ${stale ? `<span style="color: #f59e0b;">⏱ ${tt("topo.stale")}</span>` : ""}
        </div>`;
    }).join("");
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
    if (p.isDown) return "#4b5563";
    if (p.isInterlink) return "#f59e0b";
    if (p.isWan) return "#f59e0b";
    if (p.isFortilink) return "#10b981";
    if (p.vlans > 0) return "#8b5cf6";
    if (p.hasIP) return "#3b82f6";
    return "#374151";
}

// portCellSVG renders one faceplate port cell. idx indexes the panel's port
// array (click handler lookup); the cyan corner square marks 802.1X ports,
// down ports render dimmed with the LED off.
function portCellSVG(p, idx, x, y, cell) {
    const col = portColor(p);
    const active = !p.isDown && (p.hasIP || p.vlans > 0 || p.isWan || p.isFortilink || p.isInterlink);
    return `
    <g class="fp-port" data-idx="${idx}" style="cursor: pointer;${p.isDown ? " opacity: 0.45;" : ""}">
        <rect x="${x}" y="${y}" width="${cell}" height="${cell}" rx="4" fill="rgba(0,0,0,0.55)" stroke="${col}" stroke-width="1.6"/>
        <rect x="${x + 8}" y="${y + cell - 11}" width="${cell - 16}" height="6" rx="1.5" fill="${col}" opacity="0.85"/>
        <circle cx="${x + 7}" cy="${y + 7}" r="2.4" fill="${active ? "#22c55e" : "#4b5563"}"/>
        ${p.dot1x ? `<rect x="${x + cell - 11}" y="${y + 4}" width="7" height="7" rx="1.5" fill="#38bdf8"/>` : ""}
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
        cells += portCellSVG(p, idx, padX + c * (cell + gap), padY + r * (cell + 22), cell);
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
        ? [["#f59e0b", tt("topo.interlink")], ["#8b5cf6", tt("topo.legend_vlan")], ["#38bdf8", "802.1X"], ["#4b5563", tt("topo.status_down")], ["#374151", tt("topo.legend_none")]]
        : [["#f59e0b", tt("topo.legend_wan")], ["#10b981", "FortiLink"], ["#8b5cf6", tt("topo.legend_vlan")], ["#3b82f6", tt("topo.legend_ip")], ["#374151", tt("topo.legend_none")]];
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
        sub = fwLabel(d);
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
        title = swName(sw);
        sub = `FortiSwitch${sw.model ? " " + sw.model : ""} · ${sw.serial || sw.switch_id}`;
        // Interlink ports of this switch → peer label ("SW-CORE02 port29").
        const inter = {};
        topoInterlinks.forEach(l => {
            if (l.from === title) (l.from_ports || []).forEach((p, i) => { inter[p] = l.to + ((l.to_ports || [])[i] ? " " + l.to_ports[i] : ""); });
            if (l.to === title) (l.to_ports || []).forEach((p, i) => { inter[p] = l.from + ((l.from_ports || [])[i] ? " " + l.from_ports[i] : ""); });
        });
        ports = (sw.ports || []).map(p => ({
            label: p.name,
            hasIP: false,
            isWan: false,
            isFortilink: false,
            isInterlink: !!inter[p.name],
            isDown: p.status === "down",
            dot1x: !!p.security_policy,
            isTrunk: p.type === "trunk",
            vlans: (p.vlan ? 1 : 0) + (p.allowed_vlans || []).length + (p.allowed_vlans_all ? 1 : 0),
            detail: `VLAN: ${p.vlan || "—"}` +
                (taggedVlans(p) ? `\n${tt("topo.tagged")}: ${taggedVlans(p)}` : "") +
                (inter[p.name] ? `\n${tt("topo.interlink")}: ${inter[p.name]}` : "") +
                (p.status === "down" ? `\n⏻ ${tt("topo.status_down")}` : "") +
                (p.security_policy ? `\n802.1X: ${p.security_policy}` : "") +
                (p.type === "trunk" ? `\nLAG: ${(p.members || []).join(", ") || "—"}` : "") +
                (p.description ? `\n${p.description}` : "") +
                (p.mac ? `\nMAC: ${p.mac}` : "") +
                (p.speed ? `\nSpeed: ${p.speed}` : "")
        }));
    }

    document.getElementById("faceTitle").textContent = title;
    document.getElementById("faceSub").textContent = sub;

    // Switch panels are drawn model-accurately when the model is known:
    // copper ports (portN ≤ base count) in two physical rows, SFP uplinks in
    // a separate block, LAG/trunk entries as chips below.
    let panelHTML = "";
    if (nodeData.kind === "switch" && ports.length) {
        const sw = nodeData.data;
        const m = /^FS-(\d{3})/.exec(sw.model || "");
        const base = m ? Number(m[1]) % 100 : 0;
        const copper = [], sfp = [], lags = [];
        ports.forEach((p, idx) => {
            p._idx = idx;
            const pm = /^port(\d+)$/i.exec(p.label);
            if (p.isTrunk || !pm) { lags.push(p); return; }
            if (base && Number(pm[1]) > base) sfp.push(p); else copper.push(p);
        });
        if (base && copper.length) {
            const byNum = (a, b) => Number((/\d+/.exec(a.label) || [0])[0]) - Number((/\d+/.exec(b.label) || [0])[0]);
            copper.sort(byNum);
            sfp.sort(byNum);
            panelHTML = switchFaceplateSVG(copper, sfp, title);
            if (lags.length) {
                panelHTML += `<div style="display: flex; flex-wrap: wrap; gap: 6px; margin-top: 10px;">` +
                    lags.map(p => `<span class="fp-port" data-idx="${p._idx}" style="cursor: pointer; padding: 3px 10px; border: 1px solid ${portColor(p)}; border-radius: 12px; font-size: 0.75em; font-family: monospace;">⇆ ${esc(p.label)}</span>`).join("") +
                    `</div>`;
            }
        }
    }
    if (!panelHTML && ports.length) panelHTML = faceplateSVG(ports, title);

    body.innerHTML = panelHTML
        ? panelHTML + faceplateLegend(nodeData.kind) + '<div id="facePortDetail"></div>'
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
        if (fwid !== selectedFwID()) return; // firewall switched mid-refresh
        topoDevices = data.devices || [];
        if (topo && topo.has_config) renderTree(topo);
        renderDevicePanel();
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
    if (params.get("embed") === "1") document.body.classList.add("topo-embed");
    const refresh = Number(params.get("refresh") || 0);
    if (refresh >= 5) setInterval(loadTopology, refresh * 1000);
    loadTopology();
});
