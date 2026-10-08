// Authenticated topology-page orchestration. The shared renderer remains in
// topology.js; this file owns the page shell, dialogs, sharing and controls.
(function () {
    "use strict";
    let maximizeOpener = null;

    function ready(callback) {
        if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", callback, { once: true });
        else callback();
    }

    function selectedFirewallID() {
        const select = document.getElementById("topoSelect");
        return select && select.value ? select.value : "";
    }

    function setShareStatus(message, error) {
        const status = document.getElementById("shareStatus");
        if (!status) return;
        status.textContent = message || "";
        status.classList.toggle("is-error", Boolean(error));
    }

    function shareURL(token) {
        return window.location.origin + "/topology/shared/" + encodeURIComponent(token);
    }

    async function writeClipboard(value) {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            await navigator.clipboard.writeText(value);
            return;
        }
        const input = document.getElementById("shareUrl");
        if (!input) return;
        input.value = value;
        input.select();
        document.execCommand("copy");
    }

    function renderShares(shares) {
        const list = document.getElementById("shareList");
        if (!list) return;
        list.replaceChildren();
        if (!shares || shares.length === 0) {
            const empty = document.createElement("p");
            empty.className = "muted";
            empty.textContent = tt("topo.share_none");
            list.appendChild(empty);
            return;
        }
        shares.forEach(function (share) {
            const row = document.createElement("div");
            row.className = "topology-share-row";

            const token = document.createElement("button");
            token.type = "button";
            token.className = "topology-share-token";
            token.dataset.shareAction = "copy-token";
            token.dataset.token = share.token;
            token.title = tt("topo.copy_hint");
            token.textContent = "…/topology/shared/" + String(share.token).slice(0, 12) + "…";
            row.appendChild(token);

            const created = document.createElement("span");
            created.className = "muted";
            created.textContent = tt("topo.created") + " " + share.created_at;
            row.appendChild(created);

            const expiry = document.createElement("span");
            expiry.className = "muted";
            expiry.textContent = share.expires_at ? tt("topo.expires") + " " + share.expires_at : tt("topo.no_expiry");
            row.appendChild(expiry);

            const revoke = document.createElement("button");
            revoke.type = "button";
            revoke.className = "btn btn-small topology-share-revoke";
            revoke.dataset.shareAction = "revoke";
            revoke.dataset.token = share.token;
            revoke.textContent = tt("topo.revoke");
            row.appendChild(revoke);
            list.appendChild(row);
        });
    }

    async function refreshShares() {
        const firewallID = selectedFirewallID();
        if (!firewallID) {
            renderShares([]);
            return;
        }
        try {
            const response = await fetch("/topology/shares?fw_id=" + encodeURIComponent(firewallID), {
                headers: { Accept: "application/json" },
            });
            if (!response.ok) throw new Error("HTTP " + response.status);
            renderShares(await response.json());
        } catch (error) {
            renderShares([]);
            setShareStatus(tt("topo.share_load_fail"), true);
            console.error("topology share list failed", error);
        }
    }

    async function createShare(button) {
        const firewallID = selectedFirewallID();
        if (!firewallID) return;
        const expiry = document.getElementById("shareExpiry");
        const devices = document.getElementById("shareDevices");
        const embed = document.getElementById("shareEmbed");
        const result = document.getElementById("shareResult");
        const output = document.getElementById("shareUrl");
        button.disabled = true;
        setShareStatus("");
        try {
            const body = new URLSearchParams({
                fw_id: firewallID,
                expiry_hours: expiry ? expiry.value : "168",
                include_devices: devices && devices.checked ? "1" : "0",
            });
            const response = await fetch("/topology/share", {
                method: "POST",
                headers: { "Content-Type": "application/x-www-form-urlencoded" },
                body: body.toString(),
            });
            if (!response.ok) throw new Error("HTTP " + response.status);
            const share = await response.json();
            if (output) output.value = shareURL(share.token) + (embed && embed.checked ? "?embed=1" : "");
            if (result) result.hidden = false;
            setShareStatus(tt("topo.share_created_ok"));
            await refreshShares();
        } catch (error) {
            setShareStatus(tt("topo.share_fail") + " " + error.message, true);
        } finally {
            button.disabled = false;
        }
    }

    async function revokeShare(button) {
        const token = button.dataset.token || "";
        if (!token) return;
        button.disabled = true;
        try {
            const body = new URLSearchParams({ token: token });
            const response = await fetch("/topology/share/revoke", {
                method: "POST",
                headers: { "Content-Type": "application/x-www-form-urlencoded" },
                body: body.toString(),
            });
            if (!response.ok) throw new Error("HTTP " + response.status);
            const result = document.getElementById("shareResult");
            if (result) result.hidden = true;
            setShareStatus(tt("topo.share_revoked"));
            await refreshShares();
        } catch (error) {
            setShareStatus(tt("topo.share_fail") + " " + error.message, true);
            button.disabled = false;
        }
    }

    async function handleShareAction(event) {
        const button = event.target.closest("[data-share-action]");
        if (!button) return;
        const action = button.dataset.shareAction;
        if (action === "create") await createShare(button);
        if (action === "revoke") await revokeShare(button);
        if (action === "copy" || action === "copy-token") {
            const output = document.getElementById("shareUrl");
            const value = action === "copy-token" ? shareURL(button.dataset.token || "") : (output ? output.value : "");
            if (!value) return;
            try {
                await writeClipboard(value);
                setShareStatus(tt("topo.copied"));
            } catch (error) {
                setShareStatus(tt("topo.share_fail") + " " + error.message, true);
            }
        }
    }

    function toggleMaximize(opener) {
        const active = document.body.classList.toggle("topo-max");
        if (active && opener && opener.id !== "topoRestoreBtn") maximizeOpener = opener;
        const graph = document.getElementById("topoSvg");
        if (graph) graph.setAttribute("height", active ? String(Math.max(400, window.innerHeight - 8)) : "640");
        if (typeof resetZoom === "function") resetZoom();
        if (!active && maximizeOpener && maximizeOpener.isConnected) {
            maximizeOpener.focus();
            maximizeOpener = null;
        }
    }

    function initPage() {
        const root = document.getElementById("topologyPage");
        if (!root) return;

        const select = document.getElementById("topoSelect");
        if (select && typeof initSearchableSelect === "function") {
            initSearchableSelect(select, { placeholder: tt("topo.firewall") });
        }
        if (select) select.addEventListener("change", function () {
            const result = document.getElementById("shareResult");
            if (result) result.hidden = true;
            loadTopology();
            refreshShares();
        });

        const searchForm = document.getElementById("topologySearchForm");
        if (searchForm) searchForm.addEventListener("submit", function (event) {
            event.preventDefault();
            const input = document.getElementById("topoSearch");
            searchTopo(input ? input.value : "");
        });
        const deviceFilter = document.getElementById("devFilter");
        if (deviceFilter) deviceFilter.addEventListener("input", renderDevicePanel);

        root.addEventListener("change", function (event) {
            const filter = event.target.closest("[data-topology-filter]");
            if (filter) setTopoFilter(filter.dataset.topologyFilter, filter.checked);
        });
        root.addEventListener("click", function (event) {
            const action = event.target.closest("[data-topology-action]");
            if (!action) return;
            if (action.dataset.topologyAction === "reset") resetZoom();
            if (action.dataset.topologyAction === "maximize") toggleMaximize(action);
            if (action.dataset.topologyAction === "fetch") fetchDevicesNow();
            if (action.dataset.topologyAction === "live") toggleLiveDevices();
            if (action.dataset.topologyAction === "debug") renderDebugModal();
        });
        root.addEventListener("click", function (event) {
            const action = event.target.closest("[data-face-action]");
            if (!action) return;
            if (action.dataset.faceAction === "width") toggleFacePanelWidth();
            if (action.dataset.faceAction === "close") closeFaceplate();
        });

        const shareDialog = document.getElementById("topologyShareDialog");
        if (shareDialog) shareDialog.addEventListener("click", handleShareAction);
        const shareOpener = document.querySelector('[data-dialog-open="topologyShareDialog"]');
        if (shareOpener) shareOpener.addEventListener("click", refreshShares);
        const shareURLInput = document.getElementById("shareUrl");
        if (shareURLInput) shareURLInput.addEventListener("focus", function () { shareURLInput.select(); });

        document.addEventListener("keydown", function (event) {
            if (event.key !== "Escape") return;
            if (document.body.classList.contains("topo-max")) {
                toggleMaximize();
                return;
            }
            const faceplate = document.getElementById("facePanel");
            if (faceplate && faceplate.classList.contains("is-open") && !document.querySelector("dialog[open]")) {
                closeFaceplate();
            }
        });
        refreshShares();
    }

    ready(initPage);
})();
