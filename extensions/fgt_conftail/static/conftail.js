(() => {
    "use strict";

    const countdown = document.getElementById("ct-next-poll-countdown");
    if (countdown) {
        const target = Date.parse(countdown.dataset.nextPoll || "");
        if (!Number.isFinite(target)) {
            countdown.textContent = "Next run is not scheduled";
        } else {
            const update = () => {
                const remaining = Math.max(0, Math.ceil((target - Date.now()) / 1000));
                if (remaining === 0) {
                    countdown.textContent = "Due now";
                    return;
                }
                const hours = Math.floor(remaining / 3600);
                const minutes = Math.floor((remaining % 3600) / 60);
                const seconds = remaining % 60;
                const parts = [];
                if (hours > 0) parts.push(`${hours}h`);
                if (minutes > 0 || hours > 0) parts.push(`${minutes}m`);
                parts.push(`${seconds}s`);
                countdown.textContent = `in ${parts.join(" ")}`;
            };

            update();
            window.setInterval(update, 1000);
        }
    }

    const pollStatus = document.querySelector("[data-ct-poll-status]");
    if (pollStatus) {
        const initialSignature = pollStatus.dataset.pollSignature || "";
        let pollRunning = pollStatus.dataset.pollRunning === "true";
        const pollStatusRefresh = () => {
            fetch("/fgt-conftail/status", {
                cache: "no-store",
                credentials: "same-origin",
                headers: { Accept: "application/json" },
            }).then((response) => {
                if (!response.ok) throw new Error(`HTTP ${response.status}`);
                return response.json();
            }).then((status) => {
                pollRunning = status.running === true;
                if (status.signature && status.signature !== initialSignature) {
                    window.location.reload();
                    return;
                }
                window.setTimeout(pollStatusRefresh, pollRunning ? 2000 : 30000);
            }).catch(() => {
                window.setTimeout(pollStatusRefresh, pollRunning ? 5000 : 30000);
            });
        };
        window.setTimeout(pollStatusRefresh, pollRunning ? 2000 : 30000);
    }

    const timeStorageKey = "fortisafe.conftail.timezone.v1";
    const timeNodes = Array.from(document.querySelectorAll("[data-ct-time]"));
    const timeToggles = Array.from(document.querySelectorAll("[data-ct-time-toggle]"));
    let timeMode = "utc";
    try {
        if (window.localStorage.getItem(timeStorageKey) === "local") timeMode = "local";
    } catch (_) {
        timeMode = "utc";
    }
    timeNodes.forEach((node) => {
        node.dataset.ctUtc = node.textContent;
    });
    const localTime = new Intl.DateTimeFormat(undefined, {
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        timeZoneName: "short",
    });
    const applyTimeMode = () => {
        timeNodes.forEach((node) => {
            if (!node.dateTime) return;
            if (timeMode === "local") {
                const parsed = new Date(node.dateTime);
                if (!Number.isNaN(parsed.getTime())) node.textContent = localTime.format(parsed);
            } else {
                node.textContent = node.dataset.ctUtc || "-";
            }
        });
        timeToggles.forEach((toggle) => {
            const local = timeMode === "local";
            toggle.textContent = local ? "Time: Browser" : "Time: UTC";
            toggle.setAttribute("aria-pressed", local ? "true" : "false");
        });
    };
    timeToggles.forEach((toggle) => {
        toggle.addEventListener("click", () => {
            timeMode = timeMode === "local" ? "utc" : "local";
            try {
                window.localStorage.setItem(timeStorageKey, timeMode);
            } catch (_) {
                // Storage can be disabled; the current page still switches.
            }
            applyTimeMode();
        });
    });
    applyTimeMode();

    const storageKey = "fortisafe.conftail.columns.v1";
    let preferences = {};
    try {
        preferences = JSON.parse(window.localStorage.getItem(storageKey) || "{}") || {};
    } catch (_) {
        preferences = {};
    }

    const applyColumn = (tableName, columnName, visible) => {
        const table = document.querySelector(`[data-ct-table="${tableName}"]`);
        if (!table) return;
        table.querySelectorAll(`[data-ct-column="${columnName}"]`).forEach((cell) => {
            cell.hidden = !visible;
        });
    };

    document.querySelectorAll("[data-ct-column-toggle]").forEach((toggle) => {
        const [tableName, columnName] = toggle.dataset.ctColumnToggle.split(":", 2);
        const preferenceKey = `${tableName}:${columnName}`;
        const visible = preferences[preferenceKey] !== false;
        toggle.checked = visible;
        applyColumn(tableName, columnName, visible);
        toggle.addEventListener("change", () => {
            preferences[preferenceKey] = toggle.checked;
            applyColumn(tableName, columnName, toggle.checked);
            try {
                window.localStorage.setItem(storageKey, JSON.stringify(preferences));
            } catch (_) {
                // Browser privacy settings may disable local storage; the current
                // page still reflects the selected columns for this visit.
            }
        });
    });
})();
