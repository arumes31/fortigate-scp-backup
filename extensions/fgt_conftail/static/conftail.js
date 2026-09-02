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
