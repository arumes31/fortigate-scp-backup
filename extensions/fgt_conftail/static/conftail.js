(() => {
    "use strict";

    const root = document.querySelector(".conftail-page");
    if (!root) return;

    const de = document.documentElement.lang === "de";
    const messages = {
        "Next run is not scheduled": "Nächster Lauf ist nicht geplant",
        "Due now": "Jetzt fällig",
        "Time: Browser": "Zeit: Browser",
        "Time: UTC": "Zeit: UTC",
        "Local views could not be saved in this browser.": "Lokale Ansichten konnten in diesem Browser nicht gespeichert werden.",
        "Select a saved view": "Gespeicherte Ansicht auswählen",
        "No saved views": "Keine gespeicherten Ansichten",
        "Enter a view name using at most 48 printable characters.": "Geben Sie einen Ansichtsnamen mit höchstens 48 druckbaren Zeichen ein.",
        "Delete a local view before saving another; the limit is 10.": "Löschen Sie eine lokale Ansicht, bevor Sie eine weitere speichern; das Limit ist 10.",
        "Delete this global ignore rule? Future matching events will enter sessions again.": "Diese globale Ignorierregel löschen? Zukünftige passende Ereignisse werden wieder in Sitzungen aufgenommen.",
    };
    const t = (english) => de ? (messages[english] || english) : english;

    const countdown = root.querySelector("#ct-next-poll-countdown");
    if (countdown) {
        const target = Date.parse(countdown.dataset.nextPoll || "");
        if (!Number.isFinite(target)) {
            countdown.textContent = t("Next run is not scheduled");
        } else {
            const update = () => {
                const remaining = Math.max(0, Math.ceil((target - Date.now()) / 1000));
                if (remaining === 0) {
                    countdown.textContent = t("Due now");
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

    const pollStatus = root.querySelector("[data-ct-poll-status]");
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
    const timeNodes = Array.from(root.querySelectorAll("[data-ct-time]"));
    const timeToggles = Array.from(root.querySelectorAll("[data-ct-time-toggle]"));
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
            toggle.textContent = local ? t("Time: Browser") : t("Time: UTC");
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

    const filterForm = root.querySelector("[data-ct-filter-form]");
    const viewNameInput = root.querySelector("[data-ct-view-name]");
    const viewSelect = root.querySelector("[data-ct-view-select]");
    const viewSave = root.querySelector("[data-ct-view-save]");
    const viewLoad = root.querySelector("[data-ct-view-load]");
    const viewDelete = root.querySelector("[data-ct-view-delete]");
    const viewFeedback = root.querySelector("[data-ct-view-feedback]");
    if (filterForm && viewNameInput && viewSelect && viewSave && viewLoad && viewDelete && viewFeedback) {
        const viewStorageKey = "fortisafe.conftail.views.v2";
        const legacyViewStorageKey = "fortisafe.conftail.views.v1";
        const maxViews = 10;
        const allowedStates = new Set(["all", "active", "sealed", "pending", "retry", "failed", "accepted"]);
        const storedFilterNames = ["firewall", "user", "source", "device", "serial", "action", "transaction", "log_id", "state", "from", "to"];
        const advancedFilterNames = new Set(["source", "device", "serial", "action", "transaction", "log_id"]);
        let views = [];

        const validPlainText = (value, maximum) => typeof value === "string" && value.length <= maximum && !/[\u0000-\u001f\u007f]/.test(value);
        const sanitizeFilters = (candidate) => {
            if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) return {};
            const sanitized = {};
            storedFilterNames.forEach((name) => {
                const raw = candidate[name];
                if (typeof raw !== "string" || raw === "") return;
                if (name === "firewall") {
                    const firewallID = Number(raw);
                    if (/^[1-9]\d{0,9}$/.test(raw) && Number.isSafeInteger(firewallID) && firewallID <= 2147483647) {
                        sanitized[name] = raw;
                    }
                    return;
                }
                if (name === "state") {
                    if (allowedStates.has(raw)) sanitized[name] = raw;
                    return;
                }
                if (name === "from" || name === "to") {
                    if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(raw)) sanitized[name] = raw;
                    return;
                }
                if (validPlainText(raw, 512)) sanitized[name] = raw;
            });
            return sanitized;
        };
        const sanitizeView = (candidate, fallbackName = "") => {
            if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) return null;
            const rawName = typeof candidate.name === "string" ? candidate.name.trim() : fallbackName.trim();
            if (!rawName || !validPlainText(rawName, 48)) return null;
            return { name: rawName, filters: sanitizeFilters(candidate.filters || candidate) };
        };
        const normalizeStoredViews = (candidate) => {
            let list = [];
            if (Array.isArray(candidate)) {
                list = candidate;
            } else if (candidate && typeof candidate === "object" && Array.isArray(candidate.views)) {
                list = candidate.views;
            } else if (candidate && typeof candidate === "object") {
                list = Object.entries(candidate).map(([name, filters]) => ({ name, filters }));
            }
            const seen = new Set();
            const clean = [];
            list.forEach((candidateView) => {
                const view = sanitizeView(candidateView);
                if (!view) return;
                const key = view.name.toLocaleLowerCase();
                if (seen.has(key) || clean.length >= maxViews) return;
                seen.add(key);
                clean.push(view);
            });
            return clean;
        };
        const persistViews = () => {
            try {
                window.localStorage.setItem(viewStorageKey, JSON.stringify({ version: 2, views }));
            } catch (_) {
                viewFeedback.dataset.state = "error";
                viewFeedback.textContent = t("Local views could not be saved in this browser.");
                return false;
            }
            return true;
        };
        const readViews = () => {
            let parsed = null;
            let current = null;
            let legacy = null;
            try {
                current = window.localStorage.getItem(viewStorageKey);
                legacy = window.localStorage.getItem(legacyViewStorageKey);
                if (current) {
                    try {
                        parsed = JSON.parse(current);
                    } catch (_) {
                        parsed = legacy ? JSON.parse(legacy) : null;
                    }
                } else if (legacy) {
                    parsed = JSON.parse(legacy);
                }
            } catch (_) {
                parsed = null;
            }
            views = normalizeStoredViews(parsed);
            if (current || legacy) {
                persistViews();
                try { window.localStorage.removeItem(legacyViewStorageKey); } catch (_) { /* storage unavailable */ }
            }
        };
        const renderViews = (selectedName = "") => {
            viewSelect.replaceChildren();
            const placeholder = document.createElement("option");
            placeholder.value = "";
            placeholder.textContent = views.length ? t("Select a saved view") : t("No saved views");
            viewSelect.appendChild(placeholder);
            views.forEach((view) => {
                const option = document.createElement("option");
                option.value = view.name;
                option.textContent = view.name;
                option.selected = view.name === selectedName;
                viewSelect.appendChild(option);
            });
            const selected = Boolean(viewSelect.value);
            viewLoad.disabled = !selected;
            viewDelete.disabled = !selected;
        };
        const currentStoredFilters = () => {
            const filters = {};
            storedFilterNames.forEach((name) => {
                const control = filterForm.elements.namedItem(name);
                const value = control && typeof control.value === "string" ? control.value.trim() : "";
                if (value) filters[name] = value;
            });
            return sanitizeFilters(filters);
        };
        const applyView = (view) => {
            ["q", ...storedFilterNames].forEach((name) => {
                const control = filterForm.elements.namedItem(name);
                if (control && typeof control.value === "string") control.value = view.filters[name] || "";
            });
            const state = filterForm.elements.namedItem("state");
            if (state && !state.value) state.value = "all";
            const advanced = root.querySelector(".ct-advanced-filters");
            if (advanced) advanced.open = [...advancedFilterNames].some((name) => Boolean(view.filters[name]));
            filterForm.requestSubmit();
        };

        readViews();
        renderViews();
        viewSelect.addEventListener("change", () => renderViews(viewSelect.value));
        viewSave.addEventListener("click", () => {
            const name = viewNameInput.value.trim();
            if (!name || !validPlainText(name, 48)) {
                viewFeedback.dataset.state = "error";
                viewFeedback.textContent = t("Enter a view name using at most 48 printable characters.");
                viewNameInput.focus();
                return;
            }
            const existing = views.findIndex((view) => view.name.toLocaleLowerCase() === name.toLocaleLowerCase());
            if (existing < 0 && views.length >= maxViews) {
                viewFeedback.dataset.state = "error";
                viewFeedback.textContent = t("Delete a local view before saving another; the limit is 10.");
                return;
            }
            const view = { name, filters: currentStoredFilters() };
            if (existing >= 0) views[existing] = view;
            else views.push(view);
            if (!persistViews()) return;
            renderViews(name);
            viewFeedback.dataset.state = "success";
            viewFeedback.textContent = de
                ? `Lokale Ansicht „${name}“ gespeichert. Die Ereignistextsuche wurde nicht gespeichert.`
                : `Saved local view “${name}”. Event-text search was not stored.`;
        });
        viewLoad.addEventListener("click", () => {
            const view = views.find((candidate) => candidate.name === viewSelect.value);
            if (view) applyView(view);
        });
        viewDelete.addEventListener("click", () => {
            const name = viewSelect.value;
            if (!name) return;
            views = views.filter((view) => view.name !== name);
            if (!persistViews()) return;
            renderViews();
            viewFeedback.dataset.state = "success";
            viewFeedback.textContent = de ? `Lokale Ansicht „${name}“ gelöscht.` : `Deleted local view “${name}”.`;
        });
    }

    const storageKey = "fortisafe.conftail.columns.v1";
    let preferences = {};
    try {
        preferences = JSON.parse(window.localStorage.getItem(storageKey) || "{}") || {};
    } catch (_) {
        preferences = {};
    }

    const applyColumn = (tableName, columnName, visible) => {
        const table = root.querySelector(`[data-ct-table="${tableName}"]`);
        if (!table) return;
        table.querySelectorAll(`[data-ct-column="${columnName}"]`).forEach((cell) => {
            cell.hidden = !visible;
        });
    };

    root.querySelectorAll("[data-ct-column-toggle]").forEach((toggle) => {
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

    const ignoreDialog = root.querySelector("#ct-ignore-dialog");
    if (ignoreDialog) {
        const eventID = ignoreDialog.querySelector("#ct-ignore-event-id");
        const attributeOption = ignoreDialog.querySelector("#ct-ignore-attribute-option");
        const operationOption = ignoreDialog.querySelector("#ct-ignore-operation-option");
        const configureOption = (option, value, output) => {
            const available = Boolean(value.trim());
            option.hidden = !available;
            option.querySelector("input").disabled = !available;
            output.textContent = value;
            return available;
        };
        root.querySelectorAll("[data-ct-ignore-open]").forEach((button) => {
            button.addEventListener("click", () => {
                eventID.value = button.dataset.eventId || "";
                const hasAttribute = configureOption(
                    attributeOption,
                    button.dataset.attribute || "",
                    attributeOption.querySelector("[data-ct-ignore-attribute]"),
                );
                const hasOperation = configureOption(
                    operationOption,
                    button.dataset.operation || "",
                    operationOption.querySelector("[data-ct-ignore-operation]"),
                );
                const selected = hasAttribute
                    ? attributeOption.querySelector("input")
                    : hasOperation ? operationOption.querySelector("input") : null;
                if (!selected) return;
                selected.checked = true;
                ignoreDialog.showModal();
                selected.focus();
            });
        });
        ignoreDialog.querySelector("[data-ct-ignore-cancel]").addEventListener("click", () => ignoreDialog.close());
        ignoreDialog.addEventListener("click", (event) => {
            if (event.target === ignoreDialog) ignoreDialog.close();
        });
    }

    root.querySelectorAll("[data-ct-ignore-delete]").forEach((form) => {
        form.addEventListener("submit", (event) => {
            if (!window.confirm(t("Delete this global ignore rule? Future matching events will enter sessions again."))) {
                event.preventDefault();
            }
        });
    });
})();
