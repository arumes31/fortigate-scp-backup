(function () {
    'use strict';
    function startADMVPNPage() {
        var root = document.getElementById('adm-vpn-page');
        if (!root) { return; }
        var presetKey = 'fortisafe.adm-vpn.columns.v1';
        var allowedPresets = { compact: true, standard: true, diagnostic: true };
        var presetSelect = root.querySelector('#vpnColumnPreset');
        var storedPreset = '';
        try { storedPreset = window.localStorage.getItem(presetKey) || ''; } catch (_) { storedPreset = ''; }
        var initialPreset = allowedPresets[storedPreset] ? storedPreset : 'standard';
        root.dataset.columnPreset = initialPreset;
        if (presetSelect) {
            presetSelect.value = initialPreset;
            presetSelect.addEventListener('change', function () {
                var preset = allowedPresets[presetSelect.value] ? presetSelect.value : 'standard';
                root.dataset.columnPreset = preset;
                try { window.localStorage.setItem(presetKey, preset); } catch (_) { /* preference stays in memory */ }
            });
        }

        var rows = Array.prototype.slice.call(root.querySelectorAll('[data-vpn-row]'));
        var panels = Array.prototype.slice.call(root.querySelectorAll('[data-vpn-detail]'));
        var emptyDetail = root.querySelector('#vpnDetailEmpty');
        function clearSelection() {
            rows.forEach(function (row) { row.setAttribute('aria-selected', 'false'); });
            panels.forEach(function (panel) { panel.hidden = true; });
            if (emptyDetail) { emptyDetail.hidden = false; }
        }
        function selectRow(id, focusDetail) {
            var selectedRow = root.querySelector('[data-vpn-row="' + CSS.escape(id) + '"]');
            var selectedPanel = root.querySelector('[data-vpn-detail="' + CSS.escape(id) + '"]');
            if (!selectedRow || !selectedPanel || selectedRow.hidden) { return; }
            rows.forEach(function (row) { row.setAttribute('aria-selected', String(row === selectedRow)); });
            panels.forEach(function (panel) { panel.hidden = panel !== selectedPanel; });
            if (emptyDetail) { emptyDetail.hidden = true; }
            if (focusDetail) { selectedPanel.focus(); }
        }
        rows.forEach(function (row) {
            row.addEventListener('click', function (event) {
                if (event.target.closest('a, button, input, select, textarea')) { return; }
                selectRow(row.dataset.vpnRow, true);
            });
            row.addEventListener('keydown', function (event) {
                if (event.target !== row || (event.key !== 'Enter' && event.key !== ' ')) { return; }
                event.preventDefault();
                selectRow(row.dataset.vpnRow, true);
            });
        });
        root.querySelectorAll('[data-vpn-select]').forEach(function (button) {
            button.addEventListener('click', function () { selectRow(button.dataset.vpnSelect, true); });
        });

        function announce(target, kind, message) {
            target.hidden = false;
            window.FortiSafeUI.announce(target, kind, message);
        }
        var editModal = root.querySelector('#editModal');
        var modalBody = root.querySelector('#modal-body-content');
        var editFeedback = root.querySelector('#editFeedback');
        var editRequest = null;
        root.querySelectorAll('.open-edit-modal').forEach(function (button) {
            button.addEventListener('click', function () {
                if (editRequest) { editRequest.abort(); }
                editRequest = new AbortController();
                modalBody.replaceChildren();
                announce(editFeedback, 'loading', 'Loading configuration…');
                fetch('/fgt-adm-vpn-conf/edit/' + encodeURIComponent(button.dataset.id), { signal: editRequest.signal })
                    .then(function (response) {
                        if (!response.ok) { throw new Error('HTTP ' + response.status); }
                        return response.text();
                    })
                    .then(function (html) {
                        modalBody.innerHTML = html;
                        editFeedback.hidden = true;
                        var form = modalBody.querySelector('form');
                        if (!form) { throw new Error('Edit form is unavailable'); }
                        form.addEventListener('submit', function (event) {
                            event.preventDefault();
                            announce(editFeedback, 'loading', 'Saving configuration…');
                            fetch(form.action, { method: 'POST', body: new FormData(form) })
                                .then(function (response) {
                                    if (!response.ok) { return response.text().then(function (text) { throw new Error(text || ('HTTP ' + response.status)); }); }
                                    window.location.assign('/fgt-adm-vpn-conf/');
                                })
                                .catch(function (error) { announce(editFeedback, 'error', 'Could not update configuration: ' + error.message); });
                        });
                    })
                    .catch(function (error) {
                        if (error.name !== 'AbortError') { announce(editFeedback, 'error', 'Could not load configuration: ' + error.message); }
                    });
            });
        });
        editModal.addEventListener('close', function () {
            if (editRequest) { editRequest.abort(); editRequest = null; }
            modalBody.replaceChildren();
        });

        var removeModal = root.querySelector('#removeModal');
        var removeForm = root.querySelector('#removeForm');
        var removeInput = root.querySelector('#removeConfirmInput');
        var removeName = root.querySelector('#removeConfirmName');
        var removalPre = root.querySelector('#removalCommands');
        var removeIntro = root.querySelector('#removeIntro');
        var removeFeedback = root.querySelector('#removeFeedback');
        var removalRequest = null;
        root.querySelectorAll('.open-remove-modal').forEach(function (button) {
            button.addEventListener('click', function () {
                var id = button.dataset.id;
                var name = button.dataset.name || ('#' + id);
                removeModal.dataset.confirmText = name;
                removeName.textContent = name;
                removeInput.value = '';
                removeInput.dispatchEvent(new Event('input'));
                removeForm.action = '/fgt-adm-vpn-conf/delete/' + encodeURIComponent(id);
                removalPre.textContent = 'Loading…';
                removeIntro.textContent = 'Configuration "' + name + '" must be removed from the FortiGate device(s) first. Run the commands below on the matching device, then confirm removal.';
                announce(removeFeedback, 'loading', 'Loading removal commands…');
                if (removalRequest) { removalRequest.abort(); }
                removalRequest = new AbortController();
                fetch('/fgt-adm-vpn-conf/removal_commands/' + encodeURIComponent(id), { signal: removalRequest.signal })
                    .then(function (response) {
                        if (!response.ok) { throw new Error('HTTP ' + response.status); }
                        return response.text();
                    })
                    .then(function (text) {
                        removalPre.textContent = text;
                        announce(removeFeedback, 'success', 'Removal commands ready');
                    })
                    .catch(function (error) {
                        if (error.name !== 'AbortError') {
                            removalPre.textContent = '';
                            announce(removeFeedback, 'error', 'Could not load removal commands: ' + error.message);
                        }
                    });
            });
        });
        removeForm.addEventListener('submit', function (event) {
            if (removeInput.value !== removeModal.dataset.confirmText) { event.preventDefault(); }
        });
        removeModal.addEventListener('close', function () {
            if (removalRequest) { removalRequest.abort(); removalRequest = null; }
        });

        var searchInput = root.querySelector('#vpnSearch');
        var searchCount = root.querySelector('#vpnSearchCount');
        if (searchInput) {
            searchInput.addEventListener('input', function () {
                var terms = searchInput.value.toLowerCase().split(/\s+/).filter(Boolean);
                var visible = 0;
                var selectedHidden = false;
                rows.forEach(function (row) {
                    var match = terms.every(function (term) { return row.textContent.toLowerCase().indexOf(term) !== -1; });
                    row.hidden = !match;
                    if (match) { visible++; }
                    if (!match && row.getAttribute('aria-selected') === 'true') { selectedHidden = true; }
                });
                searchCount.textContent = terms.length ? visible + ' / ' + rows.length : '';
                if (selectedHidden) { clearSelection(); }
            });
        }

        function updateGraylogCheckTimers() {
            var now = Date.now();
            root.querySelectorAll('.next-graylog-check').forEach(function (element) {
                var target = new Date(element.dataset.next).getTime();
                if (isNaN(target)) { element.textContent = '-'; return; }
                var difference = Math.round((target - now) / 1000);
                if (difference <= 0) { element.textContent = 'due'; return; }
                var minutes = Math.floor(difference / 60);
                var seconds = difference % 60;
                element.textContent = 'next ' + minutes + 'm ' + String(seconds).padStart(2, '0') + 's';
            });
        }
        updateGraylogCheckTimers();
        window.setInterval(updateGraylogCheckTimers, 1000);
    }
    if (document.readyState === 'loading') { document.addEventListener('DOMContentLoaded', startADMVPNPage, { once: true }); }
    else { startADMVPNPage(); }
}());
