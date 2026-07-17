// searchable.js (Version 1.4)
function initSearchableSelect(selectElement, options = {}) {
    if (selectElement._searchableTeardown) {
        selectElement._searchableTeardown();
    }
    const placeholder = options.placeholder || 'Select an option';

    // Create wrapper for the combo box
    const wrapper = document.createElement('div');
    wrapper.className = 'searchable-select-wrapper';
    selectElement.parentNode.insertBefore(wrapper, selectElement);
    wrapper.appendChild(selectElement);

    // Create single input for both display and filtering
    const comboInput = document.createElement('input');
    comboInput.type = 'text';
    comboInput.className = 'searchable-select-input';
    comboInput.placeholder = placeholder;
    
    // Unique listbox ID for ARIA
    const listboxId = 'listbox-' + Math.random().toString(36).substr(2, 9);
    comboInput.setAttribute('role', 'combobox');
    comboInput.setAttribute('aria-autocomplete', 'list');
    comboInput.setAttribute('aria-expanded', 'false');
    comboInput.setAttribute('aria-haspopup', 'listbox');
    comboInput.setAttribute('aria-controls', listboxId);

    // Carry the select's accessible name over to the combobox input, since
    // the native select is hidden while wrapped.
    const labelledby = selectElement.getAttribute('aria-labelledby');
    const labelEl = (selectElement.id && document.querySelector(`label[for="${CSS.escape(selectElement.id)}"]`))
        || selectElement.closest('label');
    if (labelledby) {
        comboInput.setAttribute('aria-labelledby', labelledby);
    } else if (labelEl) {
        if (!labelEl.id) labelEl.id = listboxId + '-label';
        comboInput.setAttribute('aria-labelledby', labelEl.id);
    } else {
        comboInput.setAttribute('aria-label', selectElement.getAttribute('aria-label') || placeholder);
    }

    // An explicit label association must follow the visible control: while the
    // select is hidden, point the label's for= at the combo input so label
    // clicks focus it. Restored on teardown; wrapping labels (no for=) are
    // left untouched.
    let labelForRestore = null;
    if (labelEl && selectElement.id && labelEl.htmlFor === selectElement.id) {
        comboInput.id = listboxId + '-input';
        labelForRestore = labelEl.htmlFor;
        labelEl.htmlFor = comboInput.id;
    }
    
    wrapper.insertBefore(comboInput, selectElement);

    // Create dropdown container
    const dropdown = document.createElement('div');
    dropdown.className = 'searchable-select-dropdown';
    dropdown.id = listboxId;
    dropdown.setAttribute('role', 'listbox');
    wrapper.appendChild(dropdown);

    // Store original options from the select element
    const originalOptions = Array.from(selectElement.options).map(opt => ({
        value: opt.value,
        text: opt.text,
        selected: opt.selected,
        optgroup: opt.closest('optgroup') ? opt.closest('optgroup').label : null
    }));

    let highlightedElement = null;

    // Helper to set highlighted option
    function highlightOption(el) {
        if (highlightedElement) {
            highlightedElement.classList.remove('highlighted');
        }
        highlightedElement = el;
        if (highlightedElement) {
            highlightedElement.classList.add('highlighted');
            comboInput.setAttribute('aria-activedescendant', highlightedElement.id);
            highlightedElement.scrollIntoView({ block: 'nearest' });
        } else {
            comboInput.removeAttribute('aria-activedescendant');
        }
    }

    // Render dropdown options based on filter
    function renderDropdown(filter = '') {
        dropdown.innerHTML = '';
        const filteredOptions = originalOptions.filter(opt => 
            opt.text.toLowerCase().includes(filter.toLowerCase())
        );

        // Group options by optgroup, preserving order
        const optgroupOrder = ['Addresses', 'Address Groups', 'Internet Services', 'Virtual IPs', 'Users', 'Groups'];
        const groupedOptions = filteredOptions.reduce((acc, opt) => {
            const group = opt.optgroup || 'Ungrouped';
            if (!acc[group]) acc[group] = [];
            acc[group].push(opt);
            return acc;
        }, {});

        // Helper to render a group of options
        function renderGroup(groupName, opts) {
            const optgroupLabel = document.createElement('div');
            optgroupLabel.className = 'searchable-optgroup-label';
            optgroupLabel.textContent = groupName;
            dropdown.appendChild(optgroupLabel);

            opts.forEach(opt => {
                const option = document.createElement('div');
                option.className = 'searchable-select-option';
                option.role = 'option';
                option.id = 'opt-' + Math.random().toString(36).substr(2, 9);
                option.setAttribute('aria-selected', opt.selected ? 'true' : 'false');
                if (opt.selected) option.classList.add('selected');
                option.textContent = opt.text;
                option.dataset.value = opt.value;
                option.addEventListener('click', () => {
                    selectOption(opt);
                });
                dropdown.appendChild(option);
            });
        }

        // Render known groups in order
        optgroupOrder.forEach(group => {
            if (groupedOptions[group] && groupedOptions[group].length > 0) {
                renderGroup(group, groupedOptions[group]);
                delete groupedOptions[group];
            }
        });

        // Render any remaining groups (including Ungrouped or other custom groups)
        Object.keys(groupedOptions).forEach(group => {
            if (groupedOptions[group] && groupedOptions[group].length > 0) {
                renderGroup(group, groupedOptions[group]);
            }
        });

        const hasResults = filteredOptions.length > 0;
        dropdown.style.display = hasResults ? 'block' : 'none';
        comboInput.setAttribute('aria-expanded', hasResults ? 'true' : 'false');
        
        // Auto-highlight selected or first option
        const optionsList = dropdown.querySelectorAll('.searchable-select-option');
        if (optionsList.length > 0) {
            const selectedOptEl = Array.from(optionsList).find(el => el.classList.contains('selected'));
            highlightOption(selectedOptEl || optionsList[0]);
        } else {
            highlightOption(null);
        }
    }

    function selectOption(opt) {
        selectElement.value = opt.value;
        selectElement.dispatchEvent(new Event('change', { bubbles: true }));
        comboInput.value = opt.text;
        originalOptions.forEach(o => o.selected = o.value === opt.value);
        dropdown.style.display = 'none';
        comboInput.setAttribute('aria-expanded', 'false');
        highlightOption(null);
    }

    // Initialize with current selection
    const selectedOption = originalOptions.find(opt => opt.selected);
    if (selectedOption) {
        comboInput.value = selectedOption.text;
    }

    const controller = new AbortController();
    const signal = controller.signal;

    // Event listeners with abort signal
    comboInput.addEventListener('focus', () => {
        const selected = originalOptions.find(opt => opt.selected);
        comboInput.value = selected ? selected.text : '';
        comboInput.select();
        // Show ALL options on focus — filtering by the selected label would
        // leave only the current choice visible; typing narrows from here.
        renderDropdown('');
    }, { signal });

    // Clicking an option must not blur the input (options are not focusable,
    // so the blur would fire focusout and close the dropdown before `click`).
    dropdown.addEventListener('mousedown', (e) => e.preventDefault(), { signal });

    // Tabbing away behaves like clicking outside: restore the selected text,
    // close the dropdown and clear transient filter/highlight state.
    wrapper.addEventListener('focusout', (e) => {
        if (wrapper.contains(e.relatedTarget)) return;
        dropdown.style.display = 'none';
        comboInput.setAttribute('aria-expanded', 'false');
        highlightOption(null);
        const selected = originalOptions.find(opt => opt.selected);
        comboInput.value = selected ? selected.text : '';
    }, { signal });

    comboInput.addEventListener('input', () => {
        renderDropdown(comboInput.value);
    }, { signal });

    // Handle keyboard navigation
    comboInput.addEventListener('keydown', (e) => {
        if (dropdown.style.display !== 'block') {
            if (e.key === 'ArrowDown' || e.key === 'ArrowUp' || e.key === 'Enter') {
                renderDropdown(comboInput.value);
                e.preventDefault();
            }
            return;
        }

        const optionsList = Array.from(dropdown.querySelectorAll('.searchable-select-option'));
        if (optionsList.length === 0) return;

        const currentIndex = optionsList.indexOf(highlightedElement);

        if (e.key === 'ArrowDown') {
            e.preventDefault();
            const nextIndex = (currentIndex + 1) % optionsList.length;
            highlightOption(optionsList[nextIndex]);
        } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            const prevIndex = (currentIndex - 1 + optionsList.length) % optionsList.length;
            highlightOption(optionsList[prevIndex]);
        } else if (e.key === 'Enter') {
            e.preventDefault();
            if (highlightedElement) {
                const val = highlightedElement.dataset.value;
                const opt = originalOptions.find(o => o.value === val);
                if (opt) {
                    selectOption(opt);
                }
            }
        } else if (e.key === 'Escape') {
            e.preventDefault();
            dropdown.style.display = 'none';
            comboInput.setAttribute('aria-expanded', 'false');
            highlightOption(null);
            const selected = originalOptions.find(opt => opt.selected);
            comboInput.value = selected ? selected.text : '';
        }
    }, { signal });

    // Close dropdown when clicking outside
    document.addEventListener('click', (e) => {
        if (!wrapper.contains(e.target)) {
            dropdown.style.display = 'none';
            comboInput.setAttribute('aria-expanded', 'false');
            highlightOption(null);
            const selected = originalOptions.find(opt => opt.selected);
            comboInput.value = selected ? selected.text : '';
        }
    }, { signal });

    // Dismantle teardown logic
    selectElement._searchableTeardown = () => {
        controller.abort();
        if (labelForRestore !== null && labelEl) {
            labelEl.htmlFor = labelForRestore;
        }
        if (wrapper && wrapper.parentNode) {
            wrapper.parentNode.insertBefore(selectElement, wrapper);
            wrapper.remove();
        }
        delete selectElement._searchableTeardown;
    };

    // Handle select change from external sources
    selectElement.addEventListener('change', () => {
        const selected = originalOptions.find(opt => opt.value === selectElement.value);
        comboInput.value = selected ? selected.text : '';
        originalOptions.forEach(opt => opt.selected = opt.value === selectElement.value);
        renderDropdown(comboInput.value);
        dropdown.style.display = 'none';
        comboInput.setAttribute('aria-expanded', 'false');
    }, { signal });

    // Prevent default select behavior
    selectElement.addEventListener('mousedown', (e) => {
        e.preventDefault();
        comboInput.focus();
    }, { signal });

    // Clear selection only when input is explicitly emptied and confirmed
    comboInput.addEventListener('change', () => {
        if (!comboInput.value.trim()) {
            selectElement.value = '';
            selectElement.dispatchEvent(new Event('change', { bubbles: true }));
            originalOptions.forEach(opt => opt.selected = false);
            dropdown.style.display = 'none';
            comboInput.setAttribute('aria-expanded', 'false');
        }
    }, { signal });
}