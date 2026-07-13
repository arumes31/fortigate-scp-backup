// searchable.js (Version 1.3)
function initSearchableSelect(selectElement, options = {}) {
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
    wrapper.insertBefore(comboInput, selectElement);

    // Create dropdown container
    const dropdown = document.createElement('div');
    dropdown.className = 'searchable-select-dropdown';
    wrapper.appendChild(dropdown);

    // Store original options from the select element
    const originalOptions = Array.from(selectElement.options).map(opt => ({
        value: opt.value,
        text: opt.text,
        selected: opt.selected,
        optgroup: opt.closest('optgroup') ? opt.closest('optgroup').label : null
    }));

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

        // Render grouped options in defined order
        optgroupOrder.forEach(group => {
            if (groupedOptions[group]) {
                const optgroupLabel = document.createElement('div');
                optgroupLabel.className = 'searchable-optgroup-label';
                optgroupLabel.textContent = group;
                dropdown.appendChild(optgroupLabel);

                groupedOptions[group].forEach(opt => {
                    const option = document.createElement('div');
                    option.className = 'searchable-select-option';
                    if (opt.selected) option.classList.add('selected');
                    option.textContent = opt.text;
                    option.dataset.value = opt.value;
                    option.addEventListener('click', () => {
                        selectElement.value = opt.value;
                        selectElement.dispatchEvent(new Event('change', { bubbles: true }));
                        comboInput.value = opt.text;
                        originalOptions.forEach(o => o.selected = o.value === opt.value);
                        dropdown.style.display = 'none';
                    });
                    dropdown.appendChild(option);
                });
            }
        });

        dropdown.style.display = filteredOptions.length > 0 ? 'block' : 'none';
    }

    // Initialize with current selection
    const selectedOption = originalOptions.find(opt => opt.selected);
    if (selectedOption) {
        comboInput.value = selectedOption.text;
    }

    // Event listeners
    comboInput.addEventListener('focus', () => {
        comboInput.value = ''; // Clear input on focus
        renderDropdown('');
    });

    comboInput.addEventListener('input', () => {
        renderDropdown(comboInput.value);
    });

    // Handle keyboard navigation
    comboInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && dropdown.style.display === 'block') {
            const firstOption = dropdown.querySelector('.searchable-select-option');
            if (firstOption) {
                firstOption.click();
            }
        } else if (e.key === 'Escape') {
            dropdown.style.display = 'none';
            const selected = originalOptions.find(opt => opt.selected);
            comboInput.value = selected ? selected.text : '';
        }
    });

    // Close dropdown when clicking outside
    document.addEventListener('click', (e) => {
        if (!wrapper.contains(e.target)) {
            dropdown.style.display = 'none';
            const selected = originalOptions.find(opt => opt.selected);
            comboInput.value = selected ? selected.text : '';
        }
    });

    // Handle select change from external sources
    selectElement.addEventListener('change', () => {
        const selected = originalOptions.find(opt => opt.value === selectElement.value);
        comboInput.value = selected ? selected.text : '';
        originalOptions.forEach(opt => opt.selected = opt.value === selectElement.value);
        renderDropdown(comboInput.value);
        dropdown.style.display = 'none';
    });

    // Prevent default select behavior
    selectElement.addEventListener('mousedown', (e) => {
        e.preventDefault();
        comboInput.focus();
    });

    // Clear selection only when input is explicitly emptied and confirmed
    comboInput.addEventListener('change', () => {
        if (!comboInput.value.trim()) {
            selectElement.value = '';
            selectElement.dispatchEvent(new Event('change', { bubbles: true }));
            originalOptions.forEach(opt => opt.selected = false);
            dropdown.style.display = 'none';
        }
    });
}