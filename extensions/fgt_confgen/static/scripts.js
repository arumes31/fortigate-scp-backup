// scripts.js (Version 1.17)
let policies = [];
let interfaces = [];
let addresses = [];
let addressGroups = [];
let internetServices = [];
let vips = [];
let ipPools = [];
let services = [];
let serviceGroups = {};
let sslSshProfiles = [];
let webfilterProfiles = [];
let applicationLists = [];
let avProfiles = [];
let ipsSensors = [];
let users = [];
let groups = [];

function showNotification(message, type = 'success') {
    const container = document.getElementById('notification-container');
    if (!container) {
        console.error('Notification container not found');
        logToBackend('Notification container not found');
        return;
    }

    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;

    container.appendChild(notification);

    setTimeout(() => {
        notification.style.opacity = '0';
        notification.style.transform = 'translateX(100%)';
        setTimeout(() => {
            notification.remove();
        }, 500);
    }, 3000);
}

// New function to send logs to backend
function logToBackend(message) {
    fetch('/fgt-confgen/log', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message })
    }).catch(error => {
        console.error('Error sending log to backend:', error);
    });
}

function addPolicy() {
    const policyId = Date.now().toString();
    policies.push({
        id: policyId,
        name: '',
        comment: '',
        srcInterfaces: [],
        dstInterfaces: [],
        srcAddresses: [],
        srcAddressGroups: [],
        srcInternetServices: [],
        srcVips: [],
        dstAddresses: [],
        dstAddressGroups: [],
        dstInternetServices: [],
        dstVips: [],
        services: [],
        action: 'accept',
        inspectionMode: 'flow',
        ssl_ssh_profile: '',
        webfilter_profile: '',
        webfilter_enabled: true,
        application_list: '',
        application_list_enabled: true,
        av_profile: '',
        av_enabled: false,
        ips_sensor: '',
        ips_sensor_enabled: true,
        logtraffic: 'all',
        logtraffic_start: 'enable',
        auto_asic_offload: 'enable',
        nat: 'disable',
        ip_pool: '',
        users: [],
        groups: []
    });
    renderPolicyList();
    selectPolicy(policyId);
}

function renderPolicyList() {
    const policyList = document.getElementById('policy-list');
    if (!policyList) {
        console.error('Policy list element not found');
        logToBackend('Policy list element not found');
        return;
    }
    policyList.innerHTML = '';
    policies.forEach(policy => {
        const div = document.createElement('div');
        div.className = 'policy-item';

        const span = document.createElement('span');
        span.textContent = policy.name || 'Unnamed Policy';
        span.addEventListener('click', () => selectPolicy(policy.id));
        div.appendChild(span);

        const cloneBtn = document.createElement('button');
        cloneBtn.className = 'clone-btn';
        cloneBtn.textContent = '➕';
        cloneBtn.dataset.policyId = policy.id;
        cloneBtn.setAttribute('aria-label', 'Clone policy');
        cloneBtn.title = 'Clone policy';
        cloneBtn.addEventListener('click', function() { clonePolicy(this); });
        div.appendChild(cloneBtn);

        const deleteBtn = document.createElement('button');
        deleteBtn.className = 'delete-btn';
        deleteBtn.textContent = '🗑️';
        deleteBtn.setAttribute('aria-label', 'Delete policy');
        deleteBtn.title = 'Delete policy';
        deleteBtn.addEventListener('click', () => deletePolicy(policy.id));
        div.appendChild(deleteBtn);

        policyList.appendChild(div);
    });
    const genBtn = document.querySelector('.generate-policies-btn');
    if (genBtn) {
        genBtn.style.display = policies.length > 0 ? 'block' : 'none';
    }
    if (policies.length === 0) {
        document.getElementById('policy-form').style.display = 'none';
        document.getElementById('policy-form-placeholder').style.display = 'block';
        const outSec = document.querySelector('.output-section');
        if (outSec) outSec.style.display = 'none';
    }
}

function toggleProfileFields(selectElement) {
    const form = selectElement.closest('#policy-form');
    if (!form) return;
    const isDeny = selectElement.value === 'deny';
    const fields = ['ssl-ssh-profile', 'webfilter-profile', 'application-list', 'av-profile', 'ips-sensor'];
    
    fields.forEach(field => {
        const select = form.querySelector(`.${field}`);
        const checkbox = form.querySelector(`.toggle-field[data-field="${field}"]`);
        if (select && checkbox) {
            select.disabled = isDeny || !checkbox.checked;
            checkbox.disabled = isDeny;
            if (isDeny) {
                select.value = '';
                checkbox.checked = false;
            }
        }
    });
}

function toggleIpPoolField(selectElement) {
    const form = selectElement.closest('#policy-form');
    if (!form) return;
    const ipPoolSection = form.querySelector('.ip-pool-section');
    if (!ipPoolSection) return;
    ipPoolSection.style.display = selectElement.value === 'enable' ? 'block' : 'none';
}

function selectPolicy(policyId) {
    const policy = policies.find(p => p.id === policyId);
    if (!policy) {
        console.error(`Policy with ID ${policyId} not found`);
        logToBackend(`Policy with ID ${policyId} not found`);
        return;
    }

    const form = document.getElementById('policy-form');
    if (!form) {
        console.error('Policy form element not found');
        logToBackend('Policy form element not found');
        return;
    }
    form.dataset.policyId = policyId;
    document.getElementById('policy-form').style.display = 'block';
    document.getElementById('policy-form-placeholder').style.display = 'none';

    try {
        form.querySelector('.policy-name').value = policy.name || '';
        form.querySelector('.policy-comment').value = policy.comment || '';
        form.querySelector('.action').value = policy.action || 'accept';
        form.querySelector('.inspection-mode').value = policy.inspectionMode || 'flow';
        form.querySelector('.ssl-ssh-profile').value = policy.ssl_ssh_profile || '';
        
        const webfilterCheckbox = form.querySelector('.toggle-field[data-field="webfilter-profile"]');
        const webfilterSelect = form.querySelector('.webfilter-profile');
        webfilterCheckbox.checked = policy.webfilter_enabled;
        webfilterSelect.disabled = !policy.webfilter_enabled || policy.action === 'deny';
        webfilterSelect.value = policy.webfilter_enabled ? (policy.webfilter_profile || '') : '';
        webfilterCheckbox.disabled = policy.action === 'deny';
        
        const appListCheckbox = form.querySelector('.toggle-field[data-field="application-list"]');
        const appListSelect = form.querySelector('.application-list');
        appListCheckbox.checked = policy.application_list_enabled;
        appListSelect.disabled = !policy.application_list_enabled || policy.action === 'deny';
        appListSelect.value = policy.application_list_enabled ? (policy.application_list || '') : '';
        appListCheckbox.disabled = policy.action === 'deny';

        const avCheckbox = form.querySelector('.toggle-field[data-field="av-profile"]');
        const avSelect = form.querySelector('.av-profile');
        avCheckbox.checked = policy.av_enabled;
        avSelect.disabled = !policy.av_enabled || policy.action === 'deny';
        avSelect.value = policy.av_enabled ? (policy.av_profile || '') : '';
        avCheckbox.disabled = policy.action === 'deny';
        
        const ipsSensorCheckbox = form.querySelector('.toggle-field[data-field="ips-sensor"]');
        const ipsSensorSelect = form.querySelector('.ips-sensor');
        ipsSensorCheckbox.checked = policy.ips_sensor_enabled;
        ipsSensorSelect.disabled = !policy.ips_sensor_enabled || policy.action === 'deny';
        ipsSensorSelect.value = policy.ips_sensor_enabled ? (policy.ips_sensor || '') : '';
        ipsSensorCheckbox.disabled = policy.action === 'deny';

        form.querySelector('.logtraffic').value = policy.logtraffic || 'all';
        form.querySelector('.logtraffic-start').value = policy.logtraffic_start || 'enable';
        form.querySelector('.auto-asic-offload').value = policy.auto_asic_offload || 'enable';
        form.querySelector('.nat').value = policy.nat || 'disable';
        form.querySelector('.ip-pool').value = policy.ip_pool || '';
        
        const ipPoolSection = form.querySelector('.ip-pool-section');
        if (ipPoolSection) {
            ipPoolSection.style.display = policy.nat === 'enable' ? 'block' : 'none';
        }

        renderInterfaces(form.querySelector('.src-interfaces .interface-items'), policy.srcInterfaces, 'src');
        renderInterfaces(form.querySelector('.dst-interfaces .interface-items'), policy.dstInterfaces, 'dst');
        renderAddresses(form.querySelector('.src-addresses .address-items'), policy.srcAddresses, policy.srcAddressGroups, policy.srcInternetServices, policy.srcVips, 'src');
        renderAddresses(form.querySelector('.dst-addresses .address-items'), policy.dstAddresses, policy.dstAddressGroups, policy.dstInternetServices, policy.dstVips, 'dst');
        renderServices(form.querySelector('.services .service-items'), policy.services);
        renderUsersGroups(form.querySelector('.src-users-groups .user-group-items'), policy.users, policy.groups);
    } catch (error) {
        console.error('Error in selectPolicy:', error);
        logToBackend(`Error in selectPolicy: ${error.message}`);
    }
}

function renderInterfaces(container, items, type) {
    if (!container) {
        console.error('Interface items container not found');
        logToBackend('Interface items container not found');
        return;
    }
    container.innerHTML = '';
    items.forEach((item, index) => {
        const div = document.createElement('div');
        div.className = 'interface-item';
        div.innerHTML = `
            <select onchange="updateInterface('${type}', ${index}, this.value)">
                <option value="">Select Interface</option>
                ${interfaces.map(intf => `<option value="${intf}" ${item === intf ? 'selected' : ''}>${intf}</option>`).join('')}
            </select>
            <button onclick="deleteInterface('${type}', ${index})">Delete</button>
        `;
        container.appendChild(div);
    });
}

function renderAddresses(container, addrItems, addrGroupItems, isdbItems, vipItems, type) {
    if (!container) {
        console.error('Address items container not found');
        logToBackend('Address items container not found');
        return;
    }
    container.innerHTML = '';
    const allItems = [
        ...addrItems.map(item => ({ type: 'address', value: item })),
        ...addrGroupItems.map(item => ({ type: 'address_group', value: item })),
        ...isdbItems.map(item => ({ type: 'isdb', value: item })),
        ...vipItems.map(item => ({ type: 'vip', value: item }))
    ];

    allItems.forEach((item, index) => {
        const div = document.createElement('div');
        div.className = 'address-item';
        div.innerHTML = `
            <select class="address-select" onchange="updateAddressOrInternetService('${type}', ${index}, this.value)">
                <option value="">Select Address/ISDB</option>
                <optgroup label="Addresses">
                    ${addresses.map(addr => `<option value="address:${addr}" ${item.type === 'address' && item.value === addr ? 'selected' : ''}>${addr}</option>`).join('')}
                </optgroup>
                <optgroup label="Address Groups">
                    ${addressGroups.map(agrp => `<option value="address_group:${agrp}" ${item.type === 'address_group' && item.value === agrp ? 'selected' : ''}>${agrp}</option>`).join('')}
                </optgroup>
                <optgroup label="Internet Services">
                    ${internetServices.map(isdb => `<option value="isdb:${isdb}" ${item.type === 'isdb' && item.value === isdb ? 'selected' : ''}>${isdb}</option>`).join('')}
                </optgroup>
                <optgroup label="Virtual IPs">
                    ${vips.map(vip => `<option value="vip:${vip}" ${item.type === 'vip' && item.value === vip ? 'selected' : ''}>${vip}</option>`).join('')}
                </optgroup>
            </select>
            <button onclick="deleteAddressOrInternetService('${type}', ${index})">Delete</button>
        `;
        container.appendChild(div);
        initSearchableSelect(div.querySelector('.address-select'), {
            placeholder: 'Select Address/ISDB'
        });
    });
}

function renderServices(container, items) {
    if (!container) {
        console.error('Service container not found');
        logToBackend('Service container not found');
        return;
    }
    container.innerHTML = '';
    items.forEach((item, index) => {
        const div = document.createElement('div');
        div.className = 'service-item';
        div.innerHTML = `
            <select onchange="updateService(${index}, this.value)">
                <option value="">Select Service/Group</option>
                <optgroup label="Service Groups">
                    ${Object.keys(serviceGroups).map(group => `<option value="group:${group}" ${item.type === 'group' && item.name === group ? 'selected' : ''}>${group}</option>`).join('')}
                </optgroup>
                <optgroup label="Individual Services">
                    ${services.map(svc => `<option value="template:${svc.name}" ${item.type === 'template' && item.name === svc.name ? 'selected' : ''}>${svc.name}</option>`).join('')}
                </optgroup>
                <optgroup label="Custom">
                    <option value="custom" ${item.type === 'custom' ? 'selected' : ''}>Custom</option>
                </optgroup>
            </select>
            ${item.type === 'custom' ? `
                <input type="text" value="${item.name}" onchange="updateCustomService(${index}, 'name', this.value)" placeholder="Service Name">
                <select onchange="updateCustomService(${index}, 'protocol', this.value)">
                    <option value="TCP" ${item.protocol === 'TCP' ? 'selected' : ''}>TCP</option>
                    <option value="UDP" ${item.protocol === 'UDP' ? 'selected' : ''}>UDP</option>
                    <option value="ICMP" ${item.protocol === 'ICMP' ? 'selected' : ''}>ICMP</option>
                </select>
                <input type="text" value="${item.port}" onchange="updateCustomService(${index}, 'port', this.value)" placeholder="Port">
            ` : ''}
            <button onclick="deleteService(${index})">Delete</button>
        `;
        container.appendChild(div);
    });
}

function renderUsersGroups(container, userItems, groupItems) {
    if (!container) {
        console.error('Users/Groups items container not found');
        logToBackend('Users/Groups items container not found');
        return;
    }
    container.innerHTML = '';
    [...userItems, ...groupItems].forEach((item, index) => {
        const isUser = userItems.includes(item);
        const div = document.createElement('div');
        div.className = 'user-group-item';
        div.innerHTML = `
            <select class="user-group-select" onchange="updateUserOrGroup(${index}, this.value)">
                <option value="">Select User/Group</option>
                <optgroup label="Users">
                    ${users.map(user => `<option value="user:${user}" ${isUser && item === user ? 'selected' : ''}>${user}</option>`).join('')}
                </optgroup>
                <optgroup label="Groups">
                    ${groups.map(group => `<option value="group:${group}" ${!isUser && item === group ? 'selected' : ''}>${group}</option>`).join('')}
                </optgroup>
            </select>
            <button onclick="deleteUserOrGroup(${index})">Delete</button>
        `;
        container.appendChild(div);
        initSearchableSelect(div.querySelector('.user-group-select'), {
            placeholder: 'Select User/Group'
        });
    });
}

function updateDropdowns() {
    const form = document.getElementById('policy-form');
    if (!form) {
        console.error('Policy form not found for updating dropdowns');
        logToBackend('Policy form not found for updating dropdowns');
        return;
    }
    const sslSshSelect = form.querySelector('.ssl-ssh-profile');
    const webfilterSelect = form.querySelector('.webfilter-profile');
    const appListSelect = form.querySelector('.application-list');
    const avSelect = form.querySelector('.av-profile');
    const ipsSensorSelect = form.querySelector('.ips-sensor');
    const ipPoolSelect = form.querySelector('.ip-pool');

    if (!sslSshSelect || !webfilterSelect || !appListSelect || !avSelect || !ipsSensorSelect || !ipPoolSelect) {
        console.error('One or more dropdown elements not found');
        logToBackend('One or more dropdown elements not found');
        return;
    }

    sslSshSelect.innerHTML = `<option value="">None</option>${sslSshProfiles.map(p => `<option value="${p}">${p}</option>`).join('')}`;
    webfilterSelect.innerHTML = `<option value="">None</option>${webfilterProfiles.map(p => `<option value="${p}">${p}</option>`).join('')}`;
    appListSelect.innerHTML = `<option value="">None</option>${applicationLists.map(l => `<option value="${l}">${l}</option>`).join('')}`;
    avSelect.innerHTML = `<option value="">None</option>${avProfiles.map(p => `<option value="${p}">${p}</option>`).join('')}`;
    ipsSensorSelect.innerHTML = `<option value="">None</option>${ipsSensors.map(s => `<option value="${s}">${s}</option>`).join('')}`;
    ipPoolSelect.innerHTML = `<option value="">None</option>${ipPools.map(p => `<option value="${p}">${p}</option>`).join('')}`;

    const policyId = form.dataset.policyId;
    if (policyId) {
        selectPolicy(policyId);
    }
}

function addSrcInterface(button) {
    const policyId = button.closest('#policy-form')?.dataset.policyId;
    if (!policyId) {
        console.error('Policy ID not found for adding source interface');
        logToBackend('Policy ID not found for adding source interface');
        return;
    }
    const policy = policies.find(p => p.id === policyId);
    if (!policy) {
        console.error(`Policy with ID ${policyId} not found`);
        logToBackend(`Policy with ID ${policyId} not found`);
        return;
    }
    policy.srcInterfaces.push('');
    selectPolicy(policyId);
}

function addDstInterface(button) {
    const policyId = button.closest('#policy-form')?.dataset.policyId;
    if (!policyId) {
        console.error('Policy ID not found for adding destination interface');
        logToBackend('Policy ID not found for adding destination interface');
        return;
    }
    const policy = policies.find(p => p.id === policyId);
    if (!policy) {
        console.error(`Policy with ID ${policyId} not found`);
        logToBackend(`Policy with ID ${policyId} not found`);
        return;
    }
    policy.dstInterfaces.push('');
    selectPolicy(policyId);
}

function addSrcAddress(button) {
    const policyId = button.closest('#policy-form')?.dataset.policyId;
    if (!policyId) {
        console.error('Policy ID not found for adding source address/ISDB');
        logToBackend('Policy ID not found for adding source address/ISDB');
        return;
    }
    const policy = policies.find(p => p.id === policyId);
    if (!policy) {
        console.error(`Policy with ID ${policyId} not found`);
        logToBackend(`Policy with ID ${policyId} not found`);
        return;
    }
    policy.srcAddresses.push('');
    selectPolicy(policyId);
}

function addDstAddress(button) {
    const policyId = button.closest('#policy-form')?.dataset.policyId;
    if (!policyId) {
        console.error('Policy ID not found for adding destination address/ISDB');
        logToBackend('Policy ID not found for adding destination address/ISDB');
        return;
    }
    const policy = policies.find(p => p.id === policyId);
    if (!policy) {
        console.error(`Policy with ID ${policyId} not found`);
        logToBackend(`Policy with ID ${policyId} not found`);
        return;
    }
    policy.dstAddresses.push('');
    selectPolicy(policyId);
}

function addService(button) {
    const policyId = button.closest('#policy-form')?.dataset.policyId;
    if (!policyId) {
        console.error('Policy ID not found for adding service');
        logToBackend('Policy ID not found for adding service');
        return;
    }
    const policy = policies.find(p => p.id === policyId);
    if (!policy) {
        console.error(`Policy with ID ${policyId} not found`);
        logToBackend(`Policy with ID ${policyId} not found`);
        return;
    }
    policy.services.push({ type: '', name: '', protocol: 'TCP', port: '' });
    selectPolicy(policyId);
}

function addSrcUserOrGroup(button) {
    const policyId = button.closest('#policy-form')?.dataset.policyId;
    if (!policyId) {
        console.error('Policy ID not found for adding user or group');
        logToBackend('Policy ID not found for adding user or group');
        return;
    }
    const policy = policies.find(p => p.id === policyId);
    if (!policy) {
        console.error(`Policy with ID ${policyId} not found`);
        logToBackend(`Policy with ID ${policyId} not found`);
        return;
    }
    policy.users.push('');
    selectPolicy(policyId);
}

function updateInterface(type, index, value) {
    const policyId = document.getElementById('policy-form')?.dataset.policyId;
    if (!policyId) {
        console.error('Policy ID not found for updating interface');
        logToBackend('Policy ID not found for updating interface');
        return;
    }
    const policy = policies.find(p => p.id === policyId);
    if (!policy) {
        console.error(`Policy with ID ${policyId} not found`);
        logToBackend(`Policy with ID ${policyId} not found`);
        return;
    }
    if (type === 'src') {
        policy.srcInterfaces[index] = value;
    } else {
        policy.dstInterfaces[index] = value;
    }
}

function updateAddressOrInternetService(type, index, value) {
    const policyId = document.getElementById('policy-form')?.dataset.policyId;
    if (!policyId) {
        console.error('Policy ID not found for updating address/ISDB');
        logToBackend('Policy ID not found for updating address/ISDB');
        return;
    }
    const policy = policies.find(p => p.id === policyId);
    if (!policy) {
        console.error(`Policy with ID ${policyId} not found`);
        logToBackend(`Policy with ID ${policyId} not found`);
        return;
    }
    const [itemType, itemValue] = value.split(':');
    const isAddress = itemType === 'address';
    const isAddressGroup = itemType === 'address_group';
    const isInternetService = itemType === 'isdb';
    const isVip = itemType === 'vip';
    
    const addrList = type === 'src' ? policy.srcAddresses : policy.dstAddresses;
    const addrGroupList = type === 'src' ? policy.srcAddressGroups : policy.dstAddressGroups;
    const isdbList = type === 'src' ? policy.srcInternetServices : policy.dstInternetServices;
    const vipList = type === 'src' ? policy.srcVips : policy.dstVips;
    
    const totalLength = addrList.length + addrGroupList.length + isdbList.length + vipList.length;
    
    if (index < addrList.length) {
        if (isAddress) {
            addrList[index] = itemValue;
        } else if (isAddressGroup) {
            addrList.splice(index, 1);
            addrGroupList.splice(index - addrList.length, 0, itemValue);
        } else if (isInternetService) {
            addrList.splice(index, 1);
            isdbList.splice(index - addrList.length, 0, itemValue);
        } else if (isVip) {
            addrList.splice(index, 1);
            vipList.splice(index - addrList.length, 0, itemValue);
        }
    } else if (index < addrList.length + addrGroupList.length) {
        const agrpIndex = index - addrList.length;
        if (isAddressGroup) {
            addrGroupList[agrpIndex] = itemValue;
        } else if (isAddress) {
            addrGroupList.splice(agrpIndex, 1);
            addrList.splice(index, 0, itemValue);
        } else if (isInternetService) {
            addrGroupList.splice(agrpIndex, 1);
            isdbList.splice(index - addrList.length - addrGroupList.length, 0, itemValue);
        } else if (isVip) {
            addrGroupList.splice(agrpIndex, 1);
            vipList.splice(index - addrList.length - addrGroupList.length, 0, itemValue);
        }
    } else if (index < addrList.length + addrGroupList.length + isdbList.length) {
        const isdbIndex = index - addrList.length - addrGroupList.length;
        if (isInternetService) {
            isdbList[isdbIndex] = itemValue;
        } else if (isAddress) {
            isdbList.splice(isdbIndex, 1);
            addrList.splice(index, 0, itemValue);
        } else if (isAddressGroup) {
            isdbList.splice(isdbIndex, 1);
            addrGroupList.splice(index - addrList.length, 0, itemValue);
        } else if (isVip) {
            isdbList.splice(isdbIndex, 1);
            vipList.splice(index - addrList.length - addrGroupList.length, 0, itemValue);
        }
    } else {
        const vipIndex = index - addrList.length - addrGroupList.length - isdbList.length;
        if (isVip) {
            vipList[vipIndex] = itemValue;
        } else if (isAddress) {
            vipList.splice(vipIndex, 1);
            addrList.splice(index, 0, itemValue);
        } else if (isAddressGroup) {
            vipList.splice(vipIndex, 1);
            addrGroupList.splice(index - addrList.length, 0, itemValue);
        } else if (isInternetService) {
            vipList.splice(vipIndex, 1);
            isdbList.splice(index - addrList.length - addrGroupList.length, 0, itemValue);
        }
    }
    selectPolicy(policyId);
}

function updateService(index, value) {
    const policyId = document.getElementById('policy-form')?.dataset.policyId;
    if (!policyId) {
        console.error('Policy ID not found for updating service');
        logToBackend('Policy ID not found for updating service');
        return;
    }
    const policy = policies.find(p => p.id === policyId);
    if (!policy) {
        console.error(`Policy with ID ${policyId} not found`);
        logToBackend(`Policy with ID ${policyId} not found`);
        return;
    }
    const [type, name] = value.split(':');
    if (type === 'custom') {
        policy.services[index] = { type: 'custom', name: '', protocol: 'TCP', port: '' };
    } else if (type === 'group') {
        policy.services[index] = { type: 'group', name: name };
    } else {
        policy.services[index] = { type: 'template', name: name };
    }
    selectPolicy(policyId);
}

function updateCustomService(index, field, value) {
    const policyId = document.getElementById('policy-form')?.dataset.policyId;
    if (!policyId) {
        console.error('Policy ID not found for updating custom service');
        logToBackend('Policy ID not found for updating custom service');
        return;
    }
    const policy = policies.find(p => p.id === policyId);
    if (!policy) {
        console.error(`Policy with ID ${policyId} not found`);
        logToBackend(`Policy with ID ${policyId} not found`);
        return;
    }
    policy.services[index][field] = value;
}

function updateUserOrGroup(index, value) {
    const policyId = document.getElementById('policy-form')?.dataset.policyId;
    if (!policyId) {
        console.error('Policy ID not found for updating user or group');
        logToBackend('Policy ID not found for updating user or group');
        return;
    }
    const policy = policies.find(p => p.id === policyId);
    if (!policy) {
        console.error(`Policy with ID ${policyId} not found`);
        logToBackend(`Policy with ID ${policyId} not found`);
        return;
    }
    const [type, name] = value.split(':');
    if (index < policy.users.length) {
        if (type === 'user') {
            policy.users[index] = name;
        } else if (type === 'group') {
            policy.users.splice(index, 1);
            policy.groups.splice(index - policy.users.length, 0, name);
        }
    } else {
        const groupIndex = index - policy.users.length;
        if (type === 'group') {
            policy.groups[groupIndex] = name;
        } else if (type === 'user') {
            policy.groups.splice(groupIndex, 1);
            policy.users.splice(index, 0, name);
        }
    }
    selectPolicy(policyId);
}

function deleteInterface(type, index) {
    const policyId = document.getElementById('policy-form')?.dataset.policyId;
    if (!policyId) {
        console.error('Policy ID not found for deleting interface');
        logToBackend('Policy ID not found for deleting interface');
        return;
    }
    const policy = policies.find(p => p.id === policyId);
    if (!policy) {
        console.error(`Policy with ID ${policyId} not found`);
        logToBackend(`Policy with ID ${policyId} not found`);
        return;
    }
    if (type === 'src') {
        policy.srcInterfaces.splice(index, 1);
    } else {
        policy.dstInterfaces.splice(index, 1);
    }
    selectPolicy(policyId);
}

function deleteAddressOrInternetService(type, index) {
    const policyId = document.getElementById('policy-form')?.dataset.policyId;
    if (!policyId) {
        console.error('Policy ID not found for deleting address/ISDB');
        logToBackend('Policy ID not found for deleting address/ISDB');
        return;
    }
    const policy = policies.find(p => p.id === policyId);
    if (!policy) {
        console.error(`Policy with ID ${policyId} not found`);
        logToBackend(`Policy with ID ${policyId} not found`);
        return;
    }
    const addrList = type === 'src' ? policy.srcAddresses : policy.dstAddresses;
    const addrGroupList = type === 'src' ? policy.srcAddressGroups : policy.dstAddressGroups;
    const isdbList = type === 'src' ? policy.srcInternetServices : policy.dstInternetServices;
    const vipList = type === 'src' ? policy.srcVips : policy.dstVips;
    
    if (index < addrList.length) {
        addrList.splice(index, 1);
    } else if (index < addrList.length + addrGroupList.length) {
        addrGroupList.splice(index - addrList.length, 1);
    } else if (index < addrList.length + addrGroupList.length + isdbList.length) {
        isdbList.splice(index - addrList.length - addrGroupList.length, 1);
    } else {
        vipList.splice(index - addrList.length - addrGroupList.length - isdbList.length, 1);
    }
    selectPolicy(policyId);
}

function deleteService(index) {
    const policyId = document.getElementById('policy-form')?.dataset.policyId;
    if (!policyId) {
        console.error('Policy ID not found for deleting service');
        logToBackend('Policy ID not found for deleting service');
        return;
    }
    const policy = policies.find(p => p.id === policyId);
    if (!policy) {
        console.error(`Policy with ID ${policyId} not found`);
        logToBackend(`Policy with ID ${policyId} not found`);
        return;
    }
    policy.services.splice(index, 1);
    selectPolicy(policyId);
}

function deleteUserOrGroup(index) {
    const policyId = document.getElementById('policy-form')?.dataset.policyId;
    if (!policyId) {
        console.error('Policy ID not found for deleting user or group');
        logToBackend('Policy ID not found for deleting user or group');
        return;
    }
    const policy = policies.find(p => p.id === policyId);
    if (!policy) {
        console.error(`Policy with ID ${policyId} not found`);
        logToBackend(`Policy with ID ${policyId} not found`);
        return;
    }
    if (index < policy.users.length) {
        policy.users.splice(index, 1);
    } else {
        policy.groups.splice(index - policy.users.length, 1);
    }
    selectPolicy(policyId);
}

function deletePolicy(policyId) {
    policies = policies.filter(p => p.id !== policyId);
    renderPolicyList();
    if (policies.length > 0) {
        selectPolicy(policies[0].id);
    } else {
        clearForm();
    }
}

function savePolicy(button) {
    console.log('savePolicy triggered');
    logToBackend('savePolicy triggered');
    try {
        const policyId = button.closest('#policy-form')?.dataset.policyId;
        if (!policyId) {
            console.error('Policy ID not found in form dataset');
            logToBackend('Policy ID not found in form dataset');
            showNotification('Error: Policy ID not found', 'error');
            return;
        }
        console.log('Policy ID:', policyId);
        logToBackend(`Policy ID: ${policyId}`);

        const policy = policies.find(p => p.id === policyId);
        if (!policy) {
            console.error(`Policy with ID ${policyId} not found`);
            logToBackend(`Policy with ID ${policyId} not found`);
            showNotification('Error: Policy not found', 'error');
            return;
        }
        console.log('Policy found:', policy);
        logToBackend(`Policy found with ID: ${policyId}`);

        const form = button.closest('#policy-form');
        if (!form) {
            console.error('Policy form not found');
            logToBackend('Policy form not found');
            showNotification('Error: Policy form not found', 'error');
            return;
        }
        console.log('Form found');
        logToBackend('Form found');

        const policyName = form.querySelector('.policy-name')?.value || '';
        const policyComment = form.querySelector('.policy-comment')?.value || '';
        const action = form.querySelector('.action')?.value || 'accept';
        const inspectionMode = form.querySelector('.inspection-mode')?.value || 'flow';
        const sslSshProfile = action === 'deny' ? '' : (form.querySelector('.ssl-ssh-profile')?.value || '');
        const webfilterProfile = form.querySelector('.webfilter-profile');
        const webfilterEnabled = action === 'deny' ? false : form.querySelector('.toggle-field[data-field="webfilter-profile"]').checked;
        const applicationList = form.querySelector('.application-list');
        const applicationListEnabled = action === 'deny' ? false : form.querySelector('.toggle-field[data-field="application-list"]').checked;
        const avProfile = form.querySelector('.av-profile');
        const avEnabled = action === 'deny' ? false : form.querySelector('.toggle-field[data-field="av-profile"]').checked;
        const ipsSensor = form.querySelector('.ips-sensor');
        const ipsSensorEnabled = action === 'deny' ? false : form.querySelector('.toggle-field[data-field="ips-sensor"]').checked;
        const logtraffic = form.querySelector('.logtraffic')?.value || 'all';
        const logtrafficStart = form.querySelector('.logtraffic-start')?.value || 'enable';
        const autoAsicOffload = form.querySelector('.auto-asic-offload')?.value || 'enable';
        const nat = form.querySelector('.nat')?.value || 'disable';
        const ipPool = nat === 'enable' ? (form.querySelector('.ip-pool')?.value || '') : '';

        console.log('Form values:', {
            policyName,
            policyComment,
            action,
            inspectionMode,
            sslSshProfile,
            webfilterProfile: webfilterProfile.value,
            webfilterEnabled,
            applicationList: applicationList.value,
            applicationListEnabled,
            avProfile: avProfile.value,
            avEnabled,
            ipsSensor: ipsSensor.value,
            ipsSensorEnabled,
            logtraffic,
            logtrafficStart,
            autoAsicOffload,
            nat,
            ipPool
        });

        policy.name = policyName;
        policy.comment = policyComment;
        policy.action = action;
        policy.inspectionMode = inspectionMode;
        policy.ssl_ssh_profile = sslSshProfile;
        policy.webfilter_enabled = webfilterEnabled;
        policy.webfilter_profile = webfilterEnabled ? webfilterProfile.value : '';
        policy.application_list_enabled = applicationListEnabled;
        policy.application_list = applicationListEnabled ? applicationList.value : '';
        policy.av_enabled = avEnabled;
        policy.av_profile = avEnabled ? avProfile.value : '';
        policy.ips_sensor_enabled = ipsSensorEnabled;
        policy.ips_sensor = ipsSensorEnabled ? ipsSensor.value : '';
        policy.logtraffic = logtraffic;
        policy.logtraffic_start = logtrafficStart;
        policy.auto_asic_offload = autoAsicOffload;
        policy.nat = nat;
        policy.ip_pool = ipPool;

        console.log('Policy updated:', policy);
        logToBackend(`Policy updated with ID: ${policyId}`);

        renderPolicyList();
        selectPolicy(policyId);
        console.log('Policy saved successfully');
        logToBackend('Policy saved successfully');
        showNotification('Policy saved successfully', 'success');
    } catch (error) {
        console.error('Error in savePolicy:', error);
        logToBackend(`Error in savePolicy: ${error.message}`);
        showNotification('Error saving policy: ' + error.message, 'error');
    }
}

function clonePolicy(button) {
    const policyId = button.closest('#policy-form')?.dataset.policyId || button.dataset.policyId;
    if (!policyId) {
        console.error('Policy ID not found for cloning policy');
        logToBackend('Policy ID not found for cloning policy');
        return;
    }
    fetch('/fgt-confgen/clone_policy', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ policy_id: policyId })
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            const isGlobalCheckbox = document.getElementById('template-global');
            if (isGlobalCheckbox) {
                isGlobalCheckbox.checked = data.is_global || false;
            }
            policies.push({
                id: data.new_policy.policy_id,
                name: data.new_policy.policy_name,
                comment: data.new_policy.policy_comment,
                srcInterfaces: data.new_policy.src_interfaces,
                dstInterfaces: data.new_policy.dst_interfaces,
                srcAddresses: data.new_policy.src_addresses,
                srcAddressGroups: data.new_policy.src_address_groups,
                srcInternetServices: data.new_policy.src_internet_services,
                srcVips: data.new_policy.src_vips,
                dstAddresses: data.new_policy.dst_addresses,
                dstAddressGroups: data.new_policy.dst_address_groups,
                dstInternetServices: data.new_policy.dst_internet_services,
                dstVips: data.new_policy.dst_vips,
                services: data.new_policy.services,
                action: data.new_policy.action,
                inspectionMode: data.new_policy.inspection_mode,
                ssl_ssh_profile: data.new_policy.ssl_ssh_profile,
                webfilter_profile: data.new_policy.webfilter_profile,
                webfilter_enabled: data.new_policy.webfilter_enabled,
                application_list: data.new_policy.application_list,
                application_list_enabled: data.new_policy.application_list_enabled,
                av_profile: data.new_policy.av_profile,
                av_enabled: data.new_policy.av_enabled,
                ips_sensor: data.new_policy.ips_sensor,
                ips_sensor_enabled: data.new_policy.ips_sensor_enabled,
                logtraffic: data.new_policy.logtraffic,
                logtraffic_start: data.new_policy.logtraffic_start,
                auto_asic_offload: data.new_policy.auto_asic_offload,
                nat: data.new_policy.nat,
                ip_pool: data.new_policy.ip_pool,
                users: data.new_policy.users,
                groups: data.new_policy.groups
            });
            renderPolicyList();
            selectPolicy(data.new_policy.policy_id);
            showNotification('Policy cloned successfully', 'success');
            logToBackend('Policy cloned successfully');
        } else {
            console.error('Error cloning policy:', data.error);
            logToBackend(`Error cloning policy: ${data.error}`);
            showNotification('Error cloning policy: ' + data.error, 'error');
        }
    })
    .catch(error => {
        console.error('Error cloning policy:', error);
        logToBackend(`Error cloning policy: ${error.message}`);
        showNotification('Error cloning policy', 'error');
    });
}

function clearForm(button) {
    const form = button ? button.closest('#policy-form') : document.getElementById('policy-form');
    if (!form) {
        console.error('Policy form not found for clearing');
        logToBackend('Policy form not found for clearing');
        return;
    }
    form.querySelector('.policy-name').value = '';
    form.querySelector('.policy-comment').value = '';
    form.querySelector('.action').value = 'accept';
    form.querySelector('.inspection-mode').value = 'flow';
    form.querySelector('.ssl-ssh-profile').value = '';
    
    const webfilterCheckbox = form.querySelector('.toggle-field[data-field="webfilter-profile"]');
    const webfilterSelect = form.querySelector('.webfilter-profile');
    webfilterCheckbox.checked = true;
    webfilterSelect.disabled = false;
    webfilterSelect.value = '';
    webfilterCheckbox.disabled = false;
    
    const appListCheckbox = form.querySelector('.toggle-field[data-field="application-list"]');
    const appListSelect = form.querySelector('.application-list');
    appListCheckbox.checked = true;
    appListSelect.disabled = false;
    appListSelect.value = '';
    appListCheckbox.disabled = false;

    const avCheckbox = form.querySelector('.toggle-field[data-field="av-profile"]');
    const avSelect = form.querySelector('.av-profile');
    avCheckbox.checked = false;
    avSelect.disabled = true;
    avSelect.value = '';
    avCheckbox.disabled = false;
    
    const ipsSensorCheckbox = form.querySelector('.toggle-field[data-field="ips-sensor"]');
    const ipsSensorSelect = form.querySelector('.ips-sensor');
    ipsSensorCheckbox.checked = true;
    ipsSensorSelect.disabled = false;
    ipsSensorSelect.value = '';
    ipsSensorCheckbox.disabled = false;

    form.querySelector('.logtraffic').value = 'all';
    form.querySelector('.logtraffic-start').value = 'enable';
    form.querySelector('.auto-asic-offload').value = 'enable';
    form.querySelector('.nat').value = 'disable';
    form.querySelector('.ip-pool').value = '';
    form.querySelector('.src-interfaces .interface-items').innerHTML = '';
    form.querySelector('.dst-interfaces .interface-items').innerHTML = '';
    form.querySelector('.src-addresses .address-items').innerHTML = '';
    form.querySelector('.dst-addresses .address-items').innerHTML = '';
    form.querySelector('.services .service-items').innerHTML = '';
    form.querySelector('.src-users-groups .user-group-items').innerHTML = '';
    form.querySelector('.ip-pool-section').style.display = 'none';

    const policyId = form.dataset.policyId;
    const policy = policies.find(p => p.id === policyId);
    if (policy) {
        policy.name = '';
        policy.comment = '';
        policy.action = 'accept';
        policy.ssl_ssh_profile = '';
        policy.logtraffic = 'all';
        policy.logtraffic_start = 'enable';
        policy.auto_asic_offload = 'enable';
        policy.nat = 'disable';
        policy.srcInterfaces = [];
        policy.dstInterfaces = [];
        policy.srcAddresses = [];
        policy.srcAddressGroups = [];
        policy.srcInternetServices = [];
        policy.srcVips = [];
        policy.dstAddresses = [];
        policy.dstAddressGroups = [];
        policy.dstInternetServices = [];
        policy.dstVips = [];
        policy.services = [];
        policy.users = [];
        policy.groups = [];
        policy.inspectionMode = 'flow';
        policy.webfilter_enabled = true;
        policy.webfilter_profile = '';
        policy.application_list_enabled = true;
        policy.application_list = '';
        policy.av_enabled = false;
        policy.av_profile = '';
        policy.ips_sensor_enabled = true;
        policy.ips_sensor = '';
        policy.ip_pool = '';
        renderPolicyList();
    }
}

function saveTemplate() {
    const templateName = document.getElementById('template-name')?.value;
    if (!templateName) {
        console.error('Template name not provided');
        logToBackend('Template name not provided');
        showNotification('Please enter a template name', 'error');
        return;
    }
    const formData = new FormData();
    formData.append('template_name', templateName);
    formData.append('is_global', document.getElementById('template-global')?.checked ? 'true' : 'false');
    formData.append('policies', JSON.stringify(policies.map(p => ({
        policy_id: p.id,
        policy_name: p.name,
        policy_comment: p.comment,
        src_interfaces: p.srcInterfaces,
        dst_interfaces: p.dstInterfaces,
        src_addresses: p.srcAddresses,
        src_address_groups: p.srcAddressGroups,
        src_internet_services: p.srcInternetServices,
        src_vips: p.srcVips,
        dst_addresses: p.dstAddresses,
        dst_address_groups: p.dstAddressGroups,
        dst_internet_services: p.dstInternetServices,
        dst_vips: p.dstVips,
        services: p.services,
        action: p.action,
        inspection_mode: p.inspectionMode,
        ssl_ssh_profile: p.ssl_ssh_profile,
        webfilter_profile: p.webfilter_enabled ? p.webfilter_profile : '',
        webfilter_enabled: p.webfilter_enabled,
        application_list: p.application_list_enabled ? p.application_list : '',
        application_list_enabled: p.application_list_enabled,
        av_profile: p.av_enabled ? p.av_profile : '',
        av_enabled: p.av_enabled,
        ips_sensor: p.ips_sensor_enabled ? p.ips_sensor : '',
        ips_sensor_enabled: p.ips_sensor_enabled,
        logtraffic: p.logtraffic,
        logtraffic_start: p.logtraffic_start,
        auto_asic_offload: p.auto_asic_offload,
        nat: p.nat,
        ip_pool: p.ip_pool,
        users: p.users,
        groups: p.groups
    }))));

    fetch('/fgt-confgen/save_template', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        showNotification(data.message, 'success');
        logToBackend(`Template saved: ${data.message}`);
        loadTemplateList();
    })
    .catch(error => {
        console.error('Error saving template:', error);
        logToBackend(`Error saving template: ${error.message}`);
        showNotification('Error saving template', 'error');
    });
}

function loadTemplateList() {
    return new Promise((resolve, reject) => {
        console.log('Loading template list, checking for preselected template:', window.preselectedTemplate);
        logToBackend(`Loading template list, preselected template: ${window.preselectedTemplate || 'none'}`);
        fetch('/fgt-confgen/load_templates')
        .then(response => response.json())
        .then(data => {
            const select = document.getElementById('template-select');
            if (!select) {
                console.error('Template select element not found');
                logToBackend('Template select element not found');
                reject('Template select element not found');
                return;
            }
            select.innerHTML = '<option value="">Select Template</option>';
            data.templates.forEach(template => {
                const option = document.createElement('option');
                option.value = template;
                option.textContent = template;
                select.appendChild(option);
            });
            console.log('Templates loaded:', data.templates);
            logToBackend(`Templates loaded: ${JSON.stringify(data.templates)}`);
            if (window.preselectedTemplate) {
                console.log('Attempting to select preselected template:', window.preselectedTemplate);
                logToBackend(`Attempting to select preselected template: ${window.preselectedTemplate}`);
                if (data.templates.includes(window.preselectedTemplate)) {
                    select.value = window.preselectedTemplate;
                    console.log(`Preselected template ${window.preselectedTemplate} found, loading template`);
                    logToBackend(`Preselected template ${window.preselectedTemplate} found, loading template`);
                    loadTemplate();
                } else {
                    console.warn(`Preselected template "${window.preselectedTemplate}" not found in available templates:`, data.templates);
                    logToBackend(`Preselected template "${window.preselectedTemplate}" not found in available templates: ${JSON.stringify(data.templates)}`);
                    showNotification(`Template "${window.preselectedTemplate}" not found`, 'error');
                    // Clear preselected template to prevent repeated attempts
                    window.preselectedTemplate = null;
                }
            } else {
                console.log('No preselected template provided');
                logToBackend('No preselected template provided');
            }
            resolve();
        })
        .catch(error => {
            console.error('Error loading templates:', error);
            logToBackend(`Error loading templates: ${error.message}`);
            showNotification('Error loading templates', 'error');
            reject(error);
        });
    });
}

function loadTemplate() {
    const select = document.getElementById('template-select');
    const templateName = select?.value;
    if (!templateName) {
        console.error('No template selected');
        logToBackend('No template selected');
        showNotification('Please select a template', 'error');
        return;
    }
    console.log(`Loading template: ${templateName}`);
    logToBackend(`Loading template: ${templateName}`);
    fetch(`/fgt-confgen/get_template/${templateName}`)
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            const isGlobalCheckbox = document.getElementById('template-global');
            if (isGlobalCheckbox) {
                isGlobalCheckbox.checked = data.is_global || false;
            }
            console.log(`Template ${templateName} data received`);
            logToBackend(`Template ${templateName} data received`);
            policies = data.data.policies.map(p => ({
                id: p.policy_id,
                name: p.policy_name,
                comment: p.policy_comment,
                srcInterfaces: p.src_interfaces,
                dstInterfaces: p.dst_interfaces,
                srcAddresses: p.src_addresses,
                srcAddressGroups: p.src_address_groups || [],
                srcInternetServices: p.src_internet_services || [],
                srcVips: p.src_vips || [],
                dstAddresses: p.dst_addresses,
                dstAddressGroups: p.dst_address_groups || [],
                dstInternetServices: p.dst_internet_services || [],
                dstVips: p.dst_vips || [],
                services: p.services,
                action: p.action,
                inspectionMode: p.inspection_mode || 'flow',
                ssl_ssh_profile: p.ssl_ssh_profile,
                webfilter_profile: p.webfilter_profile,
                webfilter_enabled: p.webfilter_enabled !== undefined ? p.webfilter_enabled : true,
                application_list: p.application_list,
                application_list_enabled: p.application_list_enabled !== undefined ? p.application_list_enabled : true,
                av_profile: p.av_profile,
                av_enabled: p.av_enabled !== undefined ? p.av_enabled : false,
                ips_sensor: p.ips_sensor,
                ips_sensor_enabled: p.ips_sensor_enabled !== undefined ? p.ips_sensor_enabled : true,
                logtraffic: p.logtraffic,
                logtraffic_start: p.logtraffic_start,
                auto_asic_offload: p.auto_asic_offload,
                nat: p.nat,
                ip_pool: p.ip_pool || '',
                users: p.users || [],
                groups: p.groups || []
            }));

            interfaces = data.config.interfaces || [];
            addresses = data.config.addresses || [];
            addressGroups = data.config.address_groups || [];
            internetServices = data.config.internet_services || [];
            vips = data.config.vips || [];
            ipPools = data.config.ip_pools || [];
            services = data.config.services || [];
            serviceGroups = data.config.service_groups || {};
            sslSshProfiles = data.config.ssl_ssh_profiles || [];
            webfilterProfiles = data.config.webfilter_profiles || [];
            applicationLists = data.config.application_lists || [];
            avProfiles = data.config.av_profiles || [];
            ipsSensors = data.config.ips_sensors || [];
            users = data.config.users || [];
            groups = data.config.groups || [];

            try {
                fetch('/fgt-confgen/parse_config', { method: 'POST', body: new FormData() })
                    .then(res => res.json())
                    .then(config => {
                        interfaces = [...new Set([...interfaces, ...(config.interfaces || [])])];
                        addresses = [...new Set([...addresses, ...(config.addresses || [])])];
                        addressGroups = [...new Set([...addressGroups, ...(config.address_groups || [])])];
                        internetServices = [...new Set([...internetServices, ...(config.internet_services || [])])];
                        vips = [...new Set([...vips, ...(config.vips || [])])];
                        ipPools = [...new Set([...ipPools, ...(config.ip_pools || [])])];
                        services = [...services, ...(config.services || []).filter(s => !services.some(existing => existing.name === s.name))];
                        serviceGroups = { ...serviceGroups, ...(config.service_groups || {}) };
                        sslSshProfiles = [...new Set([...sslSshProfiles, ...(config.ssl_ssh_profiles || [])])];
                        webfilterProfiles = [...new Set([...webfilterProfiles, ...(config.webfilter_profiles || [])])];
                        applicationLists = [...new Set([...applicationLists, ...(config.application_lists || [])])];
                        avProfiles = [...new Set([...avProfiles, ...(config.av_profiles || [])])];
                        ipsSensors = [...new Set([...ipsSensors, ...(config.ips_sensors || [])])];
                        users = [...new Set([...users, ...(config.users || [])])];
                        groups = [...new Set([...groups, ...(config.groups || [])])];
                        updateDropdowns();
                        renderPolicyList();
                        if (policies.length > 0) {
                            selectPolicy(policies[0].id);
                        }
                        const templateNameInput = document.getElementById('template-name');
                        if (templateNameInput) {
                            templateNameInput.value = templateName;
                        }
                        showNotification(`Template '${templateName}' loaded successfully`, 'success');
                        logToBackend(`Template '${templateName}' loaded successfully`);
                    })
                    .catch(() => {
                        updateDropdowns();
                        renderPolicyList();
                        if (policies.length > 0) {
                            selectPolicy(policies[0].id);
                        }
                        const templateNameInput = document.getElementById('template-name');
                        if (templateNameInput) {
                            templateNameInput.value = templateName;
                        }
                        showNotification(`Template '${templateName}' loaded successfully`, 'success');
                        logToBackend(`Template '${templateName}' loaded successfully`);
                    });
            } catch (error) {
                console.error('Error merging config data:', error);
                logToBackend(`Error merging config data: ${error.message}`);
                updateDropdowns();
                renderPolicyList();
                if (policies.length > 0) {
                    selectPolicy(policies[0].id);
                }
                const templateNameInput = document.getElementById('template-name');
                if (templateNameInput) {
                    templateNameInput.value = templateName;
                }
                showNotification(`Template '${templateName}' loaded successfully`, 'success');
                logToBackend(`Template '${templateName}' loaded successfully`);
            }
        } else {
            console.error('Error loading template:', data.error);
            logToBackend(`Error loading template: ${data.error}`);
            showNotification('Error loading template: ' + data.error, 'error');
        }
    })
    .catch(error => {
        console.error('Error loading template:', error);
        logToBackend(`Error loading template: ${error.message}`);
        showNotification('Error loading template', 'error');
    });
}

function cloneTemplate() {
    const templateName = document.getElementById('template-select')?.value;
    if (!templateName) {
        console.error('No template selected for cloning');
        logToBackend('No template selected for cloning');
        showNotification('Please select a template to clone', 'error');
        return;
    }
    fetch(`/fgt-confgen/clone_template/${templateName}`, {
        method: 'POST'
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            const isGlobalCheckbox = document.getElementById('template-global');
            if (isGlobalCheckbox) {
                isGlobalCheckbox.checked = data.is_global || false;
            }
            showNotification(`Template cloned as ${data.new_template_name}`, 'success');
            logToBackend(`Template cloned as ${data.new_template_name}`);
            loadTemplateList();
        } else {
            console.error('Error cloning template:', data.error);
            logToBackend(`Error cloning template: ${data.error}`);
            showNotification('Error cloning template: ' + data.error, 'error');
        }
    })
    .catch(error => {
        console.error('Error cloning template:', error);
        logToBackend(`Error cloning template: ${error.message}`);
        showNotification('Error cloning template', 'error');
    });
}

function deleteTemplate() {
    const templateName = document.getElementById('template-select')?.value;
    if (!templateName) {
        console.error('No template selected for deletion');
        logToBackend('No template selected for deletion');
        showNotification('Please select a template', 'error');
        return;
    }
    if (confirm(`Are you sure you want to delete ${templateName}?`)) {
        fetch(`/fgt-confgen/delete_template/${templateName}?is_global=` + (document.getElementById('template-global')?.checked ? 'true' : 'false'), {
            method: 'DELETE'
        })
        .then(response => response.json())
        .then(data => {
            showNotification(data.message, 'success');
            logToBackend(`Template deleted: ${data.message}`);
            loadTemplateList();
            const templateNameInput = document.getElementById('template-name');
            if (templateNameInput) {
                templateNameInput.value = '';
            }
        })
        .catch(error => {
            console.error('Error deleting template:', error);
            logToBackend(`Error deleting template: ${error.message}`);
            showNotification('Error deleting template', 'error');
        });
    }
}

function renameTemplate() {
    const oldName = document.getElementById('template-select')?.value;
    const newName = document.getElementById('template-name')?.value;

    if (!oldName) {
        console.error('No template selected for renaming');
        logToBackend('No template selected for renaming');
        showNotification('Please select a template to rename', 'error');
        return;
    }
    if (!newName) {
        console.error('New template name not provided');
        logToBackend('New template name not provided');
        showNotification('Please enter a new template name', 'error');
        return;
    }
    if (oldName === newName) {
        console.warn('Old and new template names are the same');
        logToBackend('Old and new template names are the same');
        showNotification('The new template name is the same as the current name', 'error');
        return;
    }

    fetch('/fgt-confgen/rename_template', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ old_name: oldName, new_name: newName, is_global: document.getElementById('template-global')?.checked || false })
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            const isGlobalCheckbox = document.getElementById('template-global');
            if (isGlobalCheckbox) {
                isGlobalCheckbox.checked = data.is_global || false;
            }
            showNotification(`Template renamed to ${newName}`, 'success');
            logToBackend(`Template renamed to ${newName}`);
            window.preselectedTemplate = newName;
            loadTemplateList();
        } else {
            console.error('Error renaming template:', data.error);
            logToBackend(`Error renaming template: ${data.error}`);
            showNotification('Error renaming template: ' + data.error, 'error');
        }
    })
    .catch(error => {
        console.error('Error renaming template:', error);
        logToBackend(`Error renaming template: ${error.message}`);
        showNotification('Error renaming template', 'error');
    });
}

function copyUrl() {
    const templateName = document.getElementById('template-select')?.value;
    if (!templateName) {
        console.error('No template selected for copying URL');
        logToBackend('No template selected for copying URL');
        showNotification('Please select a template to copy its URL', 'error');
        return;
    }

    const templateUrl = `/fgt-confgen/get_template/${templateName}`;
    console.log(`Generating URL for: ${templateUrl}`);
    logToBackend(`Generating URL for: ${templateUrl}`);

    fetch('/fgt-confgen/shorten_url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: templateUrl })
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            const isGlobalCheckbox = document.getElementById('template-global');
            if (isGlobalCheckbox) {
                isGlobalCheckbox.checked = data.is_global || false;
            }
            const shortCode = data.short_code;
            const shortUrl = `${window.location.origin}/fgt-confgen/s/${shortCode}`;
            console.log(`URL generated: ${shortUrl}`);
            logToBackend(`URL generated: ${shortUrl}`);

            navigator.clipboard.writeText(shortUrl)
                .then(() => {
                    console.log(`Successfully copied URL: ${shortUrl}`);
                    logToBackend(`Successfully copied URL: ${shortUrl}`);
                    showNotification('URL copied to clipboard', 'success');
                })
                .catch(error => {
                    console.error('Error copying URL:', error.message);
                    logToBackend(`Error copying URL: ${error.message}`);
                    if (error.message.includes('secure context')) {
                        console.error('Clipboard API requires a secure context (HTTPS or localhost). Ensure the page is served over HTTPS.');
                        logToBackend('Clipboard API requires a secure context (HTTPS or localhost). Ensure the page is served over HTTPS.');
                        showNotification('Error copying URL: This feature requires a secure context (HTTPS or localhost)', 'error');
                    } else if (error.message.includes('permission')) {
                        console.error('Clipboard access denied. Check browser permissions for clipboard access.');
                        logToBackend('Clipboard access denied. Check browser permissions for clipboard access.');
                        showNotification('Error copying URL: Clipboard access denied. Please allow clipboard permissions in your browser', 'error');
                    } else {
                        showNotification('Error copying URL: ' + error.message, 'error');
                    }
                });
        } else {
            console.error('Error generating URL:', data.error);
            logToBackend(`Error generating URL: ${data.error}`);
            showNotification('Error generating URL: ' + data.error, 'error');
        }
    })
    .catch(error => {
        console.error('Error generating URL:', error);
        logToBackend(`Error generating URL: ${error.message}`);
        showNotification('Error generating URL', 'error');
    });
}

function importTemplate(event) {
    const fileInput = event.target;
    if (!fileInput?.files.length) {
        console.error('No template file selected');
        logToBackend('No template file selected');
        showNotification('Please select a JSON file to import', 'error');
        return;
    }

    const file = fileInput.files[0];
    const reader = new FileReader();

    reader.onload = function(e) {
        try {
            const templateData = JSON.parse(e.target.result);
            if (!templateData.name || !templateData.data || !templateData.data.policies) {
                throw new Error('Invalid template format: Must contain name and data with policies');
            }

            const formData = new FormData();
            formData.append('template_name', templateData.name);
            formData.append('template_data', JSON.stringify(templateData.data));

            fetch('/fgt-confgen/import_template', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
            const isGlobalCheckbox = document.getElementById('template-global');
            if (isGlobalCheckbox) {
                isGlobalCheckbox.checked = data.is_global || false;
            }
                    showNotification(`Template '${templateData.name}' imported successfully`, 'success');
                    logToBackend(`Template '${templateData.name}' imported successfully`);
                    loadTemplateList();
                    fileInput.value = '';
                } else {
                    console.error('Error importing template:', data.error);
                    logToBackend(`Error importing template: ${data.error}`);
                    showNotification('Error importing template: ' + data.error, 'error');
                }
            })
            .catch(error => {
                console.error('Error importing template:', error);
                logToBackend(`Error importing template: ${error.message}`);
                showNotification('Error importing template', 'error');
            });
        } catch (error) {
            console.error('Error parsing template file:', error);
            logToBackend(`Error parsing template file: ${error.message}`);
            showNotification('Error parsing template file: ' + error.message, 'error');
        }
    };

    reader.onerror = function() {
        console.error('Error reading template file');
        logToBackend('Error reading template file');
        showNotification('Error reading template file', 'error');
    };

    reader.readAsText(file);
}

function exportTemplate() {
    const templateName = document.getElementById('template-select')?.value;
    if (!templateName) {
        console.error('No template selected for export');
        logToBackend('No template selected for export');
        showNotification('Please select a template to export', 'error');
        return;
    }

    fetch(`/fgt-confgen/export_template/${templateName}`)
    .then(response => {
        if (!response.ok) {
            return response.json().then(data => {
                throw new Error(data.error || 'Failed to export template');
            });
        }
        return response.blob();
    })
    .then(blob => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${templateName}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
        showNotification(`Template '${templateName}' exported successfully`, 'success');
        logToBackend(`Template '${templateName}' exported successfully`);
    })
    .catch(error => {
        console.error('Error exporting template:', error);
        logToBackend(`Error exporting template: ${error.message}`);
        showNotification('Error exporting template: ' + error.message, 'error');
    });
}

function importConfig() {
    const fileInput = document.getElementById('config-file');
    if (!fileInput?.files.length) {
        console.error('No config file selected');
        logToBackend('No config file selected');
        showNotification('Please select a file', 'error');
        return;
    }
    const formData = new FormData();
    formData.append('config_file', fileInput.files[0]);

    fetch('/fgt-confgen/parse_config', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        interfaces = data.interfaces || [];
        addresses = data.addresses || [];
        addressGroups = data.address_groups || [];
        internetServices = data.internet_services || [];
        vips = data.vips || [];
        ipPools = data.ip_pools || [];
        services = data.services || [];
        serviceGroups = data.service_groups || {};
        sslSshProfiles = data.ssl_ssh_profiles || [];
        webfilterProfiles = data.webfilter_profiles || [];
        applicationLists = data.application_lists || [];
        avProfiles = data.av_profiles || [];
        ipsSensors = data.ips_sensors || [];
        users = data.users || [];
        groups = data.groups || [];
        
        updateDropdowns();
        renderPolicyList();
        if (policies.length > 0) {
            selectPolicy(policies[0].id);
        }
        showNotification('Configuration imported successfully', 'success');
        logToBackend('Configuration imported successfully');
    })
    .catch(error => {
        console.error('Error importing config:', error);
        logToBackend(`Error importing config: ${error.message}`);
        showNotification('Error importing config', 'error');
    });
}

function generatePolicies() {
    if (!policies.length) {
        console.error('No policies to generate');
        logToBackend('No policies to generate');
        showNotification('No policies to generate', 'error');
        return;
    }
    const formData = new FormData();
    formData.append('policies', JSON.stringify(policies.map(p => ({
        policy_id: p.id,
        policy_name: p.name,
        policy_comment: p.comment,
        src_interfaces: p.srcInterfaces,
        dst_interfaces: p.dstInterfaces,
        src_addresses: p.srcAddresses,
        src_address_groups: p.srcAddressGroups,
        src_internet_services: p.srcInternetServices,
        src_vips: p.srcVips,
        dst_addresses: p.dstAddresses,
        dst_address_groups: p.dstAddressGroups,
        dst_internet_services: p.dstInternetServices,
        dst_vips: p.dstVips,
        services: p.services,
        action: p.action,
        inspection_mode: p.inspectionMode,
        ssl_ssh_profile: p.ssl_ssh_profile,
        webfilter_profile: p.webfilter_enabled ? p.webfilter_profile : '',
        webfilter_enabled: p.webfilter_enabled,
        application_list: p.application_list_enabled ? p.application_list : '',
        application_list_enabled: p.application_list_enabled,
        av_profile: p.av_enabled ? p.av_profile : '',
        av_enabled: p.av_enabled,
        ips_sensor: p.ips_sensor_enabled ? p.ips_sensor : '',
        ips_sensor_enabled: p.ips_sensor_enabled,
        logtraffic: p.logtraffic,
        logtraffic_start: p.logtraffic_start,
        auto_asic_offload: p.auto_asic_offload,
        nat: p.nat,
        ip_pool: p.ip_pool,
        users: p.users,
        groups: p.groups
    }))));

    fetch('/fgt-confgen/generate_policy', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById('output1').textContent = data.outputs.map(o => o.output1).join('\n\n');
        document.getElementById('output2').textContent = data.outputs.map(o => o.output2).join('\n\n');
        document.getElementById('output3').textContent = data.outputs.map(o => o.output3).join('\n\n');
        showNotification('Policies generated successfully', 'success');
        const outSec = document.querySelector('.output-section');
        if (outSec) outSec.style.display = 'block';
        logToBackend('Policies generated successfully');
    })
    .catch(error => {
        console.error('Error generating policies:', error);
        logToBackend(`Error generating policies: ${error.message}`);
        showNotification('Error generating policies', 'error');
    });
}

function copyOutput(outputId) {
    const outputElement = document.getElementById(outputId);
    if (!outputElement) {
        console.error(`Output element ${outputId} not found`);
        logToBackend(`Output element ${outputId} not found`);
        return;
    }
    const text = outputElement.textContent;
    if (!text) {
        console.error(`No content to copy for element ${outputId}`);
        logToBackend(`No content to copy for element ${outputId}`);
        showNotification('No content to copy', 'error');
        return;
    }
    navigator.clipboard.writeText(text)
        .then(() => {
            console.log(`Successfully copied content for ${outputId}`);
            logToBackend(`Successfully copied content for ${outputId}`);
            showNotification('Output copied to clipboard', 'success');
        })
        .catch(error => {
            console.error('Error copying output:', error.message);
            logToBackend(`Error copying output: ${error.message}`);
            if (error.message.includes('secure context')) {
                console.error('Clipboard API requires a secure context (HTTPS or localhost). Ensure the page is served over HTTPS.');
                logToBackend('Clipboard API requires a secure context (HTTPS or localhost). Ensure the page is served over HTTPS.');
                showNotification('Error copying output: This feature requires a secure context (HTTPS or localhost)', 'error');
            } else if (error.message.includes('permission')) {
                console.error('Clipboard access denied. Check browser permissions for clipboard access.');
                logToBackend('Clipboard access denied. Check browser permissions for clipboard access.');
                showNotification('Error copying output: Clipboard access denied. Please allow clipboard permissions in your browser', 'error');
            } else {
                showNotification('Error copying output: ' + error.message, 'error');
            }
        });
}



function toggleTheme() {
    const html = document.documentElement;
    const currentTheme = html.getAttribute('data-theme') || 'light';
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    
    html.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
    
    const toggleButton = document.getElementById('theme-toggle');
    if (toggleButton) {
        toggleButton.textContent = newTheme === 'dark' ? '☀️ Light Mode' : '🌙 Dark Mode';
        toggleButton.setAttribute('aria-label', `Toggle ${newTheme === 'dark' ? 'light' : 'dark'} mode`);
    }
    
    logToBackend(`Theme toggled to: ${newTheme}`);
}

document.addEventListener('DOMContentLoaded', () => {
    // Determine initial theme
    let initialTheme = localStorage.getItem('theme');
    if (!initialTheme) {
        initialTheme = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
        localStorage.setItem('theme', initialTheme);
    }
    
    // Apply initial theme
    const html = document.documentElement;
    html.setAttribute('data-theme', initialTheme);
    
    const toggleButton = document.getElementById('theme-toggle');
    if (toggleButton) {
        toggleButton.textContent = initialTheme === 'dark' ? '☀️ Light Mode' : '🌙 Dark Mode';
        toggleButton.setAttribute('aria-label', `Toggle ${initialTheme === 'dark' ? 'light' : 'dark'} mode`);
        toggleButton.addEventListener('click', toggleTheme);
    }

    const form = document.getElementById('policy-form');
    if (form) {
        const toggleCheckboxes = form.querySelectorAll('.toggle-field');
        toggleCheckboxes.forEach(checkbox => {
            checkbox.addEventListener('change', (e) => {
                const field = e.target.dataset.field;
                const select = form.querySelector(`.${field}`);
                select.disabled = !e.target.checked || form.querySelector('.action').value === 'deny';

                const policyId = form.dataset.policyId;
                const policy = policies.find(p => p.id === policyId);
                if (policy) {
                    policy[`${field}_enabled`] = e.target.checked;
                    if (!e.target.checked) {
                        policy[field] = '';
                    }
                }
                logToBackend(`Toggle field ${field} changed to: ${e.target.checked}`);
            });
        });
    }

    console.log('DOM loaded, checking preselected template immediately:', window.preselectedTemplate);
    logToBackend(`DOM loaded, initial preselected template: ${window.preselectedTemplate || 'none'}`);

    // Function to initialize templates
    const initializeTemplates = () => {
        console.log('Initializing template list, final preselected template:', window.preselectedTemplate);
        logToBackend(`Initializing template list, final preselected template: ${window.preselectedTemplate || 'none'}`);
        loadTemplateList().then(() => {
            updateDropdowns();
            if (!window.preselectedTemplate) {
                console.log('No preselected template, adding new policy');
                logToBackend('No preselected template, adding new policy');
                addPolicy();
            }
        }).catch(error => {
            console.error('Failed to initialize templates:', error);
            logToBackend(`Failed to initialize templates: ${error.message}`);
            addPolicy();
            updateDropdowns();
        });
    };

    // If preselectedTemplate is already set, initialize immediately
    if (typeof window.preselectedTemplate !== 'undefined') {
        initializeTemplates();
    } else {
        // Otherwise, wait for the window 'load' event to ensure inline scripts have run
        window.addEventListener('load', () => {
            console.log('Window load event, preselected template:', window.preselectedTemplate);
            logToBackend(`Window load event, preselected template: ${window.preselectedTemplate || 'none'}`);
            initializeTemplates();
        });
        // Fallback: if load event takes too long, check after a short delay
        setTimeout(() => {
            if (typeof window.preselectedTemplate !== 'undefined') {
                console.log('Fallback check, preselected template set:', window.preselectedTemplate);
                logToBackend(`Fallback check, preselected template set: ${window.preselectedTemplate}`);
                initializeTemplates();
            } else {
                console.warn('Fallback check, preselected template still not set, proceeding without it');
                logToBackend('Fallback check, preselected template still not set, proceeding without it');
                window.preselectedTemplate = null;
                initializeTemplates();
            }
        }, 1000);
    }
});

function loadFirewallConfig() {
    const select = document.getElementById('firewall-select');
    const fwId = select?.value;
    if (!fwId) {
        showNotification('Please select a firewall', 'error');
        return;
    }
    showNotification('Loading firewall config...', 'info');
    fetch('/fgt-confgen/load_firewall_config?fw_id=' + fwId)
    .then(response => {
        if (!response.ok) {
            return response.text().then(text => { throw new Error(text); });
        }
        return response.json();
    })
    .then(data => {
        interfaces = data.interfaces || [];
        addresses = data.addresses || [];
        addressGroups = data.address_groups || [];
        internetServices = data.internet_services || [];
        vips = data.vips || [];
        ipPools = data.ip_pools || [];
        services = data.services || [];
        serviceGroups = data.service_groups || {};
        sslSshProfiles = data.ssl_ssh_profiles || [];
        webfilterProfiles = data.webfilter_profiles || [];
        applicationLists = data.application_lists || [];
        avProfiles = data.av_profiles || [];
        ipsSensors = data.ips_sensors || [];
        users = data.users || [];
        groups = data.groups || [];
        
        updateDropdowns();
        renderPolicyList();
        if (policies.length > 0) {
            selectPolicy(policies[0].id);
        } else {
            document.getElementById('policy-form').style.display = 'none';
            document.getElementById('policy-form-placeholder').style.display = 'block';
        }
        showNotification('Configuration loaded successfully', 'success');
    })
    .catch(error => {
        console.error('Error loading config:', error);
        showNotification('Error loading config: ' + error.message, 'error');
    });
}
