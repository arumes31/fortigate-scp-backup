// scripts.js (Version 1.17)
(function () {
'use strict';

const confGenRoot = document.getElementById('confgen-page');
if (!confGenRoot) return;

const initSearchableSelect = window.FortiSafeConfGen?.initSearchableSelect;
let preselectedTemplate = confGenRoot.dataset.preselectedTemplate || '';
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
let workspaceDirty = false;
let dirtyTrackingReady = false;

function setWorkspaceDirty(dirty) {
    if (!dirtyTrackingReady && dirty) return;
    workspaceDirty = dirty;
    const marker = document.getElementById('confgen-dirty');
    if (marker) marker.hidden = !dirty;
    confGenRoot.dataset.dirty = String(dirty);
}

function markWorkspaceDirty() {
    if (!dirtyTrackingReady) return;
    setWorkspaceDirty(true);
    resetReviewResults();
}
function markWorkspaceClean() { setWorkspaceDirty(false); }

window.addEventListener('beforeunload', event => {
    if (!workspaceDirty) return;
    event.preventDefault();
    event.returnValue = '';
});

function showNotification(message, type = 'success') {
    const feedback = document.getElementById('confgen-feedback');
    const kind = type === 'info' ? 'loading' : type;
    if (window.FortiSafeUI?.announce) {
        window.FortiSafeUI.announce(feedback, kind, message);
    } else if (feedback) {
        feedback.dataset.feedback = kind;
        feedback.textContent = message;
    }
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

// newPolicyId returns a collision-resistant client-side policy ID (the server
// assigns real UUIDs on clone/import; Date.now() collides on rapid clicks).
function newPolicyId() {
    return (window.crypto && crypto.randomUUID)
        ? crypto.randomUUID()
        : Date.now().toString(36) + '-' + Math.random().toString(36).slice(2);
}

function addPolicy() {
    const policyId = newPolicyId();
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
    markWorkspaceDirty();
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
        genBtn.hidden = policies.length === 0;
    }
    if (policies.length === 0) {
        document.getElementById('policy-form').style.display = 'none';
        document.getElementById('policy-form-placeholder').style.display = 'block';
        const outSec = document.querySelector('.output-section');
        if (outSec) outSec.hidden = true;
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

// escHtml escapes config-derived names (interfaces, addresses, services, …)
// before they are interpolated into innerHTML/attribute contexts. Object names
// come from uploaded configs, shared backups and imported templates, so they
// are attacker-influenceable.
function escHtml(s) {
    return String(s ?? '').replace(/[&<>"']/g, c => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));
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
            <select data-change-action="update-interface" data-item-type="${type}" data-item-index="${index}">
                <option value="">Select Interface</option>
                ${interfaces.map(intf => `<option value="${escHtml(intf)}" ${item === intf ? 'selected' : ''}>${escHtml(intf)}</option>`).join('')}
            </select>
            <button type="button" data-action="delete-interface" data-item-type="${type}" data-item-index="${index}">Delete</button>
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
            <select class="address-select" data-change-action="update-address" data-item-type="${type}" data-item-index="${index}">
                <option value="">Select Address/ISDB</option>
                <optgroup label="Addresses">
                    ${addresses.map(addr => `<option value="address:${escHtml(addr)}" ${item.type === 'address' && item.value === addr ? 'selected' : ''}>${escHtml(addr)}</option>`).join('')}
                </optgroup>
                <optgroup label="Address Groups">
                    ${addressGroups.map(agrp => `<option value="address_group:${escHtml(agrp)}" ${item.type === 'address_group' && item.value === agrp ? 'selected' : ''}>${escHtml(agrp)}</option>`).join('')}
                </optgroup>
                <optgroup label="Internet Services">
                    ${internetServices.map(isdb => `<option value="isdb:${escHtml(isdb)}" ${item.type === 'isdb' && item.value === isdb ? 'selected' : ''}>${escHtml(isdb)}</option>`).join('')}
                </optgroup>
                <optgroup label="Virtual IPs">
                    ${vips.map(vip => `<option value="vip:${escHtml(vip)}" ${item.type === 'vip' && item.value === vip ? 'selected' : ''}>${escHtml(vip)}</option>`).join('')}
                </optgroup>
            </select>
            <button type="button" data-action="delete-address" data-item-type="${type}" data-item-index="${index}">Delete</button>
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
            <select data-change-action="update-service" data-item-index="${index}">
                <option value="">Select Service/Group</option>
                <optgroup label="Service Groups">
                    ${Object.keys(serviceGroups).map(group => `<option value="group:${escHtml(group)}" ${item.type === 'group' && item.name === group ? 'selected' : ''}>${escHtml(group)}</option>`).join('')}
                </optgroup>
                <optgroup label="Individual Services">
                    ${services.map(svc => `<option value="template:${escHtml(svc.name)}" ${item.type === 'template' && item.name === svc.name ? 'selected' : ''}>${escHtml(svc.name)}</option>`).join('')}
                </optgroup>
                <optgroup label="Custom">
                    <option value="custom" ${item.type === 'custom' ? 'selected' : ''}>Custom</option>
                </optgroup>
            </select>
            ${item.type === 'custom' ? `
                <input type="text" value="${escHtml(item.name)}" data-change-action="update-custom-service" data-item-index="${index}" data-item-field="name" placeholder="Service Name" aria-label="Custom service name">
                <select data-change-action="update-custom-service" data-item-index="${index}" data-item-field="protocol" aria-label="Custom service protocol">
                    <option value="TCP" ${item.protocol === 'TCP' ? 'selected' : ''}>TCP</option>
                    <option value="UDP" ${item.protocol === 'UDP' ? 'selected' : ''}>UDP</option>
                    <option value="SCTP" ${item.protocol === 'SCTP' ? 'selected' : ''}>SCTP</option>
                    <option value="ICMP" ${item.protocol === 'ICMP' ? 'selected' : ''}>ICMP</option>
                </select>
                <input type="text" value="${escHtml(item.port)}" data-change-action="update-custom-service" data-item-index="${index}" data-item-field="port" placeholder="Port" aria-label="Custom service port">
            ` : ''}
            <button type="button" data-action="delete-service" data-item-index="${index}">Delete</button>
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
            <select class="user-group-select" data-change-action="update-user-group" data-item-index="${index}">
                <option value="">Select User/Group</option>
                <optgroup label="Users">
                    ${users.map(user => `<option value="user:${escHtml(user)}" ${isUser && item === user ? 'selected' : ''}>${escHtml(user)}</option>`).join('')}
                </optgroup>
                <optgroup label="Groups">
                    ${groups.map(group => `<option value="group:${escHtml(group)}" ${!isUser && item === group ? 'selected' : ''}>${escHtml(group)}</option>`).join('')}
                </optgroup>
            </select>
            <button type="button" data-action="delete-user-group" data-item-index="${index}">Delete</button>
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

    const opts = list => `<option value="">None</option>${list.map(v => `<option value="${escHtml(v)}">${escHtml(v)}</option>`).join('')}`;
    sslSshSelect.innerHTML = opts(sslSshProfiles);
    webfilterSelect.innerHTML = opts(webfilterProfiles);
    appListSelect.innerHTML = opts(applicationLists);
    avSelect.innerHTML = opts(avProfiles);
    ipsSensorSelect.innerHTML = opts(ipsSensors);
    ipPoolSelect.innerHTML = opts(ipPools);

    const policyId = form.dataset.policyId;
    if (policyId && policies.some(policy => policy.id === policyId)) {
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
    markWorkspaceDirty();
}

function savePolicy(button) {
    logToBackend('savePolicy triggered');
    try {
        const policyId = button.closest('#policy-form')?.dataset.policyId;
        if (!policyId) {
            console.error('Policy ID not found in form dataset');
            logToBackend('Policy ID not found in form dataset');
            showNotification('Error: Policy ID not found', 'error');
            return;
        }
        logToBackend(`Policy ID: ${policyId}`);

        const policy = policies.find(p => p.id === policyId);
        if (!policy) {
            console.error(`Policy with ID ${policyId} not found`);
            logToBackend(`Policy with ID ${policyId} not found`);
            showNotification('Error: Policy not found', 'error');
            return;
        }
        logToBackend(`Policy found with ID: ${policyId}`);

        const form = button.closest('#policy-form');
        if (!form) {
            console.error('Policy form not found');
            logToBackend('Policy form not found');
            showNotification('Error: Policy form not found', 'error');
            return;
        }
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

        logToBackend(`Policy updated with ID: ${policyId}`);

        renderPolicyList();
        selectPolicy(policyId);
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
    const policy = policies.find(p => p.id === policyId);
    if (!policy) {
        console.error(`Policy with ID ${policyId} not found`);
        logToBackend(`Policy with ID ${policyId} not found`);
        showNotification('Policy not found', 'error');
        return;
    }
    const clone = JSON.parse(JSON.stringify(policy));
    clone.id = newPolicyId();
    if (clone.name.length > 20) {
        clone.name = clone.name.substring(0, 20) + '_cl';
    } else {
        clone.name = clone.name + '_cl';
    }
    policies.push(clone);
    renderPolicyList();
    selectPolicy(clone.id);
    showNotification('Policy cloned successfully', 'success');
    logToBackend('Policy cloned successfully (client-side)');
    markWorkspaceDirty();
}

function clearForm(button) {
    const form = button?.closest('#policy-form') || document.getElementById('policy-form');
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
    resetReviewResults();
    markWorkspaceClean();
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
        console.log('Loading template list, checking for preselected template:', preselectedTemplate);
        logToBackend(`Loading template list, preselected template: ${preselectedTemplate || 'none'}`);
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
            if (preselectedTemplate) {
                console.log('Attempting to select preselected template:', preselectedTemplate);
                logToBackend(`Attempting to select preselected template: ${preselectedTemplate}`);
                if (data.templates.includes(preselectedTemplate)) {
                    select.value = preselectedTemplate;
                    console.log(`Preselected template ${preselectedTemplate} found, loading template`);
                    logToBackend(`Preselected template ${preselectedTemplate} found, loading template`);
                    loadTemplate();
                } else {
                    console.warn(`Preselected template "${preselectedTemplate}" not found in available templates:`, data.templates);
                    logToBackend(`Preselected template "${preselectedTemplate}" not found in available templates: ${JSON.stringify(data.templates)}`);
                    showNotification(`Template "${preselectedTemplate}" not found`, 'error');
                    // Clear preselected template to prevent repeated attempts
                    preselectedTemplate = '';
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
                        resetReviewResults();
                        markWorkspaceClean();
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
                        resetReviewResults();
                        markWorkspaceClean();
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
                resetReviewResults();
                markWorkspaceClean();
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
            preselectedTemplate = newName;
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

function policyRequestPayload() {
    return { policies: policies.map(p => ({
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
    })) };
}

function setReviewTab(name, focus = false) {
    const tabs = Array.from(confGenRoot.querySelectorAll('[data-review-tab]'));
    tabs.forEach(tab => {
        const selected = tab.dataset.reviewTab === name;
        tab.setAttribute('aria-selected', String(selected));
        tab.tabIndex = selected ? 0 : -1;
        const panel = document.getElementById(tab.getAttribute('aria-controls'));
        if (panel) panel.hidden = !selected;
        if (selected && focus) tab.focus();
    });
}

function renderIssueList(listID, issues) {
    const list = document.getElementById(listID);
    if (!list) return;
    const items = issues.map(issue => {
        const item = document.createElement('li');
        item.textContent = `${issue.code}: ${issue.message}`;
        return item;
    });
    list.replaceChildren(...items);
}

function renderValidationReview(validation) {
    const errors = Array.isArray(validation?.errors) ? validation.errors : [];
    const warnings = Array.isArray(validation?.warnings) ? validation.warnings : [];
    document.getElementById('validation-count').textContent = String(errors.length);
    document.getElementById('warning-count').textContent = String(warnings.length);
    document.getElementById('validation-summary').textContent = errors.length
        ? `${errors.length} blocking ${errors.length === 1 ? 'issue' : 'issues'} found.`
        : 'Server validation passed.';
    document.getElementById('warning-summary').textContent = warnings.length
        ? `${warnings.length} non-blocking ${warnings.length === 1 ? 'warning' : 'warnings'} found.`
        : 'No warnings reported.';
    renderIssueList('validation-list', errors);
    renderIssueList('warning-list', warnings);
    return { errors, warnings };
}

function resetReviewResults() {
    renderValidationReview({ errors: [], warnings: [] });
    const validationSummary = document.getElementById('validation-summary');
    if (validationSummary) validationSummary.textContent = 'Run validation to review this policy set.';
    const outputSection = document.querySelector('.output-section');
    if (outputSection) outputSection.hidden = true;
    const outputPlaceholder = document.getElementById('output-placeholder');
    if (outputPlaceholder) outputPlaceholder.hidden = false;
    ['output1', 'output2', 'output3'].forEach(id => {
        const output = document.getElementById(id);
        if (output) output.textContent = '';
    });
    setReviewTab('validation');
}

async function requestPolicyReview(path) {
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 3500);
    try {
        const response = await fetch(path, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(policyRequestPayload()),
            signal: controller.signal
        });
        const data = await response.json().catch(() => ({ code: 'invalid_response', message: 'The server returned an unreadable response.' }));
        if (!response.ok) {
            const error = new Error(data.message || `Request failed with HTTP ${response.status}.`);
            error.apiResponse = data;
            throw error;
        }
        return data;
    } catch (error) {
        if (error.name === 'AbortError') {
            const timeoutError = new Error('Policy processing timed out. Try a smaller policy set.');
            timeoutError.apiResponse = { code: 'request_timeout', message: timeoutError.message };
            throw timeoutError;
        }
        throw error;
    } finally {
        window.clearTimeout(timeout);
    }
}

function showReviewFailure(error) {
    const response = error.apiResponse || { code: 'request_failed', message: 'Policy review failed.' };
    const validation = response.validation || {
        valid: false,
        errors: [{ code: response.code || 'request_failed', message: response.message || 'Policy review failed.' }],
        warnings: []
    };
    renderValidationReview(validation);
    setReviewTab('validation');
    logToBackend(`Policy review failed (${response.code || 'request_failed'})`);
    showNotification(response.message || 'Policy review failed.', 'error');
}

async function validatePoliciesOnServer() {
    showNotification('Validating policies…', 'info');
    try {
        const validation = await requestPolicyReview('/fgt-confgen/validate_policy');
        const result = renderValidationReview(validation);
        setReviewTab(result.errors.length ? 'validation' : (result.warnings.length ? 'warnings' : 'validation'));
        showNotification(validation.valid ? 'Server validation passed' : 'Server validation found blocking issues', validation.valid ? 'success' : 'error');
        logToBackend(`Policy validation completed (errors=${result.errors.length}, warnings=${result.warnings.length})`);
    } catch (error) {
        showReviewFailure(error);
    }
}

async function generatePolicies() {
    if (!policies.length) {
        showNotification('No policies to generate', 'error');
        return;
    }

    showNotification('Generating policies…', 'info');
    try {
        const data = await requestPolicyReview('/fgt-confgen/generate_policy');
        renderValidationReview(data.validation || { valid: true, errors: [], warnings: [] });
        document.getElementById('output1').textContent = data.outputs.map(o => o.output1).join('\n\n');
        document.getElementById('output2').textContent = data.outputs.map(o => o.output2).join('\n\n');
        document.getElementById('output3').textContent = data.outputs.map(o => o.output3).join('\n\n');
        const outSec = document.querySelector('.output-section');
        if (outSec) outSec.hidden = false;
        const outputPlaceholder = document.getElementById('output-placeholder');
        if (outputPlaceholder) outputPlaceholder.hidden = true;
        setReviewTab('cli');
        showNotification('Policies generated successfully', 'success');
        logToBackend('Policies generated successfully');
        markWorkspaceClean();
    } catch (error) {
        showReviewFailure(error);
    }
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



function itemIndex(control) {
    return Number.parseInt(control.dataset.itemIndex, 10);
}

function downloadOutput(outputId) {
    const outputElement = document.getElementById(outputId);
    const text = outputElement?.textContent || '';
    if (!text) {
        showNotification('No content to download', 'error');
        return;
    }
    const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `fortisafe-confgen-${outputId}.txt`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 0);
    logToBackend(`Downloaded generated output ${outputId}`);
    showNotification('Output download started', 'success');
}

function bindPageActions() {
    const clickActions = {
        'load-template': () => loadTemplate(),
        'clone-template': () => cloneTemplate(),
        'copy-url': () => copyUrl(),
        'save-template': () => saveTemplate(),
        'delete-template': () => deleteTemplate(),
        'rename-template': () => renameTemplate(),
        'export-template': () => exportTemplate(),
        'choose-template-file': () => document.getElementById('import-template')?.click(),
        'add-policy': () => addPolicy(),
        'load-firewall-config': () => loadFirewallConfig(),
        'add-src-interface': button => addSrcInterface(button),
        'add-src-address': button => addSrcAddress(button),
        'add-src-user-group': button => addSrcUserOrGroup(button),
        'add-dst-interface': button => addDstInterface(button),
        'add-dst-address': button => addDstAddress(button),
        'add-service': button => addService(button),
        'save-policy': button => savePolicy(button),
        'clear-form': button => clearForm(button),
        'clone-policy': button => clonePolicy(button),
        'validate-policies': () => validatePoliciesOnServer(),
        'generate-policies': () => generatePolicies(),
        'copy-output': button => copyOutput(button.dataset.outputId),
        'download-output': button => downloadOutput(button.dataset.outputId),
        'delete-interface': button => deleteInterface(button.dataset.itemType, itemIndex(button)),
        'delete-address': button => deleteAddressOrInternetService(button.dataset.itemType, itemIndex(button)),
        'delete-service': button => deleteService(itemIndex(button)),
        'delete-user-group': button => deleteUserOrGroup(itemIndex(button)),
    };
    const changeActions = {
        'import-template': (control, event) => importTemplate(event),
        'toggle-profile-fields': control => toggleProfileFields(control),
        'toggle-ip-pool-field': control => toggleIpPoolField(control),
        'update-interface': control => updateInterface(control.dataset.itemType, itemIndex(control), control.value),
        'update-address': control => updateAddressOrInternetService(control.dataset.itemType, itemIndex(control), control.value),
        'update-service': control => updateService(itemIndex(control), control.value),
        'update-custom-service': control => updateCustomService(itemIndex(control), control.dataset.itemField, control.value),
        'update-user-group': control => updateUserOrGroup(itemIndex(control), control.value),
    };

    confGenRoot.addEventListener('click', event => {
        const reviewTab = event.target.closest('[data-review-tab]');
        if (reviewTab && confGenRoot.contains(reviewTab)) {
            setReviewTab(reviewTab.dataset.reviewTab);
        }
        const button = event.target.closest('[data-action]');
        if (!button || !confGenRoot.contains(button)) return;
        const action = clickActions[button.dataset.action];
        if (action) {
            action(button, event);
            if (['add-src-interface', 'add-src-address', 'add-src-user-group', 'add-dst-interface', 'add-dst-address', 'add-service'].includes(button.dataset.action)) {
                markWorkspaceDirty();
            }
        }
        if (event.target.closest('.remove-btn, .delete-btn')) markWorkspaceDirty();
    });
    confGenRoot.addEventListener('change', event => {
        const control = event.target.closest('[data-change-action]');
        if (!control || !confGenRoot.contains(control)) return;
        const action = changeActions[control.dataset.changeAction];
        if (action) action(control, event);
        if (event.target.closest('#policy-form')) markWorkspaceDirty();
    });
    confGenRoot.addEventListener('input', event => {
        if (event.target.closest('#policy-form')) markWorkspaceDirty();
    });
    confGenRoot.addEventListener('keydown', event => {
        const current = event.target.closest('[data-review-tab]');
        if (!current || !['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
        const tabs = Array.from(confGenRoot.querySelectorAll('[data-review-tab]'));
        const currentIndex = tabs.indexOf(current);
        let nextIndex = currentIndex;
        if (event.key === 'ArrowLeft') nextIndex = (currentIndex - 1 + tabs.length) % tabs.length;
        if (event.key === 'ArrowRight') nextIndex = (currentIndex + 1) % tabs.length;
        if (event.key === 'Home') nextIndex = 0;
        if (event.key === 'End') nextIndex = tabs.length - 1;
        event.preventDefault();
        setReviewTab(tabs[nextIndex].dataset.reviewTab, true);
    });
}

document.addEventListener('DOMContentLoaded', () => {
	bindPageActions();

    const form = document.getElementById('policy-form');
    if (form) {
        // The DOM uses hyphenated data-field names while the policy JSON keys
        // are underscored — and the *_enabled keys drop the "-profile" suffix
        // (webfilter_enabled, av_enabled), so a plain hyphen→underscore
        // mapping is not enough; map each field explicitly.
        const TOGGLE_KEYS = {
            'webfilter-profile': { value: 'webfilter_profile', enabled: 'webfilter_enabled' },
            'av-profile': { value: 'av_profile', enabled: 'av_enabled' },
            'application-list': { value: 'application_list', enabled: 'application_list_enabled' },
            'ips-sensor': { value: 'ips_sensor', enabled: 'ips_sensor_enabled' },
        };
        const toggleCheckboxes = form.querySelectorAll('.toggle-field');
        toggleCheckboxes.forEach(checkbox => {
            checkbox.addEventListener('change', (e) => {
                const field = e.target.dataset.field;
                const select = form.querySelector(`.${field}`);
                select.disabled = !e.target.checked || form.querySelector('.action').value === 'deny';

                const policyId = form.dataset.policyId;
                const policy = policies.find(p => p.id === policyId);
                const keys = TOGGLE_KEYS[field];
                if (policy && keys) {
                    policy[keys.enabled] = e.target.checked;
                    if (!e.target.checked) {
                        policy[keys.value] = '';
                    }
                }
                logToBackend(`Toggle field ${field} changed to: ${e.target.checked}`);
            });
        });
    }

    // Firewall dropdown becomes a searchable combobox.
    const fwSelect = document.getElementById('firewall-select');
    if (fwSelect && typeof initSearchableSelect === 'function') {
        initSearchableSelect(fwSelect, { placeholder: 'Select Firewall' });
    }

    console.log('DOM loaded, checking preselected template immediately:', preselectedTemplate);
    logToBackend(`DOM loaded, initial preselected template: ${preselectedTemplate || 'none'}`);

    // Function to initialize templates
    let _templatesInitialized = false;
    const initializeTemplates = () => {
        if (_templatesInitialized) return;
        _templatesInitialized = true;
        console.log('Initializing template list, final preselected template:', preselectedTemplate);
        logToBackend(`Initializing template list, final preselected template: ${preselectedTemplate || 'none'}`);
        loadTemplateList().then(() => {
            updateDropdowns();
            if (!preselectedTemplate) {
                console.log('No preselected template, adding new policy');
                logToBackend('No preselected template, adding new policy');
                addPolicy();
            }
        }).catch(error => {
            console.error('Failed to initialize templates:', error);
            logToBackend(`Failed to initialize templates: ${error.message}`);
            addPolicy();
            updateDropdowns();
        }).finally(() => {
            dirtyTrackingReady = true;
            markWorkspaceClean();
        });
    };

    initializeTemplates();
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
        resetReviewResults();
        markWorkspaceClean();
    })
    .catch(error => {
        console.error('Error loading config:', error);
        showNotification('Error loading config: ' + error.message, 'error');
    });
}

})();
