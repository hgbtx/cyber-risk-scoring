// =====================
// ADMIN PANEL
// =====================

// TOGGLE USER CREATE FORM
document.getElementById('adminCreateUserBtn')?.addEventListener('click', () => {
    const form = document.getElementById('adminCreateUserForm');
    form.style.display = form.style.display === 'none' ? 'block' : 'none';
    document.getElementById('adminCreateResult').innerHTML = '';
});

// LOAD ADMIN DATA ON ADMIN TAB CLICK
document.querySelector('[data-tab="admin"]')?.addEventListener('click', () => {
    if (hasMinRole('admin')) {
        loadOrgPolicies();
        loadAdminUsers();
        loadPermissions();
    }
});

// =====================
// ORG POLICIES
// =====================

// LOAD ORG POLICIES
async function loadOrgPolicies() {
    try {
        const res = await fetch('/admin/policies');
        const data = await res.json();
        if (data.otp_expiry_hours) document.getElementById('policyOtpExpiry').value = data.otp_expiry_hours;
    } catch (e) { console.error('Failed to load policies:', e); }
}

// SAVE ORG POLICIES
async function saveOrgPolicies() {
    const status = document.getElementById('policyStatus');
    status.textContent = 'Saving...';
    status.style.color = '#57534E';
    try {
        const res = await fetch('/admin/policies', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                otp_expiry_hours: parseInt(document.getElementById('policyOtpExpiry').value)
            })
        });
        const data = await res.json();
        if (data.success) { status.textContent = 'Saved'; status.style.color = '#50b88e'; }
        else { status.textContent = data.error || 'Failed'; status.style.color = '#c01e19'; }
    } catch (e) { status.textContent = 'Connection error'; status.style.color = '#c01e19'; }
    setTimeout(() => status.textContent = '', 3000);
}

// =====================
// USER MANAGEMENT
// =====================

// LOAD USERS
async function loadAdminUsers() {
    try {
        const res = await fetch('/admin/users');
        const users = await res.json();
        renderAdminUsers(users);
    } catch (e) { console.error('Failed to load users:', e); }
}

// RENDER USER GRID
function renderAdminUsers(users) {
    const tbody = document.getElementById('adminUsersBody');
    tbody.innerHTML = '';
    users.forEach(u => {
        const isSelf = currentUser && currentUser.username === u.username;
        const status = u.must_change_password ? '<span style="color:#e67e22;">Pending</span>' : '<span style="color:#50b88e;">Active</span>';
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${u.username}</td>
            <td>
                <select onchange="adminUpdateRole('${u.username}', this.value)" ${isSelf ? 'disabled' : ''} style="padding:4px;border:1px solid #ccc;border-radius:4px;">
                    <option value="viewer" ${u.role === 'viewer' ? 'selected' : ''}>Viewer</option>
                    <option value="tier 1 analyst" ${u.role === 'tier 1 analyst' ? 'selected' : ''}>Tier 1 Analyst</option>
                    <option value="tier 2 analyst" ${u.role === 'tier 2 analyst' ? 'selected' : ''}>Tier 2 Analyst</option>
                    <option value="manager" ${u.role === 'manager' ? 'selected' : ''}>Manager</option>
                    <option value="admin" ${u.role === 'admin' ? 'selected' : ''}>Admin</option>
                </select>
            </td>
            <td>${status}</td>
            <td>${u.created_at || ''}</td>
            <td>
                <button onclick="adminResetOtp('${u.username}')" style="padding:3px 8px;font-size:0.8em;background:#d9af6f;color:#57534E;border:none;border-radius:3px;cursor:pointer;" ${!u.must_change_password ? '' : 'disabled'}>Reset OTP</button>
                <button onclick="adminDeleteUser('${u.username}')" style="padding:3px 8px;font-size:0.8em;background:#c01e19;color:white;border:none;border-radius:3px;cursor:pointer;margin-left:4px;" ${isSelf ? 'disabled' : ''}>Delete</button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

// CREATE USER
async function adminCreateUser() {
    const username = document.getElementById('adminNewUsername').value.trim();
    const role = document.getElementById('adminNewRole').value;
    const result = document.getElementById('adminCreateResult');
    result.innerHTML = '';
    if (!username) { result.innerHTML = '<span style="color:#c01e19;">Username is required.</span>'; return; }
    try {
        const res = await fetch('/admin/users/create', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, role })
        });
        const data = await res.json();
        if (data.success) {
            result.innerHTML = `<span style="color:#50b88e;">Created!</span><br>
                <strong>OTP:</strong> <code style="background:#f5f5f5;padding:2px 6px;border-radius:3px;user-select:all;">${data.otp}</code><br>
                <strong>Expires:</strong> ${data.expires_at}<br>
                <span style="color:#e67e22;font-size:0.85em;">Copy the OTP now — it won't be shown again.</span>`;
            document.getElementById('adminNewUsername').value = '';
            loadAdminUsers();
        } else { result.innerHTML = `<span style="color:#c01e19;">${data.error}</span>`; }
    } catch (e) { result.innerHTML = '<span style="color:#c01e19;">Connection error.</span>'; }
}

// UPDATE USER ROLE
async function adminUpdateRole(username, role) {
    try {
        const res = await fetch('/admin/users/update-role', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, role })
        });
        const data = await res.json();
        if (!data.success) alert(data.error || 'Failed to update role.');
    } catch (e) { alert('Connection error.'); }
}

// RESET OTP
async function adminResetOtp(username) {
    if (!confirm(`Reset OTP for ${username}? Their current password will be cleared.`)) return;
    try {
        const res = await fetch('/admin/users/reset-otp', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });
        const data = await res.json();
        if (data.success) {
            alert(`New OTP for ${username}: ${data.otp}\nExpires: ${data.expires_at}\n\nCopy this now — it won't be shown again.`);
            loadAdminUsers();
        } else { alert(data.error || 'Failed to reset OTP.'); }
    } catch (e) { alert('Connection error.'); }
}

// DELETE USER
async function adminDeleteUser(username) {
    if (!confirm(`Delete user "${username}"? This cannot be undone.`)) return;
    try {
        const res = await fetch('/admin/users/delete', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });
        const data = await res.json();
        if (data.success) { loadAdminUsers(); }
        else { alert(data.error || 'Failed to delete user.'); }
    } catch (e) { alert('Connection error.'); }
}

// =====================
// ROLE PERMISSIONS
// =====================

const DEFAULT_PERMISSIONS = {
    Search: {
        'view Search tab':               { viewer:1, 'tier 1 analyst':0, 'tier 2 analyst':0, manager:1, admin:1 },
        'perform searches':              { viewer:0, 'tier 1 analyst':0, 'tier 2 analyst':0, manager:1, admin:1 },
        'drag and drop to Assets folder':{ viewer:0, 'tier 1 analyst':0, 'tier 2 analyst':0, manager:1, admin:1 },
        'add assets to Asset Directory': { viewer:0, 'tier 1 analyst':0, 'tier 2 analyst':0, manager:1, admin:1 }
    },
    'Asset Directory': {
        'view Asset Directory tab': { viewer:1, 'tier 1 analyst':1, 'tier 2 analyst':1, manager:1, admin:1 },
        'archive assets':           { viewer:0, 'tier 1 analyst':0, 'tier 2 analyst':0, manager:1, admin:1 },
        'delete assets':            { viewer:0, 'tier 1 analyst':0, 'tier 2 analyst':0, manager:0, admin:1 },
        'download CSV':             { viewer:1, 'tier 1 analyst':1, 'tier 2 analyst':1, manager:1, admin:1 },
        'download JSON':            { viewer:1, 'tier 1 analyst':1, 'tier 2 analyst':1, manager:1, admin:1 }
    },
    myCharts: {
        'view myCharts tab':                  { viewer:1, 'tier 1 analyst':1, 'tier 2 analyst':1, manager:1, admin:1 },
        'drag and drop charts to dashboard':  { viewer:1, 'tier 1 analyst':1, 'tier 2 analyst':1, manager:1, admin:1 },
        'download PNG':                       { viewer:1, 'tier 1 analyst':1, 'tier 2 analyst':1, manager:1, admin:1 },
        'download PDF':                       { viewer:1, 'tier 1 analyst':1, 'tier 2 analyst':1, manager:1, admin:1 }
    },
    myTickets: {
        'view myTickets tab':       { viewer:1, 'tier 1 analyst':1, 'tier 2 analyst':1, manager:1, admin:1 },
        'create tickets':           { viewer:0, 'tier 1 analyst':1, 'tier 2 analyst':1, manager:1, admin:1 },
        'delete tickets':           { viewer:0, 'tier 1 analyst':0, 'tier 2 analyst':0, manager:1, admin:1 },
        'resolve tickets':          { viewer:0, 'tier 1 analyst':1, 'tier 2 analyst':1, manager:1, admin:1 },
        'reassign tickets':         { viewer:0, 'tier 1 analyst':0, 'tier 2 analyst':0, manager:1, admin:1 },
        'reopen tickets':           { viewer:0, 'tier 1 analyst':0, 'tier 2 analyst':1, manager:1, admin:1 },
        'accept tickets':           { viewer:0, 'tier 1 analyst':1, 'tier 2 analyst':1, manager:1, admin:1 },
        'update ticket status':     { viewer:0, 'tier 1 analyst':1, 'tier 2 analyst':1, manager:1, admin:1 },
        'comment tickets':          { viewer:0, 'tier 1 analyst':1, 'tier 2 analyst':1, manager:1, admin:1 },
        'fix comment tickets':      { viewer:0, 'tier 1 analyst':1, 'tier 2 analyst':1, manager:1, admin:1 },
        'accept ticket resolution': { viewer:0, 'tier 1 analyst':1, 'tier 2 analyst':1, manager:1, admin:1 },
        'download ticket log':      { viewer:1, 'tier 1 analyst':0, 'tier 2 analyst':0, manager:1, admin:1 }
    }
};

const PERM_ROLES = ['viewer', 'tier 1 analyst', 'tier 2 analyst', 'manager', 'admin'];

let currentPermissions = null;

function deepCopy(obj) { return JSON.parse(JSON.stringify(obj)); }

function renderPermissionsTable(perms) {
    const tbody = document.getElementById('permissionsBody');
    if (!tbody) return;
    tbody.innerHTML = '';
    for (const [category, actions] of Object.entries(perms)) {
        // Category header row
        const catRow = document.createElement('tr');
        catRow.className = 'perm-category-row';
        catRow.innerHTML = `<td colspan="6">${category}</td>`;
        tbody.appendChild(catRow);

        for (const [action, roles] of Object.entries(actions)) {
            const tr = document.createElement('tr');
            let cells = `<td class="perm-label">${action}</td>`;
            PERM_ROLES.forEach(role => {
                const checked = roles[role] ? 'checked' : '';
                const isAdmin = role === 'admin';
                const disabled = isAdmin ? 'disabled' : '';
                cells += `
                    <td>
                        <label class="perm-toggle">
                            <input type="checkbox" ${checked} ${disabled}
                                data-category="${category}"
                                data-action="${action}"
                                data-role="${role}"
                                onchange="onPermToggle(this)">
                            <span class="slider"></span>
                        </label>
                    </td>`;
            });
            tr.innerHTML = cells;
            tbody.appendChild(tr);
        }
    }
}

function onPermToggle(el) {
    const cat = el.dataset.category;
    const action = el.dataset.action;
    const role = el.dataset.role;
    if (currentPermissions[cat] && currentPermissions[cat][action]) {
        currentPermissions[cat][action][role] = el.checked ? 1 : 0;
    }
}

async function loadPermissions() {
    try {
        const res = await fetch('/admin/permissions');
        const data = await res.json();
        if (data.permissions) {
            currentPermissions = mergePermissions(data.permissions);
        } else {
            currentPermissions = deepCopy(DEFAULT_PERMISSIONS);
        }
    } catch (e) {
        currentPermissions = deepCopy(DEFAULT_PERMISSIONS);
    }
    renderPermissionsTable(currentPermissions);
}

function mergePermissions(saved) {
    const merged = deepCopy(DEFAULT_PERMISSIONS);
    for (const [category, actions] of Object.entries(merged)) {
        if (saved[category]) {
            for (const [action, roles] of Object.entries(actions)) {
                if (saved[category][action]) {
                    merged[category][action] = saved[category][action];
                }
            }
        }
    }
    return merged;
}

async function savePermissions() {
    const status = document.getElementById('permissionsStatus');
    status.textContent = 'Saving...';
    status.style.color = '#57534E';
    try {
        const res = await fetch('/admin/permissions', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ permissions: currentPermissions })
        });
        const data = await res.json();
        if (data.success) {
            status.textContent = 'Saved';
            status.style.color = '#50b88e';
        } else {
            status.textContent = data.error || 'Failed';
            status.style.color = '#c01e19';
        }
    } catch (e) {
        status.textContent = 'Connection error';
        status.style.color = '#c01e19';
    }
    setTimeout(() => status.textContent = '', 3000);
}

function resetPermissions() {
    if (!confirm('Reset all permissions to defaults?')) return;
    requestAnimationFrame(() => {
        currentPermissions = deepCopy(DEFAULT_PERMISSIONS);
        renderPermissionsTable(currentPermissions);
        const status = document.getElementById('permissionsStatus');
    status.textContent = 'Reset to defaults (unsaved)';
    status.style.color = '#e67e22';
    setTimeout(() => status.textContent = '', 3000);
})
}