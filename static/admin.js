// =====================
// ADMIN PANEL
// =====================

// Toggle create user form
document.getElementById('adminCreateUserBtn')?.addEventListener('click', () => {
    const form = document.getElementById('adminCreateUserForm');
    form.style.display = form.style.display === 'none' ? 'block' : 'none';
    document.getElementById('adminCreateResult').innerHTML = '';
});

// Load admin data when admin tab is clicked
document.querySelector('[data-tab="admin"]')?.addEventListener('click', () => {
    if (hasMinRole('admin')) {
        loadOrgPolicies();
        loadAdminUsers();
        loadPermissionsMatrix();
    }
});

// =====================
// ORG POLICIES
// =====================

async function loadOrgPolicies() {
    try {
        const res = await fetch('/admin/policies');
        const data = await res.json();
        if (data.asset_sharing_mode) document.getElementById('policyAssetSharing').value = data.asset_sharing_mode;
        if (data.sod_enforcement) document.getElementById('policySodEnforcement').value = data.sod_enforcement;
        if (data.otp_expiry_hours) document.getElementById('policyOtpExpiry').value = data.otp_expiry_hours;
    } catch (e) { console.error('Failed to load policies:', e); }
}

async function saveOrgPolicies() {
    const status = document.getElementById('policyStatus');
    status.textContent = 'Saving...';
    status.style.color = '#57534E';
    try {
        const res = await fetch('/admin/policies', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                asset_sharing_mode: document.getElementById('policyAssetSharing').value,
                sod_enforcement: document.getElementById('policySodEnforcement').value,
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

async function loadAdminUsers() {
    try {
        const res = await fetch('/admin/users');
        const users = await res.json();
        renderAdminUsers(users);
    } catch (e) { console.error('Failed to load users:', e); }
}

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
                    <option value="analyst" ${u.role === 'analyst' ? 'selected' : ''}>Analyst</option>
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
// PERMISSIONS MATRIX
// =====================

const PERM_ACCESS_LEVELS = ['blocked', 'read only', 'read/write', 'managerial approval', 'admin approval'];
const PERM_ROLES = ['viewer', 'analyst', 'manager', 'admin'];

const PERM_COLORS = {
    'blocked':              { bg: '#fde8e8', text: '#991b1b' },
    'read only':            { bg: '#e8f0fe', text: '#1e40af' },
    'read/write':           { bg: '#e6f4ea', text: '#166534' },
    'managerial approval':  { bg: '#fef3c7', text: '#92400e' },
    'admin approval':       { bg: '#f3e8ff', text: '#6b21a8' }
};

async function loadPermissionsMatrix() {
    const container = document.getElementById('permissionsMatrixContainer');
    if (!container) return;
    try {
        const res = await fetch('/admin/permissions');
        const data = await res.json();
        renderPermissionsMatrix(data, container);
    } catch (e) {
        container.innerHTML = '<p style="color:#c01e19;">Failed to load permissions.</p>';
        console.error('Failed to load permissions:', e);
    }
}

function renderPermissionsMatrix(data, container) {
    container.innerHTML = '';

    for (const category of Object.keys(data)) {
        const section = document.createElement('div');
        section.style.marginBottom = '24px';

        const heading = document.createElement('h4');
        heading.textContent = category + ' Permissions';
        heading.style.cssText = 'margin:0 0 8px 0;color:#57534E;font-size:0.95em;';
        section.appendChild(heading);

        const table = document.createElement('table');
        table.className = 'admin-perm-table';

        // Header row
        const thead = document.createElement('thead');
        const headerRow = document.createElement('tr');
        const thPerm = document.createElement('th');
        thPerm.textContent = 'Permission';
        headerRow.appendChild(thPerm);
        for (const role of PERM_ROLES) {
            const th = document.createElement('th');
            th.textContent = role.charAt(0).toUpperCase() + role.slice(1);
            headerRow.appendChild(th);
        }
        thead.appendChild(headerRow);
        table.appendChild(thead);

        // Body rows
        const tbody = document.createElement('tbody');
        const permissions = data[category];
        for (const permName of Object.keys(permissions)) {
            const tr = document.createElement('tr');
            const tdLabel = document.createElement('td');
            tdLabel.textContent = permName;
            tdLabel.style.fontWeight = '500';
            tr.appendChild(tdLabel);

            for (const role of PERM_ROLES) {
                const td = document.createElement('td');
                td.className = 'perm-cell';
                const currentVal = permissions[permName][role] || 'blocked';

                const display = document.createElement('span');
                display.className = 'perm-badge';
                display.textContent = currentVal;
                const colors = PERM_COLORS[currentVal] || { bg: '#f5f5f5', text: '#333' };
                display.style.cssText = `background:${colors.bg};color:${colors.text};padding:3px 8px;border-radius:4px;font-size:0.8em;cursor:pointer;display:inline-block;`;
                display.title = 'Click to change';

                const select = document.createElement('select');
                select.className = 'perm-select';
                select.style.display = 'none';
                for (const level of PERM_ACCESS_LEVELS) {
                    const opt = document.createElement('option');
                    opt.value = level;
                    opt.textContent = level;
                    if (level === currentVal) opt.selected = true;
                    select.appendChild(opt);
                }

                // Click badge → show dropdown
                display.addEventListener('click', () => {
                    display.style.display = 'none';
                    select.style.display = 'inline-block';
                    select.focus();
                });

                // Dropdown change → save & update badge
                select.addEventListener('change', async () => {
                    const newVal = select.value;
                    select.style.display = 'none';
                    display.style.display = 'inline-block';
                    display.textContent = newVal;
                    const newColors = PERM_COLORS[newVal] || { bg: '#f5f5f5', text: '#333' };
                    display.style.background = newColors.bg;
                    display.style.color = newColors.text;
                    await savePermission(category, permName, role, newVal);
                });

                // Dropdown blur → cancel
                select.addEventListener('blur', () => {
                    select.style.display = 'none';
                    display.style.display = 'inline-block';
                });

                td.appendChild(display);
                td.appendChild(select);
                tr.appendChild(td);
            }
            tbody.appendChild(tr);
        }
        table.appendChild(tbody);
        section.appendChild(table);
        container.appendChild(section);
    }
}

async function savePermission(category, permission, role, accessLevel) {
    const status = document.getElementById('permSaveStatus');
    try {
        const res = await fetch('/admin/permissions', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ category, permission, role, access_level: accessLevel })
        });
        const data = await res.json();
        if (data.success) {
            status.textContent = 'Saved';
            status.style.color = '#50b88e';
        } else {
            status.textContent = data.error || 'Save failed';
            status.style.color = '#c01e19';
        }
    } catch (e) {
        status.textContent = 'Connection error';
        status.style.color = '#c01e19';
    }
    setTimeout(() => status.textContent = '', 2500);
}