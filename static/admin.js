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