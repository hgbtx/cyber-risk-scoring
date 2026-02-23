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