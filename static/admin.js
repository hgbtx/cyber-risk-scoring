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
        loadAuditLog(1);
        loadScanSettings();
        loadScanHistory();
        loadFalsePositives();
        loadRiskTolerance();
    }
});

// =====================
// ORG POLICIES
// =====================

// LOAD ORG POLICIES
async function loadOrgPolicies() {
    try {
        const [policyRes, orgRes] = await Promise.all([
            fetch('/admin/policies'),
            fetch('/admin/organization')
        ]);
        const data = await policyRes.json();
        const orgData = await orgRes.json();
        if (data.otp_expiry_hours) document.getElementById('policyOtpExpiry').value = data.otp_expiry_hours;
        const mfaSelect = document.getElementById('policyMfaRequired');
        if (mfaSelect) mfaSelect.value = data.mfa_required_role != null ? String(data.mfa_required_role) : '';
        if (data.sla_enabled !== undefined) {
            const slaEn = document.getElementById('slaEnabled');
            const slaCrit = document.getElementById('slaCriticalDays');
            const slaStd = document.getElementById('slaStandardDays');
            if (slaEn)   slaEn.checked = !!data.sla_enabled;
            if (slaCrit) slaCrit.value = data.sla_critical_days || 7;
            if (slaStd)  slaStd.value  = data.sla_standard_days || 30;
        }
        if (orgData.name) {
            const orgInput = document.getElementById('orgName');
            orgInput.value = orgData.name;
            if (orgData.name !== 'Default') {
                orgInput.disabled = true;
                orgInput.title = 'Organization name cannot be changed after registration.';
                orgInput.style.background = '#f5f5f5';
                orgInput.style.color = '#999';
                orgInput.style.cursor = 'not-allowed';
            }
        }
    } catch (e) { console.error('Failed to load policies:', e); }
}

// SAVE ORG POLICIES
async function saveOrgPolicies() {
    const status = document.getElementById('policyStatus');
    status.textContent = 'Saving...';
    status.style.color = '#57534E';
    try {
        const orgInput = document.getElementById('orgName');
        const orgName = orgInput.value.trim();
        const orgLocked = orgInput.disabled;
        const [policyRes, orgRes] = await Promise.all([
            fetch('/admin/policies', {
                method: 'POST', headers: csrfHeaders(),
                body: JSON.stringify({
                    otp_expiry_hours: parseInt(document.getElementById('policyOtpExpiry').value),
                    mfa_required_role: (() => { const v = document.getElementById('policyMfaRequired')?.value; return v ? parseInt(v) : null; })(),
                    sla_enabled:       document.getElementById('slaEnabled')?.checked ? 1 : 0,
                    sla_critical_days: parseInt(document.getElementById('slaCriticalDays')?.value || '7'),
                    sla_standard_days: parseInt(document.getElementById('slaStandardDays')?.value || '30')
                })
            }),
            (!orgLocked && orgName) ? fetch('/admin/organization', {
                method: 'POST', headers: csrfHeaders(),
                body: JSON.stringify({ name: orgName })
            }) : Promise.resolve({ json: () => ({ success: true }) })
        ]);
        const data = await policyRes.json();
        const orgData = await orgRes.json();
        if (data.success && orgData.success) { status.textContent = 'Saved'; status.style.color = '#50b88e'; }
        else { status.textContent = data.error || orgData.error || 'Failed'; status.style.color = '#c01e19'; }
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
            method: 'POST', headers: csrfHeaders(),
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
            method: 'POST', headers: csrfHeaders(),
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
            method: 'POST', headers: csrfHeaders(),
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
            method: 'POST', headers: csrfHeaders(),
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
        'archive tickets':          { viewer:0, 'tier 1 analyst':0, 'tier 2 analyst':0, manager:1, admin:1 },
        'restore tickets':          { viewer:0, 'tier 1 analyst':0, 'tier 2 analyst':0, manager:1, admin:1 },
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
            headers: csrfHeaders(),
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

// =====================
// AUDIT LOG VIEWER
// =====================

async function loadAuditLog(page = 1) {
    const action = document.getElementById('auditFilterAction')?.value || '';
    const user = document.getElementById('auditFilterUser')?.value || '';
    const dateFrom = document.getElementById('auditFilterFrom')?.value || '';
    const dateTo = document.getElementById('auditFilterTo')?.value || '';

    const params = new URLSearchParams({ page, per_page: 50 });
    if (action) params.set('action', action);
    if (user) params.set('user', user);
    if (dateFrom) params.set('date_from', dateFrom);
    if (dateTo) params.set('date_to', dateTo);

    try {
        const res = await fetch(`/admin/audit-log?${params}`);
        const data = await res.json();
        renderAuditLog(data);
    } catch (e) { console.error('Failed to load audit log:', e); }
}

function renderAuditLog(data) {
    const tbody = document.getElementById('auditLogBody');
    if (!tbody) return;
    tbody.innerHTML = '';

    for (const entry of (data.entries || [])) {
        const tr = document.createElement('tr');
        let details = '';
        if (entry.details) {
            try { details = JSON.stringify(JSON.parse(entry.details)); } catch { details = entry.details; }
        }
        const resource = [entry.resource_type, entry.resource_id].filter(Boolean).join(': ');
        tr.innerHTML = `
            <td style="white-space:nowrap;font-size:0.82em;">${escapeHtml(entry.timestamp || '')}</td>
            <td>${escapeHtml(entry.username || '—')}</td>
            <td><code style="background:#f5f5f5;padding:1px 4px;border-radius:2px;font-size:0.85em;">${escapeHtml(entry.action)}</code></td>
            <td style="font-size:0.85em;">${escapeHtml(resource || '—')}</td>
            <td style="font-size:0.82em;max-width:200px;overflow:hidden;text-overflow:ellipsis;" title="${escapeHtml(details)}">${escapeHtml(details || '—')}</td>
            <td style="font-size:0.82em;">${escapeHtml(entry.ip_address || '—')}</td>
        `;
        tbody.appendChild(tr);
    }

    // Pagination
    const pagDiv = document.getElementById('auditLogPagination');
    if (pagDiv && data.pages > 1) {
        let html = '';
        if (data.page > 1) html += `<a href="#" onclick="loadAuditLog(${data.page - 1}); return false;" style="margin:0 4px;color:#be7a15;">‹ Prev</a>`;
        html += `Page ${data.page} of ${data.pages}`;
        if (data.page < data.pages) html += `<a href="#" onclick="loadAuditLog(${data.page + 1}); return false;" style="margin:0 4px;color:#be7a15;">Next ›</a>`;
        pagDiv.innerHTML = html;
    } else if (pagDiv) {
        pagDiv.innerHTML = '';
    }
}

function exportAuditLog() {
    window.open('/admin/audit-log/export', '_blank');
}

// =====================
// SCHEDULED SCANNING
// =====================

async function loadScanSettings() {
    try {
        const res = await fetch('/admin/policies');
        const data = await res.json();
        const rescanEn = document.getElementById('rescanEnabled');
        const rescanInt = document.getElementById('rescanInterval');
        const autoTicketEn = document.getElementById('autoTicketEnabled');
        const autoTicketTh = document.getElementById('autoTicketThreshold');
        if (rescanEn) rescanEn.checked = !!data.rescan_enabled;
        if (rescanInt) rescanInt.value = data.rescan_interval_hours || 168;
        if (autoTicketEn) autoTicketEn.checked = !!data.auto_ticket_enabled;
        if (autoTicketTh) autoTicketTh.value = data.auto_ticket_threshold || 7.0;
    } catch (e) { console.error('Failed to load scan settings:', e); }
}

async function saveScanSettings() {
    const status = document.getElementById('scanSettingsStatus');
    status.textContent = 'Saving...';
    status.style.color = '#57534E';
    try {
        const res = await fetch('/admin/policies', {
            method: 'POST',
            headers: csrfHeaders(),
            body: JSON.stringify({
                otp_expiry_hours: parseInt(document.getElementById('policyOtpExpiry').value),
                rescan_enabled: document.getElementById('rescanEnabled').checked ? 1 : 0,
                rescan_interval_hours: parseInt(document.getElementById('rescanInterval').value),
                auto_ticket_enabled: document.getElementById('autoTicketEnabled').checked ? 1 : 0,
                auto_ticket_threshold: parseFloat(document.getElementById('autoTicketThreshold').value),
            })
        });
        const data = await res.json();
        if (data.success) { status.textContent = 'Saved'; status.style.color = '#50b88e'; }
        else { status.textContent = data.error || 'Failed'; status.style.color = '#c01e19'; }
    } catch (e) { status.textContent = 'Connection error'; status.style.color = '#c01e19'; }
    setTimeout(() => status.textContent = '', 3000);
}

async function triggerRescanNow() {
    const status = document.getElementById('scanSettingsStatus');
    status.textContent = 'Scanning...';
    status.style.color = '#57534E';
    try {
        const res = await fetch('/admin/rescan-now', { method: 'POST', headers: csrfHeaders() });
        const data = await res.json();
        if (data.success) {
            status.textContent = `Scan complete: ${data.assets_scanned} assets, ${data.new_cves} new CVEs`;
            status.style.color = '#50b88e';
            loadScanHistory();
        } else {
            status.textContent = data.error || 'Scan failed';
            status.style.color = '#c01e19';
        }
    } catch (e) { status.textContent = 'Connection error'; status.style.color = '#c01e19'; }
    setTimeout(() => status.textContent = '', 5000);
}

async function loadScanHistory() {
    try {
        const res = await fetch('/admin/scan-history');
        const data = await res.json();
        renderScanHistory(data.entries || []);
    } catch (e) { console.error('Failed to load scan history:', e); }
}

function renderScanHistory(entries) {
    const tbody = document.getElementById('scanHistoryBody');
    if (!tbody) return;
    tbody.innerHTML = '';
    for (const e of entries) {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td style="font-size:0.82em;white-space:nowrap;">${escapeHtml(e.completed_at || e.started_at || '—')}</td>
            <td style="font-size:0.82em;">${escapeHtml(e.cpe_name || '—')}</td>
            <td>${escapeHtml(e.scan_type || '—')}</td>
            <td>${e.new_cve_count}</td>
            <td>${e.total_cve_count}</td>
            <td>${e.tickets_created}</td>
            <td><span style="color:${e.status === 'completed' ? '#50b88e' : e.status === 'failed' ? '#c01e19' : '#57534E'}">${escapeHtml(e.status)}</span></td>
        `;
        tbody.appendChild(tr);
    }
}

// =====================
// FALSE POSITIVE REVIEW
// =====================

async function loadFalsePositives() {
    const container = document.getElementById('falsePositiveReviewContainer');
    if (!container) return;
    try {
        const res = await fetch('/admin/false-positives');
        const data = await res.json();
        if (!data.length) {
            container.innerHTML = '<p style="color:#999;font-style:italic;">No active false positive determinations.</p>';
            return;
        }
        const table = document.createElement('table');
        table.className = 'admin-users-table';
        table.style.width = '100%';
        table.innerHTML = `<thead><tr>
            <th>CVE ID</th><th>CPE Name</th><th>Justification</th>
            <th>Decided By</th><th>Date</th><th>Action</th>
        </tr></thead>`;
        const tbody = document.createElement('tbody');
        for (const fp of data) {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td style="font-size:0.85em;">${escapeHtml(fp.cve_id || '—')}</td>
                <td style="font-size:0.82em;word-break:break-all;">${escapeHtml(fp.cpe_name || '—')}</td>
                <td style="font-size:0.82em;">${escapeHtml(fp.justification || '—')}</td>
                <td>${escapeHtml(fp.decided_by_username || '—')}</td>
                <td style="font-size:0.82em;white-space:nowrap;">${escapeHtml(fp.created_at || '—')}</td>
                <td><button onclick="reverseFalsePositive(${fp.id})"
                    style="padding:3px 10px;background:#c01e19;color:white;border:none;border-radius:4px;cursor:pointer;font-size:0.82em;">Reverse</button></td>
            `;
            tbody.appendChild(tr);
        }
        table.appendChild(tbody);
        container.innerHTML = '';
        container.appendChild(table);
    } catch (e) { console.error('Failed to load false positives:', e); }
}

async function reverseFalsePositive(decisionId) {
    if (!confirm('Reverse this false positive determination? The CVE will reappear in charts and scoring.')) return;
    try {
        const res = await fetch('/admin/reverse-false-positive', {
            method: 'POST',
            headers: csrfHeaders(),
            body: JSON.stringify({ decision_id: decisionId })
        });
        const data = await res.json();
        if (data.success) {
            await loadFalsePositives();
            await loadRiskDecisions();
        } else {
            alert(data.error || 'Failed to reverse false positive.');
        }
    } catch (e) { console.error('Failed to reverse false positive:', e); }
}

// =====================
// RISK TOLERANCE (GV.RM-02)
// =====================

async function loadRiskTolerance() {
    try {
        const res = await fetch('/admin/risk-tolerance');
        const data = await res.json();
        orgRiskThreshold = data.risk_threshold ?? 7.0;
        orgRiskToleranceStatement = data.risk_tolerance_statement || '';

        // Update admin form if admin
        if (hasMinRole('admin')) {
            const thresholdInput = document.getElementById('riskToleranceThreshold');
            const statementInput = document.getElementById('riskToleranceStatement');
            if (thresholdInput) thresholdInput.value = orgRiskThreshold;
            if (statementInput) statementInput.value = orgRiskToleranceStatement;
        }

        // Sync chart slider to match org threshold
        const slider = document.getElementById('riskThresholdSlider');
        const label = document.getElementById('thresholdValue');
        if (slider) { slider.value = orgRiskThreshold; chartRiskThreshold = orgRiskThreshold; }
        if (label) label.textContent = orgRiskThreshold.toFixed(1);

        // Populate readonly display for all users (charts panel)
        const display = document.getElementById('riskToleranceDisplay');
        if (display) {
            const updatedBy = data.updated_by ? `by ${escapeHtml(data.updated_by)}` : '';
            const updatedAt = data.updated_at ? new Date(data.updated_at).toLocaleDateString() : '';
            display.innerHTML = `
                <div style="margin-bottom:8px;">
                    <strong>Org Risk Threshold:</strong> <span style="font-size:1.1em;color:#c01e19;font-weight:700;">${orgRiskThreshold.toFixed(1)}</span> / 10
                </div>
                <div style="margin-bottom:8px;">
                    <strong>Risk Appetite Statement:</strong><br>
                    <div style="background:#f9f9f9;border:1px solid #eee;border-radius:4px;padding:10px;margin-top:4px;font-size:0.9em;white-space:pre-wrap;">${
                        orgRiskToleranceStatement ? escapeHtml(orgRiskToleranceStatement) : '<em style="color:#999;">No risk appetite statement has been set.</em>'
                    }</div>
                </div>
                ${updatedAt ? `<div style="font-size:0.8em;color:#999;">Last updated ${updatedAt} ${updatedBy}</div>` : ''}
            `;
        }
        loadThresholdHistory();
    } catch (e) { console.error('Failed to load risk tolerance:', e); }
}

async function saveRiskTolerance() {
    const thresholdInput = document.getElementById('riskToleranceThreshold');
    const statementInput = document.getElementById('riskToleranceStatement');
    const reasonInput = document.getElementById('riskToleranceReason');
    const status = document.getElementById('riskToleranceStatus');
    if (!thresholdInput || !status) return;
    const payload = {
        risk_threshold: parseFloat(thresholdInput.value),
        risk_tolerance_statement: statementInput ? statementInput.value : '',
        reason: reasonInput ? reasonInput.value.trim() : '',
    };
    try {
        const res = await fetch('/admin/risk-tolerance', {
            method: 'POST',
            headers: csrfHeaders(),
            body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (data.success) {
            status.textContent = 'Saved';
            status.style.color = '#50b88e';
            await loadRiskTolerance();
            if (reasonInput) reasonInput.value = '';
        } else {
            status.textContent = data.error || 'Error saving';
            status.style.color = '#c01e19';
        }
    } catch (e) {
        status.textContent = 'Connection error';
        status.style.color = '#c01e19';
    }
    setTimeout(() => { status.textContent = ''; }, 5000);
}

async function loadThresholdHistory() {
    try {
        const res = await fetch('/admin/risk-threshold-history');
        const data = await res.json();
        renderThresholdHistory(data.entries || []);
    } catch (e) { console.error('Failed to load threshold history:', e); }
}

function renderThresholdHistory(entries) {
    const tbody = document.getElementById('thresholdHistoryBody');
    if (!tbody) return;
    tbody.innerHTML = '';
    if (!entries.length) {
        tbody.innerHTML = '<tr><td colspan="5" style="color:#999;font-style:italic;text-align:center;">No history yet.</td></tr>';
        return;
    }
    for (const e of entries) {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td style="font-size:0.82em;white-space:nowrap;">${escapeHtml(e.created_at || '—')}</td>
            <td>${escapeHtml(e.username || '—')}</td>
            <td>${typeof e.old_value === 'number' ? e.old_value.toFixed(1) : '—'}</td>
            <td>${typeof e.new_value === 'number' ? e.new_value.toFixed(1) : '—'}</td>
            <td style="font-size:0.85em;">${escapeHtml(e.reason || '—')}</td>
        `;
        tbody.appendChild(tr);
    }
}