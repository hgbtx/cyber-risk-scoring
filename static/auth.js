async function checkAuth() {
    try {
        const res = await fetch('/auth/me');
        const data = await res.json();
        if (data.authenticated) { currentUser = data.user; showApp(); }
        else { showAuthOverlay(); }
    } catch (e) { showAuthOverlay(); }
}

function showAuthOverlay() {
    currentUser = null;
    document.getElementById('authOverlay').style.display = 'flex';
    document.getElementById('appContainer').style.display = 'none';
    document.getElementById('userBar').style.display = 'none';
    showLoginForm();
}

function showApp() {
    document.getElementById('authOverlay').style.display = 'none';
    document.getElementById('appContainer').style.display = 'flex';
    const bar = document.getElementById('userBar');
    bar.style.display = 'flex';
    document.getElementById('userUsername').textContent = currentUser.username;
    document.getElementById('userRole').textContent = currentUser.role;
    loadPersistedData();
    const adminTab = document.querySelector('[data-tab="admin"]');
    if (adminTab) adminTab.style.display = hasMinRole('admin') ? '' : 'none';
    if (hasMinRole('admin')) {
        loadOrgPolicies();
        loadAdminUsers();
    }
    // Enforce tab visibility based on role permissions
    applyTabPermissions();
}

function showLoginForm() {
    document.getElementById('loginForm').style.display = 'block';
    document.getElementById('newUserForm').style.display = 'none';
    document.getElementById('setPasswordForm').style.display = 'none';
    document.getElementById('authError').textContent = '';
}

function showNewUserForm() {
    document.getElementById('loginForm').style.display = 'none';
    document.getElementById('newUserForm').style.display = 'block';
    document.getElementById('setPasswordForm').style.display = 'none';
    document.getElementById('authError').textContent = '';
}

function showSetPasswordForm() {
    document.getElementById('loginForm').style.display = 'none';
    document.getElementById('newUserForm').style.display = 'none';
    document.getElementById('setPasswordForm').style.display = 'block';
    document.getElementById('authError').textContent = '';
}

async function handleLogin() {
    const username = document.getElementById('loginUsername').value.trim();
    const password = document.getElementById('loginPassword').value;
    const err = document.getElementById('authError');
    err.textContent = '';
    if (!username || !password) { err.textContent = 'Please enter username and password.'; return; }
    try {
        const res = await fetch('/auth/login', {
            method: 'POST', headers: {'Content-Type':'application/json'},
            body: JSON.stringify({ username, password })
        });
        const data = await res.json();
        if (data.success) { currentUser = data.user; showApp(); }
        else { err.textContent = data.error || 'Login failed.'; }
    } catch (e) { err.textContent = 'Connection error.'; }
}

async function handleOtpLogin() {
    const username = document.getElementById('otpUsername').value.trim();
    const otp = document.getElementById('otpPassword').value.trim();
    const err = document.getElementById('authError');
    err.textContent = '';
    if (!username || !otp) { err.textContent = 'Please enter username and one-time password.'; return; }
    try {
        const res = await fetch('/auth/verify-otp', {
            method: 'POST', headers: {'Content-Type':'application/json'},
            body: JSON.stringify({ username, otp })
        });
        const data = await res.json();
        if (data.success && data.must_change_password) { showSetPasswordForm(); }
        else if (data.success) { checkAuth(); }
        else { err.textContent = data.error || 'Verification failed.'; }
    } catch (e) { err.textContent = 'Connection error.'; }
}

async function handleSetPassword() {
    const password = document.getElementById('newPassword').value;
    const confirm = document.getElementById('confirmNewPassword').value;
    const err = document.getElementById('authError');
    err.textContent = '';
    if (!password) { err.textContent = 'Password is required.'; return; }
    if (password !== confirm) { err.textContent = 'Passwords do not match.'; return; }
    if (password.length < 8) { err.textContent = 'Password must be 8+ characters.'; return; }
    try {
        const res = await fetch('/auth/set-password', {
            method: 'POST', headers: {'Content-Type':'application/json'},
            body: JSON.stringify({ password })
        });
        const data = await res.json();
        if (data.success) { checkAuth(); }
        else { err.textContent = data.error || 'Failed to set password.'; }
    } catch (e) { err.textContent = 'Connection error.'; }
}

async function handleLogout() {
    await fetch('/auth/logout', { method: 'POST' }).catch(() => {});
    currentUser = null;
    allResults = []; cveDataStore = {}; cpeDataStore = {};
    totalCveCount = 0; tickets = []; ticketIdCounter = 1;
    selectedItems.innerHTML = '<p id="placeholder" style="color:#999;font-style:italic;">Drag and drop your assets here...</p>';
    document.getElementById('cveCounts').textContent = '0 CVEs found';
    resultsList.innerHTML = ''; resultsContainer.style.display = 'none';
    document.getElementById('ticketsList').innerHTML = '';
    if (epssChartInstance) { epssChartInstance.destroy(); epssChartInstance = null; }
    if (cvssHistogramInstance) { cvssHistogramInstance.destroy(); cvssHistogramInstance = null; }
    archivedAssets = new Set();
    showAuthOverlay();
}

//============================
// TAB PERMISSION ENFORCEMENT
//============================

// Maps permission category → data-tab attribute value
const TAB_PERM_MAP = {
    'Search':           'search',
    'Asset Directory':  'cve',
    'myCharts':         'charts',
    'myTickets':        'tickets'
};

async function applyTabPermissions() {
    // Admins always see all tabs
    if (currentUser && currentUser.role === 'admin') return;
    try {
        const res = await fetch('/auth/my-permissions');
        const data = await res.json();
        const perms = data.permissions || {};
        for (const [category, tabId] of Object.entries(TAB_PERM_MAP)) {
            const viewKey = Object.keys(perms[category] || {}).find(k => k.startsWith('view '));
            const allowed = viewKey ? perms[category][viewKey] : 1;
            const tabBtn = document.querySelector(`[data-tab="${tabId}"]`);
            const tabPanel = document.querySelector(`[data-panel="${tabId}"]`);
            if (tabBtn) tabBtn.style.display = allowed ? '' : 'none';
            if (tabPanel && !allowed) tabPanel.classList.remove('active');
        }
        // If the active tab got hidden, fall back to the first visible tab
        const activeBtn = document.querySelector('.tab-button.active');
        if (!activeBtn || activeBtn.style.display === 'none') {
            const firstVisible = document.querySelector('.tab-button:not([style*="display: none"])');
            if (firstVisible) firstVisible.click();
        }
    } catch (e) {
        console.error('Failed to load tab permissions:', e);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('loginPassword')?.addEventListener('keypress', e => { if (e.key==='Enter') handleLogin(); });
    document.getElementById('otpPassword')?.addEventListener('keypress', e => { if (e.key==='Enter') handleOtpLogin(); });
    document.getElementById('confirmNewPassword')?.addEventListener('keypress', e => { if (e.key==='Enter') handleSetPassword(); });
    checkAuth();
});