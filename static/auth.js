let mfaSessionToken = null;

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
    stopNotifPolling();
    document.getElementById('authOverlay').style.display = 'flex';
    document.getElementById('appContainer').style.display = 'none';
    document.getElementById('userBar').style.display = 'none';
    showLoginForm();
}

async function showApp() {
    document.getElementById('authOverlay').style.display = 'none';
    document.getElementById('appContainer').style.display = 'flex';
    const bar = document.getElementById('userBar');
    bar.style.display = 'flex';
    document.getElementById('userUsername').textContent = currentUser.username;
    document.getElementById('userRole').textContent = currentUser.role;

    // MFA badge
    const mfaBadge = document.getElementById('mfaBadge');
    if (mfaBadge) {
        mfaBadge.style.display = 'inline';
        if (currentUser.totp_enabled) {
            mfaBadge.style.color = '#50b88e';
            mfaBadge.title = '2FA Enabled — click to disable';
            mfaBadge.onclick = () => disableTotp();
        } else {
            mfaBadge.style.color = '#e67e22';
            mfaBadge.title = '2FA Not Enabled — click to set up';
            mfaBadge.onclick = () => startTotpSetup();
        }
    }

    // Hide admin tab and panel BEFORE permission-based tab logic runs,
    // so the fallback "first visible tab" never lands on admin
    const adminTab = document.querySelector('[data-tab="admin"]');
    const adminPanel = document.querySelector('[data-panel="admin"]');
    if (adminTab) adminTab.style.display = hasMinRole('admin') ? '' : 'none';
    if (adminPanel && !hasMinRole('admin')) adminPanel.style.display = 'none';

    // Read saved tab BEFORE applyTabPermissions() can overwrite sessionStorage via click()
    const savedTab = sessionStorage.getItem('activeTab');

    // Load permissions BEFORE rendering data so hasPermission() works in render functions
    await loadUserPermissions();
    applyTabPermissions();
    applyPermissions();

    // Restore the tab the user was on before the page reload
    if (savedTab) {
        const savedBtn = document.querySelector(`.tab-button[data-tab="${savedTab}"]`);
        if (savedBtn && savedBtn.style.display !== 'none') savedBtn.click();
    }

    loadPersistedData();
    if (hasMinRole('admin')) {
        loadOrgPolicies();
        loadAdminUsers();
    }
    // Initialize notifications
    startNotifPolling();
    // Load org risk tolerance (for chart slider sync + display)
    loadRiskTolerance();
}

function hideAllAuthForms() {
    for (const id of ['loginForm', 'newUserForm', 'setPasswordForm', 'totpForm', 'backupCodeForm']) {
        const el = document.getElementById(id);
        if (el) el.style.display = 'none';
    }
    document.getElementById('authError').textContent = '';
}

function showLoginForm() {
    hideAllAuthForms();
    document.getElementById('loginForm').style.display = 'block';
}

function showNewUserForm() {
    hideAllAuthForms();
    document.getElementById('newUserForm').style.display = 'block';
}

function showSetPasswordForm() {
    hideAllAuthForms();
    document.getElementById('setPasswordForm').style.display = 'block';
}

function showTotpForm() {
    hideAllAuthForms();
    document.getElementById('totpForm').style.display = 'block';
}

function showBackupCodeForm() {
    hideAllAuthForms();
    document.getElementById('backupCodeForm').style.display = 'block';
}

async function handleLogin() {
    const username = document.getElementById('loginUsername').value.trim();
    const password = document.getElementById('loginPassword').value;
    const err = document.getElementById('authError');
    err.textContent = '';
    if (!username || !password) { err.textContent = 'Please enter username and password.'; return; }
    try {
        const res = await fetch('/auth/login', {
            method: 'POST', headers: csrfHeaders(),
            body: JSON.stringify({ username, password })
        });
        const data = await res.json();
        if (data.requires_mfa) {
            mfaSessionToken = data.mfa_session_token;
            showTotpForm();
        } else if (data.success && data.mfa_setup_required) {
            currentUser = data.user;
            hideAllAuthForms();
            document.getElementById('authOverlay').style.display = 'flex';
            alert('MFA is required for your role. Please set up two-factor authentication to continue.');
            startTotpSetup();
        } else if (data.success) {
            currentUser = data.user; showApp();
        } else {
            err.textContent = data.error || 'Login failed.';
        }
    } catch (e) { err.textContent = 'Connection error.'; }
}

async function handleTotpVerify() {
    const code = document.getElementById('totpCode').value.trim();
    const err = document.getElementById('authError');
    err.textContent = '';
    if (!code) { err.textContent = 'Please enter the 6-digit code.'; return; }
    try {
        const res = await fetch('/auth/totp-verify', {
            method: 'POST', headers: csrfHeaders(),
            body: JSON.stringify({ code, mfa_session_token: mfaSessionToken })
        });
        const data = await res.json();
        if (data.success) { currentUser = data.user; mfaSessionToken = null; showApp(); }
        else { err.textContent = data.error || 'Verification failed.'; }
    } catch (e) { err.textContent = 'Connection error.'; }
}

async function handleBackupCodeVerify() {
    const code = document.getElementById('backupCode').value.trim();
    const err = document.getElementById('authError');
    err.textContent = '';
    if (!code) { err.textContent = 'Please enter a backup code.'; return; }
    try {
        const res = await fetch('/auth/totp-verify', {
            method: 'POST', headers: csrfHeaders(),
            body: JSON.stringify({ code, mfa_session_token: mfaSessionToken })
        });
        const data = await res.json();
        if (data.success) { currentUser = data.user; mfaSessionToken = null; showApp(); }
        else { err.textContent = data.error || 'Verification failed.'; }
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
            method: 'POST', headers: csrfHeaders(),
            body: JSON.stringify({ username, otp })
        });
        const data = await res.json();
        if (data.success && data.must_change_password) { showSetPasswordForm(); }
        else if (data.success) { checkAuth(); }
        else { err.textContent = data.error || 'Verification failed.'; }
    } catch (e) { err.textContent = 'Connection error.'; }
}

function validatePassword(pw) {
    if (pw.length < 8) return 'Password must be at least 8 characters.';
    if (!/[A-Z]/.test(pw)) return 'Must contain at least one uppercase letter.';
    if (!/[a-z]/.test(pw)) return 'Must contain at least one lowercase letter.';
    if (!/\d/.test(pw)) return 'Must contain at least one digit.';
    if (!/[^A-Za-z0-9]/.test(pw)) return 'Must contain at least one special character.';
    return null;
}

async function handleSetPassword() {
    const password = document.getElementById('newPassword').value;
    const confirm = document.getElementById('confirmNewPassword').value;
    const err = document.getElementById('authError');
    err.textContent = '';
    if (!password) { err.textContent = 'Password is required.'; return; }
    if (password !== confirm) { err.textContent = 'Passwords do not match.'; return; }
    const pwErr = validatePassword(password);
    if (pwErr) { err.textContent = pwErr; return; }
    try {
        const res = await fetch('/auth/set-password', {
            method: 'POST', headers: csrfHeaders(),
            body: JSON.stringify({ password })
        });
        const data = await res.json();
        if (data.success) { checkAuth(); }
        else { err.textContent = data.error || 'Failed to set password.'; }
    } catch (e) { err.textContent = 'Connection error.'; }
}

async function handleLogout() {
    await fetch('/auth/logout', { method: 'POST', headers: csrfHeaders() }).catch(() => {});
    currentUser = null;
    userPermissions = null;
    allResults = []; cveDataStore = {}; cpeDataStore = {};
    totalCveCount = 0; tickets = []; ticketIdCounter = 1;
    checkedSearchItems = new Set();
    leftPanel.style.display = '';
    // Reset admin panel visibility for next login
    const adminPanelEl = document.querySelector('[data-panel="admin"]');
    if (adminPanelEl) adminPanelEl.style.display = '';
    resultsList.innerHTML = ''; resultsContainer.style.display = 'none';
    document.getElementById('ticketsList').innerHTML = '';
    chartLayout.forEach(id => {
        if (!id) return;
        const c = document.getElementById(id);
        if (c) { const inst = Chart.getChart(c); if (inst) inst.destroy(); }
    });
    chartLayout = [];
    const chartDashboardEl = document.getElementById('chartDashboard');
    if (chartDashboardEl) chartDashboardEl.innerHTML = '';
    const chartPaletteEl = document.getElementById('chartPalette');
    if (chartPaletteEl) chartPaletteEl.innerHTML = '';
    archivedAssets = new Set();
    activeTicketFilter = null;
    const sortSelect = document.getElementById('ticketSortSelect');
    if (sortSelect) sortSelect.value = 'default';

    // Reset chart config state and DOM to defaults
    chartAggMethod = 'mean';
    chartRiskThreshold = 7.0;
    const aggMethodSelect = document.getElementById('aggMethodSelect');
    if (aggMethodSelect) aggMethodSelect.value = 'mean';
    const riskThresholdSlider = document.getElementById('riskThresholdSlider');
    if (riskThresholdSlider) riskThresholdSlider.value = '7';
    const thresholdValue = document.getElementById('thresholdValue');
    if (thresholdValue) thresholdValue.textContent = '7.0';

    // Reset active tab DOM to default (Search) so the next user doesn't inherit the previous tab
    tabButtons.forEach(btn => btn.classList.remove('active'));
    tabPanels.forEach(panel => panel.classList.remove('active'));
    const defaultTabBtn = document.querySelector('.tab-button[data-tab="search"]');
    const defaultTabPanel = document.querySelector('.tab-panel[data-panel="search"]');
    if (defaultTabBtn) defaultTabBtn.classList.add('active');
    if (defaultTabPanel) defaultTabPanel.classList.add('active');
    document.getElementById('chartConfig').style.display = 'none';

    sessionStorage.removeItem('activeTab');
    showAuthOverlay();
}

//============================
// PERMISSION ENFORCEMENT
//============================

// Fetch the current user's permission matrix and store globally
async function loadUserPermissions() {
    if (currentUser && currentUser.role === 'admin') { userPermissions = null; return; }
    try {
        const res = await fetch('/auth/my-permissions');
        const data = await res.json();
        const saved = data.permissions || {};
        // Fill in any missing keys from DEFAULT_PERMISSIONS so newly-added
        // permissions work even if the DB hasn't been re-saved by an admin.
        const role = currentUser?.role || 'viewer';
        const filled = {};
        for (const [cat, actions] of Object.entries(DEFAULT_PERMISSIONS)) {
            filled[cat] = {};
            for (const [action, roleMap] of Object.entries(actions)) {
                filled[cat][action] = (saved[cat] && action in saved[cat])
                    ? saved[cat][action]
                    : (roleMap[role] ?? 0);
            }
        }
        userPermissions = filled;
    } catch (e) {
        console.error('Failed to load user permissions:', e);
        userPermissions = {};
    }
}

// Check a single permission — safe to call from any render function
function hasPermission(category, action) {
    if (!currentUser) return false;
    if (currentUser.role === 'admin') return true;
    if (!userPermissions) return true;
    return !!(userPermissions[category] && userPermissions[category][action]);
}

// Hide/show static DOM elements tagged with data-permission-category/action
function applyPermissions() {
    if (currentUser && currentUser.role === 'admin') return;
    const perms = userPermissions || {};
    document.querySelectorAll('[data-permission-category]').forEach(el => {
        const cat = el.dataset.permissionCategory;
        const act = el.dataset.permissionAction;
        if (!cat || !act) return;
        el.style.display = (perms[cat] && perms[cat][act]) ? '' : 'none';
    });
}

// Maps permission category → data-tab attribute value
const TAB_PERM_MAP = {
    'Search':           'search',
    'Asset Directory':  'cve',
    'myCharts':         'charts',
    'myTickets':        'tickets'
};

// Hide/show tabs based on "view X tab" permissions
function applyTabPermissions() {
    if (currentUser && currentUser.role === 'admin') return;
    const perms = userPermissions || {};
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
}

// =====================
// TOTP SETUP (Settings)
// =====================

async function startTotpSetup() {
    try {
        const res = await fetch('/auth/totp-setup', { method: 'POST', headers: csrfHeaders() });
        const data = await res.json();
        if (data.error) { alert(data.error); return; }

        // Show modal with QR code
        const modal = document.getElementById('totpSetupModal');
        modal.style.display = 'flex';
        document.getElementById('totpSetupStep1').style.display = 'block';
        document.getElementById('totpSetupStep2').style.display = 'none';

        document.getElementById('totpQrCode').innerHTML = `<img src="${data.qr_code}" alt="QR Code" style="max-width:200px;">`;
        document.getElementById('totpSecretDisplay').textContent = data.secret;
        // Store backup codes for display after verification
        modal.dataset.backupCodes = JSON.stringify(data.backup_codes);
    } catch (e) { alert('Failed to start TOTP setup.'); }
}

async function verifyTotpSetup() {
    const code = document.getElementById('totpSetupCode').value.trim();
    if (!code) { alert('Please enter the 6-digit code from your authenticator.'); return; }
    try {
        const res = await fetch('/auth/totp-verify-setup', {
            method: 'POST', headers: csrfHeaders(),
            body: JSON.stringify({ code })
        });
        const data = await res.json();
        if (data.success) {
            document.getElementById('totpSetupStep1').style.display = 'none';
            document.getElementById('totpSetupStep2').style.display = 'block';
            const modal = document.getElementById('totpSetupModal');
            const codes = JSON.parse(modal.dataset.backupCodes || '[]');
            document.getElementById('totpBackupCodes').innerHTML = codes.map(c => `<div>${c}</div>`).join('');
            // Update user state
            if (currentUser) currentUser.totp_enabled = true;
        } else {
            alert(data.error || 'Verification failed.');
        }
    } catch (e) { alert('Connection error.'); }
}

function closeTotpSetupModal() {
    document.getElementById('totpSetupModal').style.display = 'none';
    document.getElementById('totpSetupCode').value = '';
    // If MFA setup was forced (mfa_setup_required), re-check auth to transition into app
    if (currentUser && document.getElementById('authOverlay').style.display !== 'none') {
        checkAuth();
    }
}

async function disableTotp() {
    const code = prompt('Enter your current TOTP code to disable 2FA:');
    if (!code) return;
    try {
        const res = await fetch('/auth/totp-disable', {
            method: 'POST', headers: csrfHeaders(),
            body: JSON.stringify({ code })
        });
        const data = await res.json();
        if (data.success) {
            alert('Two-factor authentication has been disabled.');
            if (currentUser) currentUser.totp_enabled = false;
        } else {
            alert(data.error || 'Failed to disable 2FA.');
        }
    } catch (e) { alert('Connection error.'); }
}

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('loginPassword')?.addEventListener('keypress', e => { if (e.key==='Enter') handleLogin(); });
    document.getElementById('otpPassword')?.addEventListener('keypress', e => { if (e.key==='Enter') handleOtpLogin(); });
    document.getElementById('confirmNewPassword')?.addEventListener('keypress', e => { if (e.key==='Enter') handleSetPassword(); });
    document.getElementById('totpCode')?.addEventListener('keypress', e => { if (e.key==='Enter') handleTotpVerify(); });
    document.getElementById('backupCode')?.addEventListener('keypress', e => { if (e.key==='Enter') handleBackupCodeVerify(); });
    checkAuth();
});