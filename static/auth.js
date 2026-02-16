let currentUser = null;

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
}

function showApp() {
    document.getElementById('authOverlay').style.display = 'none';
    document.getElementById('appContainer').style.display = 'flex';
    const bar = document.getElementById('userBar');
    bar.style.display = 'flex';
    document.getElementById('userEmail').textContent = currentUser.email;
    document.getElementById('userRole').textContent = currentUser.role;
    loadPersistedData();
}

function showLoginForm() {
    document.getElementById('loginForm').style.display = 'block';
    document.getElementById('registerForm').style.display = 'none';
    document.getElementById('authError').textContent = '';
}
function showRegisterForm() {
    document.getElementById('loginForm').style.display = 'none';
    document.getElementById('registerForm').style.display = 'block';
    document.getElementById('authError').textContent = '';
}

async function handleLogin() {
    const email = document.getElementById('loginEmail').value.trim();
    const password = document.getElementById('loginPassword').value;
    const err = document.getElementById('authError');
    err.textContent = '';
    if (!email || !password) { err.textContent = 'Please enter email and password.'; return; }
    try {
        const res = await fetch('/auth/login', {
            method: 'POST', headers: {'Content-Type':'application/json'},
            body: JSON.stringify({ email, password })
        });
        const data = await res.json();
        if (data.success) { currentUser = data.user; showApp(); }
        else { err.textContent = data.error || 'Login failed.'; }
    } catch (e) { err.textContent = 'Connection error.'; }
}

async function handleRegister() {
    const email = document.getElementById('registerEmail').value.trim();
    const password = document.getElementById('registerPassword').value;
    const confirm = document.getElementById('registerConfirm').value;
    const err = document.getElementById('authError');
    err.textContent = '';
    if (!email || !password) { err.textContent = 'Email and password required.'; return; }
    if (password !== confirm) { err.textContent = 'Passwords do not match.'; return; }
    if (password.length < 8) { err.textContent = 'Password must be 8+ characters.'; return; }
    try {
        const res = await fetch('/auth/register', {
            method: 'POST', headers: {'Content-Type':'application/json'},
            body: JSON.stringify({ email, password })
        });
        const data = await res.json();
        if (data.success) { currentUser = data.user; showApp(); }
        else { err.textContent = data.error || 'Registration failed.'; }
    } catch (e) { err.textContent = 'Connection error.'; }
}

async function handleLogout() {
    await fetch('/auth/logout', { method: 'POST' }).catch(() => {});
    currentUser = null;
    allResults = []; cveDataStore = {}; cpeDataStore = {};
    cpeSearchCache = {}; totalCveCount = 0; tickets = []; ticketIdCounter = 1;
    selectedItems.innerHTML = '<p id="placeholder" style="color:#999;font-style:italic;">Drag and drop your assets here...</p>';
    document.getElementById('cveCounts').textContent = '0 CVEs found';
    resultsList.innerHTML = ''; resultsContainer.style.display = 'none';
    document.getElementById('ticketsList').innerHTML = '';
    if (epssChartInstance) { epssChartInstance.destroy(); epssChartInstance = null; }
    if (ciaRadarChartInstance) { ciaRadarChartInstance.destroy(); ciaRadarChartInstance = null; }
    archivedAssets = new Set();
    showAuthOverlay();
}

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('loginPassword')?.addEventListener('keypress', e => { if (e.key==='Enter') handleLogin(); });
    document.getElementById('registerConfirm')?.addEventListener('keypress', e => { if (e.key==='Enter') handleRegister(); });
    checkAuth();
});