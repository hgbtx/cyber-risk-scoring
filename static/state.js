// =====================
// STATE
// =====================
let allResults = [];
let currentPage = 1; // Pagination starts at page 1
let cveDataStore = {}; // Stores CVE data by CPE name
let cpeDataStore = {}; // Stores CPE metadata by CPE name
let totalCveCount = 0
let expandedCveData = null; // Stores currently expanded CVE
let epssChartInstance = null;
let ciaRadarChartInstance = null;
let riskMatrixChartInstance = null;
let threatVelocityChartInstance = null;
let attackSurfaceChartInstance = null;
let priorityBreakdownChartInstance = null;
let remediationFunnelInstance = null;
let chartLayout = [];
let draggedChartId = null;
const resultsPerPage = 10; // Search results per paginated page
let folderSortKey = 'epss';
let folderSortDir = 'desc';
let activeFolderCpe = null;
let tickets = [];
let ticketIdCounter = 1;
let archivedAssets = new Set(); // CPE names hidden from grid/charts
let assetCriticality = {};  // { cpeName: 1-5 }
let assetTags = {};         // { cpeName: ['tag1', 'tag2'] }

const CRITICALITY_LABELS = { 1: 'Minimal', 2: 'Low', 3: 'Medium', 4: 'High', 5: 'Critical' };
const CRITICALITY_COLORS = { 1: '#50b88e', 2: '#4a90d9', 3: '#d9af6f', 4: '#e67e22', 5: '#c01e19' };
const CRITICALITY_MULTIPLIERS = { 1: 0.5, 2: 0.75, 3: 1.0, 4: 1.25, 5: 1.5 };

function getAdjustedPriorityScore(rawScore, cpeName) {
    const multiplier = CRITICALITY_MULTIPLIERS[assetCriticality[cpeName] || 3] || 1.0;
    return rawScore * multiplier;
}
let chartAggMethod = 'mean';
let chartRiskThreshold = 7.0;
let _dateSliderDates = []; // sorted unique date strings
let activeTicketFilter = null;
let _publishedDateSliderDates = [];
let cpeDetailSortKey = 'title';
let cpeDetailSortDir = 'asc';
let cveEnteredFromDetailView = false;
let currentUser = null;
let userPermissions = null;
let riskDecisions = [];
let notifications = [];
let unreadNotifCount = 0;
let notifPollInterval = null;
let notificationPreferences = {};
let orgRiskThreshold = 7.0;
let orgRiskToleranceStatement = '';

// =====================
// DOM REFERENCES
// =====================
const tabButtons = document.querySelectorAll('.tab-button');
const tabPanels = document.querySelectorAll('.tab-panel');
const searchInput = document.getElementById('searchInput');
const searchButton = document.getElementById('searchButton');
const leftPanel = document.querySelector('.left-panel-container');
const resultsContainer = document.getElementById('resultsContainer');
const resultsList = document.getElementById('resultsList');
const pagination = document.getElementById('pagination');
const goBackLink = document.getElementById('cveFolderBack');
const chartFsBtn = document.getElementById('chartFullscreenToggle');
// Theoretical max: KEV(1000) + EPSS(500) + Age(100) + CVSS(50) + AV(25) + Priv(20) + UI(15) + AC(10) + CIA(24) = 1744
const PRIORITY_SCORE_MAX = 1744;
let checkedSearchItems = new Set();
const ROLE_LEVELS = {
    'viewer': 1,
    'tier 1 analyst': 2,
    'tier 2 analyst': 3,
    'manager': 4,
    'admin': 5
};

// =====================
// HELPERS HELPERS
// =====================

// CSRF / JSON HEADERS
function getCsrfToken() {
    const m = document.cookie.match(/(?:^|;\s*)csrf_token=([^;]*)/);
    return m ? decodeURIComponent(m[1]) : '';
}

function csrfHeaders(extra = {}) {
    return { 'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken(), ...extra };
}

// LOAD FEATURE CATEGORIES INTO TICKET FORM DROPDOWN
async function loadFeatureCategories() {
    const res = await fetch('/db/feature-categories');
    if (!res.ok) throw new Error(`feature-categories ${res.status}`);
    const data = await res.json();
    const select = document.getElementById('ticketFeature');
    if (!select) return;
    select.innerHTML = '<option value="">— Select feature —</option>';
    for (const cat of data.categories) {
        const opt = document.createElement('option');
        opt.value = cat.name;
        opt.textContent = cat.name;
        select.appendChild(opt);
    }
}

// SAVE TICKETS TO BACKEND
function saveTickets() {
    const uid = currentUser?.id;
    const myTickets = tickets.filter(t => t.user_id === uid || !t.user_id);
    fetch('/db/save-tickets', {
        method: 'POST',
        headers: csrfHeaders(),
        body: JSON.stringify({ tickets: myTickets })
    });
}

// SAVE ASSETS TO BACKEND
async function saveAssets() {
    const assets = [];
    for (const cpeName in cveDataStore) {
        const cveEntry = cveDataStore[cpeName] || {};
        // Title may be on the cveDataStore entry (set at fetch time) or the cpeDataStore
        const title = cveEntry.title || cpeDataStore[cpeName]?.titles?.[0]?.title || cpeName;
        assets.push({
            cpeName,
            title,
            cpeData: cpeDataStore[cpeName] || {},
            cveData: cveEntry,
            criticality: assetCriticality[cpeName] ?? 3,
            tags: assetTags[cpeName] ?? []
        });
    }
    try {
        const r = await fetch('/db/save-assets', {
            method: 'POST',
            headers: csrfHeaders(),
            body: JSON.stringify({ assets })
        });
        if (!r.ok) console.error('save-assets failed:', r.status);
        const d = await r.json();
        console.log('save-assets response:', d);
    } catch (e) {
        console.error('save-assets error:', e);
    }
}

// LOAD PERSISTED DATA ON STARTUP
async function loadPersistedData() {
    // Load feature categories for ticket form
    try { await loadFeatureCategories(); } catch (e) { console.error('Failed to load feature categories:', e); }

    // Load risk decisions
    try { await loadRiskDecisions(); } catch (e) { console.error('Failed to load risk decisions:', e); }

    // Load tickets
    try {
        const res = await fetch('/db/load-tickets');
        const data = await res.json();
        if (data.length) {
            tickets = data;
            ticketIdCounter = Math.max(...data.map(t => t.id)) + 1;
            renderTickets();
        }
    } catch (e) { console.error('Failed to load tickets:', e); }
    // Load assets
    try {
        const res = await fetch('/db/load-assets');
        const data = await res.json();
        for (const a of data) {
            cpeDataStore[a.cpeName] = a.cpeData;
            cveDataStore[a.cpeName] = a.cveData;
            assetCriticality[a.cpeName] = a.criticality ?? 3;
            assetTags[a.cpeName] = a.tags ?? [];
        }

        loadTicketStats();

        // Hydrate cpeDataStore from cpe_cache
        const cpeNames = Object.keys(cveDataStore);
        if (cpeNames.length) {
            try {
                const cpeRes = await fetch('/db/load-cpe-cache', {
                    method: 'POST',
                    headers: csrfHeaders(),
                    body: JSON.stringify({ cpeNames })
                });
                const cpeCache = await cpeRes.json();
                for (const [cpeName, cpeData] of Object.entries(cpeCache)) {
                    cpeDataStore[cpeName] = cpeData;
                }
            } catch (e) { console.error('Failed to load CPE cache:', e); }
        }

        // Load archived assets BEFORE rendering
        try {
            const archRes = await fetch('/db/load-archived-assets');
            const archData = await archRes.json();
            archivedAssets = new Set(archData);
        } catch (e) { console.error('Failed to load archived assets:', e); }

        if (data.length) {
            updateCveCounter();
            renderCveList();
            await loadChartLayout();
            initPublishedDateSlider();
        }
    } catch (e) { console.error('Failed to load assets:', e); }
}

function hasMinRole(minRole) {
    if (!currentUser) return false;
    return (ROLE_LEVELS[currentUser.role] || 0) >= (ROLE_LEVELS[minRole] || 0);
}

// PRIORITY SCORE NORMALIZATION
function normalizePriorityScore(priorityScore) {
    if (!priorityScore || priorityScore <= 0) return 0;
    return Math.min((priorityScore / PRIORITY_SCORE_MAX) * 10, 10);
}

// AGGREGATION METHOD
function applyAggMethod(arr) {
    if (!arr || !arr.length) return 0;
    if (chartAggMethod === 'max') return Math.max(...arr);
    if (chartAggMethod === 'median') {
        const sorted = [...arr].sort((a, b) => a - b);
        const mid = Math.floor(sorted.length / 2);
        return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
    }
    if (chartAggMethod === 'sum') return arr.reduce((a, b) => a + b, 0);
    // default: mean
    return arr.reduce((a, b) => a + b, 0) / arr.length;
}

// =====================
// SECURITY HELPERS
// =====================

// RISK DECISION HELPERS
function getRiskDecision(cpeName, cveId) {
    return riskDecisions.find(d => d.cpe_name === cpeName && d.cve_id === cveId && d.status === 'active');
}

function isFalsePositive(cpeName, cveId) {
    return riskDecisions.some(d =>
        d.cpe_name === cpeName && d.cve_id === cveId &&
        d.decision === 'false_positive' && d.status === 'active'
    );
}

async function loadRiskDecisions() {
    try {
        const res = await fetch('/db/risk-decisions?status=active');
        riskDecisions = await res.json();
    } catch (e) { console.error('Failed to load risk decisions:', e); }
}

// HTML ESCAPING TO PREVENT XSS IN DYNAMIC CONTENT
function escapeHtml(str) {
    const div = document.createElement('div');
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
}