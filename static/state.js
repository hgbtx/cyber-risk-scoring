// =====================
// STATE
// =====================
let allResults = [];
let currentPage = 1; // Pagination starts at page 1
let cveDataStore = {}; // Stores CVE data by CPE name
let cpeDataStore = {}; // Stores CPE metadata by CPE name
let cpeSearchCache = {}; // Temp cache of CPE data from search results
let totalCveCount = 0
let expandedCveData = null; // Stores currently expanded CVE
let epssChartInstance = null;
let ciaRadarChartInstance = null;
const resultsPerPage = 10; // Search results per paginated page
let folderSortKey = 'epss';
let folderSortDir = 'desc';
let activeFolderCpe = null;
let chartRiskFormula = 'weighted_average';
let chartAggMethod = 'mean';
let chartRiskThreshold = 7.0;
let tickets = [];
let ticketIdCounter = 1;
let archivedAssets = new Set(); // CPE names hidden from grid/charts

// =====================
// DOM REFERENCES
// =====================
const tabButtons = document.querySelectorAll('.tab-button');
const tabPanels = document.querySelectorAll('.tab-panel');
const searchInput = document.getElementById('searchInput');
const searchButton = document.getElementById('searchButton');
const dropZone = document.getElementById('dropZone');
const selectedItems = document.getElementById('selectedItems');
const leftPanel = document.querySelector('.left-panel-container');
const resultsContainer = document.getElementById('resultsContainer');
const resultsList = document.getElementById('resultsList');
const pagination = document.getElementById('pagination');
const placeholder = document.getElementById('placeholder');
const goBackLink = document.getElementById('cveFolderBack');
const chartFsBtn = document.getElementById('chartFullscreenToggle');
// Theoretical max: KEV(1000) + EPSS(500) + Age(100) + CVSS(50) + AV(25) + Priv(20) + UI(15) + AC(10) + CIA(24) = 1744
const PRIORITY_SCORE_MAX = 1744;
const cveCounts = document.getElementById('cveCounts');

// =====================
// HELPERS HELPERS
// =====================

// SAVE TICKETS TO BACKEND
function saveTickets() {
    const uid = currentUser?.id;
    const myTickets = tickets.filter(t => t.user_id === uid || !t.user_id);
    fetch('/db/save-tickets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tickets: myTickets })
    });
}

// SAVE ASSETS TO BACKEND
function saveAssets() {
    const assets = [];
    for (const cpeName in cveDataStore) {
        assets.push({
            cpeName,
            title: cveDataStore[cpeName]?.title || '',
            cpeData: cpeDataStore[cpeName] || {},
            cveData: cveDataStore[cpeName] || {}
        });
    }
    fetch('/db/save-assets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ assets })
    });
}
// LOAD PERSISTED DATA ON STARTUP
async function loadPersistedData() {
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
            // Rebuild the left-panel item
        }
        if (data.length) {
            updateCveCounter();
            renderCveList();
            renderEpssChart();
            renderCiaRadarChart();
        }
    } catch (e) { console.error('Failed to load assets:', e); }
}

// RISK FORMULA HELPER
function applyRiskFormula(values, weights) {
    if (!values.length) return 0;
    switch (chartRiskFormula) {
        case 'weighted_average': {
            const totalW = weights.reduce((s, w) => s + w, 0);
            return totalW ? values.reduce((s, v, i) => s + v * weights[i], 0) / totalW : 0;
        }
        case 'multiplicative': {
            const totalW = weights.reduce((s, w) => s + w, 0);
            return values.reduce((prod, v, i) => prod * Math.pow(v, weights[i] / totalW), 1);
        }
        case 'max':
            return Math.max(...values);
        case 'simple_mean':
            return values.reduce((s, v) => s + v, 0) / values.length;
        default:
            return values.reduce((s, v) => s + v, 0) / values.length;
    }
}

// AGGREGATION METHOD HELPER
function applyAggMethod(values) {
    if (!values.length) return 0;
    switch (chartAggMethod) {
        case 'max':
            return Math.max(...values);
        case 'mean':
            return values.reduce((s, v) => s + v, 0) / values.length;
        case 'median': {
            const sorted = [...values].sort((a, b) => a - b);
            return sorted[Math.floor(sorted.length / 2)];
        }
        case 'sum':
            return values.reduce((s, v) => s + v, 0);
        default:
            return values.reduce((s, v) => s + v, 0) / values.length;
    }
}

// PRIORITY SCORE NORMALIZATION
function normalizePriorityScore(priorityScore) {
    if (!priorityScore || priorityScore <= 0) return 0;
    return Math.min((priorityScore / PRIORITY_SCORE_MAX) * 10, 10);
}

// =====================
// SECURITY HELPERS
// =====================

// HTML ESCAPING TO PREVENT XSS IN DYNAMIC CONTENT
function escapeHtml(str) {
    const div = document.createElement('div');
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
}