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
let tickets = JSON.parse(localStorage.getItem('remediationTickets') || '[]');
let ticketIdCounter = parseInt(localStorage.getItem('ticketIdCounter') || '1');

function saveTickets() {
    localStorage.setItem('remediationTickets', JSON.stringify(tickets));
    localStorage.setItem('ticketIdCounter', ticketIdCounter);
}

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

// =====================
// RISK FORMULA & AGGREGATION HELPERS
// =====================

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
// HELPERS
// =====================

// HTML ESCAPING TO PREVENT XSS IN DYNAMIC CONTENT
function escapeHtml(str) {
    const div = document.createElement('div');
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
}

// =====================
// TABS
// =====================

// TAB EVENT LISTENERS
tabButtons.forEach(button => {
    button.addEventListener('click', () => {
        tabButtons.forEach(btn => btn.classList.remove('active'));
        tabPanels.forEach(panel => panel.classList.remove('active'));

        // Auto-close expanded view when leaving charts tab
        if (button.dataset.tab !== 'charts' && document.getElementById('expandedViewContainer').style.display !== 'none') {
            goBackLink.click();
        }

        button.classList.add('active');

        document.getElementById('chartConfig').style.display = button.dataset.tab === 'charts' ? 'flex' : 'none';
        
        // Show/hide filter panel based on active tab
        const filterPanel = document.getElementById('searchFilterPanel');
        filterPanel.style.display = (button.dataset.tab === 'search' && allResults.length > 0) ? 'block' : 'none';
        
        const targetPanel = document.querySelector(`.tab-panel[data-panel="${button.dataset.tab}"]`);
        if (targetPanel) targetPanel.classList.add('active');

        if (button.dataset.tab === 'charts' && epssChartInstance) {
            setTimeout(() => epssChartInstance.resize(), 50);
        }
    });
});

// =====================
// SEARCH & PAGINATION
// =====================

// PERFORM SEARCH
async function performSearch() {
    const searchTerm = searchInput.value.trim();
    if (searchTerm) {
        searchButton.disabled = true;
        searchButton.textContent = 'Searching...';
        try {
            const response = await fetch('/api/search', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ searchTerm: searchTerm })
            });
            
            const results = await response.json();
            displayResults(results);
            
        } catch (error) {
            console.error('Error:', error);
            alert('Search failed. Please try again.');
        } finally {
            searchButton.disabled = false;
            searchButton.textContent = 'Search';
        }
    }
}

// SEARCH EVENT LISTENERS
searchButton.addEventListener('click', performSearch);
searchInput.addEventListener('keypress', function(event) {
    if (event.key === 'Enter') {
        performSearch();
    }
});

// ADVANCED SEARCH TOGGLE
document.getElementById('toggleAdvancedSearch').addEventListener('click', (e) => {
    e.preventDefault();
    document.getElementById('simpleSearch').style.display = 'none';
    document.getElementById('advancedSearch').style.display = 'block';
});

document.getElementById('toggleSimpleSearch').addEventListener('click', (e) => {
    e.preventDefault();
    document.getElementById('advancedSearch').style.display = 'none';
    document.getElementById('simpleSearch').style.display = 'block';
});

// ADVANCED SEARCH
async function performAdvancedSearch() {
    const fields = {
        part: document.getElementById('advPart').value,
        vendor: document.getElementById('advVendor').value.trim(),
        product: document.getElementById('advProduct').value.trim(),
        version: document.getElementById('advVersion').value.trim(),
        update: document.getElementById('advUpdate').value.trim(),
        edition: document.getElementById('advEdition').value.trim(),
        language: document.getElementById('advLanguage').value.trim(),
        sw_edition: document.getElementById('advSwEdition').value.trim(),
        target_sw: document.getElementById('advTargetSw').value.trim(),
        target_hw: document.getElementById('advTargetHw').value.trim(),
        other: document.getElementById('advOther').value.trim(),
    };

    // Build CPE 2.3 match string: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
    const components = [
        fields.part || '*',
        fields.vendor || '*',
        fields.product || '*',
        fields.version || '*',
        fields.update || '*',
        fields.edition || '*',
        fields.language || '*',
        fields.sw_edition || '*',
        fields.target_sw || '*',
        fields.target_hw || '*',
        fields.other || '*',
    ];

    // Don't search if everything is wildcard
    if (components.every(c => c === '*')) {
        alert('Please fill in at least one field.');
        return;
    }

    const cpeMatchString = 'cpe:2.3:' + components.join(':');

    const btn = document.getElementById('advSearchButton');
    btn.disabled = true;
    btn.textContent = 'Searching...';

    try {
        const response = await fetch('/api/search', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ cpeMatchString })
        });
        const results = await response.json();
        displayResults(results);
    } catch (error) {
        console.error('Error:', error);
        alert('Search failed. Please try again.');
    } finally {
        btn.disabled = false;
        btn.textContent = 'Search';
    }
}

document.getElementById('advSearchButton').addEventListener('click', performAdvancedSearch);

function parseCpeParts(cpeName) {
    const parts = cpeName.split(':');
    return {
        part: parts[2] || '*',
        vendor: parts[3] || '*',
        product: parts[4] || '*',
        version: parts[5] || '*',
        update: parts[6] || '*',
        edition: parts[7] || '*',
        language: parts[8] || '*',
        sw_edition: parts[9] || '*',
        target_sw: parts[10] || '*',
        target_hw: parts[11] || '*',
    };
}

// DISPLAY RESULTS
function displayResults(results) {
    allResults = results;
    currentPage = 1;
    document.getElementById('clearFilters').click();
    cpeSearchCache = {}; // Clear previous cache before repopulating

    // Cache CPE metadata from search results
    for (const r of results) {
        if (r.cpeName && r.cpeData) {
            cpeSearchCache[r.cpeName] = r.cpeData;
        }
    }

    renderPage();
    document.getElementById('clearResults').style.display = 'inline';
    
    document.getElementById('searchFilterPanel').style.display = 'block';
    document.getElementById('clearFilters').click();

    // Convert filter fields to dropdowns when multiple values exist
    const dropdownFields = {
        filterVendor: r => parseCpeParts(r.cpeName).vendor,
        filterProduct: r => parseCpeParts(r.cpeName).product,
        filterVersion: r => parseCpeParts(r.cpeName).version,
        filterUpdate: r => parseCpeParts(r.cpeName).update,
        filterEdition: r => parseCpeParts(r.cpeName).edition,
        filterLanguage: r => parseCpeParts(r.cpeName).language,
        filterSwEdition: r => parseCpeParts(r.cpeName).sw_edition,
        filterTargetSw: r => parseCpeParts(r.cpeName).target_sw,
        filterTargetHw: r => parseCpeParts(r.cpeName).target_hw,
    };
    
    for (const [id, extractor] of Object.entries(dropdownFields)) {
        const unique = [...new Set(allResults.map(extractor))].filter(v => v && v !== '*').sort();
        const parent = document.getElementById(id).parentElement;
        const label = parent.querySelector('label');
        const old = document.getElementById(id);
        const single = unique.length <= 1;
    
        const el = document.createElement(single ? 'input' : 'select');
        el.id = id;
        if (single) {
            el.type = 'text';
            el.disabled = true;
            el.style.opacity = '0.4';
            el.placeholder = unique[0] || '';
        } else {
            el.innerHTML = '<option value="">Any</option>' +
                unique.map(v => `<option value="${escapeHtml(v)}">${escapeHtml(v)}</option>`).join('');
        }
        old.replaceWith(el);
    }
    
    // Deprecated field
    const depUnique = new Set(allResults.map(r => String(r.cpeData?.deprecated ?? false)));
    const depEl = document.getElementById('filterDeprecated');
    depEl.disabled = depUnique.size <= 1;
    depEl.style.opacity = depUnique.size <= 1 ? '0.4' : '1';
    
    // Date fields
    const uniqueDates = new Set(allResults.map(r => r.cpeData?.created || ''));
    const dateSingle = uniqueDates.size <= 1;
    ['filterDateFrom', 'filterDateTo'].forEach(id => {
        const el = document.getElementById(id);
        el.disabled = dateSingle;
        el.style.opacity = dateSingle ? '0.4' : '1';
    });
    
    document.getElementById('searchFilterPanel').style.display = 'block';
    updateFilterFieldStates();
}

// RENDER PAGE
function renderPage() {
    
    resultsList.innerHTML = '';
    const displayResults = window._filteredResults || allResults;
    
    if (displayResults.length === 0) {
        resultsList.innerHTML = '<p>No results found.</p>';
        resultsContainer.style.display = 'block';
        pagination.style.display = 'none';
        return;
    }
    
    const startIndex = (currentPage - 1) * resultsPerPage;
    const endIndex = startIndex + resultsPerPage;
    const pageResults = displayResults.slice(startIndex, endIndex);
    
    pageResults.forEach((result) => {
        const div = document.createElement('div');
        div.className = 'result-item';
        div.draggable = true;
        div.dataset.title = result.title;
        div.dataset.cpeName = result.cpeName;
        
        div.innerHTML = `
            <div>
                <strong>${escapeHtml(result.title)}</strong><br>
                <small>${escapeHtml(result.cpeName)}</small>
            </div>
        `;
        
        div.addEventListener('dragstart', handleDragStart);
        div.addEventListener('dragend', handleDragEnd);
        
        resultsList.appendChild(div);
    });
    
    resultsContainer.style.display = 'block';
    
    // Update pagination
    const totalPages = Math.ceil(displayResults.length / resultsPerPage);
    document.getElementById('pageInput').value = currentPage;
    document.getElementById('pageInput').max = totalPages;
    document.getElementById('totalPages').textContent = totalPages;
    document.getElementById('prevPage').disabled = currentPage === 1;
    document.getElementById('nextPage').disabled = currentPage === totalPages;
    pagination.style.display = totalPages > 1 ? 'block' : 'none';
}

// DRAG HANDLERS
function handleDragStart(e) {
    e.currentTarget.classList.add('dragging');
    e.dataTransfer.effectAllowed = 'copy';
    e.dataTransfer.setData('text/plain', JSON.stringify({
        title: e.currentTarget.dataset.title,
        cpeName: e.currentTarget.dataset.cpeName
    }));
}
function handleDragEnd(e) {
    e.currentTarget.classList.remove('dragging');
}

// PAGINATION LISTENERS
document.getElementById('prevPage').addEventListener('click', () => {
    if (currentPage > 1) {
        currentPage--;
        renderPage();
    }
});
document.getElementById('nextPage').addEventListener('click', () => {
    const totalPages = Math.ceil(allResults.length / resultsPerPage);
    if (currentPage < totalPages) {
        currentPage++;
        renderPage();
    }
});
document.getElementById('pageInput').addEventListener('change', (e) => {
    const totalPages = Math.ceil(allResults.length / resultsPerPage);
    let newPage = parseInt(e.target.value);
    
    if (isNaN(newPage) || newPage < 1) {
        newPage = 1;
    } else if (newPage > totalPages) {
        newPage = totalPages;
    }
    
    currentPage = newPage;
    renderPage();
});

// CLEAR RESULTS LISTENER
document.getElementById('clearResults').addEventListener('click', (e) => {
    e.preventDefault();
    allResults = [];
    currentPage = 1;
    resultsList.innerHTML = '';
    resultsContainer.style.display = 'none';
    document.getElementById('searchFilterPanel').style.display = 'none';
    searchInput.value = '';
    cpeSearchCache = {}; // Clear search cache
    document.getElementById('searchFilterPanel').style.display = 'none';
});

// ==============================
// DRAG & DROP / ASSET SELECTION
// ==============================

// DRAG & DROP EVENT LISTENERS
dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'copy';
    dropZone.classList.add('drag-over');
});
dropZone.addEventListener('dragleave', (e) => {
    if (e.target === dropZone) {
        dropZone.classList.remove('drag-over');
    }
});
dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
    
    const data = JSON.parse(e.dataTransfer.getData('text/plain'));
    addSelectedItem(data);
});
searchInput.addEventListener('dragover', (e) => e.preventDefault());
searchInput.addEventListener('drop', (e) => e.preventDefault());

// ASSET SELECTION
function addSelectedItem(data) {
    const itemTitle = data.title;
    const itemCpeName = data.cpeName;

    // Check if item already exists
    const existingItems = selectedItems.querySelectorAll('.selected-item');
    for (let item of existingItems) {
        if (item.dataset.cpeName === data.cpeName) {
            return; // Item already added
        }
    }

    // Hide placeholder when first item is added
    if (placeholder) {
        placeholder.style.display = 'none';
    }

    const itemDiv = document.createElement('div');
    itemDiv.className = 'selected-item';
    itemDiv.dataset.cpeName = data.cpeName;
    itemDiv.innerHTML = `
        <button class="remove-btn"><small>X</small></button>
        <div>
            <strong>${escapeHtml(data.title)}</strong><br>
            <small>${escapeHtml(data.cpeName)}</small>
        </div>
    `;
    
    itemDiv.querySelector('.remove-btn').addEventListener('click', () => {
        itemDiv.remove();
        delete cveDataStore[itemCpeName]; // Remove CVE data for this CPE
        delete cpeDataStore[itemCpeName]; // Clean up CPE data
        updateCveCounter(); // Update counter after removing
        renderCveList();
        renderEpssChart();
        renderCiaRadarChart();
        // Show placeholder again if no items left
        if (selectedItems.querySelectorAll('.selected-item').length === 0) {
            placeholder.style.display = 'block';
        }
    });
    
    selectedItems.appendChild(itemDiv);

    // Store CPE metadata if available from search cache
    if (cpeSearchCache[itemCpeName]) {
        cpeDataStore[itemCpeName] = cpeSearchCache[itemCpeName];
    }

    // Fetch CVEs for this CPE in the background
    fetch('/api/fetch-cves', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ cpeUri: itemCpeName })
    })
    .then(response => response.json())
    .then(data => {
        console.log('CVE data received:', data); // Check the structure
        data.title = itemTitle;
        cveDataStore[itemCpeName] = data; // Store the CVE data
        updateCveCounter(); // Update counter after adding
        renderCveList();
        renderEpssChart();
        renderCiaRadarChart();
    })
    .catch(error => console.error('Error fetching CVEs:', error));
}

// =====================
// CHARTS
// =====================

// RENDER EPSS SCATTER PLOT
function renderEpssChart() {
    const canvas = document.getElementById('epssChart');
    const placeholder = document.getElementById('chartPlaceholder');
    
    // Collect all CVEs with EPSS scores and published dates
    const dataPoints = [];
    
    for (const cpe in cveDataStore) {
        const data = cveDataStore[cpe];
        if (!data?.vulnerabilities) continue;
        
        for (const vuln of data.vulnerabilities) {
            const c = vuln.cve || {};
            const published = c.published;
            const epss = vuln.epssScore;
            
            if (published && typeof epss === 'number' && epss > 0) {
                const normalizedPriority = normalizePriorityScore(vuln.priorityScore ?? 0);
                dataPoints.push({
                    x: new Date(published),
                    y: epss,
                    cveId: c.id || 'Unknown',
                    cpe: data.title || cpe,
                    riskScore: normalizedPriority,
                    aboveThreshold: normalizedPriority >= chartRiskThreshold
                });
            }
        }
    }
    
    if (dataPoints.length === 0) {
        canvas.style.display = 'none';
        placeholder.style.display = 'block';
        if (epssChartInstance) {
            epssChartInstance.destroy();
            epssChartInstance = null;
        }
        return;
    }
    
    canvas.style.display = 'block';
    placeholder.style.display = 'none';
    
    // Group by CPE for color-coded datasets
    const grouped = {};
    for (const pt of dataPoints) {
        if (!grouped[pt.cpe]) grouped[pt.cpe] = [];
        grouped[pt.cpe].push(pt);
    }
    
    const colors = ['#d9af6f', '#c01e19', '#4a90d9', '#50b88e', '#8b5cf6', '#e67e22', '#1abc9c'];
    let colorIndex = 0;
    
    const datasets = Object.entries(grouped).map(([cpe, points]) => {
        const color = colors[colorIndex % colors.length];
        colorIndex++;
        return {
            label: cpe,
            data: points.map(p => ({ x: p.x, y: p.y, cveId: p.cveId, riskScore: p.riskScore, aboveThreshold: p.aboveThreshold })),
            backgroundColor: points.map(p => p.aboveThreshold ? '#c01e1999' : color + '99'),
            borderColor: points.map(p => p.aboveThreshold ? '#c01e19' : color),
            pointRadius: points.map(p => p.aboveThreshold ? 7 : 5),
            pointHoverRadius: 8,
        };
    });
    
    if (epssChartInstance) {
        epssChartInstance.destroy();
    }
    
    epssChartInstance = new Chart(canvas, {
        type: 'scatter',
        data: { datasets },
        options: {
            responsive: true,
            scales: {
                x: {
                    type: 'time',
                    time: { unit: 'month', tooltipFormat: 'MMM yyyy' },
                    title: { display: true, text: 'Published Date' }
                },
                y: {
                    beginAtZero: true,
                    max: 1,
                    title: { display: true, text: 'EPSS Score' }
                }
            },
            plugins: {
                tooltip: {
                    callbacks: {
                        label: (ctx) => {
                            const pt = ctx.raw;
                            const flag = pt.aboveThreshold ? ' ⚠️' : '';
                            return `${pt.cveId}: EPSS ${pt.y.toFixed(4)} | Priority ${pt.riskScore.toFixed(1)}/10${flag}`;
                        }
                    }
                },
                legend: { position: 'bottom' },
                },

                onClick: (evt, elements) => {
                    if (!elements.length) return;
                    const el = elements[0];
                    const pt = epssChartInstance.data.datasets[el.datasetIndex].data[el.index];
                    const vuln = findVulnByCveId(pt.cveId);
                    if (!vuln) return;
                    const panel = document.querySelector('.right-panel-container');
                    if (panel.classList.contains('collapsed')) {
                        document.getElementById('toggleRightPanel').click();
                    }
                    if (epssChartInstance) {
                        epssChartInstance.options.responsive = false;
                        setTimeout(() => {
                            epssChartInstance.options.responsive = true;
                            epssChartInstance.resize();
                        }, 245);
                    }
                    displayExpandedView(vuln);
            }
        }
    });
}

// RENDER CIA RADAR CHART
function renderCiaRadarChart() {
    const canvas = document.getElementById('ciaRadarChart');
    const impactMap = { 'HIGH': 3, 'LOW': 1, 'NONE': 0 };

    // Aggregate CIA scores per asset
    const assetProfiles = {};

    for (const cpe in cveDataStore) {
        const data = cveDataStore[cpe];
        if (!data?.vulnerabilities?.length) continue;
    
        const cScores = [], iScores = [], aScores = [];
    
        for (const vuln of data.vulnerabilities) {
            const cvss = vuln.cve?.metrics?.cvssMetricV31?.[0]?.cvssData;
            if (!cvss) continue;
    
            cScores.push(impactMap[cvss.confidentialityImpact] ?? 0);
            iScores.push(impactMap[cvss.integrityImpact] ?? 0);
            aScores.push(impactMap[cvss.availabilityImpact] ?? 0);
        }
    
        if (cScores.length > 0) {
            assetProfiles[data.title || cpe] = {
                confidentiality: applyAggMethod(cScores),
                integrity: applyAggMethod(iScores),
                availability: applyAggMethod(aScores),
            };
        }
    }

    if (!Object.keys(assetProfiles).length) {
        canvas.style.display = 'none';
        if (ciaRadarChartInstance) { ciaRadarChartInstance.destroy(); ciaRadarChartInstance = null; }
        return;
    }

    canvas.style.display = 'block';

    const colors = ['#d9af6f', '#c01e19', '#4a90d9', '#50b88e', '#8b5cf6', '#e67e22'];
    let colorIdx = 0;

    const datasets = Object.entries(assetProfiles).map(([label, profile]) => {
        const color = colors[colorIdx++ % colors.length];
        return {
            label,
            data: [profile.confidentiality, profile.integrity, profile.availability],
            backgroundColor: color + '33',
            borderColor: color,
            borderWidth: 2,
            pointBackgroundColor: color,
        };
    });

    if (ciaRadarChartInstance) ciaRadarChartInstance.destroy();

    ciaRadarChartInstance = new Chart(canvas, {
        type: 'radar',
        data: {
            labels: ['Confidentiality', 'Integrity', 'Availability'],
            datasets,
        },
        options: {
            responsive: true,
            scales: {
                r: {
                    beginAtZero: true,
                    max: chartAggMethod === 'sum' ? undefined : 3,
                    ticks: {
                        stepSize: chartAggMethod === 'sum' ? undefined : 1,
                        callback: chartAggMethod === 'sum' 
                            ? undefined 
                            : (val) => ['None', 'Low', '', 'High'][val] || '',
                    },
                    pointLabels: { font: { size: 14 } },
                },
            },
            plugins: {
                tooltip: {
                    callbacks: {
                        label: (ctx) => {
                            const val = ctx.raw.toFixed(2);
                            const axis = ctx.label;
                            return `${ctx.dataset.label} — ${axis}: ${val}`;
                        },
                    },
                },
                legend: { position: 'bottom' },
            },
        },
    });
}

// CVE ID FINDER FOR CHART INTERACTIONS
function findVulnByCveId(cveId) {
    for (const cpe in cveDataStore) {
        const data = cveDataStore[cpe];
        if (!data?.vulnerabilities) continue;
        for (const vuln of data.vulnerabilities) {
            if (vuln.cve?.id === cveId) return vuln;
        }
    }
    return null;
}

// =====================
// CVE DATA
// =====================

// CVE COUNTER
function updateCveCounter() {
    totalCveCount = 0;
    for (let cpe in cveDataStore) {
        if (cveDataStore[cpe] && cveDataStore[cpe].count) {
            totalCveCount += cveDataStore[cpe].count;
        }
    }
    cveCounts.textContent = `${totalCveCount} CVEs found`;
}

// DISPLAY CVE RESULTS
function displayCveList(cves) {
    allCves = cves;
    renderCveList();
}

// DISPLAY CVE EXPANDED VIEW
function displayExpandedView(cve_data) {
    expandedCveData = cve_data;
    document.getElementById('cveContainer').style.display = 'none';
    document.getElementById('expandedViewContainer').style.display = 'block';
    renderExpandedView();
}

// RENDER CVE EXPANDED VIEW
function renderExpandedView() {
    const container = document.getElementById('expandedDetails');

    const hasCves = totalCveCount > 0;
    document.getElementById('toggleRightPanel').style.display = hasCves ? 'block' : 'none';
    document.querySelector('.right-panel-container').style.display = hasCves ? 'block' : 'none';

    updateChartFullscreenBtn();
    container.innerHTML = '';

    if (!expandedCveData) return;

    const c = expandedCveData.cve || {};
    const id = c.id || 'Unknown';
    const status = c.vulnStatus || 'N/A';
    const published = c.published || 'N/A';
    const lastMod = c.lastModified || 'N/A';
    const hasKev = expandedCveData.hasKev ? 'Yes' : 'No';

    // Find parent CPE info
    let cpeTitle = 'N/A';
    let cpeName = 'N/A';
    let cpeInfo = null;
    for (const cpe in cveDataStore) {
        const data = cveDataStore[cpe];
        if (data?.vulnerabilities?.includes(expandedCveData)) {
            cpeTitle = data.title || 'N/A';
            cpeName = cpe;
            cpeInfo = cpeDataStore[cpe] || null;
            break;
        }
    }

    const detailLi = document.createElement('li');
    const cveHeader = document.createElement('div');
    cveHeader.className = 'cve-id-header';
    cveHeader.innerHTML = `<span class="cve-toggle">&#9654;</span> ${escapeHtml(id)}`;

    // --- CPE Information ---
    let html = `<h3>${escapeHtml(cpeInfo?.titles?.[0]?.title || cpeTitle)}</h3>
        <h3>CPE Information</h3>
        <div><strong>Deprecated:</strong> ${cpeInfo ? escapeHtml(String(cpeInfo.deprecated ?? 'N/A')) : 'N/A'}</div>
        <div><strong>CPE Name:</strong> ${escapeHtml(cpeName)}</div>
        <div><strong>UUID:</strong> ${escapeHtml(cpeInfo?.cpeNameId || 'N/A')}</div>
        <div><strong>Last Modified:</strong> ${escapeHtml(cpeInfo?.lastModified || 'N/A')}</div>
        <div><strong>Created:</strong> ${escapeHtml(cpeInfo?.created || 'N/A')}</div>`;

    if (cpeInfo?.cpeNameId) {
        html += `<div><a href="https://nvd.nist.gov/products/cpe/detail/${escapeHtml(cpeInfo.cpeNameId)}" target="_blank" rel="noopener">More Information</a></div>`;
    }

    // --- CPE References ---
    const cpeRefs = cpeInfo?.refs || [];
    if (cpeRefs.length) {
        html += `<h3>CPE References</h3>`;
        for (const ref of cpeRefs) {
            html += `<div><strong>Reference:</strong> <a href="${escapeHtml(ref.ref)}" target="_blank" rel="noopener">${escapeHtml(ref.ref)}</a></div>
                <div><strong>Type:</strong> ${escapeHtml(ref.type || 'N/A')}</div>
                <div>---</div>`;
        }
    }

    // --- CVE Information ---
    html += `<h3>CVE Information</h3>
        <div><strong>ID:</strong> ${escapeHtml(id)}</div>
        <div><strong>Source Identifier:</strong> ${escapeHtml(c.sourceIdentifier || 'N/A')}</div>
        <div><strong>Status:</strong> ${escapeHtml(status)}</div>
        <div><strong>Published:</strong> ${escapeHtml(published)}</div>
        <div><strong>Last Modified:</strong> ${escapeHtml(lastMod)}</div>
        <div><strong>Priority Score:</strong> ${escapeHtml(String(expandedCveData.priorityScore ?? 'N/A'))}</div>
        <div><strong>EPSS Score:</strong> ${escapeHtml(String(expandedCveData.epssScore ?? 'N/A'))}</div>
        <div><strong>KEV: </strong>${hasKev === 'Yes' ? `<a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=${escapeHtml(id)}" target="_blank" rel="noopener">Yes</a>` : 'No'}</div>
        <div><a href="https://nvd.nist.gov/vuln/detail/${escapeHtml(id)}" target="_blank" rel="noopener">More Information</a></div>
        `;

    // --- Descriptions ---
    const descriptions = c.descriptions || [];
    if (descriptions.length) {
        html += `<h3>Descriptions</h3>`;
        for (const desc of descriptions) {
            const langLabel = desc.lang === 'en' ? 'English' : desc.lang === 'es' ? 'Spanish' : desc.lang;
            html += `<h4>${escapeHtml(langLabel)}</h4><p>${escapeHtml(desc.value)}</p>`;
        }
    }

    // --- CVE Tags ---
    const cveTags = c.cveTags || [];
    if (cveTags.length) {
        html += `<h3>CVE Tags</h3>`;
        for (const tag of cveTags) {
            html += `<div>${escapeHtml(tag)}</div>`;
        }
    } else {
        html += `<h3>CVE Tags</h3><div>(none)</div>`;
    }

    // --- Metrics ---
    html += `<h3>Metrics</h3>`;

    const cvss31 = c.metrics?.cvssMetricV31 || [];
    for (const metric of cvss31) {
        const d = metric.cvssData || {};
        html += `<h4>CVSS v3.1 Metric (${escapeHtml(metric.type || 'N/A')})</h4>
            <div><strong>Source:</strong> ${escapeHtml(metric.source || 'N/A')}</div>
            <div><strong>Base Severity:</strong> ${escapeHtml(d.baseSeverity || 'N/A')}</div>
            <div><strong>Base Score:</strong> ${escapeHtml(String(d.baseScore ?? 'N/A'))}</div>
            <div><strong>Vector String:</strong> ${escapeHtml(d.vectorString || 'N/A')}</div>
            <div><strong>Attack Vector:</strong> ${escapeHtml(d.attackVector || 'N/A')}</div>
            <div><strong>Attack Complexity:</strong> ${escapeHtml(d.attackComplexity || 'N/A')}</div>
            <div><strong>Privileges Required:</strong> ${escapeHtml(d.privilegesRequired || 'N/A')}</div>
            <div><strong>User Interaction:</strong> ${escapeHtml(d.userInteraction || 'N/A')}</div>
            <div><strong>Scope:</strong> ${escapeHtml(d.scope || 'N/A')}</div>
            <div><strong>Confidentiality Impact:</strong> ${escapeHtml(d.confidentialityImpact || 'N/A')}</div>
            <div><strong>Integrity Impact:</strong> ${escapeHtml(d.integrityImpact || 'N/A')}</div>
            <div><strong>Availability Impact:</strong> ${escapeHtml(d.availabilityImpact || 'N/A')}</div>
            <div><strong>Exploitability Score:</strong> ${escapeHtml(String(metric.exploitabilityScore ?? 'N/A'))}</div>
            <div><strong>Impact Score:</strong> ${escapeHtml(String(metric.impactScore ?? 'N/A'))}</div>`;
    }

    const cvss2 = c.metrics?.cvssMetricV2 || [];
    for (const metric of cvss2) {
        const d = metric.cvssData || {};
        html += `<h4>CVSS v2 Metric (${escapeHtml(metric.type || 'N/A')})</h4>
            <div><strong>Source:</strong> ${escapeHtml(metric.source || 'N/A')}</div>
            <div><strong>Base Severity:</strong> ${escapeHtml(metric.baseSeverity || 'N/A')}</div>
            <div><strong>Base Score:</strong> ${escapeHtml(String(d.baseScore ?? 'N/A'))}</div>
            <div><strong>Vector String:</strong> ${escapeHtml(d.vectorString || 'N/A')}</div>
            <div><strong>Access Vector:</strong> ${escapeHtml(d.accessVector || 'N/A')}</div>
            <div><strong>Access Complexity:</strong> ${escapeHtml(d.accessComplexity || 'N/A')}</div>
            <div><strong>Authentication:</strong> ${escapeHtml(d.authentication || 'N/A')}</div>
            <div><strong>Confidentiality Impact:</strong> ${escapeHtml(d.confidentialityImpact || 'N/A')}</div>
            <div><strong>Integrity Impact:</strong> ${escapeHtml(d.integrityImpact || 'N/A')}</div>
            <div><strong>Availability Impact:</strong> ${escapeHtml(d.availabilityImpact || 'N/A')}</div>
            <div><strong>Exploitability Score:</strong> ${escapeHtml(String(metric.exploitabilityScore ?? 'N/A'))}</div>
            <div><strong>Impact Score:</strong> ${escapeHtml(String(metric.impactScore ?? 'N/A'))}</div>
            <div><strong>AC Insuf Info:</strong> ${escapeHtml(String(metric.acInsufInfo ?? 'N/A'))}</div>
            <div><strong>Obtain All Privilege:</strong> ${escapeHtml(String(metric.obtainAllPrivilege ?? 'N/A'))}</div>
            <div><strong>Obtain User Privilege:</strong> ${escapeHtml(String(metric.obtainUserPrivilege ?? 'N/A'))}</div>
            <div><strong>Obtain Other Privilege:</strong> ${escapeHtml(String(metric.obtainOtherPrivilege ?? 'N/A'))}</div>
            <div><strong>User Interaction Required:</strong> ${escapeHtml(String(metric.userInteractionRequired ?? 'N/A'))}</div>`;
    }

    // --- Weaknesses ---
    const weaknesses = c.weaknesses || [];
    if (weaknesses.length) {
        html += `<h3>Weaknesses</h3>`;
        for (const w of weaknesses) {
            const cweLinks = (w.description || []).map(d => {
                const num = d.value.match(/\d+/)?.[0] || 'N/A';
                return `<a href="https://cwe.mitre.org/data/definitions/${escapeHtml(num)}" target="_blank" rel="noopener">${escapeHtml(d.value)}</a>`;
            }).join(', ');
            html += `<div><strong>Source:</strong> ${escapeHtml(w.source || 'N/A')}</div>
                <div><strong>Type:</strong> ${escapeHtml(w.type || 'N/A')}</div>
                <div><strong>Weakness:</strong> ${cweLinks}</div>
                <div>---</div>`;
        }
    }

    // --- Configurations ---
    const configs = c.configurations || [];
    if (configs.length) {
        html += `<h3>Configurations</h3>`;
        let matchNum = 1;
        for (const config of configs) {
            for (const node of (config.nodes || [])) {
                html += `<div><strong>Operator:</strong> ${escapeHtml(node.operator || 'N/A')} | <strong>Negate:</strong> ${escapeHtml(String(node.negate ?? 'N/A'))}</div>
                <div>---</div>`;
            for (const match of (node.cpeMatch || [])) {
                html += `<div><strong>${matchNum}.</strong> ${escapeHtml(match.criteria || 'N/A')}
                    <br>&nbsp;&nbsp;&nbsp;Match Criteria ID: ${escapeHtml(match.matchCriteriaId || 'N/A')}
                    <br>&nbsp;&nbsp;&nbsp;Vulnerable: ${escapeHtml(String(match.vulnerable ?? 'N/A'))}`;
                if (match.versionStartIncluding) html += `<br>&nbsp;&nbsp;&nbsp;Version Start (incl): ${escapeHtml(match.versionStartIncluding)}`;
                if (match.versionEndExcluding) html += `<br>&nbsp;&nbsp;&nbsp;Version End (excl): ${escapeHtml(match.versionEndExcluding)}`;
                    html += `</div>`;
                    matchNum++;
                }
            }
        }
    }

    // --- References ---
    const refs = c.references || [];
    if (refs.length) {
        html += `<h3>References</h3>`;
        for (const ref of refs) {
            html += `<div><strong>Source:</strong> ${escapeHtml(ref.source || 'N/A')} | 
                <a href="${escapeHtml(ref.url)}" target="_blank" rel="noopener">${escapeHtml(ref.url)}</a></div>`;
        }
    }

    container.innerHTML = html;
}

// RENDER CVE LIST
function renderCveList() {

    cveList.innerHTML = '';

    for (const cpe in cveDataStore) {
        const data = cveDataStore[cpe];
        if (data?.count === undefined) continue;

        const li = document.createElement('li');

        const header = document.createElement('div');
        header.className = 'cve-header';
        header.innerHTML = `
            <span class="cve-toggle">&#9654;</span>
            <span class="cpe-title">${escapeHtml(data.title)}</span>
            <span class="cve-count">${data.count} CVEs Found</span>
        `;

        const details = document.createElement('ul');
        details.className = 'cve-details';

        if (data.vulnerabilities) {
            data.vulnerabilities.sort((a, b) => (b.priorityScore ?? 0) - (a.priorityScore ?? 0));
            for (const vuln of data.vulnerabilities) {
                const c = vuln.cve || {};
                const id = c.id || 'Unknown';

            }
        }

        renderCveGrid();
    }
}

// RENDER CVE GRID (folder view)
function renderCveGrid() {
    const grid = document.getElementById('cveGrid');
    const folderView = document.getElementById('cveFolderView');
    grid.innerHTML = '';
    folderView.style.display = 'none';
    document.getElementById('cpeInfoIcon').style.display = 'none';
    grid.style.display = 'grid';

    if (Object.keys(cveDataStore).length > 0) {
        const allCell = document.createElement('div');
        allCell.className = 'cve-grid-cell';
        allCell.style.borderStyle = 'dashed';
        allCell.innerHTML = `
            <div class="cell-title">📁 View All</div>
            <div class="cell-cpe">All assets</div>
            <div class="cell-count">${totalCveCount} CVEs</div>
        `;
        allCell.addEventListener('click', () => openAllCveFolder());
        grid.appendChild(allCell);
    }

    for (const cpe in cveDataStore) {
        const data = cveDataStore[cpe];
        if (data?.count === undefined) continue;

        const cell = document.createElement('div');
        cell.className = 'cve-grid-cell';
        cell.innerHTML = `
            <div class="cell-title">${escapeHtml(data.title || cpe)}</div>
            <div class="cell-cpe">${escapeHtml(cpe)}</div>
            <div class="cell-count">${data.count} CVEs</div>
        `;
        cell.addEventListener('click', () => openCveFolder(cpe, data));
        grid.appendChild(cell);
    }

    if (!Object.keys(cveDataStore).length) {
        grid.innerHTML = '<p style="color: #999; font-style: italic;">Add assets to view CVE details.</p>';
    }
}

// OPEN CVE FOLDER VIEW
function openCveFolder(cpe, data) {
    const grid = document.getElementById('cveGrid');
    const folderView = document.getElementById('cveFolderView');
    grid.style.display = 'none';
    folderView.style.display = 'block';
    activeFolderCpe = cpe;
    document.getElementById('cpeInfoIcon').style.display = 'inline';
    document.getElementById('cveFolderTitle').textContent = data.title || cpe;

    // Store reference for sorting
    folderView.dataset.cpe = cpe;

    renderFolderTable(cpe, data);

    // Attach sort listeners (only once)
    if (!folderView.dataset.sortBound) {
        folderView.dataset.sortBound = 'true';
        document.querySelectorAll('#cveFolderTable thead th[data-sort]').forEach(th => {
            th.addEventListener('click', () => {
                const key = th.dataset.sort;
                if (folderSortKey === key) {
                    folderSortDir = folderSortDir === 'asc' ? 'desc' : 'asc';
                } else {
                    folderSortKey = key;
                    folderSortDir = 'desc';
                }
                const cpeKey = folderView.dataset.cpe;
                if (cpeKey === '__all__') {
                    const allVulns = [];
                    for (const c in cveDataStore) {
                        if (cveDataStore[c]?.vulnerabilities) allVulns.push(...cveDataStore[c].vulnerabilities);
                    }
                    renderFolderTable('__all__', { vulnerabilities: allVulns });
                } else {
                    renderFolderTable(cpeKey, cveDataStore[cpeKey]);
                }
            });
        });
    }
}

// OPEN ALL CVEs FOLDER VIEW
function openAllCveFolder() {
    const grid = document.getElementById('cveGrid');
    const folderView = document.getElementById('cveFolderView');
    grid.style.display = 'none';
    folderView.style.display = 'block';
    activeFolderCpe = null;
    document.getElementById('cpeInfoIcon').style.display = 'none';
    document.getElementById('cveFolderTitle').textContent = 'All CVEs';

    folderView.dataset.cpe = '__all__';

    // Build combined data object
    const allVulns = [];
    for (const cpe in cveDataStore) {
        const data = cveDataStore[cpe];
        if (data?.vulnerabilities) {
            allVulns.push(...data.vulnerabilities);
        }
    }

    renderFolderTable('__all__', { vulnerabilities: allVulns });

    if (!folderView.dataset.sortBound) {
        folderView.dataset.sortBound = 'true';
        document.querySelectorAll('#cveFolderTable thead th[data-sort]').forEach(th => {
            th.addEventListener('click', () => {
                const key = th.dataset.sort;
                if (folderSortKey === key) {
                    folderSortDir = folderSortDir === 'asc' ? 'desc' : 'asc';
                } else {
                    folderSortKey = key;
                    folderSortDir = 'desc';
                }
                const cpeKey = folderView.dataset.cpe;
                if (cpeKey === '__all__') {
                    openAllCveFolder();
                } else {
                    renderFolderTable(cpeKey, cveDataStore[cpeKey]);
                }
            });
        });
    }
}

// EXTRACT CVE DATA FOR FOLDER ROWS
function extractCveRowData(vuln) {
    const c = vuln.cve || {};
    const cvss31 = c.metrics?.cvssMetricV31?.[0]?.cvssData || {};
    const cvss2 = c.metrics?.cvssMetricV2?.[0]?.cvssData || {};
    const baseScore = cvss31.baseScore ?? cvss2.baseScore ?? null;
    const severity = cvss31.baseSeverity || c.metrics?.cvssMetricV2?.[0]?.baseSeverity || '';
    const cwe = (c.weaknesses || []).flatMap(w => (w.description || []).map(d => d.value)).join(', ') || '';
    const tags = (c.cveTags || []).join(', ');

    return {
        id: c.id || 'Unknown',
        published: c.published || '',
        kev: vuln.hasKev ? 'Yes' : 'No',
        epss: vuln.epssScore ?? 0,
        cwe,
        status: c.vulnStatus || '',
        tags,
        cvss: baseScore,
        severity,
        _vuln: vuln
    };
}

// RENDER FOLDER TABLE
function renderFolderTable(cpe, data) {
    const body = document.getElementById('cveFolderBody');
    body.innerHTML = '';

    if (!data?.vulnerabilities) return;

    // Build row data
    let rows = data.vulnerabilities.map(extractCveRowData);

    // Sort
    rows.sort((a, b) => {
        let va = a[folderSortKey];
        let vb = b[folderSortKey];

        // Numeric sorts
        if (['epss', 'cvss'].includes(folderSortKey)) {
            va = va ?? -1;
            vb = vb ?? -1;
            return folderSortDir === 'asc' ? va - vb : vb - va;
        }
        // KEV: Yes before No
        if (folderSortKey === 'kev') {
            return folderSortDir === 'asc'
                ? (va === vb ? 0 : va === 'Yes' ? -1 : 1)
                : (va === vb ? 0 : va === 'Yes' ? -1 : 1);
        }
        // Date sort
        if (folderSortKey === 'published') {
            const da = va ? new Date(va).getTime() : 0;
            const db = vb ? new Date(vb).getTime() : 0;
            return folderSortDir === 'asc' ? da - db : db - da;
        }
        // String sort
        va = String(va).toLowerCase();
        vb = String(vb).toLowerCase();
        return folderSortDir === 'asc' ? va.localeCompare(vb) : vb.localeCompare(va);
    });

    // Update header arrows
    document.querySelectorAll('#cveFolderTable thead th[data-sort]').forEach(th => {
        th.classList.remove('sort-asc', 'sort-desc');
        if (th.dataset.sort === folderSortKey) {
            th.classList.add(folderSortDir === 'asc' ? 'sort-asc' : 'sort-desc');
        }
    });

    // Render rows
    for (const row of rows) {
        const tr = document.createElement('tr');
        const sevClass = row.severity ? `severity-${row.severity.toLowerCase()}` : '';
        const publishedFmt = row.published ? new Date(row.published).toLocaleDateString() : 'N/A';

        tr.innerHTML = `
            <td><strong>${escapeHtml(row.id)}</strong></td>
            <td>${escapeHtml(publishedFmt)}</td>
            <td class="${row.kev === 'Yes' ? 'kev-yes' : ''}">${row.kev}</td>
            <td>${row.epss > 0 ? row.epss.toFixed(4) : '—'}</td>
            <td title="${escapeHtml(row.cwe)}">${escapeHtml(row.cwe || '—')}</td>
            <td>${escapeHtml(row.status || '—')}</td>
            <td title="${escapeHtml(row.tags)}">${escapeHtml(row.tags || '—')}</td>
            <td>${row.cvss !== null ? row.cvss.toFixed(1) : '—'}</td>
            <td class="${sevClass}">${escapeHtml(row.severity || '—')}</td>
        `;

        tr.addEventListener('click', () => {
            displayExpandedView(row._vuln);
            const panel = document.querySelector('.right-panel-container');
            if (panel.classList.contains('collapsed')) {
                document.getElementById('toggleRightPanel').click();
            }
        });

        body.appendChild(tr);
    }
}

// CVE GRID Back button
document.getElementById('cveFolderBack').addEventListener('click', (e) => {
    e.preventDefault();
    renderCveGrid();
    // Restore header download buttons
    if (totalCveCount > 0) {
    }
});

// CPE INFO ICON CLICK
document.getElementById('cpeInfoIcon').addEventListener('click', () => {
    const folderView = document.getElementById('cveFolderView');
    const cpeKey = folderView.dataset.cpe;
    if (!cpeKey || cpeKey === '__all__') return;

    const panel = document.querySelector('.right-panel-container');
    panel.style.display = 'block';
    document.getElementById('toggleRightPanel').style.display = 'block';
    if (panel.classList.contains('collapsed')) {
        document.getElementById('toggleRightPanel').click();
    }

    document.getElementById('cveContainer').style.display = 'none';
    document.getElementById('expandedViewContainer').style.display = 'block';

    const cpeInfo = cpeDataStore[cpeKey] || cveDataStore[cpeKey]?.cpeData || null;
    const title = cveDataStore[cpeKey]?.title || cpeKey;
    const container = document.getElementById('expandedDetails');

    let html = `<h3>${escapeHtml(cpeInfo?.titles?.[0]?.title || title)}</h3>
        <h3>CPE Information</h3>
        <div><strong>Deprecated:</strong> ${cpeInfo ? escapeHtml(String(cpeInfo.deprecated ?? 'N/A')) : 'N/A'}</div>
        <div><strong>CPE Name:</strong> ${escapeHtml(cpeKey)}</div>
        <div><strong>UUID:</strong> ${escapeHtml(cpeInfo?.cpeNameId || 'N/A')}</div>
        <div><strong>Last Modified:</strong> ${escapeHtml(cpeInfo?.lastModified || 'N/A')}</div>
        <div><strong>Created:</strong> ${escapeHtml(cpeInfo?.created || 'N/A')}</div>`;

    if (cpeInfo?.cpeNameId) {
        html += `<div><a href="https://nvd.nist.gov/products/cpe/detail/${escapeHtml(cpeInfo.cpeNameId)}" target="_blank" rel="noopener">More Information</a></div>`;
    }

    const cpeRefs = cpeInfo?.refs || [];
    if (cpeRefs.length) {
        html += `<h3>CPE References</h3>`;
        for (const ref of cpeRefs) {
            html += `<div><strong>Reference:</strong> <a href="${escapeHtml(ref.ref)}" target="_blank" rel="noopener">${escapeHtml(ref.ref)}</a></div>
                <div><strong>Type:</strong> ${escapeHtml(ref.type || 'N/A')}</div>
                <div>---</div>`;
        }
    }

    container.innerHTML = html;
});

// =====================
// RIGHT PANEL TOGGLE
// =====================

// TOGGLE RIGHT PANEL
document.getElementById('toggleRightPanel').addEventListener('click', () => {
    const panel = document.querySelector('.right-panel-container');
    const btn = document.getElementById('toggleRightPanel');
    const isCollapsed = panel.classList.toggle('collapsed');
    btn.innerHTML = isCollapsed ? '&#9664;' : '&#9654;';
    if (epssChartInstance) {
        setTimeout(() => epssChartInstance.resize(), 350);
    }
    setTimeout(updateChartFullscreenBtn, 50);
});

// CHART FULLSCREEN TOGGLE
function updateChartFullscreenBtn() {
    if (totalCveCount === 0) { chartFsBtn.style.display = 'none'; return; }
    const panel = document.querySelector('.right-panel-container');
    const isCollapsed = panel.classList.contains('collapsed');
    chartFsBtn.style.display = 'inline-block';
    chartFsBtn.title = isCollapsed ? 'Show side panel' : 'Expand chart';
    chartFsBtn.innerHTML = isCollapsed ? '&#x26F6;' : '&#x26F6;';
}
chartFsBtn.addEventListener('click', () => {
    document.getElementById('toggleRightPanel').click();
});


// =====================
// EXPORT (CSV, JSON)
// =====================

// JSON DOWNLOAD
function downloadCveJSON() {
    const exportStore = activeFolderCpe
        ? { [activeFolderCpe]: cveDataStore[activeFolderCpe] }
        : cveDataStore;

    if (!Object.keys(exportStore).length) return alert('No CVE data to export.');

    const blob = new Blob([JSON.stringify(exportStore, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = activeFolderCpe ? 'cve_data_folder.json' : 'cve_data.json';
    a.click();
    URL.revokeObjectURL(a.href);
}

// FLATTEN JSON
function flattenObject(obj, prefix = '') {
    const result = {};
    for (const key in obj) {
        const fullKey = prefix ? `${prefix}.${key}` : key;
        const val = obj[key];
        if (val && typeof val === 'object' && !Array.isArray(val)) {
            Object.assign(result, flattenObject(val, fullKey));
        } else if (Array.isArray(val)) {
            if (val.every(v => typeof v !== 'object')) {
                result[fullKey] = val.join('; ');
            } else {
                val.forEach((item, i) => {
                    if (typeof item === 'object') {
                        Object.assign(result, flattenObject(item, `${fullKey}[${i}]`));
                    } else {
                        result[`${fullKey}[${i}]`] = item;
                    }
                });
            }
        } else {
            result[fullKey] = val;
        }
    }
    return result;
}

// CSV DOWNLOAD
function downloadCveCSV() {
    const flatRows = [];
    const allKeys = new Set();

    const cpeList = activeFolderCpe ? [activeFolderCpe] : Object.keys(cveDataStore);

    for (const cpe of cpeList) {
        const data = cveDataStore[cpe];
        if (!data?.vulnerabilities) continue;

        for (const vuln of data.vulnerabilities) {
            const flat = flattenObject(vuln);
            flat['_cpeName'] = cpe;
            flatRows.push(flat);
            Object.keys(flat).forEach(k => allKeys.add(k));
        }
    }

    if (!flatRows.length) return alert('No CVE data to export.');

    const headers = ['_cpeName', ...Array.from(allKeys).filter(k => k !== '_cpeName').sort()];

    const csvRows = [headers.join(',')];
    for (const row of flatRows) {
        csvRows.push(headers.map(h => {
            const val = row[h] ?? '';
            const str = String(val);
            return str.includes(',') || str.includes('"') || str.includes('\n')
                ? `"${str.replace(/"/g, '""')}"` 
                : str;
        }).join(','));
    }

    const blob = new Blob([csvRows.join('\n')], { type: 'text/csv;charset=utf-8;' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = activeFolderCpe ? 'cve_data_folder.csv' : 'cve_data.csv';
    a.click();
    URL.revokeObjectURL(a.href);
}

// =====================
// CHART CONFIGURATION
// =====================

document.getElementById('riskFormulaSelect').addEventListener('change', (e) => {
    chartRiskFormula = e.target.value;
    renderEpssChart();
    renderCiaRadarChart();
});

document.getElementById('aggMethodSelect').addEventListener('change', (e) => {
    chartAggMethod = e.target.value;
    renderEpssChart();
    renderCiaRadarChart();
});

document.getElementById('riskThresholdSlider').addEventListener('input', (e) => {
    chartRiskThreshold = parseFloat(e.target.value);
    document.getElementById('thresholdValue').textContent = chartRiskThreshold.toFixed(1);
    renderEpssChart();
    renderCiaRadarChart();
});

// ======================
// SEARCH RESULT FILTERS
// ======================

function parseCpeParts(cpeName) {
    // cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
    const parts = cpeName.split(':');
    return {
        part: parts[2] || '*',
        vendor: parts[3] || '*',
        product: parts[4] || '*',
        version: parts[5] || '*',
        update: parts[6] || '*',
        edition: parts[7] || '*',
        language: parts[8] || '*',
        sw_edition: parts[9] || '*',
        target_sw: parts[10] || '*',
        target_hw: parts[11] || '*',
    };
}

function getActiveFilters() {
    return {
        deprecated: document.getElementById('filterDeprecated').value,
        dateFrom: document.getElementById('filterDateFrom').value,
        dateTo: document.getElementById('filterDateTo').value,
        vendor: document.getElementById('filterVendor').value.toLowerCase(),
        product: document.getElementById('filterProduct').value.toLowerCase(),
        version: document.getElementById('filterVersion').value.toLowerCase(),
        update: document.getElementById('filterUpdate').value.toLowerCase(),
        edition: document.getElementById('filterEdition').value.toLowerCase(),
        language: document.getElementById('filterLanguage').value.toLowerCase(),
        sw_edition: document.getElementById('filterSwEdition').value.toLowerCase(),
        target_sw: document.getElementById('filterTargetSw').value.toLowerCase(),
        target_hw: document.getElementById('filterTargetHw').value.toLowerCase(),
    };
}

function applyResultFilters() {
    const filters = getActiveFilters();
    const filtered = allResults.filter(r => {
        const cpeData = r.cpeData || cpeSearchCache[r.cpeName] || {};
        const parts = parseCpeParts(r.cpeName || '');

        // Deprecated filter
        if (filters.deprecated !== '') {
            const isDeprecated = String(cpeData.deprecated ?? false);
            if (isDeprecated !== filters.deprecated) return false;
        }

        // Date Created filter
        if (filters.dateFrom || filters.dateTo) {
            const created = cpeData.created ? new Date(cpeData.created) : null;
            if (!created) return false;
            if (filters.dateFrom && created < new Date(filters.dateFrom)) return false;
            if (filters.dateTo && created > new Date(filters.dateTo + 'T23:59:59')) return false;
        }

        // CPE component filters
        if (filters.vendor && !parts.vendor.toLowerCase().includes(filters.vendor)) return false;
        if (filters.product && !parts.product.toLowerCase().includes(filters.product)) return false;
        if (filters.version && !parts.version.toLowerCase().includes(filters.version)) return false;
        if (filters.update && !parts.update.toLowerCase().includes(filters.update)) return false;
        if (filters.edition && !parts.edition.toLowerCase().includes(filters.edition)) return false;
        if (filters.language && !parts.language.toLowerCase().includes(filters.language)) return false;
        if (filters.sw_edition && !parts.sw_edition.toLowerCase().includes(filters.sw_edition)) return false;
        if (filters.target_sw && !parts.target_sw.toLowerCase().includes(filters.target_sw)) return false;
        if (filters.target_hw && !parts.target_hw.toLowerCase().includes(filters.target_hw)) return false;

        return true;
    });

    // Temporarily swap allResults for rendering, then restore
    const original = allResults;
    allResults = filtered;
    currentPage = 1;
    renderPage();
    allResults = original;
    // Store filtered set for pagination
    window._filteredResults = filtered;
}

function updateFilterFieldStates() {
    const fieldMap = {
        filterDeprecated: r => String(r.cpeData?.deprecated ?? false),
        filterVendor: r => parseCpeParts(r.cpeName).vendor,
        filterProduct: r => parseCpeParts(r.cpeName).product,
        filterVersion: r => parseCpeParts(r.cpeName).version,
        filterUpdate: r => parseCpeParts(r.cpeName).update,
        filterEdition: r => parseCpeParts(r.cpeName).edition,
        filterLanguage: r => parseCpeParts(r.cpeName).language,
        filterSwEdition: r => parseCpeParts(r.cpeName).sw_edition,
        filterTargetSw: r => parseCpeParts(r.cpeName).target_sw,
        filterTargetHw: r => parseCpeParts(r.cpeName).target_hw,
    };

    for (const [id, extractor] of Object.entries(fieldMap)) {
        const unique = new Set(allResults.map(extractor));
        const el = document.getElementById(id);
        const single = unique.size <= 1;
        el.disabled = single;
        el.style.opacity = single ? '0.4' : '1';
    }

    // Date fields: disable if all created dates are identical
    const uniqueDates = new Set(allResults.map(r => r.cpeData?.created || ''));
    const dateSingle = uniqueDates.size <= 1;
    ['filterDateFrom', 'filterDateTo'].forEach(id => {
        const el = document.getElementById(id);
        el.disabled = dateSingle;
        el.style.opacity = dateSingle ? '0.4' : '1';
    });
}

document.getElementById('applyFilters').addEventListener('click', applyResultFilters);

document.getElementById('clearFilters').addEventListener('click', (e) => {
    e.preventDefault();
    document.getElementById('filterDeprecated').value = '';
    document.getElementById('filterDateFrom').value = '';
    document.getElementById('filterDateTo').value = '';
    document.getElementById('filterVendor').value = '';
    document.getElementById('filterProduct').value = '';
    document.getElementById('filterVersion').value = '';
    document.getElementById('filterUpdate').value = '';
    document.getElementById('filterEdition').value = '';
    document.getElementById('filterLanguage').value = '';
    document.getElementById('filterSwEdition').value = '';
    document.getElementById('filterTargetSw').value = '';
    document.getElementById('filterTargetHw').value = '';
    // Re-render unfiltered
    currentPage = 1;
    window._filteredResults = null;
    renderPage();
});

// =====================
// REMEDIATION TICKETS
// =====================

document.getElementById('createTicketBtn').addEventListener('click', () => {
    document.getElementById('ticketFormContainer').style.display = 'block';
    document.getElementById('ticketDescription').focus();
});

document.getElementById('cancelTicketBtn').addEventListener('click', () => {
    document.getElementById('ticketFormContainer').style.display = 'none';
    document.getElementById('ticketDescription').value = '';
});

document.getElementById('submitTicketBtn').addEventListener('click', () => {
    const desc = document.getElementById('ticketDescription').value.trim();
    const feature = document.getElementById('ticketFeature').value;
    if (!desc) { alert('Please enter a description.'); return; }
    if (!feature) { alert('Please select a related feature.'); return; }

    const ticket = {
        id: ticketIdCounter++,
        description: desc,
        feature: feature,
        created: new Date().toLocaleString(),
        resolved: false
    };
    tickets.push(ticket);
    saveTickets();

    document.getElementById('ticketDescription').value = '';
    document.getElementById('ticketFeature').value = '';
    document.getElementById('ticketFormContainer').style.display = 'none';
    renderTickets();
});

function renderTickets() {
    const container = document.getElementById('ticketsList');
    container.innerHTML = '';

    if (!tickets.length) return;

    for (const t of tickets) {
        const div = document.createElement('div');
        div.style.cssText = 'border: 1px solid #ddd; border-radius: 6px; padding: 12px; margin-bottom: 10px; max-width: 600px; background:' + (t.resolved ? '#e8f5e9' : '#fff');
        div.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <strong>Ticket #${t.id}</strong>
            <span style="font-size: 0.8em; color: #888;">${escapeHtml(t.created)}</span>
        </div>
        <div style="margin-top: 4px;">
            <span style="display: inline-block; padding: 2px 8px; background: #d5bf9f; color: #57534E; border-radius: 3px; font-size: 0.8em; font-weight: 600;">${escapeHtml(t.feature)}</span>
        </div>
        <p style="margin: 8px 0;">${escapeHtml(t.description)}</p>
        <div style="display: flex; gap: 8px; align-items: center;">
            ${t.resolved
                ? '<span style="color: #2e7d32; font-weight: 600;">✔ Resolved</span>'
                : `<button onclick="resolveTicket(${t.id})" style="padding: 4px 12px; background-color: #50b88e; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 0.85em;">Mark Resolved</button>`
            }
            <button onclick="deleteTicket(${t.id})" style="padding: 4px 12px; background-color: #c01e19; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 0.85em;">Delete</button>
        </div>
    `;
        container.appendChild(div);
    }
}

function resolveTicket(id) {
    const t = tickets.find(t => t.id === id);
    if (t) { t.resolved = true; saveTickets(); renderTickets(); }
}

function deleteTicket(id) {
    tickets = tickets.filter(t => t.id !== id);
    saveTickets();
    renderTickets();
}

// Load persisted tickets on startup
renderTickets();

// =====================
// 
// =====================



// =====================
// 
// =====================