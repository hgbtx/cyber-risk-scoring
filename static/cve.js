// =====================
// CVE DATA
// =====================

// CVE COUNTER
function updateCveCounter() {
    totalCveCount = 0;
    for (let cpe in cveDataStore) {
        if (archivedAssets.has(cpe)) continue;
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
    document.getElementById('cpeDetailView').style.display = 'none';
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
        if (archivedAssets.has(cpe)) continue;  // ← add this
        const data = cveDataStore[cpe];

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
    // Add Detail View toggle at the top of the grid (insert after grid.style.display = 'grid')
    if (Object.keys(cveDataStore).length > 0) {
        const detailToggle = document.createElement('div');
        detailToggle.style.cssText = 'grid-column: 1 / -1; margin-bottom: 4px;';
        detailToggle.innerHTML = `<a href="#" id="switchToDetailView" class="cve-folder-back">Detail View</a>`;
        grid.prepend(detailToggle);

        document.getElementById('switchToDetailView').addEventListener('click', (e) => {
            e.preventDefault();
            renderCpeDetailView();
        });
    }
}

// RENDER CPE DETAIL VIEW (table of all CPE records)
function renderCpeDetailView() {
    const grid = document.getElementById('cveGrid');
    const folderView = document.getElementById('cveFolderView');
    const detailView = document.getElementById('cpeDetailView');
    grid.style.display = 'none';
    folderView.style.display = 'none';
    detailView.style.display = 'block';

    const body = document.getElementById('cpeDetailBody');
    body.innerHTML = '';

    // Build row data from cveDataStore
    let rows = [];
    for (const cpe in cveDataStore) {
        if (archivedAssets.has(cpe)) continue;
        const data = cveDataStore[cpe];
        const cpeInfo = cpeDataStore[cpe] || data?.cpeData || null;
        const parts = cpe.split(':');
        const partMap = { a: 'Application', h: 'Hardware', o: 'OS' };

        rows.push({
            title: data.title || cpeInfo?.titles?.[0]?.title || cpe,
            cpeName: cpe,
            part: partMap[parts[2]] || parts[2] || '*',
            vendor: parts[3] || '*',
            product: parts[4] || '*',
            version: parts[5] || '*',
            deprecated: cpeInfo ? String(cpeInfo.deprecated ?? 'N/A') : 'N/A',
            created: cpeInfo?.created || 'N/A',
            lastModified: cpeInfo?.lastModified || 'N/A',
            cveCount: data.count || 0,
            _cpe: cpe,
            _data: data
        });
    }

    // Sort
    rows.sort((a, b) => {
        let va = a[cpeDetailSortKey];
        let vb = b[cpeDetailSortKey];
        if (cpeDetailSortKey === 'cveCount') {
            va = va ?? -1;
            vb = vb ?? -1;
            return cpeDetailSortDir === 'asc' ? va - vb : vb - va;
        }
        if (['created', 'lastModified'].includes(cpeDetailSortKey)) {
            const da = va && va !== 'N/A' ? new Date(va).getTime() : 0;
            const db = vb && vb !== 'N/A' ? new Date(vb).getTime() : 0;
            return cpeDetailSortDir === 'asc' ? da - db : db - da;
        }
        va = String(va).toLowerCase();
        vb = String(vb).toLowerCase();
        return cpeDetailSortDir === 'asc' ? va.localeCompare(vb) : vb.localeCompare(va);
    });

    // Update header arrows
    document.querySelectorAll('#cpeDetailTable thead th[data-sort]').forEach(th => {
        th.classList.remove('sort-asc', 'sort-desc');
        if (th.dataset.sort === cpeDetailSortKey) {
            th.classList.add(cpeDetailSortDir === 'asc' ? 'sort-asc' : 'sort-desc');
        }
    });

    // Render rows
    for (const row of rows) {
        const tr = document.createElement('tr');
        const createdFmt = row.created && row.created !== 'N/A' ? new Date(row.created).toLocaleDateString() : 'N/A';
        const modifiedFmt = row.lastModified && row.lastModified !== 'N/A' ? new Date(row.lastModified).toLocaleDateString() : 'N/A';

        tr.innerHTML = `
            <td><strong>${escapeHtml(row.title)}</strong></td>
            <td>${escapeHtml(row.part)}</td>
            <td>${escapeHtml(row.vendor)}</td>
            <td>${escapeHtml(row.product)}</td>
            <td>${escapeHtml(row.version)}</td>
            <td>${escapeHtml(row.deprecated)}</td>
            <td>${escapeHtml(createdFmt)}</td>
            <td>${escapeHtml(modifiedFmt)}</td>
            <td>${row.cveCount}</td>
        `;

        // Click row to open the CPE's CVE folder
        tr.addEventListener('click', () => {
            openCveFolder(row._cpe, row._data);
        });

        body.appendChild(tr);
    }

    // Attach sort listeners (only once)
    if (!detailView.dataset.sortBound) {
        detailView.dataset.sortBound = 'true';
        document.querySelectorAll('#cpeDetailTable thead th[data-sort]').forEach(th => {
            th.addEventListener('click', () => {
                const key = th.dataset.sort;
                if (cpeDetailSortKey === key) {
                    cpeDetailSortDir = cpeDetailSortDir === 'asc' ? 'desc' : 'asc';
                } else {
                    cpeDetailSortKey = key;
                    cpeDetailSortDir = 'asc';
                }
                renderCpeDetailView();
            });
        });
    }
}

// CPE DETAIL VIEW back button
document.getElementById('cpeDetailBackToFolders').addEventListener('click', (e) => {
    e.preventDefault();
    document.getElementById('cpeDetailView').style.display = 'none';
    renderCveGrid();
});

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