// =====================
// CHARTS
// =====================

const colors = ['#d9af6f', '#c01e19', '#4a90d9', '#50b88e', '#8b5cf6', '#e67e22', '#1abc9c'];

// =====================
// CHART REGISTRY
// =====================
const CHART_REGISTRY = {
    riskMatrixChart:        { label: 'Risk Matrix',          render: () => renderRiskMatrix()        },
    threatVelocityChart:    { label: 'Threat Velocity',      render: () => renderThreatVelocity()    },
    attackSurfaceChart:     { label: 'Attack Surface',       render: () => renderAttackSurface()     },
    priorityBreakdownChart: { label: 'Priority Breakdown',   render: () => renderPriorityBreakdown() },
    remediationFunnelChart: { label: 'Remediation Pipeline', render: () => renderRemediationFunnel() },
    ciaRadarChart:          { label: 'CIA Triad',            render: () => renderCiaGroupedBar()     },
    epssChart:              { label: 'EPSS Distribution',    render: () => renderEpssChart()         },
    cweClusterChart:        { label: 'CWE Clusters',         render: () => renderCweCluster()        },
    backlogAgingChart:      { label: 'Backlog Aging',        render: () => renderBacklogAging()      },
};

// =====================
// HELPER: computePriorityComponents
// Mirrors app.py priority_score() — returns object of additive component values
// =====================
function computePriorityComponents(vuln, cpeName) {
    const c = vuln.cve || {};
    const cvss31 = c.metrics?.cvssMetricV31?.[0]?.cvssData || {};
    const cveId = c.id || '';

    const kev = vuln.hasKev ? 1000 : 0;

    const epss = vuln.epssScore || 0;
    let epssPoints = 0;
    if (epss > 0.5) epssPoints = 500;
    else if (epss > 0.1) epssPoints = 200;

    let agePoints = 0;
    const published = c.published;
    if (published) {
        const daysOld = Math.floor((Date.now() - new Date(published).getTime()) / 86400000);
        if (daysOld < 30) agePoints = 100;
        else if (daysOld < 90) agePoints = 50;
    }

    const baseScore = cvss31.baseScore || 0;
    let cvssPoints = 0;
    if (baseScore >= 9.0) cvssPoints = 50;
    else if (baseScore >= 7.0) cvssPoints = 30;
    else if (baseScore >= 4.0) cvssPoints = 10;

    const av = cvss31.attackVector || '';
    let avPoints = 0;
    if (av === 'NETWORK') avPoints = 25;
    else if (av === 'ADJACENT') avPoints = 10;

    const priv = cvss31.privilegesRequired || '';
    let privPoints = 0;
    if (priv === 'NONE') privPoints = 20;
    else if (priv === 'LOW') privPoints = 10;

    const ui = cvss31.userInteraction || '';
    const uiPoints = ui === 'NONE' ? 15 : 0;

    const ac = cvss31.attackComplexity || '';
    const acPoints = ac === 'LOW' ? 10 : 0;

    let ciaPoints = 0;
    if (cvss31.confidentialityImpact === 'HIGH') ciaPoints += 8;
    if (cvss31.integrityImpact === 'HIGH') ciaPoints += 8;
    if (cvss31.availabilityImpact === 'HIGH') ciaPoints += 8;

    const rawTotal = kev + epssPoints + agePoints + cvssPoints + avPoints + privPoints + uiPoints + acPoints + ciaPoints;
    const critMultiplier = CRITICALITY_MULTIPLIERS[assetCriticality[cpeName] || 3] || 1.0;
    const crit = Math.round(rawTotal * (critMultiplier - 1));

    return { kev, epss: epssPoints, age: agePoints, cvss: cvssPoints, av: avPoints, priv: privPoints, ui: uiPoints, ac: acPoints, cia: ciaPoints, crit };
}

// =====================
// CVE ID FINDER FOR CHART INTERACTIONS
// =====================
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
// CHART 1: Risk Posture Matrix (Bubble Scatter)
// =====================
function renderRiskMatrix() {
    const canvas = document.getElementById('riskMatrixChart');
    if (!canvas) return;

    const assetPoints = [];
    const { from, to } = getPublishedDateRange();

    for (const cpe in cveDataStore) {
        if (archivedAssets.has(cpe)) continue;
        const data = cveDataStore[cpe];
        if (!data?.vulnerabilities?.length) continue;

        const exploitScores = [];
        const impactScores = [];
        let aboveThresholdCount = 0;

        for (const vuln of data.vulnerabilities) {
            const cveId = vuln.cve?.id;
            if (cveId && isFalsePositive(cpe, cveId)) continue;
            const published = vuln.cve?.published;
            if (published) {
                const pubDate = new Date(published);
                if (from && pubDate < from) continue;
                if (to && pubDate > to) continue;
            }
            const metric31 = vuln.cve?.metrics?.cvssMetricV31?.[0];
            if (metric31) {
                if (typeof metric31.exploitabilityScore === 'number') exploitScores.push(metric31.exploitabilityScore);
                if (typeof metric31.impactScore === 'number') impactScores.push(metric31.impactScore);
            }
            const norm = normalizePriorityScore(vuln.priorityScore ?? 0);
            if (norm >= chartRiskThreshold) aboveThresholdCount++;
        }

        if (!exploitScores.length || !impactScores.length) continue;

        const hasOpenTicket = tickets.some(t => !t.isArchived && t.status !== 'Resolved' && t.feature === data.title);
        const fillColor = hasOpenTicket ? '#d9af6f' : '#c01e19';
        const borderColor = hasOpenTicket ? '#be7a15' : '#8b0000';
        const critLevel = assetCriticality[cpe] ?? 3;
        const opacity = { 1: 0.3, 2: 0.5, 3: 0.7, 4: 0.85, 5: 1.0 }[critLevel] || 0.7;

        assetPoints.push({
            x: applyAggMethod(exploitScores),
            y: applyAggMethod(impactScores),
            r: Math.min(Math.max(5, aboveThresholdCount * 3), 30),
            label: data.title || cpe,
            cpe,
            aboveThresholdCount,
            hasOpenTicket,
            fillColor,
            borderColor,
            opacity
        });
    }

    if (assetPoints.length === 0) {
        canvas.style.display = 'none';
        const inst = Chart.getChart(canvas);
        if (inst) inst.destroy();
        return;
    }

    canvas.style.display = 'block';
    const inst = Chart.getChart(canvas);
    if (inst) inst.destroy();

    new Chart(canvas, {
        type: 'bubble',
        data: {
            datasets: [{
                label: 'Assets',
                data: assetPoints,
                backgroundColor: assetPoints.map(p => {
                    const alpha = Math.round(p.opacity * 255).toString(16).padStart(2, '0');
                    return p.fillColor + alpha;
                }),
                borderColor: assetPoints.map(p => p.borderColor),
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { display: false },
                title: { display: true, text: 'Risk Posture Matrix' },
                tooltip: {
                    callbacks: {
                        label: ctx => {
                            const p = ctx.raw;
                            return [
                                p.label,
                                `Exploit: ${p.x.toFixed(2)}  Impact: ${p.y.toFixed(2)}`,
                                `Above-threshold CVEs: ${p.aboveThresholdCount}`,
                                p.hasOpenTicket ? 'Has open ticket' : 'No open ticket'
                            ];
                        }
                    }
                },
                annotation: {
                    annotations: {
                        xLine: {
                            type: 'line',
                            xMin: chartRiskThreshold,
                            xMax: chartRiskThreshold,
                            borderColor: '#c01e1966',
                            borderWidth: 1,
                            borderDash: [6, 4]
                        },
                        yLine: {
                            type: 'line',
                            yMin: chartRiskThreshold,
                            yMax: chartRiskThreshold,
                            borderColor: '#c01e1966',
                            borderWidth: 1,
                            borderDash: [6, 4]
                        }
                    }
                }
            },
            scales: {
                x: { min: 0, max: 10, title: { display: true, text: 'Exploitability Score' } },
                y: { min: 0, max: 10, title: { display: true, text: 'Impact Score' } }
            },
            onClick: (evt, elements) => {
                if (!elements.length) return;
                const chart = Chart.getChart(canvas);
                if (!chart) return;
                const p = chart.data.datasets[0].data[elements[0].index];
                const data = cveDataStore[p.cpe];
                if (!data?.vulnerabilities?.length) return;
                const topVuln = [...data.vulnerabilities].sort((a, b) => (b.priorityScore ?? 0) - (a.priorityScore ?? 0))[0];
                if (!topVuln) return;
                const panel = document.querySelector('.right-panel-container');
                if (panel.classList.contains('collapsed')) document.getElementById('toggleRightPanel').click();
                displayExpandedView(topVuln);
            }
        }
    });
}

// =====================
// CHART 2: Threat Velocity Time Series (Mixed Line + Bar)
// =====================
function renderThreatVelocity() {
    const canvas = document.getElementById('threatVelocityChart');
    if (!canvas) return;
    const { from, to } = getPublishedDateRange();

    // Build monthly buckets from CVE published dates
    const kevByMonth = {};
    const cveByMonth = {};

    for (const cpe in cveDataStore) {
        if (archivedAssets.has(cpe)) continue;
        const data = cveDataStore[cpe];
        if (!data?.vulnerabilities) continue;
        for (const vuln of data.vulnerabilities) {
            const cveId = vuln.cve?.id;
            if (cveId && isFalsePositive(cpe, cveId)) continue;
            const published = vuln.cve?.published;
            if (!published) continue;
            const pubDate = new Date(published);
            if (from && pubDate < from) continue;
            if (to && pubDate > to) continue;
            const key = published.slice(0, 7); // YYYY-MM
            cveByMonth[key] = (cveByMonth[key] || 0) + 1;
            if (vuln.hasKev) kevByMonth[key] = (kevByMonth[key] || 0) + 1;
        }
    }

    const ticketByMonth = {};
    for (const t of tickets) {
        if (!t.created) continue;
        const key = new Date(t.created).toISOString().slice(0, 7);
        ticketByMonth[key] = (ticketByMonth[key] || 0) + 1;
    }

    const allMonths = [...new Set([...Object.keys(cveByMonth), ...Object.keys(ticketByMonth)])].sort();

    if (allMonths.length === 0) {
        canvas.style.display = 'none';
        const inst = Chart.getChart(canvas);
        if (inst) inst.destroy();
        return;
    }

    canvas.style.display = 'block';
    const inst = Chart.getChart(canvas);
    if (inst) inst.destroy();

    const kevCounts = allMonths.map(m => kevByMonth[m] || 0);
    let cumulative = 0;
    const kevCumulative = allMonths.map(m => { cumulative += (kevByMonth[m] || 0); return cumulative; });
    const ticketCounts = allMonths.map(m => ticketByMonth[m] || 0);

    // Point styles: triangle where any CVE exceeds threshold
    const pointStyles = allMonths.map(m => {
        return Object.values(cveDataStore).some(d =>
            d?.vulnerabilities?.some(v => {
                const pub = v.cve?.published;
                return pub && pub.slice(0, 7) === m && normalizePriorityScore(v.priorityScore ?? 0) >= chartRiskThreshold;
            })
        ) ? 'triangle' : 'circle';
    });
    const pointRadii = pointStyles.map(s => s === 'triangle' ? 8 : 4);

    const todayStr = new Date().toISOString().slice(0, 7);

    new Chart(canvas, {
        type: 'bar',
        data: {
            labels: allMonths,
            datasets: [
                {
                    type: 'line',
                    label: 'KEV CVEs/month',
                    data: kevCounts,
                    borderColor: '#c01e19',
                    backgroundColor: '#c01e1922',
                    yAxisID: 'y',
                    pointStyle: pointStyles,
                    pointRadius: pointRadii,
                    tension: 0.3,
                    fill: false
                },
                {
                    type: 'line',
                    label: 'Cumulative KEV',
                    data: kevCumulative,
                    borderColor: '#e67e22',
                    backgroundColor: 'transparent',
                    yAxisID: 'y',
                    borderDash: [6, 4],
                    pointRadius: 0,
                    tension: 0.3,
                    fill: false
                },
                {
                    type: 'bar',
                    label: 'Tickets/month',
                    data: ticketCounts,
                    backgroundColor: '#50b88e66',
                    yAxisID: 'y2'
                }
            ]
        },
        options: {
            responsive: true,
            plugins: {
                title: { display: true, text: 'Threat Velocity' },
                legend: { display: true, position: 'bottom' },
                annotation: {
                    annotations: {
                        today: {
                            type: 'line',
                            xMin: todayStr,
                            xMax: todayStr,
                            borderColor: '#4a90d9',
                            borderWidth: 1,
                            borderDash: [4, 4],
                            label: { display: true, content: 'Today', position: 'start', font: { size: 10 } }
                        }
                    }
                }
            },
            scales: {
                x: { title: { display: true, text: 'Month' } },
                y: { beginAtZero: true, title: { display: true, text: 'KEV Count' }, position: 'left' },
                y2: { beginAtZero: true, title: { display: true, text: 'Tickets' }, position: 'right', grid: { drawOnChartArea: false } }
            }
        }
    });
}

// =====================
// CHART 3: Attack Surface Composition (Stacked Bar)
// =====================
function renderAttackSurface() {
    const canvas = document.getElementById('attackSurfaceChart');
    if (!canvas) return;
    const { from, to } = getPublishedDateRange();

    const assetData = [];

    for (const cpe in cveDataStore) {
        if (archivedAssets.has(cpe)) continue;
        const data = cveDataStore[cpe];
        if (!data?.vulnerabilities?.length) continue;

        let critical = 0, high = 0, medium = 0, low = 0;
        for (const vuln of data.vulnerabilities) {
            const cveId = vuln.cve?.id;
            if (cveId && isFalsePositive(cpe, cveId)) continue;
            const published = vuln.cve?.published;
            if (published) {
                const pubDate = new Date(published);
                if (from && pubDate < from) continue;
                if (to && pubDate > to) continue;
            }
            const cvss31 = vuln.cve?.metrics?.cvssMetricV31?.[0]?.cvssData;
            if (!cvss31) { low++; continue; }
            const av = cvss31.attackVector || '';
            const pr = cvss31.privilegesRequired || '';

            if (av === 'NETWORK' && pr === 'NONE') critical++;
            else if ((av === 'NETWORK' && pr === 'LOW') || (av === 'ADJACENT' && pr === 'NONE')) high++;
            else if ((av === 'NETWORK' && pr === 'HIGH') || (av === 'LOCAL' && pr === 'NONE')) medium++;
            else low++;
        }
        assetData.push({ label: data.title || cpe, cpe, critical, high, medium, low });
    }

    if (assetData.length === 0) {
        canvas.style.display = 'none';
        const inst = Chart.getChart(canvas);
        if (inst) inst.destroy();
        return;
    }

    assetData.sort((a, b) => {
        const critDiff = (assetCriticality[b.cpe] ?? 3) - (assetCriticality[a.cpe] ?? 3);
        return critDiff !== 0 ? critDiff : b.critical - a.critical;
    });
    canvas.style.display = 'block';
    const inst = Chart.getChart(canvas);
    if (inst) inst.destroy();

    new Chart(canvas, {
        type: 'bar',
        data: {
            labels: assetData.map(a => a.label),
            datasets: [
                { label: 'Critical Surface', data: assetData.map(a => a.critical), backgroundColor: '#c01e19' },
                { label: 'High Surface',     data: assetData.map(a => a.high),     backgroundColor: '#e67e22' },
                { label: 'Medium Surface',   data: assetData.map(a => a.medium),   backgroundColor: '#d9af6f' },
                { label: 'Low Surface',      data: assetData.map(a => a.low),      backgroundColor: '#50b88e' }
            ]
        },
        options: {
            responsive: true,
            plugins: {
                title: { display: true, text: 'Attack Surface Composition' },
                legend: { display: true, position: 'bottom' }
            },
            scales: {
                x: { stacked: true, ticks: { maxRotation: 45 } },
                y: { stacked: true, beginAtZero: true, title: { display: true, text: 'CVE Count' } }
            }
        }
    });
}

// =====================
// CHART 4: Priority Score Component Breakdown (Horizontal Stacked Bar)
// =====================
function renderPriorityBreakdown() {
    const canvas = document.getElementById('priorityBreakdownChart');
    if (!canvas) return;

    const allVulns = [];
    for (const cpe in cveDataStore) {
        if (archivedAssets.has(cpe)) continue;
        const data = cveDataStore[cpe];
        if (!data?.vulnerabilities) continue;
        for (const vuln of data.vulnerabilities) {
            const cveId = vuln.cve?.id;
            if (cveId && isFalsePositive(cpe, cveId)) continue;
            allVulns.push({ ...vuln, _cpeName: cpe });
        }
    }

    if (allVulns.length === 0) {
        canvas.style.display = 'none';
        const inst = Chart.getChart(canvas);
        if (inst) inst.destroy();
        return;
    }

    const top15 = [...allVulns]
        .sort((a, b) => (b.priorityScore ?? 0) - (a.priorityScore ?? 0))
        .slice(0, 15);

    canvas.style.display = 'block';
    const inst = Chart.getChart(canvas);
    if (inst) inst.destroy();

    const labels = top15.map(v => v.cve?.id || 'Unknown');
    const components = top15.map(v => computePriorityComponents(v, v._cpeName));

    const thresholdX = (chartRiskThreshold / 10) * PRIORITY_SCORE_MAX;

    new Chart(canvas, {
        type: 'bar',
        data: {
            labels,
            datasets: [
                { label: 'KEV',             data: components.map(c => c.kev),  backgroundColor: '#7b1fa2' },
                { label: 'EPSS',            data: components.map(c => c.epss), backgroundColor: '#c01e19' },
                { label: 'Age',             data: components.map(c => c.age),  backgroundColor: '#e67e22' },
                { label: 'CVSS',            data: components.map(c => c.cvss), backgroundColor: '#d9af6f' },
                { label: 'Attack Vector',   data: components.map(c => c.av),   backgroundColor: '#4a90d9' },
                { label: 'Privileges',      data: components.map(c => c.priv), backgroundColor: '#50b88e' },
                { label: 'User Interaction',data: components.map(c => c.ui),   backgroundColor: '#8b5cf6' },
                { label: 'Attack Complexity',data: components.map(c => c.ac),  backgroundColor: '#1abc9c' },
                { label: 'CIA Impact',      data: components.map(c => c.cia),  backgroundColor: '#78909c' },
                { label: 'Criticality',     data: components.map(c => c.crit), backgroundColor: '#8b5cf6' }
            ]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            plugins: {
                title: { display: true, text: 'Priority Score Breakdown (Top 15)' },
                legend: { display: true, position: 'bottom' },
                annotation: {
                    annotations: {
                        threshold: {
                            type: 'line',
                            xMin: thresholdX,
                            xMax: thresholdX,
                            borderColor: '#c01e19',
                            borderWidth: 2,
                            borderDash: [6, 4],
                            label: {
                                display: true,
                                content: `Threshold`,
                                position: 'start',
                                backgroundColor: '#c01e19',
                                color: 'white',
                                font: { size: 10 }
                            }
                        }
                    }
                }
            },
            scales: {
                x: { stacked: true, max: PRIORITY_SCORE_MAX, title: { display: true, text: 'Priority Score' } },
                y: { stacked: true }
            },
            onClick: (evt, elements) => {
                if (!elements.length) return;
                const idx = elements[0].index;
                const cveId = labels[idx];
                const vuln = findVulnByCveId(cveId);
                if (!vuln) return;
                const panel = document.querySelector('.right-panel-container');
                if (panel.classList.contains('collapsed')) document.getElementById('toggleRightPanel').click();
                displayExpandedView(vuln);
            }
        }
    });
}

// =====================
// CHART 5: Remediation Pipeline Funnel (Concentric Doughnut)
// =====================
function renderRemediationFunnel() {
    const canvas = document.getElementById('remediationFunnelChart');
    if (!canvas) return;

    // Outer ring: ticket pipeline
    let ticketOpen = 0, ticketInProgress = 0, ticketResolved = 0, ticketArchived = 0;
    for (const t of tickets) {
        if (t.isArchived || t.status === 'Archived') ticketArchived++;
        else if (t.status === 'Open') ticketOpen++;
        else if (t.status === 'In Progress') ticketInProgress++;
        else if (t.status === 'Resolved') ticketResolved++;
    }

    // Inner ring: CVE coverage
    const coveredAssets = new Set(tickets.filter(t => !t.isArchived && t.status !== 'Archived').map(t => t.feature));
    let coveredCves = 0, uncoveredCves = 0;
    for (const cpe in cveDataStore) {
        if (archivedAssets.has(cpe)) continue;
        const data = cveDataStore[cpe];
        if (!data?.vulnerabilities?.length) continue;
        let count = 0;
        for (const vuln of data.vulnerabilities) {
            const cveId = vuln.cve?.id;
            if (cveId && isFalsePositive(cpe, cveId)) continue;
            count++;
        }
        if (coveredAssets.has(data.title)) coveredCves += count;
        else uncoveredCves += count;
    }

    const totalCves = coveredCves + uncoveredCves;
    const totalTickets = ticketOpen + ticketInProgress + ticketResolved + ticketArchived;

    if (totalCves === 0 && totalTickets === 0) {
        canvas.style.display = 'none';
        const inst = Chart.getChart(canvas);
        if (inst) inst.destroy();
        return;
    }

    canvas.style.display = 'block';
    const inst = Chart.getChart(canvas);
    if (inst) inst.destroy();

    const coveragePct = totalCves > 0 ? Math.round((coveredCves / totalCves) * 100) : 0;

    new Chart(canvas, {
        type: 'doughnut',
        data: {
            labels: ['Open', 'In Progress', 'Resolved', 'Archived', 'Covered CVEs', 'Untracked CVEs'],
            datasets: [
                {
                    label: 'Ticket Pipeline',
                    data: [ticketOpen, ticketInProgress, ticketResolved, ticketArchived],
                    backgroundColor: ['#e67e22', '#4a90d9', '#50b88e', '#78909c'],
                    borderWidth: 2
                },
                {
                    label: 'CVE Coverage',
                    data: [coveredCves, uncoveredCves],
                    backgroundColor: ['#50b88e66', '#c01e1966'],
                    borderWidth: 2
                }
            ]
        },
        options: {
            responsive: true,
            cutout: '40%',
            plugins: {
                title: { display: true, text: 'Remediation Pipeline' },
                legend: { display: true, position: 'bottom' },
                tooltip: {
                    callbacks: {
                        label: ctx => {
                            const val = ctx.raw;
                            const total = ctx.dataset.data.reduce((s, v) => s + v, 0);
                            const pct = total > 0 ? ((val / total) * 100).toFixed(1) : 0;
                            return `${ctx.label}: ${val} (${pct}%)`;
                        }
                    }
                }
            }
        },
        plugins: [{
            id: 'centerText',
            afterDraw(chart) {
                const { ctx, chartArea: { width, height, left, top } } = chart;
                ctx.save();
                ctx.font = 'bold 16px Calibri';
                ctx.fillStyle = '#57534E';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillText(`${coveragePct}%`, left + width / 2, top + height / 2 - 8);
                ctx.font = '11px Calibri';
                ctx.fillStyle = '#888';
                ctx.fillText('covered', left + width / 2, top + height / 2 + 10);
                ctx.restore();
            }
        }]
    });
}

// =====================
// CHART 6: CIA Triad Grouped Bar (replaces radar)
// =====================
function renderCiaGroupedBar() {
    const canvas = document.getElementById('ciaRadarChart');
    if (!canvas) return;
    const { from, to } = getPublishedDateRange();

    const ciaMap = { 'NONE': 0, 'LOW': 0.5, 'HIGH': 1.0 };
    const tiers = {
        CRITICAL: { c: [], i: [], a: [] },
        HIGH:     { c: [], i: [], a: [] },
        MEDIUM:   { c: [], i: [], a: [] },
        LOW:      { c: [], i: [], a: [] }
    };

    for (const cpe in cveDataStore) {
        if (archivedAssets.has(cpe)) continue;
        const data = cveDataStore[cpe];
        if (!data?.vulnerabilities) continue;
        for (const vuln of data.vulnerabilities) {
            const cveId = vuln.cve?.id;
            if (cveId && isFalsePositive(cpe, cveId)) continue;
            const published = vuln.cve?.published;
            if (published) {
                const pubDate = new Date(published);
                if (from && pubDate < from) continue;
                if (to && pubDate > to) continue;
            }
            const cvss31 = vuln.cve?.metrics?.cvssMetricV31?.[0];
            if (!cvss31) continue;
            const severity = cvss31.cvssData?.baseSeverity?.toUpperCase();
            if (!tiers[severity]) continue;
            const d = cvss31.cvssData;
            tiers[severity].c.push(ciaMap[d.confidentialityImpact] ?? 0);
            tiers[severity].i.push(ciaMap[d.integrityImpact] ?? 0);
            tiers[severity].a.push(ciaMap[d.availabilityImpact] ?? 0);
        }
    }

    const tierColors = {
        CRITICAL: '#7b1fa2',
        HIGH: '#c01e19',
        MEDIUM: '#e67e22',
        LOW: '#50b88e'
    };

    const datasets = [];
    for (const [tier, vals] of Object.entries(tiers)) {
        if (!vals.c.length) continue;
        datasets.push({
            label: tier,
            data: [
                applyAggMethod(vals.c),
                applyAggMethod(vals.i),
                applyAggMethod(vals.a)
            ],
            backgroundColor: tierColors[tier] + 'cc',
            borderColor: tierColors[tier],
            borderWidth: 1
        });
    }

    if (datasets.length === 0) {
        canvas.style.display = 'none';
        const inst = Chart.getChart(canvas);
        if (inst) inst.destroy();
        return;
    }

    canvas.style.display = 'block';
    const inst = Chart.getChart(canvas);
    if (inst) inst.destroy();

    new Chart(canvas, {
        type: 'bar',
        data: {
            labels: ['Confidentiality', 'Integrity', 'Availability'],
            datasets
        },
        options: {
            responsive: true,
            plugins: {
                title: { display: true, text: 'CIA Triad by Severity Tier' },
                legend: { display: true, position: 'bottom' }
            },
            scales: {
                x: { title: { display: true, text: 'CIA Component' } },
                y: { min: 0, max: 1, ticks: { stepSize: 0.25 }, title: { display: true, text: 'Average Impact' } }
            }
        }
    });
}

// =====================
// CHART 7: EPSS Distribution Scatter
// =====================
function renderEpssChart() {
    const canvas = document.getElementById('epssChart');
    if (!canvas) return;
    const { from, to } = getPublishedDateRange();

    const datasets = [];
    let colorIdx = 0;

    for (const cpe in cveDataStore) {
        if (archivedAssets.has(cpe)) continue;
        const data = cveDataStore[cpe];
        if (!data?.vulnerabilities) continue;

        const points = [];
        for (const vuln of data.vulnerabilities) {
            const cveId = vuln.cve?.id;
            if (cveId && isFalsePositive(cpe, cveId)) continue;
            const published = vuln.cve?.published;
            if (!published) continue;
            const pubDate = new Date(published);
            if (from && pubDate < from) continue;
            if (to && pubDate > to) continue;
            const epss = vuln.epssScore;
            if (typeof epss !== 'number') continue;
            points.push({ x: pubDate, y: epss, cveId: vuln.cve?.id });
        }

        if (!points.length) continue;

        const color = colors[colorIdx % colors.length];
        colorIdx++;
        datasets.push({
            label: data.title || cpe,
            data: points,
            backgroundColor: color + '99',
            borderColor: color,
            borderWidth: 1,
            pointRadius: 5,
            pointHoverRadius: 7
        });
    }

    if (datasets.length === 0) {
        canvas.style.display = 'none';
        const inst = Chart.getChart(canvas);
        if (inst) inst.destroy();
        return;
    }

    canvas.style.display = 'block';
    const inst = Chart.getChart(canvas);
    if (inst) inst.destroy();

    new Chart(canvas, {
        type: 'scatter',
        data: { datasets },
        options: {
            responsive: true,
            plugins: {
                title: { display: true, text: 'EPSS Score Distribution by Published Date' },
                legend: { display: true, position: 'bottom' },
                tooltip: {
                    callbacks: {
                        label: ctx => {
                            const p = ctx.raw;
                            return `${p.cveId}: EPSS ${p.y.toFixed(3)} (${new Date(p.x).toISOString().slice(0, 10)})`;
                        }
                    }
                },
                annotation: {
                    annotations: {
                        highLine: {
                            type: 'line',
                            yMin: 0.5, yMax: 0.5,
                            borderColor: '#c01e19',
                            borderWidth: 1,
                            borderDash: [6, 4],
                            label: { display: true, content: 'High (0.5)', position: 'end', font: { size: 10 }, backgroundColor: '#c01e19', color: 'white' }
                        },
                        medLine: {
                            type: 'line',
                            yMin: 0.1, yMax: 0.1,
                            borderColor: '#e67e22',
                            borderWidth: 1,
                            borderDash: [6, 4],
                            label: { display: true, content: 'Med (0.1)', position: 'end', font: { size: 10 }, backgroundColor: '#e67e22', color: 'white' }
                        }
                    }
                }
            },
            scales: {
                x: {
                    type: 'time',
                    time: { unit: 'month' },
                    title: { display: true, text: 'Published Date' }
                },
                y: {
                    min: 0, max: 1,
                    title: { display: true, text: 'EPSS Score' }
                }
            },
            onClick: (evt, elements) => {
                if (!elements.length) return;
                const el = elements[0];
                const point = datasets[el.datasetIndex].data[el.index];
                if (!point?.cveId) return;
                const vuln = findVulnByCveId(point.cveId);
                if (!vuln) return;
                const panel = document.querySelector('.right-panel-container');
                if (panel.classList.contains('collapsed')) document.getElementById('toggleRightPanel').click();
                displayExpandedView(vuln);
            }
        }
    });
}

// =====================
// CHART 8: CWE Cluster Scatter
// x = published date, y = CWE (discrete rows),
// color = asset (CPE), size = count of CVEs from that asset sharing the same CWE
// =====================
function renderCweCluster() {
    const canvas = document.getElementById('cweClusterChart');
    if (!canvas) return;
    const { from, to } = getPublishedDateRange();

    // cweAssetFreq[cweId][assetLabel] = count of CVEs for that (cwe, asset) pair
    const cweAssetFreq = {};
    // raw points before frequency lookup
    const rawPoints = [];

    for (const cpe in cveDataStore) {
        if (archivedAssets.has(cpe)) continue;
        const data = cveDataStore[cpe];
        if (!data?.vulnerabilities) continue;
        const assetLabel = data.title || cpe;

        for (const vuln of data.vulnerabilities) {
            const cveId = vuln.cve?.id;
            if (cveId && isFalsePositive(cpe, cveId)) continue;
            const published = vuln.cve?.published;
            if (!published) continue;
            const pubDate = new Date(published);
            if (from && pubDate < from) continue;
            if (to && pubDate > to) continue;
            if (!cveId) continue;

            const cwes = (vuln.cve?.weaknesses || [])
                .flatMap(w => (w.description || []).map(d => d.value))
                .filter(v => v && v.startsWith('CWE-'));
            const keys = cwes.length ? cwes : ['Unknown'];

            for (const cweId of keys) {
                if (!cweAssetFreq[cweId]) cweAssetFreq[cweId] = {};
                cweAssetFreq[cweId][assetLabel] = (cweAssetFreq[cweId][assetLabel] || 0) + 1;
                rawPoints.push({ x: pubDate, cveId, cweId, assetLabel, vuln });
            }
        }
    }

    if (rawPoints.length === 0) {
        canvas.style.display = 'none';
        const inst = Chart.getChart(canvas);
        if (inst) inst.destroy();
        return;
    }

    // Build ordered CWE list — sort by total frequency descending
    const cweFreq = {};
    for (const { cweId } of rawPoints) cweFreq[cweId] = (cweFreq[cweId] || 0) + 1;
    const cweList = Object.keys(cweFreq).sort((a, b) => cweFreq[b] - cweFreq[a]);
    const cweIndex = Object.fromEntries(cweList.map((id, i) => [id, i]));

    // One dataset per asset
    const assetList = [...new Set(rawPoints.map(p => p.assetLabel))];
    const datasets = assetList.map((assetLabel, i) => {
        const color = colors[i % colors.length];
        const data = rawPoints
            .filter(p => p.assetLabel === assetLabel)
            .map(p => {
                const freq = cweAssetFreq[p.cweId]?.[assetLabel] || 1;
                const r = Math.max(4, Math.min(20, 4 + Math.round(Math.sqrt(freq) * 3)));
                return { x: p.x, y: cweIndex[p.cweId], r, cveId: p.cveId, cweId: p.cweId, freq, vuln: p.vuln };
            });
        return {
            label: assetLabel,
            data,
            backgroundColor: color + 'aa',
            borderColor: color,
            borderWidth: 1
        };
    });

    canvas.style.display = 'block';
    const inst = Chart.getChart(canvas);
    if (inst) inst.destroy();

    new Chart(canvas, {
        type: 'bubble',
        data: { datasets },
        options: {
            responsive: true,
            plugins: {
                title: { display: true, text: 'CVE Clusters by CWE' },
                legend: { display: true, position: 'bottom' },
                tooltip: {
                    callbacks: {
                        label: ctx => {
                            const p = ctx.raw;
                            return [
                                `${p.cveId}`,
                                `CWE: ${p.cweId}`,
                                `Asset: ${ctx.dataset.label}`,
                                `CVEs with this CWE: ${p.freq}`
                            ];
                        }
                    }
                }
            },
            scales: {
                x: {
                    type: 'time',
                    time: { unit: 'month' },
                    title: { display: true, text: 'Published Date' }
                },
                y: {
                    ticks: {
                        callback: val => cweList[Math.round(val)] || '',
                        stepSize: 1,
                        autoSkip: false
                    },
                    min: -0.5,
                    max: cweList.length - 0.5,
                    grid: { color: '#f0f0f0' }
                }
            },
            onClick: (evt, elements) => {
                if (!elements.length) return;
                const el = elements[0];
                const p = datasets[el.datasetIndex].data[el.index];
                if (!p?.vuln) return;
                const panel = document.querySelector('.right-panel-container');
                if (panel.classList.contains('collapsed')) document.getElementById('toggleRightPanel').click();
                displayExpandedView(p.vuln);
            }
        }
    });
}

// =====================
// RENDER ALL PLACED CHARTS
// =====================
function renderAllPlacedCharts() {
    for (const id of chartLayout) {
        if (id && CHART_REGISTRY[id]) CHART_REGISTRY[id].render();
    }
}

// =====================
// PLACEHOLDER MANAGEMENT
// =====================
function updateChartPlaceholder() {
    const anyActive = chartLayout.some(id => {
        if (!id) return false;
        const c = document.getElementById(id);
        return c && c.style.display !== 'none';
    });
    const ph = document.getElementById('chartPlaceholder');
    if (ph) ph.style.display = anyActive ? 'none' : 'block';
    const pdfBtn = document.getElementById('chartDownloadPdfBtn');
    if (pdfBtn && hasPermission('myCharts', 'download PDF')) {
        pdfBtn.style.display = anyActive ? '' : 'none';
    }
}

// =====================
// CHART DASHBOARD RENDERER
// =====================
function renderChartDashboard() {
    const dashboard = document.getElementById('chartDashboard');
    if (!dashboard) return;
    dashboard.innerHTML = '';

    // Ensure minimum 3 slots
    while (chartLayout.length < 3) chartLayout.push(null);

    const canDragDrop = hasPermission('myCharts', 'drag and drop charts to dashboard');

    // Add slot button at the TOP (max 7 slots)
    if (chartLayout.length < 7 && canDragDrop) {
        const addBtn = document.createElement('button');
        addBtn.className = 'chart-add-slot-btn';
        addBtn.textContent = '+ Add Chart Slot';
        addBtn.addEventListener('click', () => {
            chartLayout.push(null);
            saveChartLayout();
            renderChartDashboard();
            renderChartPalette();
        });
        dashboard.appendChild(addBtn);
    }

    chartLayout.forEach((chartId, index) => {
        const slot = document.createElement('div');
        slot.className = 'chart-slot ' + (chartId ? 'chart-slot--filled' : 'chart-slot--empty');
        slot.dataset.index = index;

        // Drag-over events (only when permitted)
        if (canDragDrop) {
            slot.addEventListener('dragover', e => {
                e.preventDefault();
                slot.classList.add('chart-slot--drag-over');
            });
            slot.addEventListener('dragleave', e => {
                if (!slot.contains(e.relatedTarget)) slot.classList.remove('chart-slot--drag-over');
            });
            slot.addEventListener('drop', e => {
                e.preventDefault();
                slot.classList.remove('chart-slot--drag-over');
                if (!draggedChartId) return;
                // If chart is already placed somewhere, remove it first
                const existing = chartLayout.indexOf(draggedChartId);
                if (existing !== -1) chartLayout[existing] = null;
                chartLayout[index] = draggedChartId;
                draggedChartId = null;
                saveChartLayout();
                renderChartDashboard();
                renderChartPalette();
            });
        }

        if (chartId) {
            if (canDragDrop) {
                const closeBtn = document.createElement('button');
                closeBtn.className = 'chart-slot-close';
                closeBtn.innerHTML = '&times;';
                closeBtn.title = 'Remove chart';
                closeBtn.addEventListener('click', () => {
                    const c = document.getElementById(chartId);
                    if (c) { const inst = Chart.getChart(c); if (inst) inst.destroy(); }
                    chartLayout.splice(index, 1);
                    while (chartLayout.length < 3) chartLayout.push(null);
                    saveChartLayout();
                    renderChartDashboard();
                    renderChartPalette();
                });
                slot.appendChild(closeBtn);
            }

            // PNG download button
            if (hasPermission('myCharts', 'download PNG')) {
                const dlBtn = document.createElement('button');
                dlBtn.className = 'chart-slot-download';
                dlBtn.innerHTML = '<i class="fa-solid fa-download"></i>';
                dlBtn.title = 'Download as PNG';
                dlBtn.addEventListener('click', () => {
                    const canvasEl = document.getElementById(chartId);
                    if (!canvasEl) return;
                    const link = document.createElement('a');
                    link.download = `${chartId}.png`;
                    link.href = canvasEl.toDataURL('image/png');
                    link.click();
                });
                slot.appendChild(dlBtn);
            }

            // Canvas for the chart
            const canvas = document.createElement('canvas');
            canvas.id = chartId;
            slot.appendChild(canvas);
        } else {
            const ph = document.createElement('div');
            ph.className = 'chart-slot-placeholder';
            ph.textContent = 'Drop a chart here';
            slot.appendChild(ph);
        }

        dashboard.appendChild(slot);
    });

    // Render charts after DOM update
    requestAnimationFrame(() => {
        renderAllPlacedCharts();
        updateChartPlaceholder();
    });
}

function downloadAllChartsPDF() {
    if (!hasPermission('myCharts', 'download PDF')) return;
    const jsPDFLib = (window.jspdf && window.jspdf.jsPDF) || window.jsPDF;
    if (!jsPDFLib) return alert('PDF library not loaded.');
    const jsPDF = jsPDFLib;
    const doc = new jsPDF('landscape', 'mm', 'a4');
    const pageW = doc.internal.pageSize.getWidth();
    const pageH = doc.internal.pageSize.getHeight();
    const margin = 10;
    let first = true;

    for (const chartId of chartLayout) {
        if (!chartId) continue;
        const canvas = document.getElementById(chartId);
        if (!canvas) continue;
        if (!first) doc.addPage();
        first = false;
        const imgData = canvas.toDataURL('image/png');
        const ratio = canvas.width / canvas.height;
        let w = pageW - margin * 2;
        let h = w / ratio;
        if (h > pageH - margin * 2) {
            h = pageH - margin * 2;
            w = h * ratio;
        }
        const x = (pageW - w) / 2;
        const y = (pageH - h) / 2;
        doc.addImage(imgData, 'PNG', x, y, w, h);
    }

    if (first) return alert('No charts to export.');
    doc.save('dashboard-charts.pdf');
}

// =====================
// DASHBOARD RESIZE OBSERVER
// Observes the tab container so charts resize when the right panel
// expands/collapses and the available width changes.
// =====================
(function () {
    let _lastWidth = 0;
    const ro = new ResizeObserver(entries => {
        for (const entry of entries) {
            const newWidth = Math.round(entry.contentRect.width);
            if (newWidth === _lastWidth) return;
            _lastWidth = newWidth;
            for (const id of chartLayout) {
                if (!id) continue;
                const c = document.getElementById(id);
                if (c) { const inst = Chart.getChart(c); if (inst) inst.resize(); }
            }
        }
    });
    const tabContainer = document.querySelector('.tab-container');
    if (tabContainer) ro.observe(tabContainer);
})();

// =====================
// CHART PALETTE RENDERER
// =====================
function renderChartPalette() {
    const palette = document.getElementById('chartPalette');
    if (!palette) return;

    const placedIds = new Set(chartLayout.filter(Boolean));
    const unplacedIds = Object.keys(CHART_REGISTRY).filter(id => !placedIds.has(id));

    // Hide palette if all charts are placed
    if (unplacedIds.length === 0) {
        palette.style.display = 'none';
        return;
    }

    palette.style.display = 'flex';
    palette.innerHTML = '';

    const canDragDropPalette = hasPermission('myCharts', 'drag and drop charts to dashboard');

    for (const chartId of unplacedIds) {
        const chip = document.createElement('div');
        chip.className = 'chart-chip';
        chip.textContent = CHART_REGISTRY[chartId].label;
        chip.draggable = canDragDropPalette;

        if (canDragDropPalette) {
            chip.addEventListener('dragstart', e => {
                draggedChartId = chartId;
                chip.classList.add('chart-chip--dragging');
                e.dataTransfer.effectAllowed = 'move';
            });
            chip.addEventListener('dragend', () => {
                draggedChartId = null;
                chip.classList.remove('chart-chip--dragging');
            });
        } else {
            chip.style.cursor = 'default';
            chip.style.opacity = '0.6';
        }

        palette.appendChild(chip);
    }
}

// =====================
// SAVE CHART LAYOUT
// =====================
async function saveChartLayout() {
    try {
        await fetch('/db/save-chart-layout', {
            method: 'POST',
            headers: csrfHeaders(),
            body: JSON.stringify({ layout: chartLayout })
        });
    } catch (e) {
        console.error('Failed to save chart layout:', e);
    }
}

// =====================
// LOAD CHART LAYOUT
// =====================
async function loadChartLayout() {
    try {
        const res = await fetch('/db/load-chart-layout');
        const data = await res.json();
        const raw = data.layout || [];
        // Validate IDs against registry
        chartLayout = raw.map(id => (id && CHART_REGISTRY[id]) ? id : null);
        // Default to 3 empty slots if nothing saved
        if (chartLayout.length === 0) chartLayout = [null, null, null];
    } catch (e) {
        console.error('Failed to load chart layout:', e);
        chartLayout = [null, null, null];
    }
    renderChartDashboard();
    renderChartPalette();
}

// =====================
// CHART CONFIGURATION
// =====================

// AGGREGATION METHOD SELECTOR
document.getElementById('aggMethodSelect').addEventListener('change', (e) => {
    chartAggMethod = e.target.value;
    renderAllPlacedCharts();
    updateChartPlaceholder();
    initPublishedDateSlider();
});

// RISK THRESHOLD SLIDER
document.getElementById('riskThresholdSlider').addEventListener('input', (e) => {
    chartRiskThreshold = parseFloat(e.target.value);
    document.getElementById('thresholdValue').textContent = chartRiskThreshold.toFixed(1);
    renderAllPlacedCharts();
    updateChartPlaceholder();
    initPublishedDateSlider();
});

// On slider release (change event), sync to server if admin
document.getElementById('riskThresholdSlider').addEventListener('change', (e) => {
    const newVal = parseFloat(e.target.value);
    if (hasMinRole('admin') && Math.abs(newVal - orgRiskThreshold) > 0.001) {
        const reason = prompt('Reason for threshold change (for audit trail):');
        if (reason !== null) {
            fetch('/admin/risk-tolerance', {
                method: 'POST',
                headers: csrfHeaders(),
                body: JSON.stringify({ risk_threshold: newVal, reason: reason })
            }).then(r => r.json()).then(data => {
                if (data.success) orgRiskThreshold = newVal;
            }).catch(() => {});
        } else {
            // User cancelled — revert slider
            e.target.value = orgRiskThreshold;
            chartRiskThreshold = orgRiskThreshold;
            document.getElementById('thresholdValue').textContent = orgRiskThreshold.toFixed(1);
            renderAllPlacedCharts();
            updateChartPlaceholder();
            initPublishedDateSlider();
        }
    }
});

// PUBLISHED DATE SLIDER
function initPublishedDateSlider() {
    const dates = [...new Set(
        Object.values(cveDataStore)
            .flatMap(d => d?.vulnerabilities || [])
            .map(v => (v.cve?.published || '').slice(0, 10))
            .filter(Boolean)
    )].sort();

    _publishedDateSliderDates = dates;

    const el = document.getElementById('publishedDateSlider');
    const minLabel = document.getElementById('publishedDateSliderMinLabel');
    const maxLabel = document.getElementById('publishedDateSliderMaxLabel');

    if (el.noUiSlider) el.noUiSlider.destroy();

    if (dates.length <= 1) {
        minLabel.textContent = dates[0] || '—';
        maxLabel.textContent = dates[0] || '—';
        return;
    }

    noUiSlider.create(el, {
        start: [0, dates.length - 1],
        connect: true,
        step: 1,
        range: { min: 0, max: dates.length - 1 }
    });

    el.noUiSlider.on('update', function (values) {
        const lo = Math.round(values[0]);
        const hi = Math.round(values[1]);
        minLabel.textContent = _publishedDateSliderDates[lo] || '—';
        maxLabel.textContent = _publishedDateSliderDates[hi] || '—';
        renderAllPlacedCharts();
        updateChartPlaceholder();
    });
}

function getPublishedDateRange() {
    const el = document.getElementById('publishedDateSlider');
    if (!el.noUiSlider || _publishedDateSliderDates.length === 0) return { from: null, to: null };
    const [lo, hi] = el.noUiSlider.get().map(v => Math.round(v));
    return {
        from: new Date(_publishedDateSliderDates[lo]),
        to:   new Date(_publishedDateSliderDates[hi] + 'T23:59:59')
    };
}

// =====================
// CHART 9: Backlog Aging Distribution (Horizontal Bar)
// =====================
async function renderBacklogAging() {
    const canvas = document.getElementById('backlogAgingChart');
    if (!canvas) return;

    try {
        const res = await fetch('/db/ticket-stats');
        const stats = await res.json();
        const buckets = stats.metrics?.aging_buckets;
        if (!buckets) { canvas.style.display = 'none'; return; }

        canvas.style.display = 'block';
        const existing = Chart.getChart(canvas);
        if (existing) existing.destroy();

        new Chart(canvas, {
            type: 'bar',
            data: {
                labels: ['0-7 days', '8-30 days', '31-90 days', '90+ days'],
                datasets: [{
                    label: 'Open Tickets',
                    data: [buckets['0-7d'], buckets['8-30d'], buckets['31-90d'], buckets['90d+']],
                    backgroundColor: ['#50b88e', '#d9af6f', '#e67e22', '#c01e19']
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                plugins: {
                    title: { display: true, text: 'Backlog Aging Distribution' },
                    legend: { display: false }
                },
                scales: {
                    x: { beginAtZero: true, title: { display: true, text: 'Ticket Count' } }
                }
            }
        });
    } catch (e) {
        console.error('Failed to render backlog aging chart:', e);
    }
}
