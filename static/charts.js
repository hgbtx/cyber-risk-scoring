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