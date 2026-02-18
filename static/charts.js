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
        if (archivedAssets.has(cpe)) continue;
        const data = cveDataStore[cpe];
        if (!data?.vulnerabilities) continue;
        
        for (const vuln of data.vulnerabilities) {
            const c = vuln.cve || {};
            const published = c.published;
            const epss = vuln.epssScore;
            
            if (published && typeof epss === 'number' && epss > 0) {
                const { from, to } = getPublishedDateRange();
                const pubDate = new Date(published);
                if (from && pubDate < from) continue;
                if (to   && pubDate > to)   continue;
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
                legend: { display: false }
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

// RENDER CVSS HISTOGRAM
function renderCvssHistogram() {
    const canvas = document.getElementById('cvssHistogramChart');
    const buckets = Array(10).fill(0); // 0-1, 1-2, ... 9-10

    for (const cpe in cveDataStore) {
        if (archivedAssets.has(cpe)) continue;
        const data = cveDataStore[cpe];
        if (!data?.vulnerabilities) continue;
        for (const vuln of data.vulnerabilities) {
            
            const published = vuln.cve?.published;
            const { from, to } = getPublishedDateRange();
            if (published) {
                const pubDate = new Date(published);
                if (from && pubDate < from) continue;
                if (to   && pubDate > to)   continue;
            }            
            const cvss31 = vuln.cve?.metrics?.cvssMetricV31?.[0]?.cvssData;
            const cvss2 = vuln.cve?.metrics?.cvssMetricV2?.[0]?.cvssData;
            const score = cvss31?.baseScore ?? cvss2?.baseScore ?? null;
            if (score !== null) {
                const idx = Math.min(Math.floor(score), 9);
                buckets[idx]++;
            }
        }
    }

    if (buckets.every(b => b === 0)) {
        canvas.style.display = 'none';
        if (cvssHistogramInstance) { cvssHistogramInstance.destroy(); cvssHistogramInstance = null; }
        return;
    }

    canvas.style.display = 'block';
    if (cvssHistogramInstance) cvssHistogramInstance.destroy();

    const labels = ['0–1', '1–2', '2–3', '3–4', '4–5', '5–6', '6–7', '7–8', '8–9', '9–10'];

    cvssHistogramInstance = new Chart(canvas, {
        type: 'bar',
        data: {
            labels,
            datasets: [{
                label: 'CVE Count',
                data: buckets,
                backgroundColor: buckets.map((_, i) => {
                    const mid = i + 0.5;
                    if (mid >= 9) return '#7b1fa2';
                    if (mid >= 7) return '#c01e19';
                    if (mid >= 4) return '#e67e22';
                    return '#50b88e';
                }),
            }]
        },
        options: {
            responsive: true,
            scales: {
                x: { title: { display: true, text: 'CVSS Base Score' } },
                y: { beginAtZero: true, title: { display: true, text: 'Count' }, ticks: { stepSize: 1 } }
            },
            plugins: {
                legend: { display: false },
                annotation: {
                    annotations: {
                        thresholdLine: {
                            type: 'line',
                            xMin: chartRiskThreshold,
                            xMax: chartRiskThreshold,
                            borderColor: '#c01e19',
                            borderWidth: 2,
                            borderDash: [6, 4],
                            label: {
                                display: true,
                                content: `Threshold: ${chartRiskThreshold}`,
                                position: 'start',
                                backgroundColor: '#c01e19',
                                color: 'white',
                                font: { size: 11 }
                            }
                        }
                    }
                }
            }
        }
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

// RISK FORMULA SELECTOR
document.getElementById('riskFormulaSelect').addEventListener('change', (e) => {
    chartRiskFormula = e.target.value;
    renderEpssChart();
    renderCvssHistogram();
    initPublishedDateSlider();

});

// AGGREGATION METHOD SELECTOR
document.getElementById('aggMethodSelect').addEventListener('change', (e) => {
    chartAggMethod = e.target.value;
    renderEpssChart();
    renderCvssHistogram();
    initPublishedDateSlider();
});

// RISK THRESHOLD SLIDER
document.getElementById('riskThresholdSlider').addEventListener('input', (e) => {
    chartRiskThreshold = parseFloat(e.target.value);
    document.getElementById('thresholdValue').textContent = chartRiskThreshold.toFixed(1);
    renderEpssChart();
    renderCvssHistogram();
    initPublishedDateSlider();
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
        renderEpssChart();
        renderCvssHistogram();
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