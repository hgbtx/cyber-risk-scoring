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

        // Collapse right panel and reset contents when switching tabs
        const rightPanel = document.querySelector('.right-panel-container');
        const toggleBtn = document.getElementById('toggleRightPanel');
        if (!rightPanel.classList.contains('collapsed')) {
            rightPanel.classList.add('collapsed');
            toggleBtn.innerHTML = '&#9664;';
        }
        // Hide toggle button and panel since there's nothing to display
        toggleBtn.style.display = 'none';
        rightPanel.style.display = 'none';
        // Reset right panel contents
        const cveContainer = document.getElementById('cveContainer');
        const expandedViewContainer = document.getElementById('expandedViewContainer');
        if (cveContainer) cveContainer.style.display = 'none';
        if (expandedViewContainer) expandedViewContainer.style.display = 'none';
        if (typeof updateChartFullscreenBtn === 'function') updateChartFullscreenBtn();

        button.classList.add('active');
        sessionStorage.setItem('activeTab', button.dataset.tab);

        document.getElementById('chartConfig').style.display = button.dataset.tab === 'charts' ? 'flex' : 'none';

        // Show/hide filter panel based on active tab
        const filterBtn = document.getElementById('openSearchFilterModal');
        filterBtn.style.display = (button.dataset.tab === 'search' && allResults.length > 0) ? 'inline-block' : 'none';

        // Show left panel only on Charts tab
        leftPanel.style.display = button.dataset.tab === 'charts' ? '' : 'none';

        const targetPanel = document.querySelector(`.tab-panel[data-panel="${button.dataset.tab}"]`);
        if (targetPanel) targetPanel.classList.add('active');

        if (button.dataset.tab === 'charts') {
            setTimeout(() => {
                if (!chartLayout.length) {
                    loadChartLayout();
                } else {
                    renderChartDashboard();
                    renderChartPalette();
                }
                for (const id of chartLayout) {
                    if (!id) continue;
                    const c = document.getElementById(id);
                    if (c) { const inst = Chart.getChart(c); if (inst) inst.resize(); }
                }
            }, 50);
        }
    });
});