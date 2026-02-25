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

        document.getElementById('chartConfig').style.display = button.dataset.tab === 'charts' ? 'flex' : 'none';
        
        // Show/hide filter panel based on active tab
        const filterBtn = document.getElementById('openSearchFilterModal');
        filterBtn.style.display = (button.dataset.tab === 'search' && allResults.length > 0) ? 'inline-block' : 'none';
        // Show/hide Assets drop zone, CVE counter, and left panel based on active tab + permissions
        const dropZoneEl = document.getElementById('dropZone');
        const cveCountsContainer = document.querySelector('.cveCounts-container');
        const isSearch = button.dataset.tab === 'search';
        const isCharts = button.dataset.tab === 'charts';
        const hasDragPerm = hasPermission('Search', 'drag and drop to Assets folder');

        dropZoneEl.style.display = (isSearch && hasDragPerm) ? 'block' : 'none';
        cveCountsContainer.style.display = (isSearch && hasDragPerm) ? 'block' : 'none';

        if (isSearch) {
            leftPanel.style.display = hasDragPerm ? '' : 'none';
        } else if (isCharts) {
            leftPanel.style.display = '';
        } else {
            leftPanel.style.display = 'none';
        }

        const targetPanel = document.querySelector(`.tab-panel[data-panel="${button.dataset.tab}"]`);
        if (targetPanel) targetPanel.classList.add('active');

        if (button.dataset.tab === 'charts' && epssChartInstance) {
            setTimeout(() => epssChartInstance.resize(), 50);
        }
    });
});