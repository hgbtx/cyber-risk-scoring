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
        // Show/hide filter button based on active tab
        const filterBtn = document.getElementById('openSearchFilterModal');
        filterBtn.style.display = (button.dataset.tab === 'search' && allResults.length > 0) ? 'inline-block' : 'none';
        // Show/hide Assets drop zone and CVE counter based on active tab
        const dropZone = document.getElementById('dropZone');
        const cveCountsContainer = document.querySelector('.cveCounts-container');
        const isSearch = button.dataset.tab === 'search';
        dropZone.style.display = isSearch ? 'block' : 'none';
        cveCountsContainer.style.display = isSearch ? 'block' : 'none';

        const targetPanel = document.querySelector(`.tab-panel[data-panel="${button.dataset.tab}"]`);
        if (targetPanel) targetPanel.classList.add('active');

        if (button.dataset.tab === 'charts' && epssChartInstance) {
            setTimeout(() => epssChartInstance.resize(), 50);
        }
    });
});