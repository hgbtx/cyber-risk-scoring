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