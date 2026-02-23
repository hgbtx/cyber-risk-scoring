// =====================
// MANAGE ASSETS MODAL
// =====================

// MANAGE ASSETS BUTTON
document.getElementById('manageAssetsBtn').addEventListener('click', () => {
    renderManageAssetsList(false);
    document.getElementById('manageAssetsModal').style.display = 'flex';
});

// CLOSE MODAL
document.getElementById('closeManageAssets').addEventListener('click', () => {
    document.getElementById('manageAssetsModal').style.display = 'none';
});

// CLOSE WHEN CLICKING OUTSIDE CONTENT
document.getElementById('manageAssetsModal').addEventListener('click', (e) => {
    if (e.target === e.currentTarget) e.currentTarget.style.display = 'none';
});

// TOGGLE ARCHIVED ASSETS
document.getElementById('showArchivedToggle').addEventListener('click', function () {
    const showing = this.dataset.showing === 'true';
    this.dataset.showing = showing ? 'false' : 'true';
    this.textContent = showing ? 'Show Archived' : 'Hide Archived';
    renderManageAssetsList(!showing);
});

// RENDER ASSETS IN MANAGE MODAL
function renderManageAssetsList(showArchived) {
    const container = document.getElementById('manageAssetsList');
    container.innerHTML = '';

    const activeCpes = Object.keys(cveDataStore).filter(c => !archivedAssets.has(c));
    const archivedCpes = Object.keys(cveDataStore).filter(c => archivedAssets.has(c));
    const list = showArchived ? archivedCpes : activeCpes;

    if (!list.length) {
        container.innerHTML = `<p style="color:#999; font-style:italic;">${showArchived ? 'No archived assets.' : 'No active assets.'}</p>`;
        return;
    }

    for (const cpe of list) {
        const data = cveDataStore[cpe];
        const title = data?.title || cpe;
        const count = data?.count ?? 0;
        const isArchived = archivedAssets.has(cpe);

        const row = document.createElement('div');
        row.style.cssText = 'display:flex; justify-content:space-between; align-items:center; padding:8px 0; border-bottom:1px solid #eee;';
        row.innerHTML = `
            <div style="min-width:0; flex:1;">
                <strong style="font-size:0.9em;">${escapeHtml(title)}</strong><br>
                <small style="color:#888;">${escapeHtml(cpe)}</small>
                <small style="color:#666; margin-left:8px;">${count} CVEs</small>
            </div>
            <div style="display:flex; gap:6px; flex-shrink:0;">
                ${isArchived
                    ? `<button class="ma-restore-btn" data-cpe="${escapeHtml(cpe)}" style="padding:4px 10px; font-size:0.8em; background:#50b88e; color:white; border:none; border-radius:4px; cursor:pointer;">Restore</button>`
                    : `<button class="ma-archive-btn" data-cpe="${escapeHtml(cpe)}" style="padding:4px 10px; font-size:0.8em; background:#d9af6f; color:#57534E; border:none; border-radius:4px; cursor:pointer;">Archive</button>`
                }
                <button class="ma-delete-btn" data-cpe="${escapeHtml(cpe)}" style="padding:4px 10px; font-size:0.8em; background:#c01e19; color:white; border:none; border-radius:4px; cursor:pointer;">Delete</button>
            </div>
        `;
        container.appendChild(row);
    }

    // Event delegation
    container.querySelectorAll('.ma-archive-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            archivedAssets.add(btn.dataset.cpe);
            archivedAssets.add(btn.dataset.cpe);
            fetch('/db/archived-assets', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ cpeName: btn.dataset.cpe, isArchived: 1 })
            });
            refreshAfterManage();
            renderManageAssetsList(showArchived);
        });
    });
    container.querySelectorAll('.ma-restore-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            archivedAssets.delete(btn.dataset.cpe);
            fetch('/db/archived-assets', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ cpeName: btn.dataset.cpe, isArchived: 0 })
            });
            refreshAfterManage();
            renderManageAssetsList(showArchived);
        });
    });
    container.querySelectorAll('.ma-delete-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const cpe = btn.dataset.cpe;
            if (!confirm(`Delete "${cveDataStore[cpe]?.title || cpe}" and all its CVE data?`)) return;
            fetch('/db/delete-asset', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ cpeName: cpe })
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    const item = selectedItems.querySelector(`.selected-item[data-cpe-name="${cpe}"]`);
                    if (item) item.remove();
                    delete cveDataStore[cpe];
                    delete cpeDataStore[cpe];
                    archivedAssets.delete(cpe);
                    refreshAfterManage();
                    renderManageAssetsList(showArchived);
                    if (!selectedItems.querySelectorAll('.selected-item').length && placeholder) {
                        placeholder.style.display = 'block';
                    }
                } else {
                    alert(data.error || 'Failed to delete asset');
                }
            })
            .catch(e => console.error('Delete asset error:', e));
        });
    });
}

// REFRESH DEPENDENCIES
function refreshAfterManage() {
    updateCveCounter();
    renderCveGrid();
    renderEpssChart();
    renderCvssHistogram();
    initPublishedDateSlider();
}