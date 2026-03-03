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
    const canArchive = hasPermission('Asset Directory', 'archive assets');
    const canDeleteAsset = hasPermission('Asset Directory', 'delete assets');

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

        const crit = assetCriticality[cpe] ?? 3;
        const critLabel = CRITICALITY_LABELS[crit] || 'Medium';
        const critColor = CRITICALITY_COLORS[crit] || '#d9af6f';
        const tags = assetTags[cpe] || [];

        const row = document.createElement('div');
        row.style.cssText = 'display:flex; justify-content:space-between; align-items:center; padding:8px 0; border-bottom:1px solid #eee;';
        row.innerHTML = `
            <div style="min-width:0; flex:1;">
                <strong style="font-size:0.9em;">${escapeHtml(title)}</strong>
                <span style="background:${critColor}22; color:${critColor}; padding:1px 6px; border-radius:3px; font-size:0.75em; margin-left:6px; font-weight:600;">${critLabel}</span>
                <br>
                <small style="color:#888;">${escapeHtml(cpe)}</small>
                <small style="color:#666; margin-left:8px;">${count} CVEs</small>
                ${tags.length ? `<div style="margin-top:3px;">${tags.map(t => `<span style="background:#f0f0f0; padding:1px 5px; border-radius:2px; font-size:0.72em; margin-right:3px;">${escapeHtml(t)}</span>`).join('')}</div>` : ''}
            </div>
            <div style="display:flex; gap:6px; flex-shrink:0; align-items:center;">
                <select class="ma-crit-select" data-cpe="${escapeHtml(cpe)}" style="padding:2px 4px; font-size:0.78em; border:1px solid #ccc; border-radius:3px;">
                    ${[1,2,3,4,5].map(v => `<option value="${v}" ${v === crit ? 'selected' : ''}>${CRITICALITY_LABELS[v]}</option>`).join('')}
                </select>
                <button class="ma-tags-btn" data-cpe="${escapeHtml(cpe)}" style="padding:4px 8px; font-size:0.78em; background:#f5f5f5; border:1px solid #ccc; border-radius:4px; cursor:pointer;" title="Edit tags"><i class="fa-solid fa-tags"></i></button>
                ${canArchive ? (isArchived
                    ? `<button class="ma-restore-btn" data-cpe="${escapeHtml(cpe)}" style="padding:4px 10px; font-size:0.8em; background:#50b88e; color:white; border:none; border-radius:4px; cursor:pointer;">Restore</button>`
                    : `<button class="ma-archive-btn" data-cpe="${escapeHtml(cpe)}" style="padding:4px 10px; font-size:0.8em; background:#d9af6f; color:#57534E; border:none; border-radius:4px; cursor:pointer;">Archive</button>`
                ) : ''}
                ${canDeleteAsset ? `<button class="ma-delete-btn" data-cpe="${escapeHtml(cpe)}" style="padding:4px 10px; font-size:0.8em; background:#c01e19; color:white; border:none; border-radius:4px; cursor:pointer;">Delete</button>` : ''}
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
                headers: csrfHeaders(),
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
                headers: csrfHeaders(),
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
            fetch('/db/deleted-assets', {
                method: 'POST',
                headers: csrfHeaders(),
                body: JSON.stringify({ cpeName: cpe })
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    delete cveDataStore[cpe];
                    delete cpeDataStore[cpe];
                    archivedAssets.delete(cpe);
                    delete assetCriticality[cpe];
                    delete assetTags[cpe];
                    refreshAfterManage();
                    renderManageAssetsList(showArchived);
                } else {
                    alert(data.error || 'Failed to delete asset');
                }
            })
            .catch(e => console.error('Delete asset error:', e));
        });
    });

    // Criticality change
    container.querySelectorAll('.ma-crit-select').forEach(sel => {
        sel.addEventListener('change', async () => {
            const cpe = sel.dataset.cpe;
            const newCrit = parseInt(sel.value);
            assetCriticality[cpe] = newCrit;
            await fetch('/db/update-asset-properties', {
                method: 'POST',
                headers: csrfHeaders(),
                body: JSON.stringify({ cpeName: cpe, criticality: newCrit })
            });
            refreshAfterManage();
            renderManageAssetsList(showArchived);
        });
    });

    // Tags edit
    container.querySelectorAll('.ma-tags-btn').forEach(btn => {
        btn.addEventListener('click', async () => {
            const cpe = btn.dataset.cpe;
            const current = (assetTags[cpe] || []).join(', ');
            const input = prompt('Tags (comma-separated):', current);
            if (input === null) return;
            const newTags = input.split(',').map(t => t.trim()).filter(Boolean);
            assetTags[cpe] = newTags;
            await fetch('/db/update-asset-properties', {
                method: 'POST',
                headers: csrfHeaders(),
                body: JSON.stringify({ cpeName: cpe, tags: newTags })
            });
            renderManageAssetsList(showArchived);
            refreshAfterManage();
        });
    });
}

// REFRESH DEPENDENCIES
function refreshAfterManage() {
    updateCveCounter();
    renderCveGrid();
    renderAllPlacedCharts();
    updateChartPlaceholder();
    initPublishedDateSlider();
}