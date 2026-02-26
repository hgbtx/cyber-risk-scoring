// ==============================
// DRAG & DROP / ASSET SELECTION
// ==============================

// DRAG & DROP EVENT LISTENERS
dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'copy';
    dropZone.classList.add('drag-over');
});
dropZone.addEventListener('dragleave', (e) => {
    if (e.target === dropZone) {
        dropZone.classList.remove('drag-over');
    }
});
dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');

    const data = JSON.parse(e.dataTransfer.getData('text/plain'));
    stageItem(data);
});
searchInput.addEventListener('dragover', (e) => e.preventDefault());
searchInput.addEventListener('drop', (e) => e.preventDefault());

// STAGE ITEM — adds item visually to the drop zone without committing (no CVE fetch, no save)
function stageItem(data) {
    // Check if item already exists (staged or committed)
    const existingItems = selectedItems.querySelectorAll('.selected-item');
    for (let item of existingItems) {
        if (item.dataset.cpeName === data.cpeName) {
            return; // Already present
        }
    }

    if (placeholder) {
        placeholder.style.display = 'none';
    }

    const itemDiv = document.createElement('div');
    itemDiv.className = 'selected-item staged';
    itemDiv.dataset.cpeName = data.cpeName;
    itemDiv.dataset.title = data.title;
    itemDiv.innerHTML = `
        <button class="remove-btn"><small>X</small></button>
        <div>
            <strong>${escapeHtml(data.title)}</strong><br>
            <small>${escapeHtml(data.cpeName)}</small>
        </div>
    `;

    itemDiv.querySelector('.remove-btn').addEventListener('click', () => {
        itemDiv.remove();
        updateAddAssetsButton();
        if (selectedItems.querySelectorAll('.selected-item').length === 0) {
            placeholder.style.display = 'block';
        }
    });

    selectedItems.appendChild(itemDiv);
    updateAddAssetsButton();
}

// COMMIT STAGED ITEMS — processes all staged items (fetch CVEs, save to DB)
async function commitStagedItems() {
    const stagedItems = selectedItems.querySelectorAll('.selected-item.staged');
    if (stagedItems.length === 0) return;

    const btn = document.getElementById('addAssetsBtn');
    if (btn) {
        btn.disabled = true;
        btn.textContent = 'Adding...';
    }

    for (const itemDiv of stagedItems) {
        const cpeName = itemDiv.dataset.cpeName;
        const title = itemDiv.dataset.title;

        // Remove staged class to mark as committed
        itemDiv.classList.remove('staged');

        // Replace remove handler with full cleanup version
        const oldBtn = itemDiv.querySelector('.remove-btn');
        const newBtn = oldBtn.cloneNode(true);
        oldBtn.replaceWith(newBtn);
        newBtn.addEventListener('click', () => {
            itemDiv.remove();
            delete cveDataStore[cpeName];
            delete cpeDataStore[cpeName];
            updateCveCounter();
            renderCveList();
            renderEpssChart();
            renderCvssHistogram();
            initPublishedDateSlider();
            saveAssets();
            updateAddAssetsButton();
            if (selectedItems.querySelectorAll('.selected-item').length === 0) {
                placeholder.style.display = 'block';
            }
        });

        // Fetch CVEs for this CPE
        try {
            const response = await fetch('/api/fetch-cves', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ cpeUri: cpeName })
            });
            const data = await response.json();
            data.title = title;
            cveDataStore[cpeName] = data;
            updateCveCounter();
            renderCveList();
            renderEpssChart();
            renderCvssHistogram();
            initPublishedDateSlider();
        } catch (error) {
            console.error('Error fetching CVEs:', error);
        }
    }

    await saveAssets();

    if (btn) {
        btn.disabled = false;
    }
    updateAddAssetsButton();
}

// UPDATE ADD ASSETS BUTTON — show/hide based on staged count and permission
function updateAddAssetsButton() {
    const btn = document.getElementById('addAssetsBtn');
    if (!btn) return;
    const stagedCount = selectedItems.querySelectorAll('.selected-item.staged').length;
    const canAdd = hasPermission('Search', 'add assets to Asset Directory');
    if (stagedCount > 0 && canAdd) {
        btn.style.display = 'block';
        btn.textContent = `Add ${stagedCount} Asset${stagedCount !== 1 ? 's' : ''}`;
    } else {
        btn.style.display = 'none';
    }
}

// ADD ASSETS BUTTON LISTENER
document.getElementById('addAssetsBtn')?.addEventListener('click', commitStagedItems);