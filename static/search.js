// =====================
// SEARCH & PAGINATION
// =====================

// PERFORM SEARCH
async function performSearch() {
    if (!hasPermission('Search', 'perform searches')) return;
    const searchTerm = searchInput.value.trim();
    if (searchTerm) {
        searchButton.disabled = true;
        searchButton.textContent = 'Searching...';
        document.getElementById('searchingContainer').style.display = 'block';
        document.getElementById('resultsContainer').style.display = 'none';
        try {
            const response = await fetch('/api/search', {
                method: 'POST',
                headers: csrfHeaders(),
                body: JSON.stringify({ searchTerm: searchTerm })
            });

            const results = await response.json();
            displayResults(results);

        } catch (error) {
            console.error('Error:', error);
            alert('Search failed. Please try again.');
        } finally {
            searchButton.disabled = false;
            searchButton.textContent = 'Search';
            document.getElementById('searchingContainer').style.display = 'none';
        }
    }
}

// SEARCH EVENT LISTENERS
searchButton.addEventListener('click', performSearch);
searchInput.addEventListener('keypress', function(event) {
    if (event.key === 'Enter' && hasPermission('Search', 'perform searches')) {
        performSearch();
    }
});

// ADVANCED SEARCH TOGGLE
document.getElementById('toggleAdvancedSearch').addEventListener('click', (e) => {
    e.preventDefault();
    document.getElementById('simpleSearch').style.display = 'none';
    document.getElementById('advancedSearch').style.display = 'block';
});

document.getElementById('toggleSimpleSearch').addEventListener('click', (e) => {
    e.preventDefault();
    document.getElementById('advancedSearch').style.display = 'none';
    document.getElementById('simpleSearch').style.display = 'block';
});

// ADVANCED SEARCH
async function performAdvancedSearch() {
    if (!hasPermission('Search', 'perform searches')) return;
    const fields = {
        part: document.getElementById('advPart').value,
        vendor: document.getElementById('advVendor').value.trim(),
        product: document.getElementById('advProduct').value.trim(),
        version: document.getElementById('advVersion').value.trim(),
        update: document.getElementById('advUpdate').value.trim(),
        edition: document.getElementById('advEdition').value.trim(),
        language: document.getElementById('advLanguage').value.trim(),
        sw_edition: document.getElementById('advSwEdition').value.trim(),
        target_sw: document.getElementById('advTargetSw').value.trim(),
        target_hw: document.getElementById('advTargetHw').value.trim(),
        other: document.getElementById('advOther').value.trim(),
    };

    // Build CPE 2.3 match string: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
    const components = [
        fields.part || '*',
        fields.vendor || '*',
        fields.product || '*',
        fields.version || '*',
        fields.update || '*',
        fields.edition || '*',
        fields.language || '*',
        fields.sw_edition || '*',
        fields.target_sw || '*',
        fields.target_hw || '*',
        fields.other || '*',
    ];

    // Don't search if everything is wildcard
    if (components.every(c => c === '*')) {
        alert('Please fill in at least one field.');
        return;
    }

    const cpeMatchString = 'cpe:2.3:' + components.join(':');

    const btn = document.getElementById('advSearchButton');
    btn.disabled = true;
    btn.textContent = 'Searching...';
    document.getElementById('searchingContainer').style.display = 'block';
    document.getElementById('resultsContainer').style.display = 'none';

    try {
        const response = await fetch('/api/search', {
            method: 'POST',
            headers: csrfHeaders(),
            body: JSON.stringify({ cpeMatchString })
        });
        const results = await response.json();
        displayResults(results);
    } catch (error) {
        console.error('Error:', error);
        alert('Search failed. Please try again.');
    } finally {
        btn.disabled = false;
        btn.textContent = 'Search';
        document.getElementById('searchingContainer').style.display = 'none';
    }
}

document.getElementById('advSearchButton').addEventListener('click', performAdvancedSearch);

function parseCpeParts(cpeName) {
    const parts = cpeName.split(':');
    return {
        part: parts[2] || '*',
        vendor: parts[3] || '*',
        product: parts[4] || '*',
        version: parts[5] || '*',
        update: parts[6] || '*',
        edition: parts[7] || '*',
        language: parts[8] || '*',
        sw_edition: parts[9] || '*',
        target_sw: parts[10] || '*',
        target_hw: parts[11] || '*',
    };
}

// DISPLAY RESULTS
function displayResults(results) {
    allResults = results;
    currentPage = 1;
    document.getElementById('clearFilters').click();

    // Populate cpeDataStore from search results (backed by cpe_cache in DB)
    for (const r of results) {
        if (r.cpeName && r.cpeData) {
            cpeDataStore[r.cpeName] = r.cpeData;
        }
    }

    renderPage();
    document.getElementById('clearResults').style.display = 'inline';

    document.getElementById('openSearchFilterModal').style.display = 'inline-block';
    document.getElementById('clearFilters').click();

    // Convert filter fields to dropdowns when multiple values exist
    const dropdownFields = {
        filterVendor: r => parseCpeParts(r.cpeName).vendor,
        filterProduct: r => parseCpeParts(r.cpeName).product,
        filterVersion: r => parseCpeParts(r.cpeName).version,
        filterUpdate: r => parseCpeParts(r.cpeName).update,
        filterEdition: r => parseCpeParts(r.cpeName).edition,
        filterLanguage: r => parseCpeParts(r.cpeName).language,
        filterSwEdition: r => parseCpeParts(r.cpeName).sw_edition,
        filterTargetSw: r => parseCpeParts(r.cpeName).target_sw,
        filterTargetHw: r => parseCpeParts(r.cpeName).target_hw,
    };

    for (const [id, extractor] of Object.entries(dropdownFields)) {
        const unique = [...new Set(allResults.map(extractor))].filter(v => v && v !== '*').sort();
        const parent = document.getElementById(id).parentElement;
        const label = parent.querySelector('label');
        const old = document.getElementById(id);
        const single = unique.length <= 1;

        const el = document.createElement(single ? 'input' : 'select');
        el.id = id;
        if (single) {
            el.type = 'text';
            el.disabled = true;
            el.style.opacity = '0.4';
            el.placeholder = unique[0] || '';
        } else {
            el.innerHTML = '<option value="">Any</option>' +
                unique.map(v => `<option value="${escapeHtml(v)}">${escapeHtml(v)}</option>`).join('');
        }
        old.replaceWith(el);
    }

    // Deprecated field

    // Create a Set of unique deprecated values (converted to strings) from all search results
    const depUnique = new Set(allResults.map(r => String(r.cpeData?.deprecated ?? false)));
    // Get reference to the deprecated filter dropdown element
    const depEl = document.getElementById('filterDeprecated');
    // Disable the filter if only 1 unique deprecated value exists (filtering would have no effect)
    depEl.disabled = depUnique.size <= 1;
    // Reduce opacity to 0.4 if disabled, otherwise 1.0 to visually indicate disabled state
    depEl.style.opacity = depUnique.size <= 1 ? '0.4' : '1';

    initDateSlider(results);

    document.getElementById('openSearchFilterModal').style.display = 'inline-block';
    updateFilterFieldStates();
}

// RENDER PAGE
function renderPage() {
    resultsList.innerHTML = '';
    const displayResults = window._filteredResults || allResults;

    if (displayResults.length === 0) {
        resultsList.innerHTML = '<p>No results found.</p>';
        resultsContainer.style.display = 'block';
        pagination.style.display = 'none';
        document.getElementById('searchBulkBar').style.display = 'none';
        return;
    }

    const canAdd = hasPermission('Search', 'add assets to Asset Directory');

    // Show bulk bar only if user can add assets
    const bulkBar = document.getElementById('searchBulkBar');
    bulkBar.style.display = canAdd ? 'flex' : 'none';

    const startIndex = (currentPage - 1) * resultsPerPage;
    const endIndex = startIndex + resultsPerPage;
    const pageResults = displayResults.slice(startIndex, endIndex);

    pageResults.forEach((result) => {
        const isAdded = !!cveDataStore[result.cpeName];
        const isChecked = checkedSearchItems.has(result.cpeName);

        const div = document.createElement('div');
        div.className = 'result-item' + (isAdded ? ' result-item--added' : '');
        div.dataset.cpeName = result.cpeName;

        let checkboxHtml = '';
        let addBtnHtml = '';

        if (canAdd) {
            checkboxHtml = `
                <input type="checkbox"
                    class="result-checkbox"
                    data-cpe-name="${escapeHtml(result.cpeName)}"
                    ${isChecked ? 'checked' : ''}
                    ${isAdded ? 'disabled' : ''}>
            `;
            if (isAdded) {
                addBtnHtml = `<button class="result-add-btn result-add-btn--done" title="Already added" disabled>&#10003;</button>`;
            } else {
                addBtnHtml = `<button class="result-add-btn" data-cpe-name="${escapeHtml(result.cpeName)}" title="Add to directory">＋</button>`;
            }
        }

        div.innerHTML = `
            <div class="result-item-row">
                ${checkboxHtml}
                ${addBtnHtml}
                <div class="result-item-text">
                    <strong>${escapeHtml(result.title)}</strong><br>
                    <small>${escapeHtml(result.cpeName)}</small>
                </div>
            </div>
        `;

        if (canAdd && !isAdded) {
            const checkbox = div.querySelector('.result-checkbox');
            checkbox.addEventListener('change', () => {
                if (checkbox.checked) {
                    checkedSearchItems.add(result.cpeName);
                } else {
                    checkedSearchItems.delete(result.cpeName);
                }
                updateBulkAddButton();
                updateSelectAllCheckbox();
            });

            const addBtn = div.querySelector('.result-add-btn');
            addBtn.addEventListener('click', () => addSingleAsset(result.cpeName, result.title));
        }

        resultsList.appendChild(div);
    });

    updateSelectAllCheckbox();
    updateBulkAddButton();

    resultsContainer.style.display = 'block';

    // Update pagination
    const totalPages = Math.ceil(displayResults.length / resultsPerPage);
    document.getElementById('pageInput').value = currentPage;
    document.getElementById('pageInput').max = totalPages;
    document.getElementById('totalPages').textContent = totalPages;
    document.getElementById('prevPage').disabled = currentPage === 1;
    document.getElementById('nextPage').disabled = currentPage === totalPages;
    pagination.style.display = totalPages > 1 ? 'block' : 'none';
}

// ADD SINGLE ASSET — fetch CVEs and save immediately
async function addSingleAsset(cpeName, title) {
    const row = resultsList.querySelector(`.result-item[data-cpe-name="${CSS.escape(cpeName)}"]`);
    const addBtn = row ? row.querySelector('.result-add-btn') : null;

    // Lock the entire row during fetch
    if (row) row.style.pointerEvents = 'none';
    if (addBtn) {
        addBtn.classList.add('result-add-btn--loading');
        addBtn.disabled = true;
    }

    let fetchSucceeded = false;

    try {
        const response = await fetch('/api/fetch-cves', {
            method: 'POST',
            headers: csrfHeaders(),
            body: JSON.stringify({ cpeUri: cpeName })
        });
        const data = await response.json();

        // Store title directly on the data object so saveAssets() can read it
        data.title = title || cpeName;
        cveDataStore[cpeName] = data;
        fetchSucceeded = true;
    } catch (error) {
        console.error('Error fetching CVEs:', error);
    }

    // Always attempt to save if we got data — in a separate try so render errors can't block it
    if (fetchSucceeded) {
        try { await saveAssets(); } catch (e) { console.error('saveAssets error:', e); }

        try {
            updateCveCounter();
            renderCveList();
            initPublishedDateSlider();
        } catch (e) { console.error('Render error after asset add:', e); }
    }

    // Update row to reflect final state
    if (row) row.style.pointerEvents = '';
    if (fetchSucceeded) {
        if (row) row.classList.add('result-item--added');
        if (addBtn) {
            addBtn.textContent = '✓';
            addBtn.classList.remove('result-add-btn--loading');
            addBtn.classList.add('result-add-btn--done');
            addBtn.title = 'Already added';
        }
        const checkbox = row ? row.querySelector('.result-checkbox') : null;
        if (checkbox) {
            checkbox.disabled = true;
            checkbox.checked = false;
            checkedSearchItems.delete(cpeName);
        }
    } else {
        if (addBtn) {
            addBtn.disabled = false;
            addBtn.textContent = '＋';
            addBtn.classList.remove('result-add-btn--loading');
        }
    }

    updateBulkAddButton();
    updateSelectAllCheckbox();
}

// BULK ADD ASSETS — process all checked items sequentially
async function bulkAddAssets() {
    const toAdd = [...checkedSearchItems].filter(cpeName => !cveDataStore[cpeName]);
    if (!toAdd.length) return;

    const bulkBtn = document.getElementById('bulkAddToDirectory');
    if (bulkBtn) {
        bulkBtn.disabled = true;
        bulkBtn.textContent = 'Adding...';
    }

    const displayResults = window._filteredResults || allResults;

    for (const cpeName of toAdd) {
        const resultEntry = displayResults.find(r => r.cpeName === cpeName);
        const title = resultEntry ? resultEntry.title : cpeName;
        await addSingleAsset(cpeName, title);
        // Small delay between requests to respect NVD rate limiting
        await new Promise(resolve => setTimeout(resolve, 100));
    }

    if (bulkBtn) {
        bulkBtn.disabled = false;
        updateBulkAddButton();
    }
}

// UPDATE BULK ADD BUTTON — show/hide with count
function updateBulkAddButton() {
    const bulkBtn = document.getElementById('bulkAddToDirectory');
    if (!bulkBtn) return;
    // Only count items that aren't already added
    const pendingCount = [...checkedSearchItems].filter(cpeName => !cveDataStore[cpeName]).length;
    if (pendingCount > 0) {
        bulkBtn.style.display = 'inline-block';
        bulkBtn.textContent = `+ Add ${pendingCount} to Directory`;
    } else {
        bulkBtn.style.display = 'none';
    }
}

// UPDATE SELECT ALL CHECKBOX — syncs indeterminate/checked state
function updateSelectAllCheckbox() {
    const selectAll = document.getElementById('selectAllResults');
    if (!selectAll) return;

    const displayResults = window._filteredResults || allResults;
    const startIndex = (currentPage - 1) * resultsPerPage;
    const endIndex = startIndex + resultsPerPage;
    const pageResults = displayResults.slice(startIndex, endIndex);

    // Only consider items not already in the directory
    const eligible = pageResults.filter(r => !cveDataStore[r.cpeName]);
    const checkedOnPage = eligible.filter(r => checkedSearchItems.has(r.cpeName));

    if (eligible.length === 0) {
        selectAll.checked = false;
        selectAll.indeterminate = false;
        selectAll.disabled = true;
    } else if (checkedOnPage.length === 0) {
        selectAll.checked = false;
        selectAll.indeterminate = false;
        selectAll.disabled = false;
    } else if (checkedOnPage.length === eligible.length) {
        selectAll.checked = true;
        selectAll.indeterminate = false;
        selectAll.disabled = false;
    } else {
        selectAll.checked = false;
        selectAll.indeterminate = true;
        selectAll.disabled = false;
    }
}

// SELECT ALL LISTENER
document.getElementById('selectAllResults')?.addEventListener('change', (e) => {
    const displayResults = window._filteredResults || allResults;
    const startIndex = (currentPage - 1) * resultsPerPage;
    const endIndex = startIndex + resultsPerPage;
    const pageResults = displayResults.slice(startIndex, endIndex);

    pageResults.forEach(r => {
        if (cveDataStore[r.cpeName]) return; // skip already-added
        if (e.target.checked) {
            checkedSearchItems.add(r.cpeName);
        } else {
            checkedSearchItems.delete(r.cpeName);
        }
        const checkbox = resultsList.querySelector(`.result-checkbox[data-cpe-name="${CSS.escape(r.cpeName)}"]`);
        if (checkbox) checkbox.checked = e.target.checked;
    });

    updateBulkAddButton();
});

// BULK ADD BUTTON LISTENER
document.getElementById('bulkAddToDirectory')?.addEventListener('click', bulkAddAssets);

// PAGINATION LISTENERS
document.getElementById('prevPage').addEventListener('click', () => {
    if (currentPage > 1) {
        currentPage--;
        renderPage();
    }
});
document.getElementById('nextPage').addEventListener('click', () => {
    const totalPages = Math.ceil(allResults.length / resultsPerPage);
    if (currentPage < totalPages) {
        currentPage++;
        renderPage();
    }
});
document.getElementById('pageInput').addEventListener('change', (e) => {
    const totalPages = Math.ceil(allResults.length / resultsPerPage);
    let newPage = parseInt(e.target.value);

    if (isNaN(newPage) || newPage < 1) {
        newPage = 1;
    } else if (newPage > totalPages) {
        newPage = totalPages;
    }

    currentPage = newPage;
    renderPage();
});

// CLEAR RESULTS LISTENER
document.getElementById('clearResults').addEventListener('click', (e) => {
    e.preventDefault();
    allResults = [];
    currentPage = 1;
    checkedSearchItems.clear();
    resultsList.innerHTML = '';
    resultsContainer.style.display = 'none';
    document.getElementById('searchBulkBar').style.display = 'none';
    document.getElementById('openSearchFilterModal').style.display = 'none';
    document.getElementById('searchFilterModal').style.display = 'none';
    searchInput.value = '';
    document.getElementById('openSearchFilterModal').style.display = 'none';
    document.getElementById('searchFilterModal').style.display = 'none';
});
