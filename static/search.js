// =====================
// SEARCH & PAGINATION
// =====================

// PERFORM SEARCH
async function performSearch() {
    const searchTerm = searchInput.value.trim();
    if (searchTerm) {
        searchButton.disabled = true;
        searchButton.textContent = 'Searching...';
        try {
            const response = await fetch('/api/search', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
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
        }
    }
}

// SEARCH EVENT LISTENERS
searchButton.addEventListener('click', performSearch);
searchInput.addEventListener('keypress', function(event) {
    if (event.key === 'Enter') {
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

    try {
        const response = await fetch('/api/search', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
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
    cpeSearchCache = {}; // Clear previous cache before repopulating

    // Cache CPE metadata from search results
    for (const r of results) {
        if (r.cpeName && r.cpeData) {
            cpeSearchCache[r.cpeName] = r.cpeData;
        }
    }

    renderPage();
    document.getElementById('clearResults').style.display = 'inline';
    
    document.getElementById('searchFilterPanel').style.display = 'block';
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
    const depUnique = new Set(allResults.map(r => String(r.cpeData?.deprecated ?? false)));
    const depEl = document.getElementById('filterDeprecated');
    depEl.disabled = depUnique.size <= 1;
    depEl.style.opacity = depUnique.size <= 1 ? '0.4' : '1';
    
    // Date fields
    const uniqueDates = new Set(allResults.map(r => r.cpeData?.created || ''));
    const dateSingle = uniqueDates.size <= 1;
    ['filterDateFrom', 'filterDateTo'].forEach(id => {
        const el = document.getElementById(id);
        el.disabled = dateSingle;
        el.style.opacity = dateSingle ? '0.4' : '1';
    });
    
    document.getElementById('searchFilterPanel').style.display = 'block';
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
        return;
    }
    
    const startIndex = (currentPage - 1) * resultsPerPage;
    const endIndex = startIndex + resultsPerPage;
    const pageResults = displayResults.slice(startIndex, endIndex);
    
    pageResults.forEach((result) => {
        const div = document.createElement('div');
        div.className = 'result-item';
        div.draggable = true;
        div.dataset.title = result.title;
        div.dataset.cpeName = result.cpeName;
        
        div.innerHTML = `
            <div>
                <strong>${escapeHtml(result.title)}</strong><br>
                <small>${escapeHtml(result.cpeName)}</small>
            </div>
        `;
        
        div.addEventListener('dragstart', handleDragStart);
        div.addEventListener('dragend', handleDragEnd);
        
        resultsList.appendChild(div);
    });
    
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

// DRAG HANDLERS
function handleDragStart(e) {
    e.currentTarget.classList.add('dragging');
    e.dataTransfer.effectAllowed = 'copy';
    e.dataTransfer.setData('text/plain', JSON.stringify({
        title: e.currentTarget.dataset.title,
        cpeName: e.currentTarget.dataset.cpeName
    }));
}
function handleDragEnd(e) {
    e.currentTarget.classList.remove('dragging');
}

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
    resultsList.innerHTML = '';
    resultsContainer.style.display = 'none';
    document.getElementById('searchFilterPanel').style.display = 'none';
    searchInput.value = '';
    cpeSearchCache = {}; // Clear search cache
    document.getElementById('searchFilterPanel').style.display = 'none';
});