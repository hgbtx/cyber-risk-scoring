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
    addSelectedItem(data);
});
searchInput.addEventListener('dragover', (e) => e.preventDefault());
searchInput.addEventListener('drop', (e) => e.preventDefault());

// ASSET SELECTION
function addSelectedItem(data) {
    const itemTitle = data.title;
    const itemCpeName = data.cpeName;

    // Check if item already exists
    const existingItems = selectedItems.querySelectorAll('.selected-item');
    for (let item of existingItems) {
        if (item.dataset.cpeName === data.cpeName) {
            return; // Item already added
        }
    }

    // Hide placeholder when first item is added
    if (placeholder) {
        placeholder.style.display = 'none';
    }

    const itemDiv = document.createElement('div');
    itemDiv.className = 'selected-item';
    itemDiv.dataset.cpeName = data.cpeName;
    itemDiv.innerHTML = `
        <button class="remove-btn"><small>X</small></button>
        <div>
            <strong>${escapeHtml(data.title)}</strong><br>
            <small>${escapeHtml(data.cpeName)}</small>
        </div>
    `;
    
    itemDiv.querySelector('.remove-btn').addEventListener('click', () => {
        itemDiv.remove();
        delete cveDataStore[itemCpeName]; // Remove CVE data for this CPE
        delete cpeDataStore[itemCpeName]; // Clean up CPE data
        updateCveCounter(); // Update counter after removing
        renderCveList();
        renderEpssChart();
        renderCvssHistogram();
        saveAssets(); // Persist the updated assets after removal
        // Show placeholder again if no items left
        if (selectedItems.querySelectorAll('.selected-item').length === 0) {
            placeholder.style.display = 'block';
        }
    });
    
    selectedItems.appendChild(itemDiv);

    // Fetch CVEs for this CPE in the background
    fetch('/api/fetch-cves', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ cpeUri: itemCpeName })
    })
    .then(response => response.json())
    .then(data => {
        console.log('CVE data received:', data); // Check the structure
        data.title = itemTitle;
        cveDataStore[itemCpeName] = data; // Store the CVE data
        updateCveCounter(); // Update counter after adding
        renderCveList();
        renderEpssChart();
        renderCvssHistogram();
        saveAssets(); // Persist the updated assets with CVE data
    })
    .catch(error => console.error('Error fetching CVEs:', error));
}