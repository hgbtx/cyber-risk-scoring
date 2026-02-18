// ======================
// SEARCH RESULT FILTERS
// ======================

// CPE PARSER
function parseCpeParts(cpeName) {
    // cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
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

// =====================
// DATE SLIDER STATE
// =====================

// INIT DATE SLIDER
function initDateSlider(results) {
    const dates = [...new Set(results.map(r => (r.cpeData?.created || '').slice(0, 10)).filter(Boolean))].sort();
    _dateSliderDates = dates;
    const el = document.getElementById('dateSlider');
    const minLabel = document.getElementById('dateSliderMinLabel');
    const maxLabel = document.getElementById('dateSliderMaxLabel');

    if (el.noUiSlider) el.noUiSlider.destroy();

    if (dates.length <= 1) {
        minLabel.textContent = dates[0] || '—';
        maxLabel.textContent = dates[0] || '—';
        return;
    }

    noUiSlider.create(el, {
        start: [0, dates.length - 1],
        connect: true,
        step: 1,
        range: { min: 0, max: dates.length - 1 }
    });

    el.noUiSlider.on('update', function (values) {
        const lo = Math.round(values[0]);
        const hi = Math.round(values[1]);
        minLabel.textContent = _dateSliderDates[lo] || '—';
        maxLabel.textContent = _dateSliderDates[hi] || '—';
    });
}

// =====================
// OTHER FILTERS
// =====================

// GET CURRENT FILTER VALUES
function getActiveFilters() {
    return {
        deprecated: document.getElementById('filterDeprecated').value,
        dateFrom: (function () {
            const el = document.getElementById('dateSlider');
            return el.noUiSlider ? _dateSliderDates[Math.round(el.noUiSlider.get()[0])] || '' : '';
        })(),
        dateTo: (function () {
            const el = document.getElementById('dateSlider');
            return el.noUiSlider ? _dateSliderDates[Math.round(el.noUiSlider.get()[1])] || '' : '';
        })(),
        vendor: document.getElementById('filterVendor').value.toLowerCase(),
        product: document.getElementById('filterProduct').value.toLowerCase(),
        version: document.getElementById('filterVersion').value.toLowerCase(),
        update: document.getElementById('filterUpdate').value.toLowerCase(),
        edition: document.getElementById('filterEdition').value.toLowerCase(),
        language: document.getElementById('filterLanguage').value.toLowerCase(),
        sw_edition: document.getElementById('filterSwEdition').value.toLowerCase(),
        target_sw: document.getElementById('filterTargetSw').value.toLowerCase(),
        target_hw: document.getElementById('filterTargetHw').value.toLowerCase(),
    };
}

// APPLY FILTERS TO CURRENT RESULTS
function applyResultFilters() {
    const filters = getActiveFilters();
    const filtered = allResults.filter(r => {
        const cpeData = r.cpeData || cpeDataStore[r.cpeName] || {};
        const parts = parseCpeParts(r.cpeName || '');

        // Deprecated filter
        if (filters.deprecated !== '') {
            const isDeprecated = String(cpeData.deprecated ?? false);
            if (isDeprecated !== filters.deprecated) return false;
        }

        // Date Created filter
        if (filters.dateFrom || filters.dateTo) {
            const created = cpeData.created ? new Date(cpeData.created) : null;
            if (!created) return false;
            if (filters.dateFrom && created < new Date(filters.dateFrom)) return false;
            if (filters.dateTo && created > new Date(filters.dateTo + 'T23:59:59')) return false;
        }

        // CPE component filters
        if (filters.vendor && !parts.vendor.toLowerCase().includes(filters.vendor)) return false;
        if (filters.product && !parts.product.toLowerCase().includes(filters.product)) return false;
        if (filters.version && !parts.version.toLowerCase().includes(filters.version)) return false;
        if (filters.update && !parts.update.toLowerCase().includes(filters.update)) return false;
        if (filters.edition && !parts.edition.toLowerCase().includes(filters.edition)) return false;
        if (filters.language && !parts.language.toLowerCase().includes(filters.language)) return false;
        if (filters.sw_edition && !parts.sw_edition.toLowerCase().includes(filters.sw_edition)) return false;
        if (filters.target_sw && !parts.target_sw.toLowerCase().includes(filters.target_sw)) return false;
        if (filters.target_hw && !parts.target_hw.toLowerCase().includes(filters.target_hw)) return false;

        return true;
    });

    window._filteredResults = filtered;
    currentPage = 1;
    renderPage();
}

// ENABLE/DISABLE FILTER FIELDS BASED ON RESULT VARIANCE
function updateFilterFieldStates() {
    const fieldMap = {
        filterDeprecated: r => String(r.cpeData?.deprecated ?? false),
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

    for (const [id, extractor] of Object.entries(fieldMap)) {
        const unique = new Set(allResults.map(extractor));
        const el = document.getElementById(id);
        const single = unique.size <= 1;
        el.disabled = single;
        el.style.opacity = single ? '0.4' : '1';
    }

    const uniqueDates = new Set(allResults.map(r => r.cpeData?.created || ''));
    const dateSingle = uniqueDates.size <= 1;
    const dateSliderEl = document.getElementById('dateSlider');
    if (dateSliderEl.noUiSlider) {
        dateSliderEl.style.opacity = dateSingle ? '0.4' : '1';
        dateSliderEl.style.pointerEvents = dateSingle ? 'none' : 'auto';
    }
}

// EVENT LISTENERS
document.getElementById('applyFilters').addEventListener('click', () => {
    applyResultFilters();
    document.getElementById('searchFilterModal').style.display = 'none';
});
document.getElementById('searchFilterModal').style.display = 'none';
document.getElementById('clearFilters').addEventListener('click', (e) => {
    e.preventDefault();
    document.getElementById('filterDeprecated').value = '';
    const dateSliderEl = document.getElementById('dateSlider');
    if (dateSliderEl.noUiSlider) {
        dateSliderEl.noUiSlider.reset();
    }
    document.getElementById('filterVendor').value = '';
    document.getElementById('filterProduct').value = '';
    document.getElementById('filterVersion').value = '';
    document.getElementById('filterUpdate').value = '';
    document.getElementById('filterEdition').value = '';
    document.getElementById('filterLanguage').value = '';
    document.getElementById('filterSwEdition').value = '';
    document.getElementById('filterTargetSw').value = '';
    document.getElementById('filterTargetHw').value = '';
    // Re-render unfiltered
    currentPage = 1;
    window._filteredResults = null;
    renderPage();
});

// FILTER MODAL OPEN/CLOSE
document.getElementById('openSearchFilterModal').addEventListener('click', () => {
    document.getElementById('searchFilterModal').style.display = 'flex';
});
document.getElementById('closeFilterModal').addEventListener('click', () => {
    document.getElementById('searchFilterModal').style.display = 'none';
});
document.getElementById('searchFilterModal').addEventListener('click', (e) => {
    if (e.target === e.currentTarget) e.currentTarget.style.display = 'none';
});