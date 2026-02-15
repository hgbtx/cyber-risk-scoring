// =====================
// EXPORT (CSV, JSON)
// =====================

// JSON DOWNLOAD
function downloadCveJSON() {
    const exportStore = activeFolderCpe
        ? { [activeFolderCpe]: cveDataStore[activeFolderCpe] }
        : cveDataStore;

    if (!Object.keys(exportStore).length) return alert('No CVE data to export.');

    const blob = new Blob([JSON.stringify(exportStore, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = activeFolderCpe ? 'cve_data_folder.json' : 'cve_data.json';
    a.click();
    URL.revokeObjectURL(a.href);
}

// FLATTEN JSON
function flattenObject(obj, prefix = '') {
    const result = {};
    for (const key in obj) {
        const fullKey = prefix ? `${prefix}.${key}` : key;
        const val = obj[key];
        if (val && typeof val === 'object' && !Array.isArray(val)) {
            Object.assign(result, flattenObject(val, fullKey));
        } else if (Array.isArray(val)) {
            if (val.every(v => typeof v !== 'object')) {
                result[fullKey] = val.join('; ');
            } else {
                val.forEach((item, i) => {
                    if (typeof item === 'object') {
                        Object.assign(result, flattenObject(item, `${fullKey}[${i}]`));
                    } else {
                        result[`${fullKey}[${i}]`] = item;
                    }
                });
            }
        } else {
            result[fullKey] = val;
        }
    }
    return result;
}

// CSV DOWNLOAD
function downloadCveCSV() {
    const flatRows = [];
    const allKeys = new Set();

    const cpeList = activeFolderCpe ? [activeFolderCpe] : Object.keys(cveDataStore);

    for (const cpe of cpeList) {
        const data = cveDataStore[cpe];
        if (!data?.vulnerabilities) continue;

        for (const vuln of data.vulnerabilities) {
            const flat = flattenObject(vuln);
            flat['_cpeName'] = cpe;
            flatRows.push(flat);
            Object.keys(flat).forEach(k => allKeys.add(k));
        }
    }

    if (!flatRows.length) return alert('No CVE data to export.');

    const headers = ['_cpeName', ...Array.from(allKeys).filter(k => k !== '_cpeName').sort()];

    const csvRows = [headers.join(',')];
    for (const row of flatRows) {
        csvRows.push(headers.map(h => {
            const val = row[h] ?? '';
            const str = String(val);
            return str.includes(',') || str.includes('"') || str.includes('\n')
                ? `"${str.replace(/"/g, '""')}"` 
                : str;
        }).join(','));
    }

    const blob = new Blob([csvRows.join('\n')], { type: 'text/csv;charset=utf-8;' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = activeFolderCpe ? 'cve_data_folder.csv' : 'cve_data.csv';
    a.click();
    URL.revokeObjectURL(a.href);
}