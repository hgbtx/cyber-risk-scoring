// =====================
// REMEDIATION TICKETS
// =====================

document.getElementById('createTicketBtn').addEventListener('click', () => {
    document.getElementById('ticketFormContainer').style.display = 'block';
    document.getElementById('ticketDescription').focus();
});

document.getElementById('cancelTicketBtn').addEventListener('click', () => {
    document.getElementById('ticketFormContainer').style.display = 'none';
    document.getElementById('ticketDescription').value = '';
});

document.getElementById('submitTicketBtn').addEventListener('click', () => {
    const desc = document.getElementById('ticketDescription').value.trim();
    const feature = document.getElementById('ticketFeature').value;
    if (!desc) { alert('Please enter a description.'); return; }
    if (!feature) { alert('Please select a related feature.'); return; }

    const ticket = {
        id: ticketIdCounter++,
        description: desc,
        feature: feature,
        created: new Date().toLocaleString(),
        resolved: false
    };
    tickets.push(ticket);
    saveTickets();

    document.getElementById('ticketDescription').value = '';
    document.getElementById('ticketFeature').value = '';
    document.getElementById('ticketFormContainer').style.display = 'none';
    renderTickets();
});

function renderTickets() {
    const container = document.getElementById('ticketsList');
    container.innerHTML = '';

    if (!tickets.length) return;

    for (const t of tickets) {
        const div = document.createElement('div');
        div.style.cssText = 'border: 1px solid #ddd; border-radius: 6px; padding: 12px; margin-bottom: 10px; max-width: 600px; background:' + (t.resolved ? '#e8f5e9' : '#fff');
        div.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <strong>Ticket #${t.id}</strong>
            <span style="font-size: 0.8em; color: #888;">${escapeHtml(t.created)}</span>
        </div>
        <div style="margin-top: 4px;">
            <span style="display: inline-block; padding: 2px 8px; background: #d5bf9f; color: #57534E; border-radius: 3px; font-size: 0.8em; font-weight: 600;">${escapeHtml(t.feature)}</span>
        </div>
        <p style="margin: 8px 0;">${escapeHtml(t.description)}</p>
        <div style="display: flex; gap: 8px; align-items: center;">
                ${t.resolved
                    ? `<span style="color: #2e7d32; font-weight: 600;">✔ Resolved</span><span style="font-size: 0.8em; color: #888; margin-left: 8px;">${escapeHtml(t.resolvedAt || '')}</span>`
                    : `<button onclick="resolveTicket(${t.id})" style="padding: 4px 12px; background-color: #50b88e; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 0.85em;">Mark Resolved</button>`
                }
                ${t.lastModified ? `<span style="font-size: 0.8em; color: #be7a15; margin-left: 8px;">(edited ${escapeHtml(t.lastModified)})</span>` : ''}
            <button onclick="deleteTicket(${t.id})" style="padding: 4px 12px; background-color: #c01e19; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 0.85em;">Delete</button>
<button onclick="editTicket(${t.id})" style="padding: 4px 12px; background-color: #d9af6f; color: #57534E; border: none; border-radius: 4px; cursor: pointer; font-size: 0.85em;">Edit</button>
        </div>
    `;
        container.appendChild(div);
    }
}

function resolveTicket(id) {
    const t = tickets.find(t => t.id === id);
    if (t) { t.resolved = true; t.resolvedAt = new Date().toLocaleString(); saveTickets(); renderTickets(); }
}

function deleteTicket(id) {
    tickets = tickets.filter(t => t.id !== id);
    saveTickets();
    renderTickets();
}

function editTicket(id) {
    const t = tickets.find(t => t.id === id);
    if (!t) return;

    const container = document.getElementById('ticketsList');
    const ticketDiv = [...container.children].find(div => div.querySelector('strong')?.textContent === `Ticket #${id}`);
    if (!ticketDiv) return;

    ticketDiv.innerHTML = `
        <div style="display: flex; flex-direction: column; gap: 10px;">
            <div>
                <label style="font-weight: 600; font-size: 0.85em; color: #57534E;">Description</label>
                <textarea id="editDesc_${id}" rows="4" style="width: 100%; padding: 8px; font-size: 14px; border: 2px solid #ddd; border-radius: 4px; resize: vertical; box-sizing: border-box;">${escapeHtml(t.description)}</textarea>
            </div>
            <div>
                <label style="font-weight: 600; font-size: 0.85em; color: #57534E;">Related Feature</label>
                <select id="editFeature_${id}" style="width: 100%; padding: 8px 10px; font-size: 14px; border: 2px solid #ddd; border-radius: 4px; background: white;">
                    <option value="" ${!t.feature ? 'selected' : ''}>— Select feature —</option>
                    <option value="Search" ${t.feature === 'Search' ? 'selected' : ''}>Search</option>
                    <option value="Charts" ${t.feature === 'Charts' ? 'selected' : ''}>Charts</option>
                    <option value="CVE Details" ${t.feature === 'CVE Details' ? 'selected' : ''}>CVE Details</option>
                    <option value="Next Steps" ${t.feature === 'Next Steps' ? 'selected' : ''}>Next Steps</option>
                    <option value="Left Panel" ${t.feature === 'Left Panel' ? 'selected' : ''}>Left Panel</option>
                    <option value="Right Panel" ${t.feature === 'Right Panel' ? 'selected' : ''}>Right Panel</option>
                </select>
            </div>
            <div style="display: flex; gap: 8px;">
                <button onclick="saveEditTicket(${id})" style="padding: 6px 16px; background-color: #be7a15; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 0.85em;">Save</button>
                <button onclick="renderTickets()" style="padding: 6px 16px; background-color: #ccc; color: #333; border: none; border-radius: 4px; cursor: pointer; font-size: 0.85em;">Cancel</button>
            </div>
        </div>
    `;
}

function saveEditTicket(id) {
    const t = tickets.find(t => t.id === id);
    if (!t) return;

    const desc = document.getElementById(`editDesc_${id}`).value.trim();
    const feature = document.getElementById(`editFeature_${id}`).value;
    if (!desc) { alert('Please enter a description.'); return; }
    if (!feature) { alert('Please select a related feature.'); return; }

    t.description = desc;
    t.feature = feature;
    t.lastModified = new Date().toLocaleString();
    saveTickets();
    renderTickets();
}

// Load persisted tickets on startup
renderTickets();