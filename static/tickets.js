// =====================
// REMEDIATION TICKETS
// =====================

// CREATE TICKET
document.getElementById('createTicketBtn').addEventListener('click', () => {
    document.getElementById('ticketFormContainer').style.display = 'block';
    document.getElementById('ticketDescription').focus();
});

// CANCEL TICKET
document.getElementById('cancelTicketBtn').addEventListener('click', () => {
    document.getElementById('ticketFormContainer').style.display = 'none';
    document.getElementById('ticketDescription').value = '';
});

// SUBMIT TICKET
document.getElementById('submitTicketBtn').addEventListener('click', () => {
    const desc = document.getElementById('ticketDescription').value.trim();
    const feature = document.getElementById('ticketFeature').value;
    if (!desc) { alert('Please enter a description.'); return; }
    if (!feature) { alert('Please select a related feature.'); return; }
    
    const ticket = {
        id: ticketIdCounter++,
        user_id: currentUser?.id,
        creator_email: currentUser?.email,
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

// RENDER TICKETS
function renderTickets() {
    const container = document.getElementById('ticketsList');
    container.innerHTML = '';
    if (!tickets.length) return;

    const uid = currentUser?.id;

    for (const t of tickets) {
        const isOwner = (t.user_id === uid || !t.user_id);
        const div = document.createElement('div');
        div.style.cssText = 'border: 1px solid #ddd; border-radius: 6px; padding: 12px; margin-bottom: 10px; max-width: 600px; background:' + (t.resolved ? '#e8f5e9' : '#fff');
        div.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <strong>Ticket #${t.id}</strong>
            <span style="font-size: 0.8em; color: #888;">${escapeHtml(t.created)}</span>
        </div>
        <div style="margin-top: 4px; display: flex; gap: 6px; align-items: center;">
            <span style="display: inline-block; padding: 2px 8px; background: #d5bf9f; color: #57534E; border-radius: 3px; font-size: 0.8em; font-weight: 600;">${escapeHtml(t.feature)}</span>
            <span style="font-size: 0.78em; color: #888;">by ${escapeHtml(t.creator_email || 'unknown')}</span>
        </div>
        <p style="margin: 8px 0;">${escapeHtml(t.description)}</p>
        <div style="display: flex; gap: 8px; align-items: center;">
            ${t.resolved
                ? '<span style="color: #2e7d32; font-weight: 600;">✔ Resolved</span>'
                : `<button onclick="resolveTicket(${t.id})" style="padding: 4px 12px; background-color: #50b88e; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 0.85em;">Mark Resolved</button>`
            }
            ${isOwner ? `<button onclick="deleteTicket(${t.id})" style="padding: 4px 12px; background-color: #c01e19; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 0.85em;">Delete</button>` : ''}
        </div>
    `;
        container.appendChild(div);
    }
}

// RESOLVE TICKETS
function resolveTicket(id) {
    const t = tickets.find(t => t.id === id);
    if (t) { t.resolved = true; saveTickets(); renderTickets(); }
}

// DELETE TICKETS
function deleteTicket(id) {
    tickets = tickets.filter(t => t.id !== id);
    saveTickets();
    renderTickets();
}

// Load persisted tickets on startup
renderTickets();