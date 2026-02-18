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
    let visibleTickets;

    if (activeTicketFilter) {
        const { feature, date, owner, status, includeArchived } = activeTicketFilter;
        visibleTickets = includeArchived ? [...tickets] : tickets.filter(t => !t.isArchived);
        if (feature) visibleTickets = visibleTickets.filter(t => t.feature === feature);
        if (owner) visibleTickets = visibleTickets.filter(t => (t.creator_email || String(t.user_id)) === owner);
        if (status) visibleTickets = visibleTickets.filter(t => t.status === status);
        if (date) {
            visibleTickets = visibleTickets.filter(t => {
                const created = new Date(t.created);
                const fd = new Date(date);
                return created.toDateString() === fd.toDateString();
            });
        }
    } else {
        visibleTickets = tickets.filter(t => !t.isArchived);
    }

    const container = document.getElementById('ticketsList');
    container.innerHTML = '';
    if (!visibleTickets.length) return;

    const uid = currentUser?.id;

    for (const t of visibleTickets) {
        const isOwner = (t.user_id === uid || !t.user_id);
        const div = document.createElement('div');
        div.style.cssText = 'border: 1px solid #ddd; border-radius: 6px; padding: 12px; margin-bottom: 10px; max-width: 600px; background:' + (t.resolved ? '#e8f5e9' : '#fff');
        div.innerHTML = `
        <!-- Header row -->
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <div style="display: flex; align-items: center; gap: 8px;">
                <strong>Ticket #${t.id}</strong>
            </div>
            <div style="display: flex; gap: 6px; align-items: flex-end;">
                <span style="font-size: 0.8em; color: #888;">${escapeHtml(t.created)}</span>
                <span style="padding: 2px 8px; background: ${
                    t.status === 'Resolved' ? '#e8f5e9' :
                    t.status === 'In Progress' ? '#e3f2fd' :
                    t.status === 'Open' ? '#e67e22' : '#e67e22'
                }; color: ${
                    t.status === 'Resolved' ? '#2e7d32' :
                    t.status === 'In Progress' ? '#1565c0' :
                    t.status === 'Open' ? '#fff3e0' : '#f5f5f5'
                }; border-radius: 3px; font-size: 0.9em; font-weight: 600;">${escapeHtml(t.status || 'Open')}</span>
            </div>
        </div>
    
        <!-- Feature tag + creator -->
        <div style="margin-top: 4px; display: flex; gap: 6px; align-items: center;">
            <span style="display: inline-block; padding: 2px 8px; background: #d5bf9f; color: #57534E; border-radius: 3px; font-size: 0.8em; font-weight: 600;">${escapeHtml(t.feature)}</span>
            <span style="font-size: 0.78em; color: #888;">by ${escapeHtml(t.creator_email || 'unknown')}</span>
        </div>
    
        <!-- Description -->
        <p style="margin: 8px 0;">${escapeHtml(t.description)}</p>
    
        <!-- Buttons row -->
        <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">
            ${t.isArchived ? '<span style="font-size: 0.82em; color: #999; font-style: italic;">Archived</span>' : `
            ${t.isAccepted
                ? `<div style="display: flex; flex-direction: column; gap: 2px;">
                    <span style="font-size: 0.82em; color: #888;"></span>
                </div>`
                : `<button onclick="acceptTicket(${t.id})" style="padding: 4px 12px; background-color: #1565c0; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 0.85em;">Accept</button>`
            }
            ${t.isResolved
                ? `${t.accepted_by === currentUser?.email
                    ? `<button onclick="reopenTicket(${t.id})" style="padding: 4px 12px; background-color: #e67e22; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 0.85em;">Reopen</button>
                    <button onclick="archiveTicket(${t.id})" style="padding: 4px 12px; background-color: #78909c; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 0.85em;">Archive</button>`
                    : ''
                }`
                : (t.isAccepted && t.accepted_by === currentUser?.email
                    ? `<button onclick="resolveTicket(${t.id})" style="padding: 4px 12px; background-color: #2e7d32; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 0.85em;">Mark Resolved</button>
                    <button onclick="reassignTicket(${t.id})" style="padding: 4px 12px; background-color: #8e24aa; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 0.85em;">Reassign</button>
                    <button onclick="commentTicket(${t.id})" style="padding: 4px 12px; background-color: #1565c0; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 0.85em;">Comment</button>`
                    : '')
            }
            ${isOwner && !t.isAccepted
                ? `<button onclick="deleteTicket(${t.id})" style="padding: 4px 12px; background-color: #c01e19; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 0.85em;">Delete</button>`
                : ''}
        `}
        </div>
        <!-- Comment input (below buttons) -->
        ${t.isAccepted && !t.isResolved && t.accepted_by === currentUser?.email
            ? `<div id="comment-input-${t.id}" style="display: none; flex-direction: column; gap: 6px; margin-top: 6px; max-width: 400px;">
                <textarea rows="2" placeholder="Add a comment..." style="width: 100%; padding: 6px 8px; font-size: 0.85em; border: 1px solid #ccc; border-radius: 4px; resize: vertical; box-sizing: border-box;"></textarea>
                <div style="display: flex; gap: 6px;">
                    <button onclick="submitComment(${t.id})" style="width: fit-content; padding: 4px 12px; background-color: #1565c0; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 0.85em;">Submit</button>
                    <button onclick="cancelComment(${t.id})" style="width: fit-content; padding: 4px 12px; background-color: #ccc; color: #333; border: none; border-radius: 4px; cursor: pointer; font-size: 0.85em;">Cancel</button>
                </div>
            </div>`
            : ''}
    
        <!-- Comments section (below buttons) -->
        ${t.comments && t.comments.length
            ? `<div style="margin-top: 8px; border-top: 1px solid #eee; padding-top: 6px;">
                ${t.comments.map(c => `
                    <div style="margin-bottom: 6px;">
                        <span style="font-size: 0.82em; color: #888;">Comment by ${escapeHtml(c.comment_by)} — ${escapeHtml(c.commented)}</span>
                        <p style="margin: 2px 0 0 0; font-size: 0.88em; color: #444;">${escapeHtml(c.comment_description)}</p>
                    </div>
                `).join('')}
            </div>`
            : ''}
    
        <!-- Activity log (below buttons) -->
        ${t.activity && t.activity.length
            ? `<div style="margin-top: 8px; border-top: 1px solid #eee; padding-top: 6px;">
                ${t.activity.map(a => `
                    <div style="margin-bottom: 4px;">
                        <span style="font-size: 0.82em; color: #888;">
                            ${escapeHtml(a.action)} by ${escapeHtml(a.action_by)} — ${escapeHtml(a.timestamp)}
                        </span>
                    </div>
                `).join('')}
            </div>`
            : ''}
    `;
        container.appendChild(div);
    }
}

// UPDATE TICKET STATUS
function statusTicket(id, status) {
    fetch('/db/ticket-status', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ticket_id: id, status: status })
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            const t = tickets.find(t => t.id === id);
            if (t) {
                t.status = data.status;
                if (!t.activity) t.activity = [];
                t.activity.push({
                    action: `Status changed to ${data.status}`,
                    action_by: currentUser?.email,
                    timestamp: data.updated
                });
            }
            renderTickets();
        } else {
            alert(data.error || 'Failed to update ticket status');
        }
    })
    .catch(e => console.error('Status ticket error:', e));
}

// ACCEPT TICKETS
function acceptTicket(id) {
    fetch('/db/ticket-acceptance', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ticket_id: id })
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            const t = tickets.find(t => t.id === id);
            if (t) {
                t.isAccepted = true;
                t.accepted = data.accepted;
                t.accepted_by = data.accepted_by;
                if (!t.activity) t.activity = [];
                t.activity.push({
                    action: 'Accepted',
                    action_by: currentUser?.email,
                    timestamp: data.accepted
                });
            }
            statusTicket(id, 'In Progress');
            renderTickets();
        } else {
            alert(data.error || 'Failed to accept ticket');
        }
    })
    .catch(e => console.error('Accept ticket error:', e));
}

// COMMENT TICKET - toggle inline input
function commentTicket(id) {
    const container = document.getElementById(`comment-input-${id}`);
    if (container.style.display === 'none' || !container.style.display) {
        container.style.display = 'flex';
        container.querySelector('textarea').focus();
    } else {
        container.style.display = 'none';
    }
}

// SUBMIT COMMENT
function submitComment(id) {
    const textarea = document.querySelector(`#comment-input-${id} textarea`);
    const desc = textarea.value.trim();
    if (!desc) { alert('Please enter a comment.'); return; }

    fetch('/db/ticket-comment', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ticket_id: id, comment_description: desc })
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            const t = tickets.find(t => t.id === id);
            if (t) {
                if (!t.comments) t.comments = [];
                t.comments.push({
                    comment_by: data.comment_by,
                    commented: data.commented,
                    comment_description: data.comment_description
                });
            }
            renderTickets();
        } else {
            alert(data.error || 'Failed to add comment');
        }
    })
    .catch(e => console.error('Comment ticket error:', e));
}

// CANCEL COMMENT
function cancelComment(id) {
    const container = document.getElementById(`comment-input-${id}`);
    container.querySelector('textarea').value = '';
    container.style.display = 'none';
}

// REASSIGN TICKET
function reassignTicket(id) {
    fetch('/db/ticket-reassign', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ticket_id: id })
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            const t = tickets.find(t => t.id === id);
            if (t) {
                t.isAccepted = false;
                t.accepted = null;
                t.accepted_by = null;
                t.isResolved = false;
                t.resolved = null;
                t.resolved_by = null;
                t.reassigned = data.reassigned;
                t.reassigned_by = data.reassigned_by;
                if (!t.activity) t.activity = [];
                t.activity.push({
                    action: 'Reassigned',
                    action_by: currentUser?.email,
                    timestamp: data.reassigned
                });
            }
            statusTicket(id, 'Open');
            renderTickets();
        } else {
            alert(data.error || 'Failed to reassign ticket');
        }
    })
    .catch(e => console.error('Reassign ticket error:', e));
}

// RESOLVE TICKETS
function resolveTicket(id) {
    fetch('/db/ticket-resolution', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ticket_id: id, isResolved: 1 })
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            const t = tickets.find(t => t.id === id);
            if (t) {
                t.isResolved = true;
                t.resolved = data.resolved;
                t.resolved_by = currentUser?.email;
                if (!t.activity) t.activity = [];
                t.activity.push({
                    action: 'Resolved',
                    action_by: currentUser?.email,
                    timestamp: data.resolved
                });
            }
            statusTicket(id, 'Resolved');
            renderTickets();
        } else {
            alert(data.error || 'Failed to resolve ticket');
        }
    })
    .catch(e => console.error('Resolve ticket error:', e));
}

// REOPEN TICKET
function reopenTicket(id) {
    fetch('/db/ticket-resolution', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ticket_id: id, isResolved: 0 })
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            const t = tickets.find(t => t.id === id);
            if (t) {
                t.isResolved = false;
                t.resolved = null;
                t.resolved_by = null;
                if (!t.activity) t.activity = [];
                t.activity.push({
                    action: 'Reopened',
                    action_by: currentUser?.email,
                    timestamp: new Date().toLocaleString()
                });
            }
            statusTicket(id, 'In Progress');
            renderTickets();
        } else {
            alert(data.error || 'Failed to reopen ticket');
        }
    })
    .catch(e => console.error('Reopen ticket error:', e));
}

// ARCHIVE TICKET
function archiveTicket(id) {
    fetch('/db/ticket-archive', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ticket_id: id, isArchived: 1 })
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            const t = tickets.find(t => t.id === id);
            if (t) {
                t.isArchived = true;
                t.archived = data.archived;
                if (!t.activity) t.activity = [];
                t.activity.push({
                    action: 'Archived',
                    action_by: currentUser?.email,
                    timestamp: data.archived
                });
            }
            statusTicket(id, 'Archived');
            renderTickets();
        } else {
            alert(data.error || 'Failed to archive ticket');
        }
    })
    .catch(e => console.error('Archive ticket error:', e));
}

// DELETE TICKETS
function deleteTicket(id) {
    tickets = tickets.filter(t => t.id !== id);
    saveTickets();
    renderTickets();
}

// Load persisted tickets on startup
renderTickets();

// =====================
// FILTER TICKETS
// =====================

function populateFilterDropdowns() {
    const featureSelect = document.getElementById('filterFeature');
    const ownerSelect = document.getElementById('filterOwner');

    featureSelect.innerHTML = '<option value="">All</option>';
    ownerSelect.innerHTML = '<option value="">All</option>';

    const features = [...new Set(tickets.map(t => t.feature).filter(Boolean))];
    const owners = [...new Set(tickets.map(t => t.creator_email || t.user_id).filter(Boolean))];

    features.forEach(f => {
        featureSelect.innerHTML += `<option value="${f}">${f}</option>`;
    });
    owners.forEach(o => {
        ownerSelect.innerHTML += `<option value="${o}">${o}</option>`;
    });
}

function openFilterModal() {
    populateFilterDropdowns();
    document.getElementById('filterModal').style.display = 'flex';
}

function closeFilterModal() {
    document.getElementById('filterModal').style.display = 'none';
}

function clearFilters() {
    document.getElementById('filterFeature').value = '';
    document.getElementById('filterDate').value = '';
    document.getElementById('filterOwner').value = '';
    document.getElementById('filterStatus').value = '';
    document.getElementById('filterIncludeArchived').checked = false;
    activeTicketFilter = null;
    renderTickets();
}

function applyFilters() {
    const feature = document.getElementById('filterFeature').value;
    const date = document.getElementById('filterDate').value;
    const owner = document.getElementById('filterOwner').value;
    const status = document.getElementById('filterStatus').value;
    const includeArchived = document.getElementById('filterIncludeArchived').checked;

    activeTicketFilter = { feature, date, owner, status, includeArchived };

    renderTickets();
    closeFilterModal();
}

// Close modal when clicking outside
document.getElementById('filterModal').addEventListener('click', function(e) {
    if (e.target === this) closeFilterModal();
});