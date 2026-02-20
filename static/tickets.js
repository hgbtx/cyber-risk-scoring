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

// USER MENTIONS IN TICKET COMMENTS
function formatMentions(text) {
    return escapeHtml(text).replace(/@(\w+)/g, '<span style="color: #e67e22; font-weight: 600;">@$1</span>');
}

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
    // Sort tickets
    const sortMode = document.getElementById('ticketSortSelect')?.value || 'default';
    if (sortMode === 'newest') {
        visibleTickets.sort((a, b) => new Date(b.created) - new Date(a.created));
    } else if (sortMode === 'oldest') {
        visibleTickets.sort((a, b) => new Date(a.created) - new Date(b.created));
    }
    const container = document.getElementById('ticketsList');
    container.innerHTML = '';
    // Show active filter bar
    if (activeTicketFilter) {
        const { feature, owner, status } = activeTicketFilter;
        const parts = [];
        if (feature) parts.push(`Feature: ${feature}`);
        if (owner) parts.push(`Owner: ${owner}`);
        if (status) parts.push(`Status: ${status}`);
        if (parts.length) {
            const bar = document.createElement('div');
            bar.style.cssText = 'max-width: 600px; margin-bottom: 10px; padding: 6px 12px; background: #fff3e0; border-radius: 4px; font-size: 0.85em; color: #57534E; display: flex; justify-content: space-between; align-items: center;';
            bar.innerHTML = `<span>Filtered by: ${parts.join(' · ')}</span><span onclick="clearFilters()" style="cursor:pointer; color:#be7a15; font-weight:600;">✕ Clear</span>`;
            container.appendChild(bar);
        }
    }
    if (!visibleTickets.length) return;
    const uid = currentUser?.id;
    for (const t of visibleTickets) {
        const isOwner = (t.user_id === uid || !t.user_id);
        const isCollaborator = (t.collaborators || []).includes(currentUser?.email);
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
                }; border-radius: 3px; font-size: 0.9em; font-weight: 600; cursor: pointer;" onclick="filterByField('status', '${escapeHtml(t.status || 'Open')}')" title="Filter by status">${escapeHtml(t.status || 'Open')}</span>
            </div>
        </div>
        <!-- Feature tag + creator -->
        <div style="margin-top: 4px; display: flex; gap: 6px; align-items: center;">
            <span style="display: inline-block; padding: 2px 8px; background: #d5bf9f; color: #57534E; border-radius: 3px; font-size: 0.8em; font-weight: 600; cursor: pointer;" onclick="filterByField('feature', '${escapeHtml(t.feature)}')" title="Filter by feature">${escapeHtml(t.feature)}</span>
            <span style="font-size: 0.78em; color: #888; cursor: pointer;" onclick="filterByField('owner', '${escapeHtml(t.creator_email || 'unknown')}')" title="Filter by owner">by ${escapeHtml(t.creator_email || 'unknown')}</span>
        </div>
        <!-- Description -->
        <p style="margin: 8px 0;">${escapeHtml(t.description)}</p>
        <!-- Buttons row -->
        <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">
        ${t.isArchived ? `${hasMinRole('manager') ? `<button onclick="restoreTicket(${t.id})" style="padding: 4px 12px; background-color: #50b88e; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 0.85em;">Restore</button>` : ''}` : `
            ${t.isAccepted
                ? `<div style="display: flex; flex-direction: column; gap: 2px;">
                    <span style="font-size: 0.82em; color: #888;"></span>
                </div>`
                : `${hasMinRole('manager') ? `<button onclick="acceptTicket(${t.id})" style="padding: 4px 12px; background-color: #1565c0; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 0.85em;">Accept</button>` : ''}`
            }
            ${t.isResolved
                ? `${t.accepted_by === currentUser?.email
                    ? `<button onclick="reopenTicket(${t.id})" style="padding: 4px 12px; background-color: #e67e22; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 0.85em;">Reopen</button>
                    ${hasMinRole('manager') ? `<button onclick="archiveTicket(${t.id})" style="padding: 4px 12px; background-color: #78909c; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 0.85em;">Archive</button>` : ''}`
                    : ''
                }`
                : (t.isAccepted && (t.accepted_by === currentUser?.email || isCollaborator)
                ? `${t.accepted_by === currentUser?.email
                    ? `${hasMinRole('analyst') ? `<button onclick="resolveTicket(${t.id})" style="padding: 4px 12px; background-color: #2e7d32; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 0.85em;">Mark Resolved</button>` : ''}
                    ${hasMinRole('manager') ? `<button onclick="reassignTicket(${t.id})" style="padding: 4px 12px; background-color: #8e24aa; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 0.85em;">Reassign</button>` : ''}`
                    : ''}
                ${hasMinRole('analyst') ? `<button onclick="commentTicket(${t.id})" style="padding: 4px 12px; background-color: #1565c0; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 0.85em;">Comment</button>` : ''}`
                : '')
            }
            ${isOwner && !t.isAccepted
                ? `<button onclick="deleteTicket(${t.id})" style="padding: 4px 12px; background-color: #c01e19; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 0.85em;">Delete</button>`
                : ''}
        `}
        </div>
        <!-- Comment input (below buttons) -->
        ${t.isAccepted && !t.isResolved && (t.accepted_by === currentUser?.email || isCollaborator)
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
                        ${c.isFixed ? '<span style="font-size: 0.78em; color: #2e7d32; font-weight: 600; margin-left: 8px;">✔ Fixed</span>' : ''}
                        <p style="margin: 2px 0 0 0; font-size: 0.88em; color: #444;">${formatMentions(c.comment_description)}</p>
                        ${(isOwner || isCollaborator) && !c.isFixed
                            ? `${hasMinRole('analyst') ? `<button onclick="fixComment(${t.id}, ${c.id})" style="margin-top: 4px; padding: 2px 10px; background-color: #2e7d32; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 0.8em;">Fix</button>` : ''}`
                            : ''}
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
    loadTicketStats();
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
                if (data.new_collaborators && data.new_collaborators.length) {
                    if (!t.collaborators) t.collaborators = [];
                    data.new_collaborators.forEach(c => {
                        if (!t.collaborators.includes(c)) t.collaborators.push(c);
                    });
                }
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

// FIX COMMENT
function fixComment(ticketId, commentId) {
    fetch('/db/ticket-comment-fix', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ticket_id: ticketId, comment_id: commentId })
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            const t = tickets.find(t => t.id === ticketId);
            if (t && t.comments) {
                const c = t.comments.find(c => c.id === commentId);
                if (c) {
                    c.isFixed = true;
                    c.fixed = data.fixed;
                }
            }
            if (!t.activity) t.activity = [];
            t.activity.push({
                action: 'Comment marked as Fixed',
                action_by: currentUser?.email,
                timestamp: data.fixed
            });
            renderTickets();
        } else {
            alert(data.error || 'Failed to fix comment');
        }
    })
    .catch(e => console.error('Fix comment error:', e));
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

// RESTORE TICKET
function restoreTicket(id) {
    fetch('/db/ticket-archive', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ticket_id: id, isArchived: 0 })
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            const t = tickets.find(t => t.id === id);
            if (t) {
                t.isArchived = false;
                t.archived = null;
                if (!t.activity) t.activity = [];
                t.activity.push({
                    action: 'Restored',
                    action_by: currentUser?.email,
                    timestamp: new Date().toLocaleString()
                });
            }
            statusTicket(id, 'Resolved');
            renderTickets();
        } else {
            alert(data.error || 'Failed to restore ticket');
        }
    })
    .catch(e => console.error('Restore ticket error:', e));
}

// DELETE TICKETS
function deleteTicket(id) {
    tickets = tickets.filter(t => t.id !== id);
    saveTickets();
    renderTickets();
}

// Load persisted tickets on startup
renderTickets();

// CLICK-TO-FILTER (inline from ticket cards)
function filterByField(field, value) {
    if (!activeTicketFilter) {
        activeTicketFilter = { feature: '', date: '', owner: '', status: '', includeArchived: false };
    }
    // Toggle: if already filtering by this exact value, clear it
    if (activeTicketFilter[field] === value) {
        activeTicketFilter[field] = '';
        // If all filters are empty, clear entirely
        const { feature, date, owner, status } = activeTicketFilter;
        if (!feature && !date && !owner && !status) activeTicketFilter = null;
    } else {
        activeTicketFilter[field] = value;
        if (field === 'status' && value === 'Archived') {
            activeTicketFilter.includeArchived = true;
        }
    }
    renderTickets();
}

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

// =====================
// TICKET DASHBOARD
// =====================

async function loadTicketStats() {
    try {
        const res = await fetch('/db/ticket-stats');
        const stats = await res.json();
        renderTicketDashboard(stats);
    } catch (e) {
        console.error('Failed to load ticket stats:', e);
    }
}

function renderTicketDashboard(stats) {
    const dashboard = document.getElementById('ticketDashboard');
    dashboard.style.display = 'block';

    // --- 1. Status badges ---
    const statusColors = {
        'Open':        { bg: '#fff3e0', fg: '#e67e22', icon: '🟡' },
        'In Progress': { bg: '#e3f2fd', fg: '#1565c0', icon: '🔵' },
        'Resolved':    { bg: '#e8f5e9', fg: '#2e7d32', icon: '🟢' },
        'Archived':    { bg: '#f5f5f5', fg: '#78909c', icon: '⚪' }
    };
    const statusRow = document.getElementById('dashStatusRow');
    statusRow.innerHTML = '';
    for (const [status, color] of Object.entries(statusColors)) {
        const count = stats.by_status[status] || 0;
        statusRow.innerHTML += `
            <span style="padding: 4px 12px; background: ${color.bg}; color: ${color.fg};
                border-radius: 4px; font-weight: 600; font-size: 0.9em;">
                ${color.icon} ${count} ${status}
            </span>`;
    }

    // --- 2. Feature breakdown (horizontal mini-bars) ---
    const featureRow = document.getElementById('dashFeatureRow');
    const featureEntries = Object.entries(stats.by_feature);
    const maxFeatureCount = Math.max(...featureEntries.map(([, c]) => c), 1);
    featureRow.innerHTML = '<div style="font-weight:600; font-size:0.85em; color:#57534E; margin-bottom:6px;">By Feature</div>';
    for (const [feature, count] of featureEntries) {
        const pct = Math.round((count / maxFeatureCount) * 100);
        featureRow.innerHTML += `
            <div style="display:flex; align-items:center; gap:8px; margin-bottom:3px;">
                <span style="width:110px; font-size:0.82em; color:#57534E; text-align:right;">${feature}</span>
                <div style="flex:1; background:#eee; border-radius:3px; height:14px; overflow:hidden;">
                    <div style="width:${pct}%; background:#d5bf9f; height:100%; border-radius:3px;"></div>
                </div>
                <span style="font-size:0.82em; color:#888; width:24px;">${count}</span>
            </div>`;
    }

    // --- 3. Workload, Resolution, Aging ---
    const detailsRow = document.getElementById('dashDetailsRow');
    let html = '';

    // Resolution rate
    const { resolved, total } = stats.resolution;
    const rate = total > 0 ? Math.round((resolved / total) * 100) : 0;
    html += `<div style="margin-bottom:8px;"><strong>Resolution Rate:</strong> ${resolved}/${total} (${rate}%)</div>`;

    // Workload
    const personEntries = Object.entries(stats.by_person);
    if (personEntries.length) {
        html += '<div style="margin-bottom:8px;"><strong>Workload:</strong> ';
        html += personEntries.map(([email, count]) => `${email} (${count})`).join(', ');
        html += '</div>';
    }

    // Aging
    if (stats.aging.length) {
        const now = new Date();
        const agingLines = stats.aging.map(t => {
            const created = new Date(t.created);
            const days = Math.floor((now - created) / (1000 * 60 * 60 * 24));
            return { id: t.id, status: t.status, days };
        }).sort((a, b) => b.days - a.days);

        const avgDays = Math.round(agingLines.reduce((s, t) => s + t.days, 0) / agingLines.length);
        html += `<div style="margin-bottom:4px;"><strong>Aging:</strong> ${agingLines.length} open/in-progress tickets, avg ${avgDays} days old</div>`;

        // Show top 3 oldest
        const oldest = agingLines.slice(0, 3);
        html += '<div style="margin-left:12px; font-size:0.82em; color:#888;">';
        html += oldest.map(t => `#${t.id} — ${t.days}d (${t.status})`).join(' &middot; ');
        html += '</div>';
    }

    detailsRow.innerHTML = html;
}