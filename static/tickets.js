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
    const visibleTickets = tickets.filter(t => !t.isArchived);
    const container = document.getElementById('ticketsList');
    container.innerHTML = '';
    if (!tickets.length) return;

    const uid = currentUser?.id;

    for (const t of visibleTickets) {
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
        <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">
        ${t.isAccepted
            ? `<div style="display: flex; flex-direction: column; gap: 2px;">
                <span style="font-size: 0.82em; color: #888;">Accepted by ${escapeHtml(t.accepted_by)} — ${escapeHtml(t.accepted)}</span>`
            : `<button onclick="acceptTicket(${t.id})" style="padding: 4px 12px; background-color: #1565c0; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 0.85em;">Accept</button>`
        }
        ${t.isResolved
            ? `<span style="font-size: 0.82em; color: #888;">Resolved by ${escapeHtml(t.resolved_by || t.accepted_by)} — ${escapeHtml(t.resolved)}</span>
               </div>
               <div style="display: flex; gap: 8px; margin-top: 6px;">
               ${t.accepted_by === currentUser?.email
                   ? `<button onclick="reopenTicket(${t.id})" style="padding: 4px 12px; background-color: #e67e22; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 0.85em;">Reopen</button>
                      <button onclick="archiveTicket(${t.id})" style="padding: 4px 12px; background-color: #78909c; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 0.85em;">Archive</button>`
                   : ''
               }
               </div>`
               : (t.isAccepted && t.accepted_by === currentUser?.email
                ? `<div style="display: flex; gap: 8px;">
                     <button onclick="resolveTicket(${t.id})" style="width: fit-content; padding: 4px 12px; background-color: #2e7d32; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 0.85em;">Mark Resolved</button>
                     <button onclick="reassignTicket(${t.id})" style="width: fit-content; padding: 4px 12px; background-color: #8e24aa; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 0.85em;">Reassign</button>
                     <button onclick="commentTicket(${t.id})" style="width: fit-content; padding: 4px 12px; background-color: #1565c0; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 0.85em;">Comment</button>
                   </div>
                   <div id="comment-input-${t.id}" style="display: none; flex-direction: column; gap: 6px; margin-top: 6px; max-width: 400px;">
                     <textarea rows="2" placeholder="Add a comment..." style="width: 100%; padding: 6px 8px; font-size: 0.85em; border: 1px solid #ccc; border-radius: 4px; resize: vertical; box-sizing: border-box;"></textarea>
                     <button onclick="submitComment(${t.id})" style="width: fit-content; padding: 4px 12px; background-color: #1565c0; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 0.85em;">Submit Comment</button>
                   </div>`
                : '')
        }
        ${(t.comments && t.comments.length) ? `
            <div style="margin-top: 8px; border-top: 1px solid #eee; padding-top: 6px;">
                ${t.comments.map(c => `
                    <div style="margin-bottom: 6px;">
                        <span style="font-size: 0.82em; color: #888;">Comment by ${escapeHtml(c.comment_by)} — ${escapeHtml(c.commented)}</span>
                        <p style="margin: 2px 0 0 0; font-size: 0.88em; color: #444;">Comment: ${escapeHtml(c.comment_description)}</p>
                    </div>
                `).join('')}
            </div>` : ''}
        ${isOwner && !t.isAccepted ? `<button onclick="deleteTicket(${t.id})" style="padding: 4px 12px; background-color: #c01e19; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 0.85em;">Delete</button>` : ''}
        ${t.reassigned && !t.isAccepted ? `<span style="font-size: 0.82em; color: #888;">Reassigned by ${escapeHtml(t.reassigned_by)} — ${escapeHtml(t.reassigned)}</span>` : ''}
        </div>
    `;
        container.appendChild(div);
    }
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
            }
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
            }
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
            }
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
            }
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
            }
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