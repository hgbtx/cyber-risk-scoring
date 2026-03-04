// =====================
// NOTIFICATION CENTER
// =====================

function getNotifIcon(type) {
    const icons = {
        ticket_assigned:      { icon: 'fa-clipboard-check',        color: '#be7a15' },
        ticket_accepted:      { icon: 'fa-handshake',              color: '#50b88e' },
        ticket_resolved:      { icon: 'fa-circle-check',           color: '#50b88e' },
        ticket_reopened:      { icon: 'fa-rotate-left',            color: '#e67e22' },
        ticket_commented:     { icon: 'fa-comment',                color: '#57534E' },
        ticket_mentioned:     { icon: 'fa-at',                     color: '#e67e22' },
        ticket_reassigned:    { icon: 'fa-arrow-right-arrow-left', color: '#57534E' },
        ticket_confirmed:     { icon: 'fa-check-double',           color: '#50b88e' },
        ticket_status_changed:{ icon: 'fa-arrow-up-right-dots',    color: '#57534E' },
        risk_decision:        { icon: 'fa-scale-balanced',         color: '#be7a15' },
        policy_updated:       { icon: 'fa-shield',                 color: '#57534E' },
        threshold_changed:    { icon: 'fa-chart-line',             color: '#c01e19' },
        rescan_completed:     { icon: 'fa-satellite-dish',         color: '#57534E' },
    };
    return icons[type] || { icon: 'fa-bell', color: '#57534E' };
}

function formatTimeAgo(isoString) {
    if (!isoString) return '';
    const now = new Date();
    const then = new Date(isoString);
    const diffMs = now - then;
    const diffMin = Math.floor(diffMs / 60000);
    if (diffMin < 1) return 'just now';
    if (diffMin < 60) return `${diffMin}m ago`;
    const diffHr = Math.floor(diffMin / 60);
    if (diffHr < 24) return `${diffHr}h ago`;
    const diffDay = Math.floor(diffHr / 24);
    if (diffDay < 7) return `${diffDay}d ago`;
    return then.toLocaleDateString();
}

function updateNotifBadge() {
    const badge = document.getElementById('notifBadge');
    if (!badge) return;
    if (unreadNotifCount > 0) {
        badge.textContent = unreadNotifCount > 99 ? '99+' : unreadNotifCount;
        badge.style.display = 'inline';
    } else {
        badge.style.display = 'none';
    }
}

let notifPollFailures = 0;

async function pollUnreadCount() {
    try {
        const res = await fetch('/notifications/unread-count');
        if (!res.ok) return;
        const data = await res.json();
        unreadNotifCount = data.unread_count || 0;
        updateNotifBadge();
        // Reset backoff on success
        if (notifPollFailures > 0) {
            notifPollFailures = 0;
            restartNotifPolling(30000);
        }
    } catch (e) {
        notifPollFailures++;
        const backoff = Math.min(30000 * Math.pow(2, notifPollFailures), 300000);
        restartNotifPolling(backoff);
    }
}

function restartNotifPolling(intervalMs) {
    if (notifPollInterval) clearInterval(notifPollInterval);
    notifPollInterval = setInterval(pollUnreadCount, intervalMs);
}

function startNotifPolling() {
    notifPollFailures = 0;
    pollUnreadCount();
    if (notifPollInterval) clearInterval(notifPollInterval);
    notifPollInterval = setInterval(pollUnreadCount, 30000);
}

function stopNotifPolling() {
    if (notifPollInterval) {
        clearInterval(notifPollInterval);
        notifPollInterval = null;
    }
    unreadNotifCount = 0;
    updateNotifBadge();
}

function toggleNotifPanel() {
    const panel = document.getElementById('notifPanel');
    if (!panel) return;
    if (panel.style.display === 'none' || !panel.style.display) {
        panel.style.display = 'block';
        loadNotifications(1);
    } else {
        panel.style.display = 'none';
    }
}

// Close dropdown when clicking outside
document.addEventListener('click', (e) => {
    const panel = document.getElementById('notifPanel');
    const bell = document.getElementById('notifBell');
    if (panel && panel.style.display !== 'none') {
        if (!panel.contains(e.target) && !bell.contains(e.target)) {
            panel.style.display = 'none';
        }
    }
});

async function loadNotifications(page) {
    const list = document.getElementById('notifList');
    if (!list) return;
    try {
        const res = await fetch(`/notifications?page=${page}&per_page=20`);
        const data = await res.json();
        notifications = data.notifications || [];
        unreadNotifCount = data.unread_count || 0;
        updateNotifBadge();
        renderNotifications(data, page);
    } catch (e) {
        list.innerHTML = '<div style="padding:16px;color:#999;font-size:0.85em;">Failed to load notifications.</div>';
    }
}

function renderNotifications(data, currentPage) {
    const list = document.getElementById('notifList');
    if (!list) return;
    if (!data.notifications || !data.notifications.length) {
        list.innerHTML = '<div style="padding:20px;color:#999;text-align:center;font-size:0.85em;">No notifications yet.</div>';
        return;
    }
    let html = '';
    for (const n of data.notifications) {
        const { icon, color } = getNotifIcon(n.type);
        const unreadClass = n.is_read ? '' : 'notif-unread';
        html += `
            <div class="notif-item ${unreadClass}" onclick="handleNotifClick(${n.id}, '${escapeHtml(n.link || '')}')">
                <div class="notif-icon"><i class="fa-solid ${icon}" style="color:${color};"></i></div>
                <div class="notif-content">
                    <div class="notif-title">${escapeHtml(n.title)}</div>
                    ${n.message ? `<div class="notif-message">${escapeHtml(n.message)}</div>` : ''}
                    <div class="notif-time">${formatTimeAgo(n.created_at)}</div>
                </div>
            </div>`;
    }
    if (data.pages > 1) {
        html += '<div class="notif-pagination">';
        if (currentPage > 1) html += `<a href="#" onclick="loadNotifications(${currentPage - 1}); return false;">« Prev</a>`;
        html += `<span>Page ${currentPage} of ${data.pages}</span>`;
        if (currentPage < data.pages) html += `<a href="#" onclick="loadNotifications(${currentPage + 1}); return false;">Next »</a>`;
        html += '</div>';
    }
    list.innerHTML = html;
}

async function handleNotifClick(notifId, link) {
    try {
        await fetch('/notifications/mark-read', {
            method: 'POST',
            headers: csrfHeaders(),
            body: JSON.stringify({ ids: [notifId] })
        });
        unreadNotifCount = Math.max(0, unreadNotifCount - 1);
        updateNotifBadge();
        // Update the item visually
        const items = document.querySelectorAll('.notif-item');
        items.forEach(el => {
            if (el.getAttribute('onclick') && el.getAttribute('onclick').includes(`handleNotifClick(${notifId},`)) {
                el.classList.remove('notif-unread');
            }
        });
    } catch (e) { /* silent */ }
    if (link) {
        document.getElementById('notifPanel').style.display = 'none';
        // Navigate to the linked resource
        window.location.hash = link.replace('#', '');
    }
}

async function markAllNotifsRead() {
    try {
        await fetch('/notifications/mark-read', {
            method: 'POST',
            headers: csrfHeaders(),
            body: JSON.stringify({ ids: [] })
        });
        unreadNotifCount = 0;
        updateNotifBadge();
        document.querySelectorAll('.notif-item').forEach(el => el.classList.remove('notif-unread'));
    } catch (e) { /* silent */ }
}

async function loadNotifPreferences() {
    try {
        const res = await fetch('/notifications/preferences');
        const data = await res.json();
        notificationPreferences = data.preferences || {};
    } catch (e) { console.error('Failed to load notification preferences:', e); }
}

function renderNotifPreferences() {
    const container = document.getElementById('notifPrefsContainer');
    if (!container) return;
    const labels = {
        ticket_assigned:       'Ticket assigned to me',
        ticket_accepted:       'My ticket accepted',
        ticket_resolved:       'Ticket resolved',
        ticket_reopened:       'Ticket reopened',
        ticket_commented:      'New comment on ticket',
        ticket_mentioned:      'Mentioned in comment',
        ticket_reassigned:     'Ticket reassigned',
        ticket_confirmed:      'Resolution confirmed',
        ticket_status_changed: 'Ticket status changed',
        risk_decision:         'Risk decision made',
        policy_updated:        'Org policy updated',
        threshold_changed:     'Risk threshold changed',
        rescan_completed:      'Rescan completed',
    };
    let html = '';
    for (const type of Object.keys(labels)) {
        const enabled = notificationPreferences[type] !== false;
        html += `
            <label class="notif-pref-row">
                <input type="checkbox" ${enabled ? 'checked' : ''} onchange="onNotifPrefToggle(this, '${type}')">
                ${labels[type]}
            </label>`;
    }
    container.innerHTML = html;
}

async function onNotifPrefToggle(el, type) {
    notificationPreferences[type] = el.checked;
    try {
        await fetch('/notifications/preferences', {
            method: 'POST',
            headers: csrfHeaders(),
            body: JSON.stringify({ preferences: { [type]: el.checked } })
        });
    } catch (e) { console.error('Failed to save notification preference:', e); }
}

async function openNotifPreferences() {
    const modal = document.getElementById('notifPrefsModal');
    if (!modal) return;
    await loadNotifPreferences();
    renderNotifPreferences();
    modal.style.display = 'flex';
}
