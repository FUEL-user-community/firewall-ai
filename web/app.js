/* ═══════════════════════════════════════════════════════
   Core Defense — Autonomous Defense Deck Application Logic
   ═══════════════════════════════════════════════════════
   Handles: Card deck rendering, SSE streaming for both
   cards and chat, filter controls, schedule modal,
   collapsible chat panel, severity counters, and audio alerts.
   ═══════════════════════════════════════════════════════ */

const STORAGE_KEY = 'nodal_history';
const MAX_HISTORY = 50;
const CARD_POLL_INTERVAL = 15000; // Poll for cards every 15s as fallback

let busy = false;
let currentFilter = 'all';
let cardSSE = null; // SSE connection for card events

// ═══════════════════════════════════════════════════════
// Initialization
// ═══════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
    bindLogin();
    bindSetup();
    bindForm();
    bindTextarea();
    bindChatPanel();
    bindResizeHandle();
    bindFilters();
    bindScheduleModal();
    bindKeyboardShortcuts();
    restoreChatWidth();
    checkHealth();

    // Check if already logged in
    const key = sessionStorage.getItem('nodal_key');
    if (key) {
        verifyKey(key).then(valid => {
            if (valid) {
                unlockApp();
            } else {
                sessionStorage.removeItem('nodal_key');
            }
        });
    }
});

// ═══════════════════════════════════════════════════════
// Health Check
// ═══════════════════════════════════════════════════════

function checkHealth() {
    fetch('/api/health')
        .then(r => r.json())
        .then(data => {
            if (!data.configured) {
                document.getElementById('loginOverlay').style.display = 'none';
                document.getElementById('setupOverlay').style.display = 'flex';
            }

            const dot = document.getElementById('statusDot');
            const text = document.getElementById('statusText');
            if (data.firewall_reachable) {
                dot.className = 'status-dot connected';
                text.textContent = data.firewall_ip || 'Connected';
            } else if (data.configured) {
                dot.className = 'status-dot disconnected';
                text.textContent = 'Firewall unreachable';
            } else {
                dot.className = 'status-dot disconnected';
                text.textContent = 'Not configured';
            }
        })
        .catch(() => {
            document.getElementById('statusDot').className = 'status-dot disconnected';
            document.getElementById('statusText').textContent = 'Offline';
        });
}

// ═══════════════════════════════════════════════════════
// Card Deck — Rendering & Management
// ═══════════════════════════════════════════════════════

function loadCards() {
    const key = sessionStorage.getItem('nodal_key');
    const params = currentFilter !== 'all' ? `?severity=${currentFilter}` : '';

    fetch(`/api/cards${params}`, {
        headers: { 'X-API-Key': key }
    })
    .then(r => r.json())
    .then(data => {
        renderCards(data.cards || []);
        updateCounters(data.counts || {});
    })
    .catch(err => {
        console.warn('[NODAL] Card load error:', err);
    });
}

function renderCards(cards) {
    const deck = document.getElementById('cardDeck');
    const empty = document.getElementById('deckEmpty');

    if (cards.length === 0) {
        if (empty) empty.style.display = 'flex';
        // Remove existing cards but keep empty state
        deck.querySelectorAll('.defense-card').forEach(c => c.remove());
        return;
    }

    if (empty) empty.style.display = 'none';

    // Build card HTML
    const existingIds = new Set();
    deck.querySelectorAll('.defense-card').forEach(c => existingIds.add(c.dataset.id));

    const newCardIds = new Set(cards.map(c => c.id));

    // Remove cards that are no longer in the list
    deck.querySelectorAll('.defense-card').forEach(c => {
        if (!newCardIds.has(c.dataset.id)) c.remove();
    });

    // Add new cards
    cards.forEach(card => {
        if (existingIds.has(card.id)) return; // Already rendered
        const cardEl = createCardElement(card);
        deck.appendChild(cardEl);
    });
}

function createCardElement(card) {
    const div = document.createElement('div');
    div.className = `defense-card severity-${card.severity}`;
    div.dataset.id = card.id;
    div.dataset.severity = card.severity;

    const timeStr = card.timestamp
        ? new Date(card.timestamp * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        : '';

    // Build evidence HTML
    let evidenceHTML = '';
    if (card.evidence && card.evidence.length > 0) {
        const items = card.evidence.map(e => `<li>${esc(String(e))}</li>`).join('');
        evidenceHTML = `
            <details class="card-evidence">
                <summary>Evidence chain (${card.evidence.length} items)</summary>
                <ul class="card-evidence-list">${items}</ul>
            </details>
        `;
    }

    // Build metrics HTML
    let metricsHTML = '';
    if (card.metrics && Object.keys(card.metrics).length > 0) {
        const chips = Object.entries(card.metrics).map(([k, v]) =>
            `<span class="metric-chip"><span class="metric-key">${esc(k)}:</span> <span class="metric-val">${esc(String(v))}</span></span>`
        ).join('');
        metricsHTML = `<div class="card-metrics">${chips}</div>`;
    }

    // Build Visibility HTML (Logprobs, Auditor, Drift)
    let visibilityHTML = '';
    let titleAdditions = '';

    // Semantic Drift badge parsing (extracting from finding text if present)
    if (card.finding && card.finding.includes("SEMANTIC DRIFT")) {
        const isCritical = card.finding.includes("SEVERE");
        const severityClass = isCritical ? 'critical' : 'caution';
        titleAdditions += `<span class="drift-badge ${severityClass}">Drift Detected</span>`;
    }

    // Confidence Bar (Logprobs)
    if (card.confidence_margin !== null && card.confidence_margin !== undefined) {
        const margin = parseFloat(card.confidence_margin);
        const percent = Math.min(100, Math.max(0, margin * 100)).toFixed(1);
        let level = 'high';
        if (margin < 0.20) level = 'low';
        else if (margin < 0.50) level = 'medium';

        visibilityHTML += `
            <div class="confidence-container">
                <div class="confidence-header">
                    <span>LLM Confidence Margin</span>
                    <span class="confidence-margin-val ${level}">${percent}%</span>
                </div>
                <div class="confidence-bar-bg">
                    <div class="confidence-fill ${level}" style="width: ${percent}%"></div>
                </div>
            </div>
        `;
    }

    // Audit Panel (Debate Protocol)
    if (card.audit_result && typeof card.audit_result.audit_score !== 'undefined') {
        const audit = card.audit_result;
        const isVerified = audit.audit_score === 1.0 && (!audit.disputes || audit.disputes.length === 0);
        
        let auditBody = '';
        if (isVerified) {
            auditBody = `<div class="audit-body">No logical flaws or fabrications detected by Flash auditor.</div>`;
        } else {
            const disputesHTML = (audit.disputes || []).map(d => `
                <div class="audit-dispute">
                    <div class="audit-dispute-claim">Claim: ${esc(d.claim || '')}</div>
                    <div class="audit-dispute-issue">Issue: ${esc(d.issue || '')}</div>
                </div>
            `).join('');
            auditBody = `<div class="audit-body">${esc(audit.summary || 'Issues found during audit.')}${disputesHTML}</div>`;
        }

        visibilityHTML += `
            <div class="audit-panel ${isVerified ? 'verified' : 'disputed'}">
                <div class="audit-header">
                    <span>Flash Auditor Protocol</span>
                    <span>Score: ${audit.audit_score.toFixed(2)}</span>
                </div>
                ${auditBody}
            </div>
        `;
    }

    // Build actions HTML
    let actionsHTML = '';
    if (card.actions && card.actions.length > 0) {
        const buttons = card.actions.map(action => {
            const type = action.type || 'tool';
            let btnClass = 'action-primary';
            if (type === 'open_chat') btnClass = 'action-primary';
            else if (type === 'suppress') btnClass = 'action-mute';
            else if (action.requires_approval) btnClass = 'action-danger';
            else btnClass = 'action-approve';

            return `<button class="card-action-btn ${btnClass}"
                data-action-type="${type}"
                data-card-id="${card.id}"
                data-card-key="${card.card_key}"
                data-card-title="${esc(card.title)}"
                data-tool="${action.tool || ''}"
                data-duration="${action.duration_hours || 24}"
                onclick="handleCardAction(this)">${esc(action.label)}</button>`;
        }).join('');

        // Always add a dismiss button
        actionsHTML = `<div class="card-actions">${buttons}
            <button class="card-action-btn action-mute" onclick="dismissCard('${card.id}')">Dismiss</button>
        </div>`;
    } else {
        actionsHTML = `<div class="card-actions">
            <button class="card-action-btn action-primary" onclick="investigateCard('${card.id}', '${esc(card.title)}')">Investigate</button>
            <button class="card-action-btn action-mute" onclick="dismissCard('${card.id}')">Dismiss</button>
        </div>`;
    }

    div.innerHTML = `
        <div class="card-header">
            <span class="card-severity-badge badge-${card.severity}">${card.severity}</span>
            <span class="card-title">${esc(card.title)} ${titleAdditions}</span>
            <span class="card-id">${esc(card.card_id)}</span>
            <span class="card-time">${timeStr}</span>
        </div>
        <div class="card-body">
            <p class="card-finding">${esc(card.finding)}</p>
            ${visibilityHTML}
        </div>
        ${metricsHTML}
        ${evidenceHTML}
        ${actionsHTML}
    `;

    return div;
}

function updateCounters(counts) {
    const crit = counts.critical || 0;
    const caut = counts.caution || 0;
    const norm = counts.normal || 0;

    const critEl = document.getElementById('countCritical');
    const cautEl = document.getElementById('countCaution');
    const normEl = document.getElementById('countNormal');

    critEl.textContent = crit;
    cautEl.textContent = caut;
    normEl.textContent = norm;

    // Animate critical counter
    if (crit > 0) {
        critEl.classList.add('active');
    } else {
        critEl.classList.remove('active');
    }
}

// ═══════════════════════════════════════════════════════
// Card Actions
// ═══════════════════════════════════════════════════════

function handleCardAction(btn) {
    const actionType = btn.dataset.actionType;
    const cardId = btn.dataset.cardId;
    const cardKey = btn.dataset.cardKey;
    const cardTitle = btn.dataset.cardTitle;

    switch (actionType) {
        case 'open_chat':
            investigateCard(cardId, cardTitle);
            break;
        case 'suppress':
            muteCard(cardId, parseInt(btn.dataset.duration) || 24);
            break;
        default:
            // Tool-based action — approve it
            approveCard(cardId);
    }
}

function investigateCard(cardId, title) {
    // Open chat panel pre-populated with investigation query
    openChat();
    const input = document.getElementById('input');
    input.value = `Investigate: ${title}`;
    input.focus();
}

function approveCard(cardId) {
    const key = sessionStorage.getItem('nodal_key');
    fetch(`/api/cards/${cardId}/approve`, {
        method: 'POST',
        headers: { 'X-API-Key': key }
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            // Remove card from deck with animation
            const cardEl = document.querySelector(`.defense-card[data-id="${cardId}"]`);
            if (cardEl) {
                cardEl.style.transition = 'all 0.3s ease';
                cardEl.style.opacity = '0';
                cardEl.style.transform = 'translateX(20px)';
                setTimeout(() => cardEl.remove(), 300);
            }
            loadCards(); // Refresh
        }
    });
}

function dismissCard(cardId) {
    const key = sessionStorage.getItem('nodal_key');
    fetch(`/api/cards/${cardId}/deny`, {
        method: 'POST',
        headers: { 'X-API-Key': key }
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            const cardEl = document.querySelector(`.defense-card[data-id="${cardId}"]`);
            if (cardEl) {
                cardEl.style.transition = 'all 0.3s ease';
                cardEl.style.opacity = '0';
                cardEl.style.transform = 'translateX(20px)';
                setTimeout(() => cardEl.remove(), 300);
            }
            loadCards();
        }
    });
}

function muteCard(cardId, hours) {
    const key = sessionStorage.getItem('nodal_key');
    fetch(`/api/cards/${cardId}/mute`, {
        method: 'POST',
        headers: {
            'X-API-Key': key,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ hours })
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            const cardEl = document.querySelector(`.defense-card[data-id="${cardId}"]`);
            if (cardEl) {
                cardEl.style.transition = 'all 0.3s ease';
                cardEl.style.opacity = '0';
                setTimeout(() => cardEl.remove(), 300);
            }
            loadCards();
        }
    });
}

// ═══════════════════════════════════════════════════════
// SSE Card Stream
// ═══════════════════════════════════════════════════════

function connectCardSSE() {
    if (cardSSE) cardSSE.close();

    const key = sessionStorage.getItem('nodal_key');
    cardSSE = new EventSource(`/api/cards/stream?key=${encodeURIComponent(key)}`);

    cardSSE.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            if (data.type === 'card') {
                // New card arrived — prepend to deck
                const deck = document.getElementById('cardDeck');
                const empty = document.getElementById('deckEmpty');
                if (empty) empty.style.display = 'none';

                const cardEl = createCardElement(data.data);
                deck.insertBefore(cardEl, deck.firstChild);

                // Update counters
                loadCards(); // Full refresh for accurate counts

                // Audio alert for CRITICAL
                if (data.data.severity === 'critical') {
                    playAlertSound();
                }
            }
        } catch (e) {
            console.warn('[NODAL] SSE parse error:', e);
        }
    };

    cardSSE.onerror = () => {
        // Reconnect after delay
        setTimeout(connectCardSSE, 5000);
    };
}

function playAlertSound() {
    try {
        const audio = document.getElementById('alertSound');
        if (audio) audio.play().catch(() => {});
    } catch (e) {}
}

// ═══════════════════════════════════════════════════════
// Filters
// ═══════════════════════════════════════════════════════

function bindFilters() {
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            currentFilter = btn.dataset.filter;
            loadCards();
        });
    });
}

// ═══════════════════════════════════════════════════════
// Chat Panel — Open / Close / Collapse / Fullscreen
// ═══════════════════════════════════════════════════════

let chatIsFullscreen = false;
let chatIsCollapsed = false;

function bindChatPanel() {
    document.getElementById('chatToggle').addEventListener('click', openChat);
    document.getElementById('btnToggleChat').addEventListener('click', toggleChat);
    document.getElementById('btnFullscreenChat').addEventListener('click', toggleFullscreenChat);
    document.getElementById('btnCollapseChat').addEventListener('click', collapseChat);
    document.getElementById('btnExpandFromStrip').addEventListener('click', expandFromCollapse);
}

function openChat() {
    const dashboard = document.getElementById('dashboard');
    dashboard.classList.remove('chat-collapsed');
    chatIsCollapsed = false;
    document.getElementById('chatToggle').style.display = 'none';
    document.getElementById('chatExpanded').style.display = 'flex';
    document.getElementById('input').focus();
}

function collapseChat() {
    const dashboard = document.getElementById('dashboard');
    // Exit fullscreen first if active
    if (chatIsFullscreen) {
        dashboard.classList.remove('chat-fullscreen');
        chatIsFullscreen = false;
    }
    dashboard.classList.add('chat-collapsed');
    chatIsCollapsed = true;
}

function expandFromCollapse() {
    const dashboard = document.getElementById('dashboard');
    dashboard.classList.remove('chat-collapsed');
    chatIsCollapsed = false;
    document.getElementById('chatExpanded').style.display = 'flex';
    document.getElementById('input').focus();
}

function toggleFullscreenChat() {
    const dashboard = document.getElementById('dashboard');
    if (chatIsFullscreen) {
        // Restore to split view
        dashboard.classList.remove('chat-fullscreen');
        chatIsFullscreen = false;
        // Restore transition temporarily disabled during fullscreen
        dashboard.style.transition = '';
    } else {
        // Go fullscreen
        dashboard.classList.add('chat-fullscreen');
        chatIsFullscreen = true;
    }
    document.getElementById('input').focus();
}

function toggleChat() {
    if (chatIsCollapsed) {
        expandFromCollapse();
    } else {
        document.getElementById('input').focus();
    }
}

function closeChat() {
    // Escape key handler — exit fullscreen first, then collapse
    if (chatIsFullscreen) {
        toggleFullscreenChat();
    } else {
        collapseChat();
    }
}

// ═══════════════════════════════════════════════════════
// Chat Panel — Drag Resize
// ═══════════════════════════════════════════════════════

const CHAT_MIN_WIDTH = 320;
const CHAT_MAX_WIDTH_RATIO = 0.65;
const CHAT_WIDTH_STORAGE_KEY = 'nodal_chat_width';

function bindResizeHandle() {
    const handle = document.getElementById('resizeHandle');
    const dashboard = document.getElementById('dashboard');
    const chatPanel = document.getElementById('chatPanel');
    let startX, startWidth;

    handle.addEventListener('mousedown', (e) => {
        e.preventDefault();
        startX = e.clientX;
        startWidth = chatPanel.offsetWidth;
        document.body.classList.add('resizing');
        handle.classList.add('dragging');
        // Disable grid transition during drag for smooth resize
        dashboard.style.transition = 'none';

        function onMouseMove(e) {
            const delta = startX - e.clientX; // dragging left = wider
            const maxW = window.innerWidth * CHAT_MAX_WIDTH_RATIO;
            const newWidth = Math.min(maxW, Math.max(CHAT_MIN_WIDTH, startWidth + delta));
            setChatWidth(newWidth);
        }

        function onMouseUp() {
            document.removeEventListener('mousemove', onMouseMove);
            document.removeEventListener('mouseup', onMouseUp);
            document.body.classList.remove('resizing');
            handle.classList.remove('dragging');
            dashboard.style.transition = '';
            // Persist
            const currentWidth = chatPanel.offsetWidth;
            localStorage.setItem(CHAT_WIDTH_STORAGE_KEY, currentWidth);
        }

        document.addEventListener('mousemove', onMouseMove);
        document.addEventListener('mouseup', onMouseUp);
    });
}

function setChatWidth(px) {
    const dashboard = document.getElementById('dashboard');
    const chatPanel = document.getElementById('chatPanel');
    dashboard.style.setProperty('--chat-width', px + 'px');
    // Toggle wide-mode class for font scaling
    if (px > 600) {
        chatPanel.classList.add('wide-mode');
    } else {
        chatPanel.classList.remove('wide-mode');
    }
}

function restoreChatWidth() {
    const saved = localStorage.getItem(CHAT_WIDTH_STORAGE_KEY);
    if (saved) {
        const w = parseInt(saved, 10);
        if (w >= CHAT_MIN_WIDTH && w <= window.innerWidth * CHAT_MAX_WIDTH_RATIO) {
            setChatWidth(w);
        }
    }
}

// ═══════════════════════════════════════════════════════
// Schedule Modal
// ═══════════════════════════════════════════════════════

function bindScheduleModal() {
    document.getElementById('btnSchedule').addEventListener('click', openSchedule);
    document.getElementById('btnCloseSchedule').addEventListener('click', closeSchedule);

    document.getElementById('scheduleModal').addEventListener('click', (e) => {
        if (e.target === document.getElementById('scheduleModal')) closeSchedule();
    });
}

function openSchedule() {
    const modal = document.getElementById('scheduleModal');
    modal.style.display = 'flex';
    loadSchedule();
}

function closeSchedule() {
    document.getElementById('scheduleModal').style.display = 'none';
}

function loadSchedule() {
    const key = sessionStorage.getItem('nodal_key');
    fetch('/api/cards/schedule', {
        headers: { 'X-API-Key': key }
    })
    .then(r => r.json())
    .then(data => {
        const body = document.getElementById('scheduleBody');
        const entries = data.schedule || [];

        if (entries.length === 0) {
            body.innerHTML = '<p style="color: #666; text-align: center; padding: 20px;">No cards registered.</p>';
            return;
        }

        body.innerHTML = entries.map(entry => `
            <div class="schedule-entry">
                <span class="schedule-id">${esc(entry.card_id)}</span>
                <span class="schedule-name">${esc(entry.name)}</span>
                <span class="schedule-freq">${esc(entry.schedule)}</span>
                <span class="schedule-last">${esc(entry.last_run_human)}</span>
                <input type="checkbox" class="schedule-toggle"
                    ${entry.enabled ? 'checked' : ''}
                    data-card-key="${esc(entry.card_key)}"
                    onchange="toggleCardSchedule(this)">
            </div>
        `).join('');
    })
    .catch(err => {
        document.getElementById('scheduleBody').innerHTML =
            `<p style="color: #f87171; text-align: center; padding: 20px;">Error loading schedule</p>`;
    });
}

function toggleCardSchedule(toggle) {
    const cardKey = toggle.dataset.cardKey;
    const enabled = toggle.checked;
    const key = sessionStorage.getItem('nodal_key');

    fetch('/api/cards/schedule', {
        method: 'POST',
        headers: {
            'X-API-Key': key,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ card_key: cardKey, enabled })
    });
}

// ═══════════════════════════════════════════════════════
// Keyboard Shortcuts
// ═══════════════════════════════════════════════════════

function bindKeyboardShortcuts() {
    document.addEventListener('keydown', (e) => {
        // Cmd+K or Ctrl+K to toggle chat
        if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
            e.preventDefault();
            toggleChat();
        }
        // Ctrl+Shift+D to toggle demo mode
        if ((e.metaKey || e.ctrlKey) && e.shiftKey && e.key === 'D') {
            e.preventDefault();
            document.body.classList.toggle('demo-mode');
        }
        // Escape — exit fullscreen first, then collapse, then close modals
        if (e.key === 'Escape') {
            closeChat();
            closeSchedule();
        }
    });
}

// ═══════════════════════════════════════════════════════
// Login & Auth (preserved)
// ═══════════════════════════════════════════════════════

function bindLogin() {
    document.getElementById('loginForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const input = document.getElementById('loginInput');
        const btn = document.getElementById('loginBtn');
        const err = document.getElementById('loginError');
        const key = input.value.trim();

        if (!key) return;

        btn.disabled = true;
        btn.textContent = 'Verifying...';
        err.textContent = '';

        const valid = await verifyKey(key);
        if (valid) {
            sessionStorage.setItem('nodal_key', key);
            unlockApp();
        } else {
            err.textContent = 'Invalid passphrase. Try again.';
            input.value = '';
            input.focus();
        }

        btn.disabled = false;
        btn.textContent = 'Connect';
    });
}

async function verifyKey(key) {
    try {
        const res = await fetch('/api/login', {
            method: 'POST',
            headers: { 'X-API-Key': key }
        });
        return res.ok;
    } catch (e) {
        return false;
    }
}

function unlockApp() {
    document.getElementById('loginOverlay').style.display = 'none';
    document.getElementById('dashboard').style.display = 'grid';

    // Load cards immediately
    loadCards();

    // Connect SSE for real-time card delivery
    connectCardSSE();

    // Start card polling as fallback
    setInterval(loadCards, CARD_POLL_INTERVAL);
}

// ═══════════════════════════════════════════════════════
// Setup Wizard (preserved)
// ═══════════════════════════════════════════════════════

function bindSetup() {
    const s1 = document.getElementById('setupStep1');
    const s2 = document.getElementById('setupStep2');
    const s3 = document.getElementById('setupStep3');

    document.getElementById('btnSetupSimple').addEventListener('click', () => {
        document.getElementById('setupBackend').value = 'dotenv';
        document.getElementById('setupSimpleFields').style.display = 'flex';
        document.getElementById('setupVaultFields').style.display = 'none';
        s1.style.display = 'none';
        s2.style.display = 'block';
    });

    document.getElementById('btnSetupVault').addEventListener('click', () => {
        document.getElementById('setupBackend').value = 'vault';
        document.getElementById('setupSimpleFields').style.display = 'none';
        document.getElementById('setupVaultFields').style.display = 'flex';
        s1.style.display = 'none';
        s2.style.display = 'block';
    });

    document.getElementById('btnSetupBack').addEventListener('click', () => {
        s2.style.display = 'none';
        s1.style.display = 'block';
    });

    document.getElementById('setupForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const btn = document.getElementById('setupSubmitBtn');
        const err = document.getElementById('setupError');

        btn.disabled = true;
        btn.textContent = 'Saving...';
        err.textContent = '';

        const payload = {
            backend_type: document.getElementById('setupBackend').value,
            firewall_ip: document.getElementById('setupFwIp').value,
            panos_key: document.getElementById('setupPanosKey').value,
            gemini_key: document.getElementById('setupGeminiKey').value,
            vault_addr: document.getElementById('setupVaultAddr').value,
            vault_role: document.getElementById('setupVaultRole').value,
            vault_secret: document.getElementById('setupVaultSecret').value
        };

        try {
            const res = await fetch('/api/setup', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const data = await res.json();

            if (data.success) {
                document.getElementById('setupPassphrase').textContent = data.passphrase;
                s2.style.display = 'none';
                s3.style.display = 'block';
            } else {
                err.textContent = data.error || 'Setup failed';
            }
        } catch (error) {
            err.textContent = 'Connection error: ' + error.message;
        }

        btn.disabled = false;
        btn.textContent = 'Save & Initialize';
    });

    document.getElementById('btnCopyPassphrase').addEventListener('click', () => {
        const text = document.getElementById('setupPassphrase').textContent;
        navigator.clipboard.writeText(text);
        const btn = document.getElementById('btnCopyPassphrase');
        btn.textContent = 'Copied!';
        setTimeout(() => btn.textContent = 'Copy to Clipboard', 2000);
    });

    document.getElementById('btnProceedLogin').addEventListener('click', () => {
        document.getElementById('setupOverlay').style.display = 'none';
        document.getElementById('loginOverlay').style.display = 'flex';
        document.getElementById('loginInput').focus();
        checkHealth();
    });
}

// ═══════════════════════════════════════════════════════
// Chat — Sending & Streaming (preserved from original)
// ═══════════════════════════════════════════════════════

function bindForm() {
    document.getElementById('chatForm').addEventListener('submit', (e) => {
        e.preventDefault();
        const input = document.getElementById('input');
        const text = input.value.trim();
        if (text && !busy) {
            sendMessage(text);
        }
    });
}

function bindTextarea() {
    const textarea = document.getElementById('input');

    textarea.addEventListener('input', () => {
        textarea.style.height = 'auto';
        textarea.style.height = Math.min(textarea.scrollHeight, 100) + 'px';
    });

    textarea.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            const text = textarea.value.trim();
            if (text && !busy) {
                sendMessage(text);
            }
        }
    });
}

function sendMessage(text) {
    const input = document.getElementById('input');
    input.value = '';
    input.style.height = 'auto';

    addMsg('user', text);
    showStatus('Investigating...');
    document.getElementById('chatPanel').classList.add('investigating');

    busy = true;
    document.getElementById('sendBtn').disabled = true;

    const key = sessionStorage.getItem('nodal_key');
    fetch('/api/chat', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-API-Key': key
        },
        body: JSON.stringify({ message: text })
    })
    .then(res => {
        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buf = '';

        function read() {
            reader.read().then(({ done, value }) => {
                if (done) return finish('');

                buf += decoder.decode(value, { stream: true });
                const lines = buf.split('\n');
                buf = lines.pop();

                for (const line of lines) {
                    if (!line.startsWith('data: ')) continue;
                    try {
                        const d = JSON.parse(line.slice(6));
                        if (d.type === 'status') {
                            updateStatus(d.content);
                        } else if (d.type === 'response') {
                            return finish(d.content);
                        } else if (d.type === 'error') {
                            return finish('⚠️ ' + d.content);
                        }
                    } catch (_) {}
                }
                read();
            });
        }
        read();
    })
    .catch(err => finish('⚠️ Connection error: ' + err.message));
}

function finish(text) {
    removeStatus();
    document.getElementById('chatPanel').classList.remove('investigating');
    if (text) {
        addMsg('agent', text);
    }
    busy = false;
    document.getElementById('sendBtn').disabled = false;
    document.getElementById('input').focus();
}

// ═══════════════════════════════════════════════════════
// Status Line
// ═══════════════════════════════════════════════════════

function showStatus(text) {
    removeStatus();
    const div = document.createElement('div');
    div.className = 'status-line';
    div.id = 'statusLine';
    div.innerHTML = `<div class="status-spinner"></div><span class="status-label">${esc(text)}</span>`;
    document.getElementById('messages').appendChild(div);
    scrollChatToBottom();
}

function updateStatus(text) {
    // --- Semantic Drift Telemetry ---
    // Format: [DRIFT:severity:similarity:turn]
    const driftMatch = text.match(/\[DRIFT:(normal|caution|critical):([\d.]+):T(\d+)\]/);
    if (driftMatch) {
        const severity = driftMatch[1];
        const similarity = parseFloat(driftMatch[2]);
        const turn = parseInt(driftMatch[3]);
        renderDriftMeter(severity, similarity, turn);
        return; // Don't overwrite the main status line with raw drift data
    }

    const label = document.querySelector('#statusLine .status-label');
    if (label) {
        label.textContent = text;
    } else {
        showStatus(text);
    }
}

function renderDriftMeter(severity, similarity, turn) {
    let meter = document.getElementById('driftMeter');
    if (!meter) {
        meter = document.createElement('div');
        meter.id = 'driftMeter';
        meter.className = 'drift-meter';
    }
    
    // Always move it to the current position (after statusLine)
    const statusLine = document.getElementById('statusLine');
    if (statusLine) {
        statusLine.parentNode.insertBefore(meter, statusLine.nextSibling);
    } else {
        document.getElementById('messages').appendChild(meter);
    }

    const pct = Math.round(similarity * 100);
    const colorMap = { normal: '#00e676', caution: '#ffab00', critical: '#ff1744' };
    const labelMap = { normal: 'COHERENT', caution: 'DIVERGING', critical: 'DRIFT DETECTED' };
    const color = colorMap[severity] || '#00e676';
    const label = labelMap[severity] || 'UNKNOWN';

    meter.innerHTML = `
        <div class="drift-header">
            <span class="drift-icon">◉</span>
            <span class="drift-title">Cognitive Coherence</span>
            <span class="drift-turn">Turn ${turn}</span>
        </div>
        <div class="drift-bar-track">
            <div class="drift-bar-fill" style="width:${pct}%;background:${color}"></div>
        </div>
        <div class="drift-footer">
            <span class="drift-score" style="color:${color}">${pct}% — ${label}</span>
            <span class="drift-raw">${similarity.toFixed(3)} cosine</span>
        </div>
    `;
    meter.style.borderColor = color + '33';
    scrollChatToBottom();
}

function removeStatus() {
    const el = document.getElementById('statusLine');
    if (el) el.remove();
}

// ═══════════════════════════════════════════════════════
// Message Rendering
// ═══════════════════════════════════════════════════════

function addMsg(role, text) {
    const container = document.createElement('div');
    container.style.display = 'flex';
    container.style.flexDirection = 'column';
    container.style.alignItems = role === 'user' ? 'flex-end' : 'flex-start';

    const msgDiv = document.createElement('div');
    msgDiv.className = role === 'user' ? 'msg-user' : 'msg-agent';
    msgDiv.innerHTML = role === 'user' ? esc(text) : renderMarkdown(text);
    container.appendChild(msgDiv);

    const timeDiv = document.createElement('div');
    timeDiv.className = 'msg-time';
    timeDiv.textContent = timeNow();
    container.appendChild(timeDiv);

    document.getElementById('messages').appendChild(container);
    scrollChatToBottom();
}

// ═══════════════════════════════════════════════════════
// Markdown Renderer
// ═══════════════════════════════════════════════════════

function renderMarkdown(t) {
    if (!t) return '';
    let h = esc(t);

    // Severity Badges
    h = h.replace(/\[CRITICAL\]/g, '<span class="badge badge-critical">CRITICAL</span>');
    h = h.replace(/\[CAUTION\]/g, '<span class="badge badge-caution">CAUTION</span>');
    h = h.replace(/\[NORMAL\]/g, '<span class="badge badge-normal">NORMAL</span>');
    h = h.replace(/\[ASSESSMENT\]/g, '<span class="badge badge-info">ASSESSMENT</span>');
    h = h.replace(/\[INVESTIGATION\]/g, '<span class="badge badge-info">INVESTIGATION</span>');

    // Fenced Code Blocks
    h = h.replace(/```(\w*)\n([\s\S]*?)```/g, (_, lang, code) => {
        const lines = code.trim().split('\n');
        const content = '<pre><code>' + code.trim() + '</code></pre>';
        if (lines.length > 10) {
            return '<details><summary>Raw data (' + lines.length + ' lines)</summary>' + content + '</details>';
        }
        return content;
    });

    // Inline Code
    h = h.replace(/`([^`]+)`/g, '<code>$1</code>');

    // Bold / Italic
    h = h.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
    h = h.replace(/\*(.+?)\*/g, '<em>$1</em>');

    // Headings
    h = h.replace(/^### (.+)$/gm, '<h3>$1</h3>');
    h = h.replace(/^## (.+)$/gm, '<h2>$1</h2>');
    h = h.replace(/^# (.+)$/gm, '<h1>$1</h1>');

    // Horizontal Rules
    h = h.replace(/^---$/gm, '<hr>');

    // Lists
    h = h.replace(/^- (.+)$/gm, '<li>$1</li>');
    h = h.replace(/(<li>.*<\/li>\n?)+/g, '<ul>$&</ul>');

    // Tables
    h = renderTables(h);

    // Line Breaks
    h = h.replace(/\n\n/g, '<br><br>');
    h = h.replace(/\n/g, '<br>');

    return h;
}

function renderTables(t) {
    const lines = t.split('\n');
    let result = [];
    let rows = [];
    let inTable = false;

    for (const line of lines) {
        const s = line.trim();
        if (s.startsWith('|') && s.endsWith('|')) {
            if (/^\|[\s\-:|]+\|$/.test(s)) continue;
            if (!inTable) { inTable = true; rows = []; }
            rows.push(s.split('|').filter(c => c.trim()).map(c => c.trim()));
        } else {
            if (inTable) { result.push(buildTable(rows)); inTable = false; rows = []; }
            result.push(line);
        }
    }
    if (inTable) result.push(buildTable(rows));
    return result.join('\n');
}

function buildTable(rows) {
    if (!rows.length) return '';
    let h = '<table><thead><tr>' + rows[0].map(c => '<th>' + c + '</th>').join('') + '</tr></thead>';
    if (rows.length > 1) {
        h += '<tbody>' + rows.slice(1).map(r =>
            '<tr>' + r.map(c => '<td>' + c + '</td>').join('') + '</tr>'
        ).join('') + '</tbody>';
    }
    return h + '</table>';
}

// ═══════════════════════════════════════════════════════
// Utilities
// ═══════════════════════════════════════════════════════

function scrollChatToBottom() {
    const m = document.getElementById('messages');
    if (m) requestAnimationFrame(() => m.scrollTop = m.scrollHeight);
}

function timeNow() {
    return new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function esc(t) {
    const d = document.createElement('div');
    d.textContent = t;
    return d.innerHTML;
}
