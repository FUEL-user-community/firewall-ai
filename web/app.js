/* ═══════════════════════════════════════════════════════
   Core Defense — Autonomous Defense Deck Application Logic
   ═══════════════════════════════════════════════════════
   Handles: Card deck rendering, SSE streaming for both
   cards and chat, filter controls, instant search,
   fleet device selection, schedule modal with on-demand run,
   collapsible chat panel, active investigation context,
   glassmorphic toast notifications, and severity counters.
   ═══════════════════════════════════════════════════════ */

const STORAGE_KEY = 'nodal_history';
const MAX_HISTORY = 50;
const CARD_POLL_INTERVAL = 15000; // Poll for cards every 15s as fallback

// Cross-tab and persistent authentication helpers
function getAuthKey() {
    return sessionStorage.getItem('nodal_key') || localStorage.getItem('nodal_key') || '';
}

function setAuthKey(key) {
    if (key) {
        sessionStorage.setItem('nodal_key', key);
        localStorage.setItem('nodal_key', key);
    }
}

function clearAuthKey() {
    sessionStorage.removeItem('nodal_key');
    localStorage.removeItem('nodal_key');
}

// Centralized SOC State Store
const state = {
    cards: [],
    counts: { critical: 0, caution: 0, normal: 0 },
    activePlaybooksCount: 19,
    totalPlaybooksCount: 19,
    filter: 'all',        // 'all' | 'critical' | 'caution'
    scope: 'all',         // 'all' | 'action' | 'exposures' | 'lateral' | 'policy'
    device: 'all',        // 'all' | device_name
    sort: 'severity',     // 'severity' | 'newest' | 'oldest'
    searchQuery: '',
    activeInvestigationCard: null,
    devices: [],
    busy: false,
};

let busy = false;
let currentFilter = 'all'; // Backwards compatibility for SSE handlers
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
    bindDeckControls();
    bindDeckEventDelegation();
    bindScheduleModal();
    bindKeyboardShortcuts();
    bindContextBanner();
    restoreChatWidth();
    checkHealth();

    // Check if already logged in (sessionStorage or cross-tab localStorage)
    const key = getAuthKey();
    if (key) {
        verifyKey(key).then(valid => {
            if (valid) {
                setAuthKey(key);
                unlockApp();
            } else {
                clearAuthKey();
            }
        });
    }

    // Real-time cross-tab unlock synchronization
    window.addEventListener('storage', (e) => {
        if (e.key === 'nodal_key' && e.newValue) {
            sessionStorage.setItem('nodal_key', e.newValue);
            const overlay = document.getElementById('loginOverlay');
            if (overlay && overlay.style.display !== 'none') {
                unlockApp();
                showToast('Synchronized authentication from active tab', 'info');
            }
        }
    });
});

// ═══════════════════════════════════════════════════════
// Health Check & Fleet Devices
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

function loadDevices() {
    const key = getAuthKey();
    fetch('/api/devices', {
        headers: { 'X-API-Key': key }
    })
    .then(r => r.json())
    .then(data => {
        const firewalls = data.firewalls || {};
        const deviceNames = Object.keys(firewalls);
        deviceNames.forEach(d => {
            if (!state.devices.includes(d)) state.devices.push(d);
        });
        updateDeviceSelect();
    })
    .catch(err => {
        console.warn('[NODAL] Device load error:', err);
    });
}

function updateDeviceSelect() {
    const select = document.getElementById('deviceFilter');
    if (!select) return;
    const currentVal = select.value || 'all';

    // Collect all devices from both devices.yaml and loaded cards
    const allDevs = new Set(state.devices);
    state.cards.forEach(c => {
        if (c.device && c.device !== 'default') allDevs.add(c.device);
    });

    const sortedDevs = Array.from(allDevs).sort();
    const existingDevs = Array.from(select.options).slice(1).map(o => o.value);
    const hasChanged = sortedDevs.length !== existingDevs.length ||
        sortedDevs.some((d, i) => d !== existingDevs[i]);

    if (!hasChanged) return;

    select.innerHTML = '<option value="all">All Firewalls</option>';
    sortedDevs.forEach(dev => {
        const opt = document.createElement('option');
        opt.value = dev;
        opt.textContent = dev;
        select.appendChild(opt);
    });

    if (Array.from(select.options).some(o => o.value === currentVal)) {
        select.value = currentVal;
    }
}

// ═══════════════════════════════════════════════════════
// Card Deck — Loading, Filtering & Management
// ═══════════════════════════════════════════════════════

function loadCards() {
    const key = getAuthKey();

    fetch('/api/cards?status=all', {
        headers: { 'X-API-Key': key }
    })
    .then(r => r.json())
    .then(data => {
        const newCards = data.cards || [];
        const newCounts = data.counts || { critical: 0, caution: 0, normal: 0 };

        const cardsUnchanged = state.cards.length === newCards.length &&
            state.cards.every((c, i) => c.id === newCards[i].id && c.timestamp === newCards[i].timestamp);
        const countsUnchanged = state.counts &&
            state.counts.critical === newCounts.critical &&
            state.counts.caution === newCounts.caution &&
            state.counts.normal === newCounts.normal;

        state.cards = newCards;
        state.counts = newCounts;

        updateCounters(state.counts);
        updateDeviceSelect();

        if (!cardsUnchanged || !countsUnchanged) {
            renderFilteredDeck();
            syncScheduleCounts();
        }
    })
    .catch(err => {
        console.warn('[NODAL] Card load error:', err);
    });
}

function renderFilteredDeck() {
    const deck = document.getElementById('cardDeck');
    const empty = document.getElementById('deckEmpty');
    const emptyDesc = document.getElementById('deckEmptyDesc');
    const clearBtn = document.getElementById('btnClearFilters');
    if (!deck) return;

    // Filter cards by scope, severity, device, and search query
    const q = state.searchQuery.trim().toLowerCase();
    const scope = state.scope || 'all';

    let filtered = state.cards.filter(card => {
        // Operational Scope Filter
        if (scope !== 'all') {
            if (scope === 'action') {
                if (card.severity !== 'critical' && card.severity !== 'caution') {
                    return false;
                }
            } else if (scope === 'exposures') {
                const exposureKeys = ['ft-06', 'ft-07', 'ft-08', 'ft-09', 'ft-10', 'ft-14', 'ft-15'];
                const cid = (card.card_id || '').toLowerCase();
                const ckey = (card.card_key || '').toLowerCase();
                const text = `${card.title || ''} ${card.finding || ''} ${(card.evidence || []).join(' ')}`.toLowerCase();
                const isExposure = exposureKeys.some(k => cid.includes(k) || ckey.includes(k)) ||
                    text.includes('exposure') || text.includes('uninspected') || text.includes('corridor') ||
                    text.includes('permit') || text.includes('boundary') || text.includes('ingress') || text.includes('egress');
                if (!isExposure) return false;
            } else if (scope === 'lateral') {
                const lateralKeys = ['ft-01', 'ft-02', 'ft-03', 'ft-04'];
                const cid = (card.card_id || '').toLowerCase();
                const ckey = (card.card_key || '').toLowerCase();
                const text = `${card.title || ''} ${card.finding || ''} ${(card.evidence || []).join(' ')}`.toLowerCase();
                const isLateral = lateralKeys.some(k => cid.includes(k) || ckey.includes(k)) ||
                    text.includes('lateral') || text.includes('traverse') || text.includes('beacon') ||
                    text.includes('c2') || text.includes('tunnel') || text.includes('chain') || text.includes('exploit');
                if (!isLateral) return false;
            } else if (scope === 'policy') {
                const policyKeys = ['ft-05', 'ft-11', 'ft-12', 'ft-13', 'ft-16', 'ft-17', 'ft-18', 'ft-19'];
                const cid = (card.card_id || '').toLowerCase();
                const ckey = (card.card_key || '').toLowerCase();
                const text = `${card.title || ''} ${card.finding || ''} ${(card.evidence || []).join(' ')}`.toLowerCase();
                const isPolicy = policyKeys.some(k => cid.includes(k) || ckey.includes(k)) ||
                    text.includes('policy') || text.includes('zero-trust') || text.includes('drift') ||
                    text.includes('hygiene') || text.includes('decryption') || text.includes('cert') ||
                    text.includes('credential') || text.includes('audit');
                if (!isPolicy) return false;
            }
        }

        // Severity filter
        if (state.filter !== 'all' && card.severity !== state.filter) {
            return false;
        }

        // Device filter
        if (state.device !== 'all' && (card.device || 'default') !== state.device) {
            return false;
        }

        // Search query filter
        if (q) {
            const cardText = [
                card.title || '',
                card.card_id || '',
                card.card_key || '',
                card.device || '',
                card.finding || '',
                (card.evidence || []).join(' '),
                JSON.stringify(card.metrics || {}),
            ].join(' ').toLowerCase();

            if (!cardText.includes(q)) {
                return false;
            }
        }

        return true;
    });

    // Sort cards
    filtered.sort((a, b) => {
        if (state.sort === 'newest') {
            return (b.timestamp || 0) - (a.timestamp || 0);
        }
        if (state.sort === 'oldest') {
            return (a.timestamp || 0) - (b.timestamp || 0);
        }
        // Default: severity rank (critical > caution > normal), then newest
        const rank = { critical: 3, caution: 2, normal: 1 };
        const diff = (rank[b.severity] || 0) - (rank[a.severity] || 0);
        if (diff !== 0) return diff;
        return (b.timestamp || 0) - (a.timestamp || 0);
    });

    renderCards(filtered);

    // Update empty state messaging
    if (filtered.length === 0) {
        if (empty) empty.style.display = 'flex';
        const hasActiveFilter = (state.scope && state.scope !== 'all') || state.filter !== 'all' || state.device !== 'all' || q.length > 0;
        if (hasActiveFilter) {
            if (emptyDesc) emptyDesc.textContent = 'No defense cards match your current search and scope criteria.';
            if (clearBtn) clearBtn.style.display = 'inline-flex';
        } else {
            if (emptyDesc) emptyDesc.textContent = 'No defense alerts pending review across your fleet.';
            if (clearBtn) clearBtn.style.display = 'none';
        }
    } else {
        if (empty) empty.style.display = 'none';
        if (clearBtn) clearBtn.style.display = 'none';
    }
}

function renderCards(cards) {
    const deck = document.getElementById('cardDeck');
    if (!deck) return;

    // Existing cards in DOM
    const existingCardsMap = new Map();
    deck.querySelectorAll('.defense-card').forEach(c => {
        existingCardsMap.set(c.dataset.id, c);
    });

    const targetIds = new Set(cards.map(c => c.id));

    // Remove cards no longer in the filtered set
    existingCardsMap.forEach((el, id) => {
        if (!targetIds.has(id)) {
            el.remove();
        }
    });

    // Append / re-order cards without unnecessary DOM re-insertion
    cards.forEach((card, idx) => {
        let el = existingCardsMap.get(card.id);
        if (!el) {
            el = createCardElement(card);
            if (idx < deck.children.length) {
                deck.insertBefore(el, deck.children[idx]);
            } else {
                deck.appendChild(el);
            }
        } else if (deck.children[idx] !== el) {
            deck.insertBefore(el, deck.children[idx] || null);
        }
    });
}

function createCardElement(card) {
    const div = document.createElement('div');
    div.className = `defense-card severity-${card.severity}`;
    div.dataset.id = card.id;
    div.dataset.cardKey = card.card_key || '';
    div.dataset.severity = card.severity;
    div.dataset.device = card.device || 'default';

    const timeStr = card.timestamp
        ? new Date(card.timestamp * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        : '';

    // Evidence HTML
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

    // Metrics HTML
    let metricsHTML = '';
    if (card.metrics && Object.keys(card.metrics).length > 0) {
        const chips = Object.entries(card.metrics).map(([k, v]) =>
            `<span class="metric-chip"><span class="metric-key">${esc(k)}:</span> <span class="metric-val">${esc(String(v))}</span></span>`
        ).join('');
        metricsHTML = `<div class="card-metrics">${chips}</div>`;
    }

    // Reasoning Trace HTML
    let reasoningHTML = '';
    if (card.reasoning_trace && Array.isArray(card.reasoning_trace) && card.reasoning_trace.length > 0) {
        const steps = card.reasoning_trace.map(s => `<li>${esc(String(s))}</li>`).join('');
        reasoningHTML = `
            <details class="card-reasoning">
                <summary>Autonomous reasoning trace (${card.reasoning_trace.length} steps)</summary>
                <ol class="reasoning-list">${steps}</ol>
            </details>
        `;
    }

    // Visibility & Trust HTML
    let visibilityHTML = '';
    let titleAdditions = '';

    if (card.finding && card.finding.includes("SEMANTIC DRIFT")) {
        const isCritical = card.finding.includes("SEVERE");
        const severityClass = isCritical ? 'critical' : 'caution';
        titleAdditions += `<span class="drift-badge ${severityClass}">Drift Detected</span>`;
    }

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

    // Build Actions HTML using DATA ATTRIBUTES (Zero inline onclick interpolation!)
    let actionsHTML = '';
    if (card.actions && card.actions.length > 0) {
        const buttons = card.actions.map(action => {
            const type = action.type || 'tool';
            let btnClass = 'action-primary';
            if (type === 'open_chat') btnClass = 'action-primary';
            else if (type === 'suppress') btnClass = 'action-mute';
            else if (action.requires_approval) btnClass = 'action-danger';
            else btnClass = 'action-approve';

            return `<button type="button" class="card-action-btn ${btnClass}"
                data-action="tool"
                data-action-type="${type}"
                data-card-id="${card.id}"
                data-card-key="${esc(card.card_key || '')}"
                data-tool="${esc(action.tool || '')}"
                data-duration="${action.duration_hours || 24}">${esc(action.label)}</button>`;
        }).join('');

        actionsHTML = `<div class="card-actions">${buttons}
            <button type="button" class="card-action-btn action-mute" data-action="dismiss" data-card-id="${card.id}">Dismiss</button>
        </div>`;
    } else {
        actionsHTML = `<div class="card-actions">
            <button type="button" class="card-action-btn action-primary" data-action="investigate" data-card-id="${card.id}">Investigate</button>
            <button type="button" class="card-action-btn action-mute" data-action="dismiss" data-card-id="${card.id}">Dismiss</button>
        </div>`;
    }

    const deviceName = card.device || 'default';

    div.innerHTML = `
        <div class="card-header">
            <span class="card-severity-badge badge-${card.severity}">${card.severity}</span>
            <span class="card-device-badge" title="Target firewall device">
                <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/>
                    <line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/>
                </svg> ${esc(deviceName)}
            </span>
            <span class="card-title">${esc(card.title)} ${titleAdditions}</span>
            <span class="card-id">${esc(card.card_id || card.card_key || '')}</span>
            <span class="card-time">${timeStr}</span>
        </div>
        <div class="card-body">
            <p class="card-finding">${esc(card.finding)}</p>
            ${reasoningHTML}
            ${visibilityHTML}
        </div>
        ${metricsHTML}
        ${evidenceHTML}
        ${actionsHTML}
    `;

    return div;
}

function updatePerimeterStatus(counts) {
    const crit = counts.critical || 0;
    const caut = counts.caution || 0;
    const chip = document.getElementById('perimeterStatusChip');
    const textEl = document.getElementById('perimeterStatusText');
    const dotEl = chip ? chip.querySelector('.status-pulse-dot') : null;
    const actionCountEl = document.getElementById('scopeCountAction');

    // Update Action Required badge in scope bar
    const actionTotal = crit + caut;
    if (actionCountEl) {
        actionCountEl.textContent = actionTotal;
        actionCountEl.style.display = actionTotal > 0 ? 'inline-flex' : 'none';
    }

    if (!chip || !textEl) return;

    const activeCount = state.activePlaybooksCount !== undefined ? state.activePlaybooksCount : 19;

    if (crit > 0) {
        chip.className = 'perimeter-status-chip critical';
        if (dotEl) dotEl.className = 'status-pulse-dot critical';
        textEl.textContent = `ACTION REQUIRED: ${crit} CRITICAL EXPOSURE${crit > 1 ? 'S' : ''}`;
        chip.title = `${crit} Critical findings requiring immediate operator review. Click to inspect.`;
    } else if (caut > 0) {
        chip.className = 'perimeter-status-chip caution';
        if (dotEl) dotEl.className = 'status-pulse-dot caution';
        textEl.textContent = `AUDIT ADVISORY: ${caut} CAUTION FINDING${caut > 1 ? 'S' : ''}`;
        chip.title = `${caut} Caution findings flagged across fleet. Click to inspect.`;
    } else {
        chip.className = 'perimeter-status-chip nominal';
        if (dotEl) dotEl.className = 'status-pulse-dot nominal';
        textEl.textContent = `${activeCount} PLAYBOOK${activeCount === 1 ? '' : 'S'} ACTIVE`;
        chip.title = `Autonomous inspection engine running ${activeCount} active playbooks. Click to manage schedule.`;
    }
}

function updateCounters(counts) {
    const crit = counts.critical || 0;
    const caut = counts.caution || 0;
    const norm = counts.normal || 0;

    // Update modern SOC perimeter status chip & scope counts
    updatePerimeterStatus(counts);

    // Fallbacks for any legacy elements
    const critEl = document.getElementById('countCritical');
    const cautEl = document.getElementById('countCaution');
    const normEl = document.getElementById('countNormal');

    if (critEl) critEl.textContent = crit;
    if (cautEl) cautEl.textContent = caut;
    if (normEl) normEl.textContent = norm;

    if (critEl) {
        if (crit > 0) critEl.classList.add('active');
        else critEl.classList.remove('active');
    }
}

// ═══════════════════════════════════════════════════════
// Card Actions & Event Delegation
// ═══════════════════════════════════════════════════════

function bindDeckEventDelegation() {
    const deck = document.getElementById('cardDeck');
    if (!deck) return;

    deck.addEventListener('click', async (e) => {
        const btn = e.target.closest('button[data-action]');
        if (!btn) return;

        const action = btn.dataset.action;
        const cardId = btn.dataset.cardId;
        const card = state.cards.find(c => c.id === cardId);

        if (action === 'investigate') {
            if (card) {
                setInvestigationContext(card);
            } else {
                investigateCard(cardId, 'Selected Alert');
            }
            return;
        }

        btn.disabled = true;
        btn.classList.add('loading');

        try {
            if (action === 'dismiss') {
                await dismissCard(cardId);
            } else if (action === 'mute') {
                const hours = parseInt(btn.dataset.duration || 24, 10);
                await muteCard(cardId, hours);
            } else if (action === 'approve' || action === 'tool') {
                const actionType = btn.dataset.actionType;
                if (actionType === 'open_chat') {
                    if (card) setInvestigationContext(card);
                    else investigateCard(cardId, 'Selected Alert');
                } else if (actionType === 'suppress') {
                    const hours = parseInt(btn.dataset.duration || 24, 10);
                    await muteCard(cardId, hours);
                } else {
                    await approveCard(cardId);
                }
            }
        } catch (err) {
            showToast(`Action failed: ${err.message}`, 'error');
        } finally {
            btn.disabled = false;
            btn.classList.remove('loading');
        }
    });
}

function setInvestigationContext(card) {
    state.activeInvestigationCard = card;
    const banner = document.getElementById('chatCardContext');
    const titleEl = document.getElementById('contextCardTitle');

    if (banner && titleEl) {
        titleEl.textContent = `${card.card_id || 'Alert'} (${card.device || 'default'}): ${card.title}`;
        banner.style.display = 'block';
    }

    openChat();
    const input = document.getElementById('input');
    input.placeholder = `Query NEO about finding ${card.card_id || 'alert'}...`;
    input.focus();
    showToast(`Attached finding ${card.card_id || 'alert'} to investigation context`, 'info');
}

function clearInvestigationContext() {
    state.activeInvestigationCard = null;
    const banner = document.getElementById('chatCardContext');
    if (banner) banner.style.display = 'none';
    const input = document.getElementById('input');
    if (input) input.placeholder = 'Query Neo copilot...';
}

function bindContextBanner() {
    const detachBtn = document.getElementById('btnDetachContext');
    if (detachBtn) {
        detachBtn.addEventListener('click', () => {
            clearInvestigationContext();
            showToast('Investigation context detached', 'info');
        });
    }
}

function investigateCard(cardId, title) {
    openChat();
    const input = document.getElementById('input');
    input.value = `Investigate finding: ${title}`;
    input.focus();
}

async function approveCard(cardId) {
    const key = getAuthKey();
    const res = await fetch(`/api/cards/${cardId}/approve`, {
        method: 'POST',
        headers: { 'X-API-Key': key }
    });
    const data = await res.json();
    if (data.success) {
        showToast('Remediation approved and dispatched to firewall fleet', 'success');
        removeCardElement(cardId);
        loadCards();
    } else {
        showToast(data.error || 'Approval failed', 'error');
    }
}

async function dismissCard(cardId) {
    const key = getAuthKey();
    const res = await fetch(`/api/cards/${cardId}/deny`, {
        method: 'POST',
        headers: { 'X-API-Key': key }
    });
    const data = await res.json();
    if (data.success) {
        showToast('Security finding acknowledged and archived', 'info');
        removeCardElement(cardId);
        loadCards();
    } else {
        showToast(data.error || 'Dismiss failed', 'error');
    }
}

async function muteCard(cardId, hours) {
    const key = getAuthKey();
    const res = await fetch(`/api/cards/${cardId}/mute`, {
        method: 'POST',
        headers: {
            'X-API-Key': key,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ hours })
    });
    const data = await res.json();
    if (data.success) {
        showToast(`Security finding suppressed for ${hours} hours`, 'warning');
        removeCardElement(cardId);
        loadCards();
    } else {
        showToast(data.error || 'Mute failed', 'error');
    }
}

function removeCardElement(cardId) {
    const cardEl = document.querySelector(`.defense-card[data-id="${cardId}"]`);
    if (cardEl) {
        cardEl.style.transition = 'all 0.3s ease';
        cardEl.style.opacity = '0';
        cardEl.style.transform = 'translateX(20px)';
        setTimeout(() => {
            cardEl.remove();
            state.cards = state.cards.filter(c => c.id !== cardId);
            renderFilteredDeck();
        }, 300);
    }
}

// ═══════════════════════════════════════════════════════
// SSE Card Stream
// ═══════════════════════════════════════════════════════

function connectCardSSE() {
    if (cardSSE) {
        try { cardSSE.close(); } catch (_) {}
        cardSSE = null;
    }

    const key = getAuthKey();
    cardSSE = new EventSource(`/api/cards/stream?key=${encodeURIComponent(key)}`);

    cardSSE.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            if (data.type === 'card' && data.data) {
                const newCard = data.data;

                // Add or update in state
                const existingIdx = state.cards.findIndex(c => c.id === newCard.id);
                if (existingIdx >= 0) {
                    state.cards[existingIdx] = newCard;
                } else {
                    state.cards.unshift(newCard);
                }

                // Show toast for real-time notification
                const sev = (newCard.severity || 'info').toLowerCase();
                const toastType = sev === 'critical' ? 'error' : (sev === 'caution' ? 'warning' : 'info');
                showToast(`New alert [${newCard.severity.toUpperCase()}]: ${newCard.title}`, toastType, 5000);

                if (newCard.severity === 'critical') {
                    playAlertSound();
                }

                renderFilteredDeck();
                loadCards(); // Sync accurate server-side counters
            }
        } catch (e) {
            console.warn('[NODAL] SSE parse error:', e);
        }
    };

    cardSSE.onerror = () => {
        if (cardSSE) {
            try { cardSSE.close(); } catch (_) {}
            cardSSE = null;
        }
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
// Toolbar Controls (Filters, Search, Device, Sort)
// ═══════════════════════════════════════════════════════

function bindFilters() {
    // Operational Scope chips binding
    document.querySelectorAll('.scope-chip[data-scope]').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.scope-chip[data-scope]').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            state.scope = btn.dataset.scope || 'all';
            renderFilteredDeck();
        });
    });

    // Fallback for any legacy filter-btn
    document.querySelectorAll('.filter-btn[data-filter]').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.filter-btn[data-filter]').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            state.filter = btn.dataset.filter || 'all';
            currentFilter = state.filter;
            renderFilteredDeck();
        });
    });

    // Perimeter Status Chip click interaction
    const chip = document.getElementById('perimeterStatusChip');
    if (chip) {
        chip.addEventListener('click', () => {
            const crit = (state.counts && state.counts.critical) || 0;
            const caut = (state.counts && state.counts.caution) || 0;

            if (crit > 0 || caut > 0) {
                // Focus on actionable findings
                document.querySelectorAll('.scope-chip[data-scope]').forEach(b => b.classList.remove('active'));
                const actionBtn = document.querySelector('.scope-chip[data-scope="action"]');
                if (actionBtn) actionBtn.classList.add('active');
                state.scope = 'action';
                renderFilteredDeck();
                showToast('Displaying findings requiring action', 'info');
            } else {
                // Nominal state -> open Autonomous Inspection Hub
                openSchedule();
            }
        });
    }
}

function bindDeckControls() {
    // Search input
    const searchInput = document.getElementById('cardSearch');
    if (searchInput) {
        searchInput.addEventListener('input', (e) => {
            state.searchQuery = e.target.value;
            renderFilteredDeck();
        });
    }

    // Device filter select
    const deviceSelect = document.getElementById('deviceFilter');
    if (deviceSelect) {
        deviceSelect.addEventListener('change', (e) => {
            state.device = e.target.value;
            renderFilteredDeck();
        });
    }

    // Sort select
    const sortSelect = document.getElementById('sortSelect');
    if (sortSelect) {
        sortSelect.addEventListener('change', (e) => {
            state.sort = e.target.value;
            renderFilteredDeck();
        });
    }

    // Refresh deck button
    const refreshBtn = document.getElementById('btnRefreshDeck');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', () => {
            loadCards();
            showToast('Defense deck refreshed', 'info');
        });
    }

    // Clear filters button inside empty state
    const clearBtn = document.getElementById('btnClearFilters');
    if (clearBtn) {
        clearBtn.addEventListener('click', () => {
            state.filter = 'all';
            state.scope = 'all';
            state.device = 'all';
            state.searchQuery = '';

            document.querySelectorAll('.scope-chip[data-scope]').forEach(b => {
                b.classList.toggle('active', b.dataset.scope === 'all');
            });
            document.querySelectorAll('.filter-btn[data-filter]').forEach(b => {
                b.classList.toggle('active', b.dataset.filter === 'all');
            });

            if (searchInput) searchInput.value = '';
            if (deviceSelect) deviceSelect.value = 'all';
            renderFilteredDeck();
            showToast('Filters cleared', 'info');
        });
    }

    // Check URL parameters for deep links (e.g. ?filter=policy or ?scope=exposures)
    try {
        const urlParams = new URLSearchParams(window.location.search);
        const initialScope = urlParams.get('scope') || urlParams.get('filter');
        if (initialScope) {
            const validScopes = ['all', 'action', 'exposures', 'lateral', 'policy'];
            const normalized = initialScope.toLowerCase();
            if (validScopes.includes(normalized)) {
                document.querySelectorAll('.scope-chip[data-scope]').forEach(b => {
                    b.classList.toggle('active', b.dataset.scope === normalized);
                });
                state.scope = normalized;
            } else {
                if (searchInput) searchInput.value = initialScope;
                state.searchQuery = initialScope;
            }
            renderFilteredDeck();
        }
    } catch (_) {}
}

// ═══════════════════════════════════════════════════════
// Chat Panel — Open / Close / Collapse / Fullscreen
// ═══════════════════════════════════════════════════════

let chatIsFullscreen = false;
let chatIsCollapsed = false;

function bindChatPanel() {
    const toggle = document.getElementById('chatToggle');
    if (toggle) toggle.addEventListener('click', openChat);
    const btnToggle = document.getElementById('btnToggleChat');
    if (btnToggle) btnToggle.addEventListener('click', toggleChat);
    const btnFull = document.getElementById('btnFullscreenChat');
    if (btnFull) btnFull.addEventListener('click', toggleFullscreenChat);
    const btnCol = document.getElementById('btnCollapseChat');
    if (btnCol) btnCol.addEventListener('click', collapseChat);
    const btnExp = document.getElementById('btnExpandFromStrip');
    if (btnExp) btnExp.addEventListener('click', expandFromCollapse);
}

function openChat() {
    const dashboard = document.getElementById('dashboard');
    if (dashboard) dashboard.classList.remove('chat-collapsed');
    chatIsCollapsed = false;
    const toggle = document.getElementById('chatToggle');
    if (toggle) toggle.style.display = 'none';
    const exp = document.getElementById('chatExpanded');
    if (exp) exp.style.display = 'flex';
    const input = document.getElementById('input');
    if (input) input.focus();
}

function collapseChat() {
    const dashboard = document.getElementById('dashboard');
    if (chatIsFullscreen && dashboard) {
        dashboard.classList.remove('chat-fullscreen');
        chatIsFullscreen = false;
    }
    if (dashboard) dashboard.classList.add('chat-collapsed');
    chatIsCollapsed = true;
}

function expandFromCollapse() {
    const dashboard = document.getElementById('dashboard');
    if (dashboard) dashboard.classList.remove('chat-collapsed');
    chatIsCollapsed = false;
    const exp = document.getElementById('chatExpanded');
    if (exp) exp.style.display = 'flex';
    const input = document.getElementById('input');
    if (input) input.focus();
}

function toggleFullscreenChat() {
    const dashboard = document.getElementById('dashboard');
    if (!dashboard) return;

    if (chatIsFullscreen) {
        dashboard.classList.remove('chat-fullscreen');
        chatIsFullscreen = false;
        dashboard.style.transition = '';
    } else {
        dashboard.classList.add('chat-fullscreen');
        chatIsFullscreen = true;
    }
    const input = document.getElementById('input');
    if (input) input.focus();
}

function toggleChat() {
    if (chatIsCollapsed) {
        expandFromCollapse();
    } else {
        const input = document.getElementById('input');
        if (input) input.focus();
    }
}

function closeChat() {
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
    if (!handle || !dashboard || !chatPanel) return;

    let startX, startWidth;

    handle.addEventListener('mousedown', (e) => {
        e.preventDefault();
        startX = e.clientX;
        startWidth = chatPanel.offsetWidth;
        document.body.classList.add('resizing');
        handle.classList.add('dragging');
        dashboard.style.transition = 'none';

        function onMouseMove(e) {
            const delta = startX - e.clientX;
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
            localStorage.setItem(CHAT_WIDTH_STORAGE_KEY, chatPanel.offsetWidth);
        }

        document.addEventListener('mousemove', onMouseMove);
        document.addEventListener('mouseup', onMouseUp);
    });
}

function setChatWidth(px) {
    const dashboard = document.getElementById('dashboard');
    const chatPanel = document.getElementById('chatPanel');
    if (dashboard) dashboard.style.setProperty('--chat-width', px + 'px');
    if (chatPanel) {
        if (px > 600) chatPanel.classList.add('wide-mode');
        else chatPanel.classList.remove('wide-mode');
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
// ═══════════════════════════════════════════════════════
// Schedule Modal: Autonomous Inspection Management Hub
// ═══════════════════════════════════════════════════════

let scheduleData = [];
let scheduleActiveTab = 'all';
let scheduleSearchQuery = '';
let scheduleStatusFilter = 'all';

function bindScheduleModal() {
    const btn = document.getElementById('btnSchedule');
    const closeBtn = document.getElementById('btnCloseSchedule');
    const modal = document.getElementById('scheduleModal');

    if (btn) btn.addEventListener('click', openSchedule);
    if (closeBtn) closeBtn.addEventListener('click', closeSchedule);

    if (modal) {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) closeSchedule();
        });
    }

    // Tab buttons
    const tabsContainer = document.getElementById('scheduleTabs');
    if (tabsContainer) {
        tabsContainer.addEventListener('click', (e) => {
            const tabBtn = e.target.closest('.schedule-tab');
            if (!tabBtn) return;
            tabsContainer.querySelectorAll('.schedule-tab').forEach(t => t.classList.remove('active'));
            tabBtn.classList.add('active');
            scheduleActiveTab = tabBtn.dataset.tab || 'all';
            renderSchedule();
        });
    }

    // Search input
    const searchInput = document.getElementById('schedSearchInput');
    const clearSearchBtn = document.getElementById('btnSchedClearSearch');
    if (searchInput) {
        searchInput.addEventListener('input', () => {
            scheduleSearchQuery = searchInput.value.trim().toLowerCase();
            if (clearSearchBtn) {
                clearSearchBtn.style.display = scheduleSearchQuery ? 'block' : 'none';
            }
            renderSchedule();
        });
    }
    if (clearSearchBtn) {
        clearSearchBtn.addEventListener('click', () => {
            if (searchInput) {
                searchInput.value = '';
                scheduleSearchQuery = '';
                clearSearchBtn.style.display = 'none';
                searchInput.focus();
                renderSchedule();
            }
        });
    }

    // Status filter buttons (All, Active, Paused)
    const statusFilter = document.getElementById('schedStatusFilter');
    if (statusFilter) {
        statusFilter.addEventListener('click', (e) => {
            const btn = e.target.closest('.status-filter-btn');
            if (!btn) return;
            statusFilter.querySelectorAll('.status-filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            scheduleStatusFilter = btn.dataset.status || 'all';
            renderSchedule();
        });
    }

    // Batch actions (Enable All, Pause All)
    const btnEnableAll = document.getElementById('btnEnableAllCards');
    const btnDisableAll = document.getElementById('btnDisableAllCards');
    if (btnEnableAll) {
        btnEnableAll.addEventListener('click', () => batchToggleSchedule(true));
    }
    if (btnDisableAll) {
        btnDisableAll.addEventListener('click', () => batchToggleSchedule(false));
    }

    // Event delegation on schedule body for Run buttons & Toggles
    const body = document.getElementById('scheduleBody');
    if (body) {
        body.addEventListener('click', (e) => {
            const runBtn = e.target.closest('.btn-run-card');
            if (runBtn) {
                const cardKey = runBtn.dataset.cardKey;
                if (cardKey) runCardNow(cardKey, runBtn);
            }
        });

        body.addEventListener('change', (e) => {
            const toggle = e.target.closest('.schedule-toggle');
            if (toggle) {
                toggleCardSchedule(toggle);
            }
        });
    }
}

function openSchedule() {
    const modal = document.getElementById('scheduleModal');
    if (modal) modal.style.display = 'flex';
    loadSchedule();
}

function closeSchedule() {
    const modal = document.getElementById('scheduleModal');
    if (modal) modal.style.display = 'none';
}

function loadSchedule() {
    const key = getAuthKey();
    fetch('/api/cards/schedule', {
        headers: { 'X-API-Key': key }
    })
    .then(r => r.json())
    .then(data => {
        scheduleData = data.schedule || [];
        updateScheduleStats();
        renderSchedule();
    })
    .catch(err => {
        const body = document.getElementById('scheduleBody');
        if (body) body.innerHTML = `<div class="sched-empty-state"><span style="color: #f87171;">Error loading inspection schedule: ${esc(err.message)}</span></div>`;
    });
}

function syncScheduleCounts() {
    const modal = document.getElementById('scheduleModal');
    if (modal && modal.style.display !== 'none') return; // Do not clobber active modal session with background polling

    const key = getAuthKey();
    if (!key) return;

    fetch('/api/cards/schedule', {
        headers: { 'X-API-Key': key }
    })
    .then(r => r.json())
    .then(data => {
        scheduleData = data.schedule || [];
        updateScheduleStats();
    })
    .catch(err => {
        console.warn('[NODAL] Schedule count sync error:', err);
    });
}

function updateScheduleStats() {
    const total = scheduleData.length;
    const active = scheduleData.filter(e => e.enabled).length;
    const paused = total - active;

    state.activePlaybooksCount = active;
    state.totalPlaybooksCount = total;

    const elTotal = document.getElementById('schedStatTotal');
    const elActive = document.getElementById('schedStatActive');
    const elPaused = document.getElementById('schedStatPaused');
    if (elTotal) elTotal.textContent = total;
    if (elActive) elActive.textContent = active;
    if (elPaused) elPaused.textContent = paused;

    // Tab count badges
    const countAll = total;
    const countContinuous = scheduleData.filter(e => e.schedule === 'continuous').length;
    const countPeriodic = scheduleData.filter(e => e.schedule === 'periodic').length;
    const countDaily = scheduleData.filter(e => e.schedule === 'daily').length;
    const countWeekly = scheduleData.filter(e => e.schedule === 'weekly').length;

    const elCountAll = document.getElementById('tabCountAll');
    const elCountContinuous = document.getElementById('tabCountContinuous');
    const elCountPeriodic = document.getElementById('tabCountPeriodic');
    const elCountDaily = document.getElementById('tabCountDaily');
    const elCountWeekly = document.getElementById('tabCountWeekly');

    if (elCountAll) elCountAll.textContent = countAll;
    if (elCountContinuous) elCountContinuous.textContent = countContinuous;
    if (elCountPeriodic) elCountPeriodic.textContent = countPeriodic;
    if (elCountDaily) elCountDaily.textContent = countDaily;
    if (elCountWeekly) elCountWeekly.textContent = countWeekly;

    // Synchronize top header status chip
    updatePerimeterStatus(state.counts);
}

function renderSchedule() {
    const body = document.getElementById('scheduleBody');
    if (!body) return;

    // Filter by tab
    let filtered = scheduleData;
    if (scheduleActiveTab !== 'all') {
        filtered = filtered.filter(e => e.schedule === scheduleActiveTab);
    }

    // Filter by status (all, active, paused)
    if (scheduleStatusFilter === 'active') {
        filtered = filtered.filter(e => e.enabled);
    } else if (scheduleStatusFilter === 'paused') {
        filtered = filtered.filter(e => !e.enabled);
    }

    // Filter by search query
    if (scheduleSearchQuery) {
        filtered = filtered.filter(e => {
            const id = (e.card_id || '').toLowerCase();
            const name = (e.name || '').toLowerCase();
            const desc = (e.description || '').toLowerCase();
            const key = (e.card_key || '').toLowerCase();
            return id.includes(scheduleSearchQuery) ||
                   name.includes(scheduleSearchQuery) ||
                   desc.includes(scheduleSearchQuery) ||
                   key.includes(scheduleSearchQuery);
        });
    }

    if (filtered.length === 0) {
        body.innerHTML = `
            <div class="sched-empty-state">
                <span>No inspection playbooks match the selected filters.</span>
                <span style="font-size: 11px; opacity: 0.6;">Try adjusting search terms or cadence tabs.</span>
            </div>
        `;
        return;
    }

    body.innerHTML = filtered.map(entry => {
        const cadence = entry.schedule || 'daily';
        let cadenceLabel = 'DAILY';
        if (cadence === 'continuous') cadenceLabel = '5 MIN';
        else if (cadence === 'periodic') cadenceLabel = '30 MIN';
        else if (cadence === 'weekly') cadenceLabel = 'WEEKLY';

        const sev = entry.severity || 'normal';
        const toolCount = entry.tool_count || 1;
        const toolsText = `${toolCount} tool${toolCount !== 1 ? 's' : ''}`;
        const pausedClass = !entry.enabled ? 'card-paused' : '';

        return `
            <div class="playbook-card ${pausedClass}" data-card-key="${esc(entry.card_key)}">
                <div class="playbook-card-top">
                    <div class="playbook-title-block">
                        <div class="playbook-meta-row">
                            <span class="playbook-id-badge">${esc(entry.card_id || entry.card_key)}</span>
                            <span class="playbook-severity-dot sev-${esc(sev)}" title="Severity: ${esc(sev)}"></span>
                            <span class="playbook-cadence-pill cadence-${esc(cadence)}">${cadenceLabel}</span>
                        </div>
                        <div class="playbook-name">${esc(entry.name || entry.card_key)}</div>
                        <div class="playbook-desc">${esc(entry.description || 'Automated inspection playbook.')}</div>
                    </div>
                </div>
                <div class="playbook-card-bottom">
                    <div class="playbook-timing">
                        <span>${toolsText}</span>
                        <span>•</span>
                        <span>Last: ${esc(entry.last_run_human || 'Never')}</span>
                    </div>
                    <div class="playbook-actions">
                        <button type="button" class="btn-run-card" data-card-key="${esc(entry.card_key)}" title="Execute inspection immediately">
                            <svg width="10" height="10" viewBox="0 0 24 24" fill="currentColor"><polygon points="5 3 19 12 5 21 5 3"/></svg>
                            Run Now
                        </button>
                        <input type="checkbox" class="schedule-toggle"
                            ${entry.enabled ? 'checked' : ''}
                            data-card-key="${esc(entry.card_key)}"
                            title="Toggle active/paused">
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

function toggleCardSchedule(toggle) {
    const cardKey = toggle.dataset.cardKey;
    const enabled = toggle.checked;
    const key = getAuthKey();

    fetch('/api/cards/schedule', {
        method: 'POST',
        headers: {
            'X-API-Key': key,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ card_key: cardKey, enabled })
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            const entry = scheduleData.find(e => e.card_key === cardKey);
            if (entry) entry.enabled = enabled;
            updateScheduleStats();
            const cardEl = document.querySelector(`.playbook-card[data-card-key="${cardKey}"]`);
            if (cardEl) {
                if (enabled) cardEl.classList.remove('card-paused');
                else cardEl.classList.add('card-paused');
            }
            showToast(`Playbook ${cardKey} ${enabled ? 'activated' : 'paused'}`, 'info');
        } else {
            toggle.checked = !enabled; // Revert
            showToast(`Failed to update schedule: ${data.error}`, 'error');
        }
    })
    .catch(err => {
        toggle.checked = !enabled;
        showToast(`Schedule update error: ${err.message}`, 'error');
    });
}

function batchToggleSchedule(enabled) {
    const key = getAuthKey();
    fetch('/api/cards/schedule', {
        method: 'POST',
        headers: {
            'X-API-Key': key,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ card_key: 'all', enabled })
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            scheduleData.forEach(e => e.enabled = enabled);
            updateScheduleStats();
            renderSchedule();
            showToast(`All playbooks ${enabled ? 'activated' : 'paused'}`, 'success');
        } else {
            showToast(`Batch update failed: ${data.error}`, 'error');
        }
    })
    .catch(err => {
        showToast(`Batch update error: ${err.message}`, 'error');
    });
}

async function runCardNow(cardKey, btn) {
    btn.disabled = true;
    const originalContent = btn.innerHTML;
    btn.innerHTML = 'Running...';

    const key = getAuthKey();
    const targetDevice = state.device !== 'all' ? state.device : 'default';

    try {
        const res = await fetch('/api/cards/run', {
            method: 'POST',
            headers: {
                'X-API-Key': key,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ card_key: cardKey, device: targetDevice })
        });
        const data = await res.json();

        if (data.success) {
            showToast(`Inspection ${data.card_id} executed: ${data.severity.toUpperCase()} finding registered`, 'success');
            loadCards();
            loadSchedule();
        } else {
            showToast(`Run failed: ${data.error || 'Unknown error'}`, 'error');
        }
    } catch (err) {
        showToast(`Execution error: ${err.message}`, 'error');
    } finally {
        btn.disabled = false;
        btn.innerHTML = originalContent;
    }
}

// ═══════════════════════════════════════════════════════
// Keyboard Shortcuts & Global Ergonomics
// ═══════════════════════════════════════════════════════

function bindKeyboardShortcuts() {
    document.addEventListener('keydown', (e) => {
        const activeTag = document.activeElement ? document.activeElement.tagName.toLowerCase() : '';
        const isInputFocused = activeTag === 'input' || activeTag === 'textarea' || activeTag === 'select';

        // Slash ( / ) focuses card search
        if (e.key === '/' && !isInputFocused) {
            e.preventDefault();
            const search = document.getElementById('cardSearch');
            if (search) {
                search.focus();
                search.select();
            }
            return;
        }

        // Cmd+K or Ctrl+K to toggle chat
        if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
            e.preventDefault();
            toggleChat();
            return;
        }

        // Ctrl+Shift+D to toggle demo mode
        if ((e.metaKey || e.ctrlKey) && e.shiftKey && e.key === 'D') {
            e.preventDefault();
            document.body.classList.toggle('demo-mode');
            showToast('Demo mode toggled', 'info');
            return;
        }

        // Escape
        if (e.key === 'Escape') {
            const search = document.getElementById('cardSearch');
            if (search && document.activeElement === search) {
                search.value = '';
                state.searchQuery = '';
                search.blur();
                renderFilteredDeck();
                return;
            }
            closeChat();
            closeSchedule();
        }
    });
}

// ═══════════════════════════════════════════════════════
// Toast Notification Utility
// ═══════════════════════════════════════════════════════

function showToast(message, type = 'info', duration = 3500) {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `soc-toast toast-${type}`;

    const iconMap = {
        success: '✓',
        error: '✕',
        warning: '!',
        info: 'ℹ'
    };

    toast.innerHTML = `
        <span class="toast-icon">${iconMap[type] || 'ℹ'}</span>
        <span class="toast-message">${esc(message)}</span>
        <button type="button" class="toast-close" title="Close">✕</button>
    `;

    const closeBtn = toast.querySelector('.toast-close');
    if (closeBtn) {
        closeBtn.addEventListener('click', () => {
            toast.classList.add('toast-exit');
            setTimeout(() => toast.remove(), 250);
        });
    }

    container.appendChild(toast);

    setTimeout(() => {
        if (toast.parentNode) {
            toast.classList.add('toast-exit');
            setTimeout(() => toast.remove(), 250);
        }
    }, duration);
}

// ═══════════════════════════════════════════════════════
// Login & Auth
// ═══════════════════════════════════════════════════════

function bindLogin() {
    const form = document.getElementById('loginForm');
    if (!form) return;

    form.addEventListener('submit', async (e) => {
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
            setAuthKey(key);
            unlockApp();
            showToast('Connected to firewall defense hub', 'success');
        } else {
            clearAuthKey();
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

    // Load devices and cards immediately
    loadDevices();
    loadCards();

    // Connect SSE for real-time card delivery
    connectCardSSE();

    // Start card polling as fallback
    setInterval(loadCards, CARD_POLL_INTERVAL);
}

// ═══════════════════════════════════════════════════════
// Setup Wizard
// ═══════════════════════════════════════════════════════

function bindSetup() {
    const s1 = document.getElementById('setupStep1');
    const s2 = document.getElementById('setupStep2');
    const s3 = document.getElementById('setupStep3');
    if (!s1 || !s2 || !s3) return;

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
        showToast('Passphrase copied to clipboard', 'info');
    });

    document.getElementById('btnProceedLogin').addEventListener('click', () => {
        document.getElementById('setupOverlay').style.display = 'none';
        document.getElementById('loginOverlay').style.display = 'flex';
        document.getElementById('loginInput').focus();
        checkHealth();
    });
}

// ═══════════════════════════════════════════════════════
// Chat — Sending, Streaming & Investigation Context
// ═══════════════════════════════════════════════════════

function bindForm() {
    const form = document.getElementById('chatForm');
    if (!form) return;

    form.addEventListener('submit', (e) => {
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
    if (!textarea) return;

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

    let payloadMessage = text;
    const activeCard = state.activeInvestigationCard;

    if (activeCard) {
        // Format structured card context
        let metricsStr = '';
        if (activeCard.metrics && Object.keys(activeCard.metrics).length > 0) {
            metricsStr = '\nMetrics: ' + Object.entries(activeCard.metrics).map(([k, v]) => `${k}=${v}`).join(', ');
        }
        let evidenceStr = '';
        if (activeCard.evidence && activeCard.evidence.length > 0) {
            evidenceStr = '\nEvidence:\n' + activeCard.evidence.map(e => '- ' + String(e)).join('\n');
        }

        payloadMessage = `[INVESTIGATION TARGET: Card ${activeCard.card_id || ''} (${activeCard.card_key || ''}) on device '${activeCard.device || 'default'}']\nTitle: ${activeCard.title}\nSeverity: ${activeCard.severity}\nFinding: ${activeCard.finding}${metricsStr}${evidenceStr}\n\nAnalyst Query: ${text}`;
        clearInvestigationContext();
    }

    addMsg('user', text);
    showStatus('Investigating...');
    const chatPanel = document.getElementById('chatPanel');
    if (chatPanel) chatPanel.classList.add('investigating');

    busy = true;
    const sendBtn = document.getElementById('sendBtn');
    if (sendBtn) sendBtn.disabled = true;

    const key = getAuthKey();
    fetch('/api/chat', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-API-Key': key
        },
        body: JSON.stringify({ message: payloadMessage })
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
                            return finish('[ERROR] ' + d.content);
                        }
                    } catch (_) {}
                }
                read();
            });
        }
        read();
    })
    .catch(err => finish('[ERROR] Connection error: ' + err.message));
}

function finish(text) {
    removeStatus();
    const chatPanel = document.getElementById('chatPanel');
    if (chatPanel) chatPanel.classList.remove('investigating');
    if (text) {
        addMsg('agent', text);
    }
    busy = false;
    const sendBtn = document.getElementById('sendBtn');
    if (sendBtn) sendBtn.disabled = false;
    const input = document.getElementById('input');
    if (input) input.focus();
}

// ═══════════════════════════════════════════════════════
// Status Line & Cognitive Drift
// ═══════════════════════════════════════════════════════

function showStatus(text) {
    removeStatus();
    const div = document.createElement('div');
    div.className = 'status-line';
    div.id = 'statusLine';
    div.innerHTML = `<div class="status-spinner"></div><span class="status-label">${esc(text)}</span>`;
    const messages = document.getElementById('messages');
    if (messages) messages.appendChild(div);
    scrollChatToBottom();
}

function updateStatus(text) {
    const driftMatch = text.match(/\[DRIFT:(normal|caution|critical):([\d.]+):T(\d+)\]/);
    if (driftMatch) {
        const severity = driftMatch[1];
        const similarity = parseFloat(driftMatch[2]);
        const turn = parseInt(driftMatch[3]);
        renderDriftMeter(severity, similarity, turn);
        return;
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
    
    const statusLine = document.getElementById('statusLine');
    const messages = document.getElementById('messages');
    if (statusLine && statusLine.parentNode) {
        statusLine.parentNode.insertBefore(meter, statusLine.nextSibling);
    } else if (messages) {
        messages.appendChild(meter);
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
// Message Rendering & Markdown
// ═══════════════════════════════════════════════════════

function addMsg(role, text) {
    const time = timeNow();
    const entry = document.createElement('div');

    let typeClass = 'msg-agent';
    let speakerPrefix = 'NEO-COPILOT';
    if (role === 'user') {
        typeClass = 'msg-user';
        speakerPrefix = 'OPERATOR';
    } else if (text && text.startsWith('[ERROR]')) {
        typeClass = 'msg-crit';
        speakerPrefix = 'SYSTEM ERROR';
    }

    entry.className = `msg ${typeClass}`;
    entry.innerHTML = `
        <div class="msg-meta">
            <span>[${speakerPrefix}]</span>
            <span>${time}</span>
        </div>
        <div class="msg-content">${role === 'user' ? esc(text) : renderMarkdown(text)}</div>
    `;

    const messages = document.getElementById('messages');
    if (messages) messages.appendChild(entry);
    scrollChatToBottom();
}

function renderMarkdown(t) {
    if (!t) return '';
    let h = esc(t);

    // Severity Badges
    h = h.replace(/\[CRITICAL\]/g, '<span class="badge badge-critical">CRITICAL</span>');
    h = h.replace(/\[CAUTION\]/g, '<span class="badge badge-caution">CAUTION</span>');
    h = h.replace(/\[NORMAL\]/g, '<span class="badge badge-normal">NORMAL</span>');
    h = h.replace(/\[ASSESSMENT\]/g, '<span class="badge badge-info">ASSESSMENT</span>');
    h = h.replace(/\[INVESTIGATION\]/g, '<span class="badge badge-info">INVESTIGATION</span>');
    h = h.replace(/\[HALTED\]/g, '<span class="badge badge-critical">HALTED</span>');
    h = h.replace(/\[BUDGET LIMIT\]/g, '<span class="badge badge-caution">BUDGET LIMIT</span>');
    h = h.replace(/\[PIVOT\]/g, '<span class="badge badge-info">PIVOT</span>');

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
