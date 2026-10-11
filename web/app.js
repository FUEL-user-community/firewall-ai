/* ═══════════════════════════════════════════════════════
   Core Defense \u2014 Autonomous Defense Deck Application Logic
   ═══════════════════════════════════════════════════════
   fleet device selection, schedule modal with on-demand run,
   collapsible chat panel, active investigation context,
   glassmorphic toast notifications, and severity counters.
   ═══════════════════════════════════════════════════════ */

const STORAGE_KEY = 'nodal_history';
const MAX_HISTORY = 50;

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
    devices: [],
    device: 'all',
    busy: false,
};

let busy = false;
let currentFilter = 'all'; // Backwards compatibility for SSE handlers

// ═══════════════════════════════════════════════════════
// Initialization
// ═══════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
    bindLogin();
    bindSetup();
    bindForm();
    bindTextarea();
    bindKeyboardShortcuts();
    checkHealth();
    bindGeminiFramework();

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
            if (data.access_token) {
                setAuthKey(data.access_token);
            }

            const loginOverlay = document.getElementById('loginOverlay');
            const setupOverlay = document.getElementById('setupOverlay');

            if (!data.configured) {
                if (loginOverlay) loginOverlay.style.display = 'none';
                if (setupOverlay) setupOverlay.style.display = 'flex';
            } else if (getAuthKey()) {
                unlockApp();
            } else {
                if (setupOverlay) setupOverlay.style.display = 'none';
                if (loginOverlay) {
                    loginOverlay.style.display = 'flex';
                    const loginInput = document.getElementById('loginInput');
                    if (loginInput) loginInput.focus();
                }
            }

            const statusChip = document.getElementById('perimeterStatusChip');
            const statusText = document.getElementById('perimeterStatusText');
            if (statusText) {
                if (data.firewall_reachable) {
                    statusText.textContent = data.firewall_ip ? `PAN-OS (${data.firewall_ip})` : 'PAN-OS CONNECTED';
                    if (statusChip) statusChip.className = 'perimeter-status-chip nominal';
                } else if (data.configured) {
                    statusText.textContent = 'PAN-OS UNREACHABLE';
                    if (statusChip) statusChip.className = 'perimeter-status-chip critical';
                } else {
                    statusText.textContent = 'NOT CONFIGURED';
                    if (statusChip) statusChip.className = 'perimeter-status-chip warning';
                }
            }
        })
        .catch(() => {
            const statusChip = document.getElementById('perimeterStatusChip');
            const statusText = document.getElementById('perimeterStatusText');
            if (statusText) statusText.textContent = 'OFFLINE';
            if (statusChip) statusChip.className = 'perimeter-status-chip critical';
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
    const currentVal = select.value;

    const allDevs = Array.from(new Set(state.devices)).sort();
    if (allDevs.length === 0) return;

    // Check if the current options already match what we need (Prevents flicker on refresh)
    const currentValues = Array.from(select.options).map(o => o.value);
    const expectedValues = allDevs.length > 1 ? ['all', ...allDevs] : allDevs;

    const isMatch = currentValues.length === expectedValues.length &&
        currentValues.every((val, idx) => val === expectedValues[idx]);

    if (isMatch) {
        // Zero DOM manipulation on refresh = ZERO flicker
        return;
    }

    // Only update if actually different
    const frag = document.createDocumentFragment();
    if (allDevs.length > 1) {
        const allOpt = document.createElement('option');
        allOpt.value = 'all';
        allOpt.textContent = 'All Firewalls';
        frag.appendChild(allOpt);
    }
    allDevs.forEach(dev => {
        const opt = document.createElement('option');
        opt.value = dev;
        opt.textContent = `${dev} (192.168.1.254)`;
        frag.appendChild(opt);
    });

    select.innerHTML = '';
    select.appendChild(frag);

    if (currentVal && Array.from(select.options).some(o => o.value === currentVal)) {
        select.value = currentVal;
    }
}

// ═══════════════════════════════════════════════════════
// Chat Panel \u2014 Open / Close / Collapse / Fullscreen
// ═══════════════════════════════════════════════════════

function bindKeyboardShortcuts() {
    document.addEventListener('keydown', (e) => {
        const activeTag = document.activeElement ? document.activeElement.tagName.toLowerCase() : '';
        const isInputFocused = activeTag === 'input' || activeTag === 'textarea' || activeTag === 'select';

        // Slash ( / ) focuses input
        if (e.key === '/' && !isInputFocused) {
            e.preventDefault();
            const search = document.getElementById('input');
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
            const search = document.getElementById('input');
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
    const loginOverlay = document.getElementById('loginOverlay');
    if (loginOverlay) loginOverlay.style.display = 'none';
    const setupOverlay = document.getElementById('setupOverlay');
    if (setupOverlay) setupOverlay.style.display = 'none';
    const dashboard = document.getElementById('dashboard');
    if (dashboard) dashboard.style.display = 'flex';

    // Load fleet devices
    loadDevices();
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
// Chat \u2014 Sending, Streaming & Investigation Context
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
        textarea.style.height = Math.min(textarea.scrollHeight, 140) + 'px';
        updateSendBtnState();
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
    const hero = document.getElementById('chatHero');
    const msgs = document.getElementById('messages');
    if (hero) hero.style.display = 'none';
    if (msgs) msgs.style.display = 'flex';

    const input = document.getElementById('input');
    if (input) {
        input.value = '';
        input.style.height = 'auto';
    }
    updateSendBtnState();

    addMsg('user', text);
    showStatus('Investigating firewall state...');
    const chatPanel = document.getElementById('chatPanel');
    if (chatPanel) chatPanel.classList.add('investigating');

    busy = true;
    const sendBtn = document.getElementById('sendBtn');
    if (sendBtn) sendBtn.disabled = true;

    const key = getAuthKey();
    let currentReceipts = [];
    let currentTraceId = '';

    fetch('/api/chat', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-API-Key': key
        },
        body: JSON.stringify({ message: text })
    })
    .then(res => {
        if (!res.ok) {
            return res.json().catch(() => ({})).then(errData => {
                const msg = errData.error || errData.detail || `HTTP ${res.status}: ${res.statusText}`;
                finish(`[ERROR] ${msg}`, [], '');
            });
        }
        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buf = '';

        function read() {
            reader.read().then(({ done, value }) => {
                if (done) return finish('', currentReceipts, currentTraceId);

                buf += decoder.decode(value, { stream: true });
                const lines = buf.split('\n');
                buf = lines.pop();

                for (const line of lines) {
                    if (!line.startsWith('data: ')) continue;
                    try {
                        const d = JSON.parse(line.slice(6));
                        if (d.type === 'status') {
                            updateStatus(d.content);
                        } else if (d.type === 'receipts') {
                            currentReceipts = d.content || [];
                            if (d.trace_id) currentTraceId = d.trace_id;
                        } else if (d.type === 'response') {
                            if (d.trace_id) currentTraceId = d.trace_id;
                            return finish(d.content, currentReceipts, currentTraceId);
                        } else if (d.type === 'done') {
                            if (d.trace_id) currentTraceId = d.trace_id;
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

function finish(text, receipts = [], traceId = '') {
    removeStatus();
    const chatPanel = document.getElementById('chatPanel');
    if (chatPanel) chatPanel.classList.remove('investigating');
    if (text) {
        addMsg('agent', text, { receipts, traceId });
    }
    busy = false;
    updateSendBtnState();
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
    const labelMap = { normal: 'ALIGNED', caution: 'DIVERGING', critical: 'DRIFT DETECTED' };
    const color = colorMap[severity] || '#00e676';
    const label = labelMap[severity] || 'UNKNOWN';

    meter.innerHTML = `
        <div class="drift-header">
            <span class="drift-icon">\u25C9</span>
            <span class="drift-title">Investigation Focus</span>
            <span class="drift-turn">Turn ${turn}</span>
        </div>
        <div class="drift-bar-track">
            <div class="drift-bar-fill" style="width:${pct}%;background:${color}"></div>
        </div>
        <div class="drift-footer">
            <span class="drift-score" style="color:${color}">${pct}% \u2014 ${label}</span>
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

function addMsg(role, text, metadata = {}) {
    const time = timeNow();
    const entry = document.createElement('div');

    let typeClass = 'msg-agent';
    let speakerPrefix = 'DIAGNOSTICS';
    if (role === 'user') {
        typeClass = 'msg-user';
        speakerPrefix = 'OPERATOR';
    } else if (text && text.startsWith('[ERROR]')) {
        typeClass = 'msg-crit';
        speakerPrefix = 'SYSTEM ERROR';
    }

    entry.className = `msg ${typeClass}`;

    let receiptsHtml = '';
    const receipts = metadata.receipts || [];
    const traceId = metadata.traceId || '';
    if (receipts.length > 0) {
        const totalMs = receipts.reduce((acc, r) => acc + (r.duration_ms || 0), 0);
        receiptsHtml = `
            <div class="receipts-container" data-trace-id="${esc(traceId)}">
                <div class="receipts-header">
                    <button class="receipts-toggle-btn" onclick="toggleReceiptsDrawer(this)" aria-expanded="false" title="Inspect raw PAN-OS CLI execution receipts">
                        <svg class="receipts-icon" viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="4 17 10 11 4 5"></polyline>
                            <line x1="12" y1="19" x2="20" y2="19"></line>
                        </svg>
                        <span class="receipts-count">${receipts.length} CLI Execution Receipts</span>
                        <span class="receipts-duration-badge">${totalMs.toFixed(1)}ms</span>
                        <span class="receipts-chevron">▼</span>
                    </button>
                    ${traceId ? `
                    <button class="export-gdoc-btn" onclick="exportInvestigationToDoc('${esc(traceId)}', this)" title="Export formatted incident diagnosis report">
                        <svg class="gdoc-icon" viewBox="0 0 24 24" width="14" height="14" fill="currentColor">
                            <path d="M14 2H6c-1.1 0-2 .9-2 2v16c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V8l-6-6zM6 20V4h7v5h5v11H6z"/>
                        </svg>
                        <span>Export to Google Doc</span>
                    </button>
                    ` : ''}
                </div>
                <div class="receipts-drawer" style="display: none;">
                    <div class="receipts-summary-bar">Deterministic pan-os-python CLI / API Audit Trail</div>
                    ${receipts.map((r, idx) => `
                        <div class="receipt-card">
                            <div class="receipt-card-header">
                                <span class="receipt-step">#${idx + 1}</span>
                                <code class="receipt-tool-name">${esc(r.tool || 'unknown')}</code>
                                <span class="receipt-ms">${(r.duration_ms || 0).toFixed(1)}ms</span>
                                <span class="receipt-status-pill status-${esc(r.status || 'success')}">${esc(r.status || 'OK')}</span>
                            </div>
                            <div class="receipt-args-row">
                                <span class="receipt-label">Args:</span>
                                <code class="receipt-args-code">${esc(JSON.stringify(r.args || {}))}</code>
                            </div>
                            <details class="receipt-raw-details">
                                <summary>Raw Output (${(r.raw_output || r.output_snippet || '').length} bytes)</summary>
                                <pre class="receipt-raw-pre"><code>${esc(r.raw_output || r.output_snippet || 'No output captured')}</code></pre>
                            </details>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    }

    entry.innerHTML = `
        <div class="msg-meta">
            <span>[${speakerPrefix}]</span>
            <span>${time}</span>
        </div>
        <div class="msg-content">${role === 'user' ? esc(text) : renderMarkdown(text)}</div>
        ${receiptsHtml}
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

// =============================================================================
// Execution Receipts & Google Workspace Export Handlers
// =============================================================================

function toggleReceiptsDrawer(btn) {
    const container = btn.closest('.receipts-container');
    if (!container) return;
    const drawer = container.querySelector('.receipts-drawer');
    const chevron = btn.querySelector('.receipts-chevron');
    if (!drawer) return;

    const isHidden = drawer.style.display === 'none';
    drawer.style.display = isHidden ? 'block' : 'none';
    btn.setAttribute('aria-expanded', isHidden ? 'true' : 'false');
    if (chevron) {
        chevron.style.transform = isHidden ? 'rotate(180deg)' : 'rotate(0deg)';
    }
    scrollChatToBottom();
}

async function exportInvestigationToDoc(traceId, btn) {
    if (!traceId) return;
    const originalHtml = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = `<span>Exporting...</span>`;

    try {
        const key = getAuthKey();
        const res = await fetch('/api/export/google-doc', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-API-Key': key
            },
            body: JSON.stringify({ trace_id: traceId })
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.error || `HTTP ${res.status}`);
        }

        const data = await res.json();
        if (data.mode === 'google_doc' && data.doc_url) {
            window.open(data.doc_url, '_blank');
            btn.innerHTML = `✓ Opened Google Doc`;
            btn.classList.add('btn-success');
        } else {
            const blob = new Blob([data.markdown || ''], { type: 'text/markdown;charset=utf-8' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${data.title || 'CoreDefense_Incident'}.md`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);

            btn.innerHTML = `✓ Downloaded (.md)`;
            btn.classList.add('btn-success');
        }
    } catch (e) {
        btn.innerHTML = `⚠ Export Failed`;
        btn.classList.add('btn-error');
        console.error('[EXPORT] Error:', e);
    } finally {
        setTimeout(() => {
            btn.disabled = false;
            btn.innerHTML = originalHtml;
            btn.classList.remove('btn-success', 'btn-error');
        }, 4000);
    }
}

// ═══════════════════════════════════════════════════════
// Gemini Interface Framework Helpers
// ═══════════════════════════════════════════════════════

function bindGeminiFramework() {
    // Bind new chat button
    const newChatBtn = document.getElementById('newChatBtn');
    if (newChatBtn) {
        newChatBtn.addEventListener('click', resetToZeroState);
    }

    updateSendBtnState();
}

function resetToZeroState() {
    const hero = document.getElementById('chatHero');
    const msgs = document.getElementById('messages');
    if (hero) hero.style.display = 'flex';
    if (msgs) {
        msgs.innerHTML = '';
        msgs.style.display = 'none';
    }
    const input = document.getElementById('input');
    if (input) {
        input.value = '';
        input.style.height = 'auto';
        input.focus();
    }
    updateSendBtnState();
}

function updateSendBtnState() {
    const input = document.getElementById('input');
    const sendBtn = document.getElementById('sendBtn');
    if (!input || !sendBtn) return;
    const hasText = input.value.trim().length > 0;
    sendBtn.disabled = !hasText || busy;
}
