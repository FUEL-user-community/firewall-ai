/* ═══════════════════════════════════════════════════════
   Core Defense — Unified Frontend API & Auth Gateway (api.js)
   ═══════════════════════════════════════════════════════
   Single source of truth for:
   - Session & LocalStorage Token Management
   - Authenticated HTTP Requests (authFetch)
   - Dynamic Setup Wizard Form Serialization
   - Health & Perimeter Telemetry Polling
   - Cross-Tab Session Synchronization
   - System Toast Notifications
   ═══════════════════════════════════════════════════════ */

(function (window) {
    'use strict';

    const TOKEN_KEY = 'nodal_key';

    // ─── 1. Authentication Token Helpers ─────────────────────────────
    function getAuthKey() {
        return sessionStorage.getItem(TOKEN_KEY) || localStorage.getItem(TOKEN_KEY) || '';
    }

    function setAuthKey(key) {
        if (key) {
            sessionStorage.setItem(TOKEN_KEY, key);
            localStorage.setItem(TOKEN_KEY, key);
        }
    }

    function clearAuthKey() {
        sessionStorage.removeItem(TOKEN_KEY);
        localStorage.removeItem(TOKEN_KEY);
    }

    // ─── 2. Authenticated Fetch Wrapper ──────────────────────────────
    async function authFetch(url, options = {}) {
        const key = getAuthKey();
        const headers = Object.assign({}, options.headers || {});

        if (key && !headers['X-API-Key']) {
            headers['X-API-Key'] = key;
        }

        const opts = Object.assign({}, options, { headers });
        const res = await fetch(url, opts);

        if (res.status === 401) {
            console.warn('[AUTH] Unauthorized access (401). Displaying login overlay.');
            clearAuthKey();
            const loginOverlay = document.getElementById('loginOverlay');
            if (loginOverlay) loginOverlay.style.display = 'flex';
        }

        return res;
    }

    // ─── 3. Toast Notifications ──────────────────────────────────────
    function showToast(message, type = 'info', duration = 3500) {
        const container = document.getElementById('toastContainer');
        if (!container) return;

        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;

        const icon = type === 'success' ? '✓' : type === 'critical' || type === 'error' ? '!' : 'ℹ';
        toast.innerHTML = `<span class="toast-icon">${icon}</span><span class="toast-msg">${message}</span>`;

        container.appendChild(toast);
        requestAnimationFrame(() => toast.classList.add('visible'));

        setTimeout(() => {
            toast.classList.remove('visible');
            setTimeout(() => toast.remove(), 300);
        }, duration);
    }

    // ─── 4. Application Unlock & Overlay Helpers ──────────────────────
    function unlockApp() {
        const loginOverlay = document.getElementById('loginOverlay');
        if (loginOverlay) loginOverlay.style.display = 'none';

        const setupOverlay = document.getElementById('setupOverlay');
        if (setupOverlay) setupOverlay.style.display = 'none';

        const workspace = document.getElementById('workspace') || document.getElementById('dashboard');
        if (workspace) workspace.style.display = 'flex';

        if (typeof window.onAppUnlocked === 'function') {
            try {
                window.onAppUnlocked();
            } catch (e) {
                console.warn('[CORE DEFENSE] onAppUnlocked hook error:', e);
            }
        }
    }

    // ─── 5. Health Check & Perimeter Status ──────────────────────────
    async function checkHealth(options = {}) {
        try {
            const res = await fetch('/api/health');
            if (!res.ok) throw new Error(`Health check returned HTTP ${res.status}`);
            const data = await res.json();

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
                }
            }

            if (typeof options.onSuccess === 'function') {
                options.onSuccess(data);
            }
            return data;
        } catch (err) {
            console.warn('[CORE DEFENSE] Health check failed:', err);
            const statusChip = document.getElementById('perimeterStatusChip');
            const statusText = document.getElementById('perimeterStatusText');
            if (statusText) statusText.textContent = 'OFFLINE';
            if (statusChip) statusChip.className = 'perimeter-status-chip critical';
            if (typeof options.onError === 'function') {
                options.onError(err);
            }
            return null;
        }
    }

    // ─── 6. Shared Login Binding ─────────────────────────────────────
    function bindLogin(options = {}) {
        const form = document.getElementById('loginForm');
        if (!form) return;

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            const input = document.getElementById('loginInput');
            const btn = document.getElementById('loginBtn');
            const err = document.getElementById('loginError');
            if (!input || !btn) return;

            const key = input.value.trim();
            if (!key) return;

            btn.disabled = true;
            btn.textContent = 'Verifying...';
            if (err) err.textContent = '';

            try {
                const res = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'X-API-Key': key }
                });

                if (res.ok) {
                    setAuthKey(key);
                    unlockApp();
                    showToast('Session unlocked successfully', 'success');
                    if (typeof options.onSuccess === 'function') options.onSuccess(key);
                } else {
                    clearAuthKey();
                    if (err) err.textContent = 'Invalid passphrase. Try again.';
                    showToast('Invalid session passphrase', 'critical');
                }
            } catch (ex) {
                if (err) err.textContent = 'Connection error verifying passphrase.';
                showToast('Network error during authentication', 'critical');
            } finally {
                btn.disabled = false;
                btn.textContent = 'Connect';
            }
        });
    }

    // ─── 7. Shared Setup Wizard Binding ──────────────────────────────
    function bindSetup(options = {}) {
        const s1 = document.getElementById('setupStep1');
        const s2 = document.getElementById('setupStep2');
        const s3 = document.getElementById('setupStep3');
        const form = document.getElementById('setupForm');
        if (!s1 || !s2 || !s3 || !form) return;

        const btnSimple = document.getElementById('btnSetupSimple');
        if (btnSimple) {
            btnSimple.addEventListener('click', () => {
                const backend = document.getElementById('setupBackend');
                if (backend) backend.value = 'dotenv';
                const sFields = document.getElementById('setupSimpleFields');
                const vFields = document.getElementById('setupVaultFields');
                if (sFields) sFields.style.display = 'flex';
                if (vFields) vFields.style.display = 'none';
                s1.style.display = 'none';
                s2.style.display = 'block';
            });
        }

        const btnVault = document.getElementById('btnSetupVault');
        if (btnVault) {
            btnVault.addEventListener('click', () => {
                const backend = document.getElementById('setupBackend');
                if (backend) backend.value = 'vault';
                const sFields = document.getElementById('setupSimpleFields');
                const vFields = document.getElementById('setupVaultFields');
                if (sFields) sFields.style.display = 'none';
                if (vFields) vFields.style.display = 'flex';
                s1.style.display = 'none';
                s2.style.display = 'block';
            });
        }

        const btnBack = document.getElementById('btnSetupBack');
        if (btnBack) {
            btnBack.addEventListener('click', () => {
                s2.style.display = 'none';
                s1.style.display = 'block';
            });
        }

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            const btn = document.getElementById('setupSubmitBtn');
            const err = document.getElementById('setupError');
            if (btn) {
                btn.disabled = true;
                btn.textContent = 'Saving...';
            }
            if (err) err.textContent = '';

            const getVal = (id) => {
                const el = document.getElementById(id);
                return el ? el.value.trim() : '';
            };

            // Canonical polymorphic payload matching server.py SetupRequest
            const payload = {
                backend_type: getVal('setupBackend') || 'dotenv',
                firewall_ip: getVal('setupFwIp'),
                panos_key: getVal('setupPanosKey'),
                gemini_key: getVal('setupGeminiKey'),
                vault_addr: getVal('setupVaultAddr'),
                vault_role: getVal('setupVaultRole'),
                vault_secret: getVal('setupVaultSecret'),
            };

            try {
                const res = await authFetch('/api/setup', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });

                const data = await res.json();
                if (data.success) {
                    const pass = data.passphrase || data.token || 'Initialized';
                    setAuthKey(pass);
                    const passBox = document.getElementById('setupPassphrase');
                    if (passBox) passBox.textContent = pass;
                    s2.style.display = 'none';
                    s3.style.display = 'block';
                    showToast('System configuration initialized', 'success');
                    if (typeof options.onSuccess === 'function') options.onSuccess(data);
                } else {
                    if (err) err.textContent = data.error || 'Setup failed';
                    showToast(data.error || 'Setup failed', 'critical');
                }
            } catch (ex) {
                if (err) err.textContent = 'Network error saving configuration: ' + ex.message;
                showToast('Network error saving configuration', 'critical');
            } finally {
                if (btn) {
                    btn.disabled = false;
                    btn.textContent = 'Save & Initialize';
                }
            }
        });

        const btnCopy = document.getElementById('btnCopyPassphrase');
        if (btnCopy) {
            btnCopy.addEventListener('click', () => {
                const passBox = document.getElementById('setupPassphrase');
                const text = passBox ? passBox.textContent : '';
                navigator.clipboard.writeText(text).then(() => {
                    showToast('Passphrase copied to clipboard', 'success');
                    btnCopy.textContent = 'Copied!';
                    setTimeout(() => btnCopy.textContent = 'Copy to Clipboard', 2000);
                });
            });
        }

        const btnProceed = document.getElementById('btnProceedLogin');
        if (btnProceed) {
            btnProceed.addEventListener('click', () => {
                unlockApp();
                if (typeof options.onProceed === 'function') options.onProceed();
            });
        }
    }

    // ─── 8. Cross-Tab Unlock Listener ────────────────────────────────
    window.addEventListener('storage', (e) => {
        if (e.key === TOKEN_KEY && e.newValue) {
            sessionStorage.setItem(TOKEN_KEY, e.newValue);
            const overlay = document.getElementById('loginOverlay');
            if (overlay && overlay.style.display !== 'none') {
                unlockApp();
                showToast('Synchronized authentication from active tab', 'info');
            }
        }
    });

    // ─── 9. Global Export & Window Attachment ────────────────────────
    window.CoreDefense = {
        getAuthKey,
        setAuthKey,
        clearAuthKey,
        authFetch,
        showToast,
        unlockApp,
        checkHealth,
        bindLogin,
        bindSetup,
    };

    // Keep top-level helper exports for seamless backward compatibility
    window.getAuthKey = getAuthKey;
    window.setAuthKey = setAuthKey;
    window.clearAuthKey = clearAuthKey;
    window.authFetch = authFetch;
    window.showToast = showToast;
    window.unlockApp = unlockApp;
    window.checkHealth = checkHealth;
    window.bindLogin = bindLogin;
    window.bindSetup = bindSetup;

})(window);
