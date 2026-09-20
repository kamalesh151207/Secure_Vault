const API_BASE = window.location.origin.includes(':') 
  ? 'http://localhost:3001' 
  : window.location.origin;

let jwtToken = localStorage.getItem('sv_jwt_token') || null;
let capabilityToken = null;
let capabilityExpiryTimer = null;

// Tab Switcher
function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach(panel => panel.classList.remove('active'));

  event.currentTarget.classList.add('active');
  document.getElementById(tabId).classList.add('active');

  if (tabId === 'dashboard-tab' && jwtToken) {
    fetchUserData();
  }
  if (tabId === 'logs-tab') {
    fetchAuditLogs();
  }
}

// Toast Notifications
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `<strong>${type.toUpperCase()}:</strong> ${message}`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(100%)';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// Update Token Display
function updateJwtDisplay() {
  const el = document.getElementById('jwt-token-display');
  if (jwtToken) {
    el.innerText = `Bearer ${jwtToken}`;
    el.style.color = 'var(--accent-emerald)';
  } else {
    el.innerText = 'No session token. Please login or register above.';
    el.style.color = 'var(--text-muted)';
  }
}

// Register Form Submit
document.getElementById('register-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const username = document.getElementById('reg-username').value;
  const email = document.getElementById('reg-email').value;
  const password = document.getElementById('reg-password').value;

  try {
    const res = await fetch(`${API_BASE}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, email, password })
    });
    const data = await res.json();

    if (res.ok) {
      jwtToken = data.token;
      localStorage.setItem('sv_jwt_token', jwtToken);
      updateJwtDisplay();
      showToast('Registration successful! Email encrypted with AES-256-GCM.', 'success');
      switchTab('dashboard-tab');
      fetchUserData();
    } else {
      showToast(data.message || data.error, 'danger');
    }
  } catch (err) {
    showToast('Failed to connect to backend server', 'danger');
  }
});

// Login Form Submit
document.getElementById('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const username = document.getElementById('login-username').value;
  const password = document.getElementById('login-password').value;

  try {
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    const data = await res.json();

    if (res.ok) {
      jwtToken = data.token;
      localStorage.setItem('sv_jwt_token', jwtToken);
      updateJwtDisplay();
      showToast('Authentication successful.', 'success');
      switchTab('dashboard-tab');
      fetchUserData();
    } else {
      showToast(data.message || data.error, 'danger');
    }
  } catch (err) {
    showToast('Login request failed', 'danger');
  }
});

// Fetch User Data & Decryption Status
async function fetchUserData() {
  if (!jwtToken) {
    document.getElementById('profile-content').innerHTML = `
      <p style="color:var(--accent-rose);">Authentication required. Please log in first.</p>
    `;
    return;
  }

  try {
    const res = await fetch(`${API_BASE}/data`, {
      headers: { 'Authorization': `Bearer ${jwtToken}` }
    });
    const result = await res.json();

    if (res.ok) {
      const u = result.data;
      document.getElementById('profile-content').innerHTML = `
        <div style="display:grid; grid-template-columns: 1fr 1fr; gap:16px;">
          <div>
            <p><strong>User ID:</strong> ${u.id}</p>
            <p><strong>Username:</strong> ${u.username}</p>
            <p><strong>Decrypted Email (On-The-Fly):</strong> <span style="color:var(--accent-emerald); font-weight:600;">${u.email}</span></p>
            <p><strong>Created At:</strong> ${new Date(u.createdAt).toLocaleString()}</p>
          </div>
          <div>
            <strong>Raw Storage in PostgreSQL (AES-256-GCM Format):</strong>
            <div class="capability-token-display" style="margin-top:6px;">${u.encryptionStatus.encryptedFormatStored}</div>
            <p style="font-size:11px; color:var(--text-muted); margin-top:4px;">Structure: iv (24 hex) : authTag (32 hex) : ciphertext</p>
          </div>
        </div>
      `;
    } else {
      document.getElementById('profile-content').innerHTML = `
        <p style="color:var(--accent-rose);">${result.message || result.error}</p>
      `;
    }
  } catch (err) {
    showToast('Failed to fetch user profile', 'danger');
  }
}

// Generate Capability Code
async function generateCapabilityToken() {
  if (!jwtToken) {
    showToast('You must be logged in to generate a Capability Code.', 'danger');
    return;
  }

  try {
    const res = await fetch(`${API_BASE}/capability/generate`, {
      method: 'POST',
      headers: { 
        'Authorization': `Bearer ${jwtToken}`,
        'Content-Type': 'application/json'
      }
    });
    const data = await res.json();

    if (res.ok) {
      capabilityToken = data.capabilityCode;
      document.getElementById('capability-token-text').innerText = capabilityToken;
      showToast('Capability Code generated! Valid for 5 minutes.', 'success');
      startCapabilityCountdown(data.expiresAt);
    } else {
      showToast(data.message || data.error, 'danger');
    }
  } catch (err) {
    showToast('Failed to request capability code', 'danger');
  }
}

// Capability Countdown Timer
function startCapabilityCountdown(expiresAtIso) {
  if (capabilityExpiryTimer) clearInterval(capabilityExpiryTimer);

  const expiresAt = new Date(expiresAtIso).getTime();
  const statusEl = document.getElementById('capability-status-text');

  capabilityExpiryTimer = setInterval(() => {
    const now = Date.now();
    const diff = Math.max(0, Math.floor((expiresAt - now) / 1000));

    if (diff > 0) {
      const minutes = Math.floor(diff / 60);
      const seconds = diff % 60;
      statusEl.innerHTML = `<span style="color:var(--accent-emerald);">Active (Expires in ${minutes}m ${seconds}s)</span>`;
    } else {
      clearInterval(capabilityExpiryTimer);
      capabilityToken = null;
      statusEl.innerHTML = `<span style="color:var(--accent-rose);">EXPIRED (Request New Token)</span>`;
      document.getElementById('capability-token-text').innerText = 'Token Expired.';
    }
  }, 1000);
}

// Set Injection Preset Payload
function setPayload(val) {
  document.getElementById('pentest-payload').value = val;
}

// Submit Pen-Test Injection Attack
document.getElementById('pentest-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const payload = document.getElementById('pentest-payload').value;
  const outputEl = document.getElementById('pentest-output');

  outputEl.innerText = 'Submitting payload to Pen-Test Sandbox...';

  const headers = { 'Content-Type': 'application/json' };
  if (capabilityToken) {
    headers['X-Capability-Token'] = capabilityToken;
  }

  try {
    const res = await fetch(`${API_BASE}/test/inject`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ payload, simulateParameterization: true })
    });

    const data = await res.json();
    outputEl.innerText = JSON.stringify(data, null, 2);

    if (res.status === 403) {
      showToast('Capability Code Authorization Failed. Header missing or expired!', 'danger');
    } else if (data.defenseAnalysis && data.defenseAnalysis.layer1_WAF.detected) {
      showToast('💥 SQL Injection Detected by Layer 1 WAF! CloudWatch & SNS Alert Fired.', 'danger');
    } else if (data.capabilityAuthorized) {
      showToast('Pen-Test payload safely executed and rolled back inside transaction.', 'success');
    }
  } catch (err) {
    outputEl.innerText = `Error: ${err.message}`;
    showToast('Pen-Test request failed', 'danger');
  }
});

// Fetch Audit Logs
async function fetchAuditLogs() {
  const tbody = document.getElementById('logs-table-body');
  try {
    const res = await fetch(`${API_BASE}/logs`);
    const data = await res.json();

    if (res.ok && data.logs) {
      if (data.logs.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;">No audit logs recorded yet.</td></tr>`;
        return;
      }
      tbody.innerHTML = data.logs.map(log => `
        <tr>
          <td>#${log.id}</td>
          <td>${new Date(log.timestamp).toLocaleTimeString()}</td>
          <td><code>${log.source_ip || '127.0.0.1'}</code></td>
          <td>
            ${log.is_malicious ? '<span class="tag-malicious">🚨 MALICIOUS (WAF ALERT)</span>' : '<span class="tag-safe">SAFE QUERY</span>'}
          </td>
          <td><code>${escapeHtml(log.query_text)}</code></td>
        </tr>
      `).join('');
    }
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color:var(--accent-rose);">Failed to load logs</td></tr>`;
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// Initial Load
updateJwtDisplay();
fetchAuditLogs();
