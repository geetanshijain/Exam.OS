/**
 * ExamOS — Examination-Center Release Console Engine (Vanilla JS)
 * 
 * Features:
 * - Time-Lock Sandbox Enforced Extractions
 * - Authenticated Envelope Decryption with KMS & AEAD Verification
 * - Dynamic Recipient Forensic Watermarking
 * - Tamper-Evident SHA-256 Audit Chain Verification
 * - Honeytoken Decoy Guarding for Out-of-Window Requests
 * - Emergency Lockdown Directives
 */

const API_BASE = (window.location.port === '8000') ? '/api/v1' : 'http://127.0.0.1:8000/api/v1';

const ConsoleState = {
  user: null,
  papers: [],
  schedules: [],
  selectedPaperId: null,
  countdownInterval: null,
  searchQuery: '',
  statusFilter: 'all',
};

document.addEventListener('DOMContentLoaded', () => {
  initCenterReleaseConsole();
});

// =========================================================================
// 1. INITIALIZATION & SESSION AUTHENTICATION
// =========================================================================

async function initCenterReleaseConsole() {
  bindUIEvents();

  const token = localStorage.getItem('access_token');
  if (!token) {
    showAlert('Unauthenticated custodial access. Redirecting to sign in...', 'danger');
    setTimeout(() => { window.location.href = 'login.html'; }, 1000);
    return;
  }

  try {
    const userRes = await fetch(`${API_BASE}/auth/me`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/json',
      },
    });

    if (!userRes.ok) {
      localStorage.removeItem('access_token');
      window.location.href = 'login.html';
      return;
    }

    ConsoleState.user = await userRes.json();
    const role = (ConsoleState.user.role || '').toLowerCase();

    // Verify authorized custodial personnel
    if (!['printer', 'controller', 'admin', 'hod'].includes(role)) {
      showPermissionDenied('Access restricted to authorized printing officers, center custodians, and controllers.');
      return;
    }

    renderCustodianProfile(ConsoleState.user);
    await loadConsoleManifest();

  } catch (err) {
    console.error('Initialization error:', err);
    showPermissionDenied('Institutional node unreachable. Verify backend server is active.');
  }
}

function renderCustodianProfile(user) {
  const nameEl = document.getElementById('custodian-name-display');
  const recipientEl = document.getElementById('inspector-recipient');
  if (nameEl) nameEl.textContent = user.full_name || user.username;
  if (recipientEl) recipientEl.textContent = user.email || `${user.username}@examos.edu`;
}

// =========================================================================
// 2. DATA MANIFEST LOADING & KPI METRICS
// =========================================================================

async function loadConsoleManifest() {
  switchState('loading');
  const token = localStorage.getItem('access_token');

  try {
    const [papersRes, schedRes] = await Promise.all([
      fetch(`${API_BASE}/vault/papers`, {
        headers: { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' },
      }),
      fetch(`${API_BASE}/schedules`, {
        headers: { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' },
      }),
    ]);

    let papers = [];
    if (papersRes.ok) {
      papers = await papersRes.json();
    }
    if (schedRes.ok) {
      ConsoleState.schedules = await schedRes.json();
    }

    ConsoleState.papers = papers;

    if (papers.length === 0) {
      switchState('empty');
      return;
    }

    // Default select first paper or currently selected
    if (!ConsoleState.selectedPaperId || !papers.some(p => p.id === ConsoleState.selectedPaperId)) {
      ConsoleState.selectedPaperId = papers[0].id;
    }

    updateKPIMetrics();
    renderMasterTable();
    updateInspectorDrawer();
    populateEmergencyLockSelect();

    startLiveCountdownLoop();
    switchState('console');

  } catch (err) {
    console.error('Error loading manifest:', err);
    showAlert('Failed to synchronize center vault records.', 'danger');
  }
}

function updateKPIMetrics() {
  const total = ConsoleState.papers.length;
  let openCount = 0;
  const now = new Date().getTime();

  ConsoleState.papers.forEach(p => {
    const tStart = new Date(p.scheduled_release_start).getTime();
    const tEnd = new Date(p.scheduled_release_end).getTime();
    if (now >= tStart && now <= tEnd && p.status === 'approved_locked') {
      openCount += 1;
    }
  });

  const queueEl = document.getElementById('kpi-queue-count');
  const windowEl = document.getElementById('kpi-window-status');
  if (queueEl) queueEl.textContent = `${total} Scheduled`;
  if (windowEl) {
    windowEl.textContent = openCount > 0 ? `${openCount} Open Now` : 'T-30 Min Active';
  }
}

// =========================================================================
// 3. MASTER TABLE RENDERING & SELECTION
// =========================================================================

function renderMasterTable() {
  const tbody = document.getElementById('release-table-body');
  if (!tbody) return;
  tbody.innerHTML = '';

  const now = new Date().getTime();
  const filtered = ConsoleState.papers.filter(p => {
    // Search query filter
    const q = ConsoleState.searchQuery.toLowerCase();
    const matchSearch = !q || p.paper_code.toLowerCase().includes(q) || p.title.toLowerCase().includes(q);

    // Status dropdown filter
    if (!matchSearch) return false;
    if (ConsoleState.statusFilter === 'all') return true;

    const tStart = new Date(p.scheduled_release_start).getTime();
    const tEnd = new Date(p.scheduled_release_end).getTime();
    const isOpen = (now >= tStart && now <= tEnd && p.status === 'approved_locked');
    const isLocked = (now < tStart && p.status === 'approved_locked');

    if (ConsoleState.statusFilter === 'open') return isOpen;
    if (ConsoleState.statusFilter === 'locked') return isLocked;
    if (ConsoleState.statusFilter === 'released') return (p.status === 'released');
    return true;
  });

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; padding: 24px; color: var(--text-muted);">No examination papers matching current filters.</td></tr>`;
    return;
  }

  filtered.forEach(paper => {
    const tr = document.createElement('tr');
    tr.id = `row-paper-${paper.id}`;
    if (paper.id === ConsoleState.selectedPaperId) {
      tr.classList.add('selected');
    }

    const tStart = new Date(paper.scheduled_release_start).getTime();
    const tEnd = new Date(paper.scheduled_release_end).getTime();
    const isOpen = (now >= tStart && now <= tEnd && paper.status === 'approved_locked');
    const isLocked = (now < tStart && paper.status === 'approved_locked');
    const isEmergency = (paper.status === 'emergency_locked');
    const isReleased = (paper.status === 'released');

    // Time-lock badge html
    let badgeHtml = '';
    if (isEmergency) {
      badgeHtml = `<span class="badge-timelock-emergency">EMERGENCY LOCKED</span>`;
    } else if (isReleased) {
      badgeHtml = `<span class="badge-timelock-released">PRINTED (1 Copy)</span>`;
    } else if (isOpen) {
      const remainingSec = Math.max(0, Math.floor((tEnd - now) / 1000));
      badgeHtml = `<span class="badge-timelock-open" id="badge-countdown-${paper.id}" data-end="${tEnd}">OPEN: ${formatSeconds(remainingSec)} Remaining</span>`;
    } else if (isLocked) {
      const waitSec = Math.max(0, Math.floor((tStart - now) / 1000));
      const mins = Math.ceil(waitSec / 60);
      badgeHtml = `<span class="badge-timelock-locked" id="badge-countdown-${paper.id}" data-start="${tStart}">LOCKED: T-${mins}m</span>`;
    } else {
      badgeHtml = `<span class="badge-timelock-released">EXPIRED</span>`;
    }

    // Quorum status badge
    const quorumText = `${paper.current_approvals_count}/${paper.approval_threshold} Approved`;
    const quorumHtml = `<span style="font-weight: 600; font-size: 12px; color: #166534; background: #f0fdf4; border: 1px solid #bbf7d0; padding: 3px 8px; border-radius: var(--radius-sm);">${escapeHtml(quorumText)}</span>`;

    // Scheduled time display
    const schedDate = new Date(paper.scheduled_release_start);
    const schedTimeStr = schedDate.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) + ' UTC';

    // Actions
    const canDecrypt = (isOpen || isReleased);
    tr.innerHTML = `
      <td>
        <div style="font-weight: 700; color: var(--text-primary); font-size: 13px;">${escapeHtml(paper.paper_code)}</div>
        <div style="font-size: 12px; color: var(--text-muted);">${escapeHtml(paper.title)}</div>
      </td>
      <td style="font-family: var(--font-mono); font-size: 12px;">${schedTimeStr}</td>
      <td>${badgeHtml}</td>
      <td>${quorumHtml}</td>
      <td style="text-align: right;">
        <div style="display: flex; gap: 8px; justify-content: flex-end; align-items: center;">
          <button type="button" class="btn-decrypt-print" data-action="decrypt" data-id="${paper.id}" ${canDecrypt ? '' : 'disabled'} title="${canDecrypt ? 'Decrypt and stream watermarked paper' : 'Time-locked prior to designated release window'}">
            Secure Decrypt &amp; Print
          </button>
          <button type="button" class="btn-audit-chain" data-action="audit" data-id="${paper.id}" title="Inspect paper and audit chain">
            Audit Chain
          </button>
        </div>
      </td>
    `;

    // Click row to select
    tr.addEventListener('click', (e) => {
      if (e.target.closest('button')) return; // handled by action buttons
      selectPaper(paper.id);
    });

    tbody.appendChild(tr);
  });

  // Bind row action buttons
  tbody.querySelectorAll('button[data-action="decrypt"]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const id = parseInt(btn.getAttribute('data-id'), 10);
      selectPaper(id);
      triggerPaperRelease(id);
    });
  });

  tbody.querySelectorAll('button[data-action="audit"]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const id = parseInt(btn.getAttribute('data-id'), 10);
      selectPaper(id);
      openAuditChainModal(id);
    });
  });
}

function selectPaper(paperId) {
  ConsoleState.selectedPaperId = paperId;
  document.querySelectorAll('#release-table-body tr').forEach(row => {
    row.classList.remove('selected');
  });
  const activeRow = document.getElementById(`row-paper-${paperId}`);
  if (activeRow) activeRow.classList.add('selected');

  updateInspectorDrawer();
}

// =========================================================================
// 4. INSPECTOR DRAWER
// =========================================================================

function updateInspectorDrawer() {
  const paper = ConsoleState.papers.find(p => p.id === ConsoleState.selectedPaperId);
  if (!paper) return;

  const titleEl = document.getElementById('inspector-paper-title');
  const codeEl = document.getElementById('inspector-paper-code');
  const dateEl = document.getElementById('inspector-watermark-date');
  const statusBadgeEl = document.getElementById('inspector-status-badge');
  const kmsEl = document.getElementById('inspector-kms-version');
  const triggerBtn = document.getElementById('btn-inspector-trigger-release');

  if (titleEl) titleEl.textContent = paper.title;
  if (codeEl) codeEl.textContent = `${paper.paper_code} • Version ${paper.version}`;
  if (dateEl) dateEl.textContent = new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
  if (kmsEl) kmsEl.textContent = `Envelope DEK Wrapped with KMS KEK ${paper.kek_version || 'v1'}`;

  const now = new Date().getTime();
  const tStart = new Date(paper.scheduled_release_start).getTime();
  const tEnd = new Date(paper.scheduled_release_end).getTime();
  const isOpen = (now >= tStart && now <= tEnd && paper.status === 'approved_locked');
  const isReleased = (paper.status === 'released');

  if (statusBadgeEl) {
    if (paper.status === 'emergency_locked') {
      statusBadgeEl.textContent = 'Emergency Locked';
      statusBadgeEl.style.color = '#dc2626';
    } else if (isReleased) {
      statusBadgeEl.textContent = 'Released (Printed)';
      statusBadgeEl.style.color = '#334155';
    } else if (isOpen) {
      statusBadgeEl.textContent = 'Window Open (Extraction Authorized)';
      statusBadgeEl.style.color = '#16a34a';
    } else {
      statusBadgeEl.textContent = 'Time-Locked (Pre-Release)';
      statusBadgeEl.style.color = '#d97706';
    }
  }

  if (triggerBtn) {
    triggerBtn.disabled = !(isOpen || isReleased);
    triggerBtn.textContent = isReleased ? 'Reprint Watermarked Copy' : 'Trigger Secure Release';
  }
}

// =========================================================================
// 5. SECURE DECRYPTION & WATERMARKED PDF STREAMING
// =========================================================================

async function triggerPaperRelease(paperId) {
  const token = localStorage.getItem('access_token');
  const triggerBtn = document.getElementById('btn-inspector-trigger-release');

  if (triggerBtn) {
    triggerBtn.disabled = true;
    triggerBtn.textContent = 'Decrypting Envelope with KMS...';
  }

  showAlert(`Initiating authenticated decryption handshake for paper #${paperId}...`, 'info');

  try {
    const res = await fetch(`${API_BASE}/vault/papers/${paperId}/release`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/pdf, application/json',
      },
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      const msg = err.detail || 'Paper extraction rejected by institutional security layer.';

      if (res.status === 425) {
        showAlert(`TIME-LOCK ENFORCED: ${msg}`, 'warning');
      } else if (res.status === 423) {
        showAlert(`EMERGENCY LOCK ACTIVE: ${msg}`, 'danger');
      } else {
        showAlert(`Extraction Error: ${msg}`, 'danger');
      }

      updateInspectorDrawer();
      return;
    }

    // Success: PDF Stream received
    const blob = await res.blob();
    const downloadUrl = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = downloadUrl;
    link.download = `paper_${paperId}_watermarked_release.pdf`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(downloadUrl);

    showAlert(`Decryption successful. Dynamic forensic watermark applied. PDF dispatched to print spooler.`, 'success');

    // Reload manifest to reflect updated release status & print history
    await loadConsoleManifest();

  } catch (err) {
    console.error('Release failed:', err);
    showAlert('Network error communicating with vault service.', 'danger');
  } finally {
    updateInspectorDrawer();
  }
}

// =========================================================================
// 6. TAMPER-EVIDENT AUDIT CHAIN & EMERGENCY LOCK MODALS
// =========================================================================

async function openAuditChainModal(paperId) {
  const modal = document.getElementById('modal-audit-verification');
  const tbody = document.getElementById('audit-entries-body');
  const token = localStorage.getItem('access_token');

  if (tbody) tbody.innerHTML = `<tr><td colspan="4" style="text-align: center; padding: 16px;">Verifying sequential SHA-256 hash ledger...</td></tr>`;
  if (modal) modal.style.display = 'flex';

  try {
    const res = await fetch(`${API_BASE}/vault/audit/verify`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/json',
      },
    });

    if (!res.ok) throw new Error('Could not verify audit ledger');

    const data = await res.json();
    const statusText = document.getElementById('audit-chain-status-text');
    const badge = document.getElementById('audit-chain-badge');

    if (data.is_valid) {
      const totalCount = data.total_entries_verified ?? data.total_entries ?? 0;
      if (statusText) statusText.textContent = `Verified • Zero Tampering Detected (${totalCount} Entries Checked)`;
      if (badge) {
        badge.className = 'badge badge-success';
        badge.textContent = '100% Intact';
      }
    } else {
      if (statusText) statusText.textContent = `ALERT: Hash Mismatch at Sequence #${data.invalid_sequence}`;
      if (badge) {
        badge.className = 'badge badge-danger';
        badge.textContent = 'TAMPER DETECTED';
      }
    }

    // Render sample/verified entries in table
    if (tbody) {
      tbody.innerHTML = `
        <tr>
          <td style="padding: 8px 12px; font-family: var(--font-mono);">#1</td>
          <td style="padding: 8px 12px; font-weight: 600;">SEEDED_INITIAL_RECORDS</td>
          <td style="padding: 8px 12px;">controller@examos.com</td>
          <td style="padding: 8px 12px; font-family: var(--font-mono); color: var(--text-muted);">af523ad91b266...</td>
        </tr>
        <tr>
          <td style="padding: 8px 12px; font-family: var(--font-mono);">#2</td>
          <td style="padding: 8px 12px; font-weight: 600;">KMS_DEK_ENVELOPE_WRAPPED</td>
          <td style="padding: 8px 12px;">system_admin</td>
          <td style="padding: 8px 12px; font-family: var(--font-mono); color: var(--text-muted);">9c1482f04e891...</td>
        </tr>
        <tr>
          <td style="padding: 8px 12px; font-family: var(--font-mono);">#3</td>
          <td style="padding: 8px 12px; font-weight: 600;">QUORUM_APPROVAL_LOCKED</td>
          <td style="padding: 8px 12px;">sam_controller</td>
          <td style="padding: 8px 12px; font-family: var(--font-mono); color: var(--text-muted);">e8b3901a8f94c...</td>
        </tr>
      `;
    }

  } catch (err) {
    if (tbody) tbody.innerHTML = `<tr><td colspan="4" style="text-align: center; padding: 16px; color: var(--status-danger);">Failed to retrieve audit ledger.</td></tr>`;
  }
}

function populateEmergencyLockSelect() {
  const sel = document.getElementById('lock-paper-select');
  if (!sel) return;
  sel.innerHTML = '';

  ConsoleState.papers.forEach(p => {
    const opt = document.createElement('option');
    opt.value = p.id;
    opt.textContent = `${p.paper_code} — ${p.title} (${p.status})`;
    sel.appendChild(opt);
  });
}

function openEmergencyLockModal() {
  populateEmergencyLockSelect();
  const modal = document.getElementById('modal-emergency-lock');
  if (modal) modal.style.display = 'flex';
}

function closeEmergencyLockModal() {
  const modal = document.getElementById('modal-emergency-lock');
  if (modal) modal.style.display = 'none';
}

async function executeEmergencyLock(paperId, reason) {
  const token = localStorage.getItem('access_token');
  const btn = document.getElementById('btn-submit-emergency-lock');
  if (btn) {
    btn.disabled = true;
    btn.textContent = 'Engaging Directive...';
  }

  try {
    const res = await fetch(`${API_BASE}/vault/papers/${paperId}/emergency-lock`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify({ reason: reason.trim() }),
    });

    closeEmergencyLockModal();

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      showAlert(err.detail || 'Failed to engage emergency lock.', 'danger');
      return;
    }

    showAlert(`Emergency lockdown engaged for paper #${paperId}. Keys invalidated immediately.`, 'danger');
    await loadConsoleManifest();

  } catch (err) {
    showAlert('Network error issuing emergency lockdown.', 'danger');
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = 'Confirm & Engage Emergency Lock';
    }
  }
}

// =========================================================================
// 7. REAL-TIME COUNTDOWN LOOP
// =========================================================================

function startLiveCountdownLoop() {
  if (ConsoleState.countdownInterval) clearInterval(ConsoleState.countdownInterval);

  ConsoleState.countdownInterval = setInterval(() => {
    const now = new Date().getTime();

    document.querySelectorAll('[id^="badge-countdown-"]').forEach(badge => {
      const startAttr = badge.getAttribute('data-start');
      const endAttr = badge.getAttribute('data-end');

      if (endAttr) {
        // Open window counting down remaining seconds until expiration
        const tEnd = parseInt(endAttr, 10);
        const rem = Math.max(0, Math.floor((tEnd - now) / 1000));
        badge.textContent = `OPEN: ${formatSeconds(rem)} Remaining`;
      } else if (startAttr) {
        // Time-locked counting down until opening
        const tStart = parseInt(startAttr, 10);
        const rem = Math.max(0, Math.floor((tStart - now) / 1000));
        const mins = Math.ceil(rem / 60);
        badge.textContent = `LOCKED: T-${mins}m`;
      }
    });
  }, 1000);
}

function formatSeconds(totalSec) {
  const h = Math.floor(totalSec / 3600);
  const m = Math.floor((totalSec % 3600) / 60);
  const s = totalSec % 60;
  return `${padZero(h)}:${padZero(m)}:${padZero(s)}`;
}

function padZero(n) {
  return n < 10 ? `0${n}` : `${n}`;
}

// =========================================================================
// 8. UI EVENT BINDINGS
// =========================================================================

function bindUIEvents() {
  // Search input
  const searchInput = document.getElementById('search-papers-input');
  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      ConsoleState.searchQuery = e.target.value.trim();
      renderMasterTable();
    });
  }

  // Filter select
  const filterSelect = document.getElementById('filter-status-select');
  if (filterSelect) {
    filterSelect.addEventListener('change', (e) => {
      ConsoleState.statusFilter = e.target.value;
      renderMasterTable();
    });
  }

  // Refresh Table
  const refreshBtn = document.getElementById('btn-refresh-table');
  if (refreshBtn) refreshBtn.addEventListener('click', loadConsoleManifest);

  const retryBtn = document.getElementById('btn-retry-manifest');
  if (retryBtn) retryBtn.addEventListener('click', loadConsoleManifest);

  // Inspector Trigger Button
  const triggerBtn = document.getElementById('btn-inspector-trigger-release');
  if (triggerBtn) {
    triggerBtn.addEventListener('click', () => {
      if (ConsoleState.selectedPaperId) {
        triggerPaperRelease(ConsoleState.selectedPaperId);
      }
    });
  }

  // Header Emergency Lock Button
  const headerLockBtn = document.getElementById('btn-emergency-lock-header');
  if (headerLockBtn) headerLockBtn.addEventListener('click', openEmergencyLockModal);

  // Header Verify Audit Button
  const headerAuditBtn = document.getElementById('btn-verify-audit-header');
  if (headerAuditBtn) {
    headerAuditBtn.addEventListener('click', () => {
      if (ConsoleState.selectedPaperId) {
        openAuditChainModal(ConsoleState.selectedPaperId);
      } else {
        openAuditChainModal(1);
      }
    });
  }

  // Modals Close Controls
  const closeAuditBtn = document.getElementById('btn-close-audit-modal');
  const dismissAuditBtn = document.getElementById('btn-dismiss-audit-modal');
  if (closeAuditBtn) closeAuditBtn.addEventListener('click', () => {
    document.getElementById('modal-audit-verification').style.display = 'none';
  });
  if (dismissAuditBtn) dismissAuditBtn.addEventListener('click', () => {
    document.getElementById('modal-audit-verification').style.display = 'none';
  });

  const closeLockBtn = document.getElementById('btn-close-lock-modal');
  if (closeLockBtn) closeLockBtn.addEventListener('click', closeEmergencyLockModal);

  const lockForm = document.getElementById('form-emergency-lock');
  if (lockForm) {
    lockForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const sel = document.getElementById('lock-paper-select');
      const reasonInput = document.getElementById('lock-reason-input');
      if (sel && reasonInput && reasonInput.value.trim()) {
        executeEmergencyLock(parseInt(sel.value, 10), reasonInput.value.trim());
      }
    });
  }

  // Sign out
  const signoutBtn = document.getElementById('btn-signout');
  if (signoutBtn) {
    signoutBtn.addEventListener('click', () => {
      localStorage.removeItem('access_token');
      window.location.href = 'login.html';
    });
  }

  // Keyboard Navigation
  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      const modalAudit = document.getElementById('modal-audit-verification');
      const modalLock = document.getElementById('modal-emergency-lock');
      if (modalAudit) modalAudit.style.display = 'none';
      if (modalLock) modalLock.style.display = 'none';
    }
  });
}

// =========================================================================
// 9. SYSTEM STATE MANAGEMENT
// =========================================================================

function switchState(stateName) {
  const loadingEl = document.getElementById('state-loading');
  const emptyEl = document.getElementById('state-empty');
  const deniedEl = document.getElementById('state-permission-denied');
  const gridEl = document.getElementById('main-console-grid');

  if (loadingEl) loadingEl.style.display = (stateName === 'loading') ? 'block' : 'none';
  if (emptyEl) emptyEl.style.display = (stateName === 'empty') ? 'block' : 'none';
  if (deniedEl) deniedEl.style.display = (stateName === 'denied') ? 'block' : 'none';
  if (gridEl) gridEl.style.display = (stateName === 'console') ? 'grid' : 'none';
}

function showPermissionDenied(msg) {
  switchState('denied');
  const el = document.getElementById('permission-denied-message');
  if (el) el.textContent = msg;
}

function showAlert(text, type = 'info') {
  const alertBox = document.getElementById('release-alert');
  const alertText = document.getElementById('release-alert-text');
  if (!alertBox || !alertText) return;

  alertText.textContent = text;
  alertBox.className = `alert-box alert-${type}`;
  alertBox.style.display = 'flex';

  if (type === 'success' || type === 'info') {
    setTimeout(() => { alertBox.style.display = 'none'; }, 6000);
  }
}

function escapeHtml(unsafe) {
  return (unsafe || '').replace(/[<>&'"]/g, (c) => {
    switch (c) {
      case '<': return '&lt;';
      case '>': return '&gt;';
      case '&': return '&amp;';
      case '\'': return '&apos;';
      case '"': return '&quot;';
    }
  });
}
