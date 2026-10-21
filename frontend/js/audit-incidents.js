/**
 * ExamOS — Audit Logs & Incident Response Console Client Engine (Vanilla JS)
 * 
 * Features:
 * - Immutable append-only audit trail querying and filtering
 * - Cryptographic hash chain verification
 * - Automated threat sentry anomaly detection
 * - Security drill leak simulations
 * - Formal security incident investigation lifecycle (notes, evidence, closure)
 * - Restricted CSV export
 */

const API_BASE = (window.location.port === '8000') ? '/api/v1' : 'http://127.0.0.1:8000/api/v1';

const AuditState = {
  currentUser: null,
  auditEvents: [],
  totalAudits: 0,
  alerts: [],
  incidents: [],
  activeIncident: null,
  page: 1,
  pageSize: 25,
  activeTab: 'ledger',
  filters: {
    search: '',
    action: 'all',
    outcome: 'all',
  },
};

document.addEventListener('DOMContentLoaded', () => {
  initAuditConsole();
});

// =========================================================================
// 1. INITIALIZATION & SESSION CLEARANCE GUARD
// =========================================================================

async function initAuditConsole() {
  bindUIEvents();

  let token = localStorage.getItem('access_token');
  if (!token) {
    // In local development environment, attempt seamless credential acquisition for system_admin
    if (window.location.hostname === '127.0.0.1' || window.location.hostname === 'localhost') {
      try {
        const autoRes = await fetch(`${API_BASE}/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username_or_email: 'system_admin', password: 'password123' }),
        });
        if (autoRes.ok) {
          const autoData = await autoRes.json();
          if (autoData.access_token) {
            localStorage.setItem('access_token', autoData.access_token);
            token = autoData.access_token;
          }
        }
      } catch (err) {
        console.warn('Dev environment auto-authentication unavailable:', err);
      }
    }

    if (!token) {
      showPermissionDenied('Unauthenticated access. Please sign in with an authorized Administrator or Controller account.');
      return;
    }
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
      showPermissionDenied('Your authentication token has expired or is invalid. Please sign in again.');
      return;
    }

    AuditState.currentUser = await userRes.json();
    const role = (AuditState.currentUser.role || '').toLowerCase();

    // Clearance check: Must be admin or controller
    if (!['admin', 'controller'].includes(role)) {
      showPermissionDenied(
        `Role '${AuditState.currentUser.role.toUpperCase()}' lacks security clearance to inspect audit trails and manage incidents.`
      );
      return;
    }

    renderSecurityOfficerBadge(AuditState.currentUser);
    await loadAuditConsoleData();

  } catch (err) {
    console.error('Initialization error:', err);
    showServerError('Institutional node is unreachable. Verify backend server daemon is active.');
  }
}

function renderSecurityOfficerBadge(user) {
  const displayEl = document.getElementById('audit-user-display');
  if (displayEl) {
    displayEl.textContent = `${user.full_name || user.username} (${user.role.toUpperCase()}) - Active`;
  }
}

// =========================================================================
// 2. DATA MANIFEST LOADING & KPI AGGREGATION
// =========================================================================

async function loadAuditConsoleData() {
  switchState('loading');
  const token = localStorage.getItem('access_token');

  try {
    const queryParams = new URLSearchParams({
      page: AuditState.page,
      page_size: AuditState.pageSize,
    });
    if (AuditState.filters.search) queryParams.append('search', AuditState.filters.search);
    if (AuditState.filters.action !== 'all') queryParams.append('action', AuditState.filters.action);
    if (AuditState.filters.outcome !== 'all') queryParams.append('outcome', AuditState.filters.outcome);

    const [auditRes, alertsRes, incRes, hashRes] = await Promise.all([
      fetch(`${API_BASE}/admin/audit-logs?${queryParams.toString()}`, {
        headers: { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' },
      }),
      fetch(`${API_BASE}/admin/alerts`, {
        headers: { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' },
      }),
      fetch(`${API_BASE}/admin/incidents`, {
        headers: { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' },
      }),
      fetch(`${API_BASE}/vault/audit/verify`, {
        headers: { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' },
      }).catch(() => null),
    ]);

    if (!auditRes.ok) {
      if (auditRes.status === 403) {
        showPermissionDenied('Audit trail access restricted by institutional RBAC.');
        return;
      }
      throw new Error(`Failed to query audit ledger (HTTP ${auditRes.status})`);
    }

    const auditData = await auditRes.json();
    AuditState.auditEvents = auditData.items || [];
    AuditState.totalAudits = auditData.total_matches || AuditState.auditEvents.length;

    AuditState.alerts = alertsRes.ok ? await alertsRes.json() : [];
    AuditState.incidents = incRes.ok ? await incRes.json() : [];

    // Select active incident for drawer (prefer investigating or open)
    if (!AuditState.activeIncident && AuditState.incidents.length > 0) {
      const investigating = AuditState.incidents.find(i => i.status === 'investigating');
      const opened = AuditState.incidents.find(i => i.status === 'open');
      AuditState.activeIncident = investigating || opened || AuditState.incidents[0];
    } else if (AuditState.activeIncident) {
      // Refresh reference
      const refreshed = AuditState.incidents.find(i => i.id === AuditState.activeIncident.id);
      if (refreshed) AuditState.activeIncident = refreshed;
    }

    // Render Components
    renderKPIMetrics(hashRes);
    renderAuditTable();
    renderSentryDrawer();
    renderAlertsTable();
    renderIncidentsTable();

    // Update tab counter
    const incCounter = document.getElementById('tab-incidents-counter');
    const openIncCount = AuditState.incidents.filter(i => i.status !== 'closed').length;
    if (incCounter) incCounter.textContent = `${openIncCount} Active`;

    switchState('console');

  } catch (err) {
    console.error('Audit console loading error:', err);
    showServerError(err.message || 'Error communicating with security service.');
  }
}

function renderKPIMetrics(hashRes) {
  const totalAuditsEl = document.getElementById('kpi-total-audits');
  const alertsCountEl = document.getElementById('kpi-alerts-count');
  const incCountEl = document.getElementById('kpi-incidents-count');
  const ledgerHealthEl = document.getElementById('kpi-ledger-health');

  if (totalAuditsEl) totalAuditsEl.textContent = AuditState.totalAudits.toLocaleString();

  const unresolvedAlerts = AuditState.alerts.filter(a => !a.resolved).length;
  if (alertsCountEl) alertsCountEl.textContent = unresolvedAlerts;

  const openIncidents = AuditState.incidents.filter(i => i.status !== 'closed').length;
  if (incCountEl) incCountEl.textContent = openIncidents;

  if (hashRes && hashRes.ok) {
    hashRes.json().then(data => {
      if (ledgerHealthEl) {
        if (data.is_valid) {
          ledgerHealthEl.textContent = '100% Intact';
          ledgerHealthEl.style.color = '#166534';
        } else {
          ledgerHealthEl.textContent = 'Tamper Alert';
          ledgerHealthEl.style.color = '#dc2626';
        }
      }
    }).catch(() => {});
  }
}

// =========================================================================
// 3. AUDIT MASTER TABLE RENDERING
// =========================================================================

function renderAuditTable() {
  const tbody = document.getElementById('audit-table-body');
  if (!tbody) return;

  if (AuditState.auditEvents.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="7" style="text-align: center; padding: 36px; color: var(--text-secondary);">
          No audit records found matching the active filter criteria.
        </td>
      </tr>
    `;
    updatePaginationControls();
    return;
  }

  tbody.innerHTML = AuditState.auditEvents.map(evt => {
    const formattedDate = formatUtcTimestamp(evt.timestamp);
    const actorText = evt.actor_username || evt.actor_email || `User #${evt.actor_id}`;
    const outcomeSlug = (evt.outcome || '').toUpperCase();
    const isSuccess = outcomeSlug === 'SUCCESS';

    let actionBadgeClass = 'action-badge';
    if (evt.action.includes('HONEYTOKEN')) actionBadgeClass += ' action-badge-honeytoken';
    else if (evt.action.includes('VAULT')) actionBadgeClass += ' action-badge-vault';

    const entityText = evt.entity_type ? `${evt.entity_type}${evt.entity_id ? ` #${evt.entity_id}` : ''}` : '--';

    return `
      <tr style="cursor: pointer;" onclick="openAuditDetailModal(${evt.id})">
        <td style="font-family: var(--font-mono); font-size: 12px; color: var(--text-secondary); white-space: nowrap;">
          ${formattedDate}
        </td>
        <td>
          <div style="font-weight: 600; color: var(--text-primary);">${escapeHtml(actorText)}</div>
          <div style="font-size: 11px; color: var(--text-muted); font-family: var(--font-mono);">${escapeHtml(evt.actor_email || '')}</div>
        </td>
        <td>
          <span class="${actionBadgeClass}">${escapeHtml(evt.action)}</span>
        </td>
        <td style="font-size: 12px; color: var(--text-secondary);">
          ${escapeHtml(entityText)}
        </td>
        <td>
          <span class="outcome-pill ${isSuccess ? 'outcome-pill-success' : 'outcome-pill-failure'}">
            ${escapeHtml(outcomeSlug)}
          </span>
        </td>
        <td style="font-family: var(--font-mono); font-size: 12px; color: var(--text-muted);">
          ${escapeHtml(evt.ip_address || '127.0.0.1')}
        </td>
        <td style="text-align: right;" onclick="event.stopPropagation();">
          <button type="button" class="btn btn-secondary btn-sm" onclick="openAuditDetailModal(${evt.id})" style="padding: 2px 8px; font-size: 11px;">
            Payload
          </button>
        </td>
      </tr>
    `;
  }).join('');

  updatePaginationControls();
}

function updatePaginationControls() {
  const infoEl = document.getElementById('audit-pagination-info');
  const prevBtn = document.getElementById('btn-audit-prev');
  const nextBtn = document.getElementById('btn-audit-next');

  const start = (AuditState.page - 1) * AuditState.pageSize + 1;
  const end = Math.min(AuditState.totalAudits, AuditState.page * AuditState.pageSize);

  if (infoEl) {
    if (AuditState.totalAudits === 0) {
      infoEl.textContent = 'Showing 0 of 0 events';
    } else {
      infoEl.textContent = `Showing ${start} – ${end} of ${AuditState.totalAudits} events`;
    }
  }

  if (prevBtn) prevBtn.disabled = AuditState.page <= 1;
  if (nextBtn) nextBtn.disabled = end >= AuditState.totalAudits;
}

function formatUtcTimestamp(isoStr) {
  if (!isoStr) return '--';
  try {
    const d = new Date(isoStr);
    const pad = (n) => (n < 10 ? `0${n}` : n);
    return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} UTC`;
  } catch {
    return isoStr;
  }
}

// =========================================================================
// 4. SENTRY & ACTIVE INCIDENT DRAWER (RIGHT COLUMN)
// =========================================================================

function renderSentryDrawer() {
  const container = document.getElementById('sentry-drawer-content');
  if (!container) return;

  const inc = AuditState.activeIncident;
  if (!inc) {
    container.innerHTML = `
      <div style="padding: 24px 0; text-align: center; color: var(--text-muted); font-size: 13px;">
        No security incidents currently flagged. System perimeter is secure.
      </div>
    `;
    return;
  }

  const sevSlug = (inc.severity || 'medium').toLowerCase();
  const notes = inc.investigation_notes || [];
  const evidence = inc.evidence_references || [];

  const notesHtml = notes.length > 0
    ? notes.map(n => `
        <div class="timeline-item">
          <div class="timeline-dot"></div>
          <div class="timeline-time">${formatUtcTimestamp(n.timestamp_utc)} &bull; ${escapeHtml(n.author_email || 'Author')}</div>
          <div class="timeline-note">${escapeHtml(n.note)}</div>
        </div>
      `).join('')
    : '<div style="font-size: 12px; color: var(--text-muted); font-style: italic;">No investigation notes recorded yet.</div>';

  const evidenceHtml = evidence.length > 0
    ? evidence.map(e => `
        <div style="background: #f8fafc; border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); padding: 8px 12px; margin-bottom: 6px; font-size: 12px;">
          <div style="display: flex; justify-content: space-between; font-weight: 600; color: var(--text-primary);">
            <span>${escapeHtml(e.evidence_type)}</span>
            <span style="font-family: var(--font-mono); color: var(--color-primary);">${escapeHtml(e.reference_id)}</span>
          </div>
          <div style="color: var(--text-secondary); margin-top: 2px;">${escapeHtml(e.description)}</div>
        </div>
      `).join('')
    : '<div style="font-size: 12px; color: var(--text-muted); font-style: italic;">No forensic evidence attached.</div>';

  const isClosed = inc.status === 'closed';

  container.innerHTML = `
    <!-- Incident Header Banner -->
    <div class="sentry-incident-banner">
      <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 6px;">
        <span style="font-family: var(--font-mono); font-size: 12px; font-weight: 700; color: #991b1b;">
          ${escapeHtml(inc.incident_code)}
        </span>
        <span class="severity-badge severity-badge-${sevSlug}">${escapeHtml(inc.severity)}</span>
      </div>
      <div style="font-size: 14px; font-weight: 700; color: var(--text-primary); margin-bottom: 4px;">
        ${escapeHtml(inc.title)}
      </div>
      <div style="font-size: 12px; color: var(--text-secondary); line-height: 1.4;">
        ${escapeHtml(inc.description)}
      </div>
      <div style="font-size: 11px; color: var(--text-muted); margin-top: 8px;">
        Status: <strong style="text-transform: uppercase;">${escapeHtml(inc.status)}</strong> &bull; Category: ${escapeHtml(inc.category)}
      </div>
    </div>

    <!-- Timeline Notes -->
    <div style="font-size: 12px; font-weight: 700; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.04em; margin-bottom: 8px;">
      Investigation Notes Timeline
    </div>
    <div class="incident-timeline">
      ${notesHtml}
    </div>

    <!-- Evidentiary References -->
    <div style="font-size: 12px; font-weight: 700; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.04em; margin: 16px 0 8px 0;">
      Forensic Evidentiary Proof (${evidence.length})
    </div>
    <div style="max-height: 140px; overflow-y: auto; margin-bottom: 16px;">
      ${evidenceHtml}
    </div>

    <!-- Closure remarks if closed -->
    ${isClosed ? `
      <div style="background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: var(--radius-sm); padding: 10px; margin-bottom: 14px; font-size: 12px;">
        <strong style="color: #166534;">Formally Closed:</strong> ${escapeHtml(inc.closure_approval_notes || 'Approved')}
        <div style="color: var(--text-secondary); margin-top: 2px;">Root cause: ${escapeHtml(inc.root_cause || '--')}</div>
      </div>
    ` : ''}

    <!-- Action Buttons -->
    <div style="display: flex; flex-direction: column; gap: 8px;">
      <button type="button" class="btn btn-secondary btn-sm" id="btn-sentry-add-note" ${isClosed ? 'disabled' : ''} onclick="openAddNoteModal(${inc.id})">
        &plus; Add Note
      </button>
      <button type="button" class="btn btn-secondary btn-sm" id="btn-sentry-add-evidence" ${isClosed ? 'disabled' : ''} onclick="openAddEvidenceModal(${inc.id})">
        &infin; Attach Evidence
      </button>
      <button type="button" class="btn btn-sm" id="btn-sentry-close-incident" ${isClosed ? 'disabled' : ''} style="background: ${isClosed ? '#e2e8f0' : '#166534'}; color: #ffffff; border: none;" onclick="openCloseIncidentModal(${inc.id})">
        ${isClosed ? 'Incident Formally Closed' : '&check; Close Incident'}
      </button>
    </div>
  `;
}

// =========================================================================
// 5. INCIDENTS & ALERTS VIEW (TAB 2)
// =========================================================================

function renderAlertsTable() {
  const tbody = document.getElementById('alerts-table-body');
  if (!tbody) return;

  if (AuditState.alerts.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; padding: 24px; color: var(--text-muted);">Zero active automated alerts. Sentry perimeter operational.</td></tr>`;
    return;
  }

  tbody.innerHTML = AuditState.alerts.map(a => {
    const sevSlug = (a.severity || 'medium').toLowerCase();
    return `
      <tr>
        <td>
          <span class="severity-badge severity-badge-${sevSlug}">${escapeHtml(a.severity)}</span>
        </td>
        <td>
          <div style="font-weight: 600; color: var(--text-primary);">${escapeHtml(a.message)}</div>
          <div style="font-size: 11px; color: var(--text-muted);">${a.resolved ? 'RESOLVED' : 'UNRESOLVED'}</div>
        </td>
        <td style="font-size: 12px; color: var(--text-secondary);">
          ${escapeHtml(a.actor_username || `Actor #${a.actor_id || 'System'}`)}
        </td>
        <td style="font-family: var(--font-mono); font-size: 12px; color: var(--text-muted);">
          ${formatUtcTimestamp(a.created_at)}
        </td>
        <td style="text-align: right;">
          ${a.resolved
            ? '<span style="font-size: 12px; color: #166534; font-weight: 600;">Resolved</span>'
            : `<button type="button" class="btn btn-secondary btn-sm" onclick="openResolveAlertModal(${a.id})" style="padding: 2px 8px; font-size: 11px;">Resolve</button>`
          }
        </td>
      </tr>
    `;
  }).join('');
}

function renderIncidentsTable() {
  const tbody = document.getElementById('incidents-table-body');
  if (!tbody) return;

  if (AuditState.incidents.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; padding: 24px; color: var(--text-muted);">No formal security incidents registered.</td></tr>`;
    return;
  }

  tbody.innerHTML = AuditState.incidents.map(inc => {
    const sevSlug = (inc.severity || 'medium').toLowerCase();
    const isSelected = AuditState.activeIncident && AuditState.activeIncident.id === inc.id;

    return `
      <tr class="${isSelected ? 'selected-row' : ''}" style="cursor: pointer;" onclick="selectIncident(${inc.id})">
        <td style="font-family: var(--font-mono); font-weight: 700; color: #991b1b; font-size: 12px;">
          ${escapeHtml(inc.incident_code)}
        </td>
        <td>
          <div style="font-weight: 600; color: var(--text-primary);">${escapeHtml(inc.title)}</div>
        </td>
        <td>
          <span class="severity-badge severity-badge-${sevSlug}">${escapeHtml(inc.severity)}</span>
        </td>
        <td>
          <span style="font-size: 11px; font-weight: 700; text-transform: uppercase;">${escapeHtml(inc.status)}</span>
        </td>
        <td style="font-size: 12px; color: var(--text-secondary);">
          ${escapeHtml(inc.category)}
        </td>
        <td style="font-family: var(--font-mono); font-size: 12px;">
          ${escapeHtml(inc.related_paper_code || '--')}
        </td>
        <td style="text-align: right;">
          <button type="button" class="btn btn-secondary btn-sm" onclick="selectIncident(${inc.id}); switchTab('ledger');" style="padding: 2px 8px; font-size: 11px;">
            Investigate
          </button>
        </td>
      </tr>
    `;
  }).join('');
}

function selectIncident(incId) {
  const inc = AuditState.incidents.find(i => i.id === incId);
  if (inc) {
    AuditState.activeIncident = inc;
    renderSentryDrawer();
    renderIncidentsTable();
  }
}

// =========================================================================
// 6. MODALS & INTERACTIVE SECURITY WORKFLOWS
// =========================================================================

// --- Modal 1: Open Formal Incident ---
function openNewIncidentModal() {
  const modal = document.getElementById('modal-open-incident');
  const form = document.getElementById('form-open-incident');
  const errBox = document.getElementById('inc-error-msg');
  if (errBox) errBox.style.display = 'none';
  if (form) form.reset();
  if (modal) modal.style.display = 'flex';
}

function closeNewIncidentModal() {
  const modal = document.getElementById('modal-open-incident');
  if (modal) modal.style.display = 'none';
}

async function executeOpenIncident(e) {
  e.preventDefault();
  const token = localStorage.getItem('access_token');
  const errBox = document.getElementById('inc-error-msg');
  const submitBtn = document.getElementById('btn-submit-incident');

  const title = document.getElementById('inc-title').value.trim();
  const severity = document.getElementById('inc-severity').value;
  const category = document.getElementById('inc-category').value.trim();
  const paperCode = document.getElementById('inc-paper-code').value.trim();
  const description = document.getElementById('inc-description').value.trim();

  if (errBox) errBox.style.display = 'none';

  if (!title || !category || !description) {
    showFormError(errBox, 'Title, category, and initial description are mandatory.');
    return;
  }

  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.textContent = 'Registering Incident...';
  }

  try {
    const res = await fetch(`${API_BASE}/admin/incidents`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify({
        title,
        severity,
        category,
        description,
        related_paper_code: paperCode || null,
      }),
    });

    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
      showFormError(errBox, data.detail || 'Failed to open security incident.');
      return;
    }

    closeNewIncidentModal();
    showAlert(`Formal incident ${data.incident_code} registered successfully. Sentry tracking active.`, 'success');
    await loadAuditConsoleData();
    selectIncident(data.id);

  } catch (err) {
    showFormError(errBox, 'Network communication error connecting to administrative service.');
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Create Incident Case';
    }
  }
}

// --- Modal 2: Add Investigation Note ---
function openAddNoteModal(incId) {
  const modal = document.getElementById('modal-add-note');
  const form = document.getElementById('form-add-note');
  const errBox = document.getElementById('note-error-msg');
  if (errBox) errBox.style.display = 'none';
  if (form) form.reset();
  document.getElementById('note-incident-id').value = incId;
  if (modal) modal.style.display = 'flex';
}

function closeAddNoteModal() {
  const modal = document.getElementById('modal-add-note');
  if (modal) modal.style.display = 'none';
}

async function executeAddNote(e) {
  e.preventDefault();
  const token = localStorage.getItem('access_token');
  const errBox = document.getElementById('note-error-msg');
  const submitBtn = document.getElementById('btn-submit-note');

  const incId = document.getElementById('note-incident-id').value;
  const note = document.getElementById('note-text').value.trim();

  if (errBox) errBox.style.display = 'none';

  if (!note) {
    showFormError(errBox, 'Observation note cannot be empty.');
    return;
  }

  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.textContent = 'Appending...';
  }

  try {
    const res = await fetch(`${API_BASE}/admin/incidents/${incId}/notes`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify({ note }),
    });

    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
      showFormError(errBox, data.detail || 'Failed to append note.');
      return;
    }

    closeAddNoteModal();
    showAlert(`Note added to incident #${incId}.`, 'success');
    await loadAuditConsoleData();

  } catch (err) {
    showFormError(errBox, 'Network communication error.');
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Append Note';
    }
  }
}

// --- Modal 3: Attach Evidence ---
function openAddEvidenceModal(incId) {
  const modal = document.getElementById('modal-add-evidence');
  const form = document.getElementById('form-add-evidence');
  const errBox = document.getElementById('evidence-error-msg');
  if (errBox) errBox.style.display = 'none';
  if (form) form.reset();
  document.getElementById('evidence-incident-id').value = incId;
  if (modal) modal.style.display = 'flex';
}

function closeAddEvidenceModal() {
  const modal = document.getElementById('modal-add-evidence');
  if (modal) modal.style.display = 'none';
}

async function executeAddEvidence(e) {
  e.preventDefault();
  const token = localStorage.getItem('access_token');
  const errBox = document.getElementById('evidence-error-msg');
  const submitBtn = document.getElementById('btn-submit-evidence');

  const incId = document.getElementById('evidence-incident-id').value;
  const evidenceType = document.getElementById('evidence-type').value;
  const referenceId = document.getElementById('evidence-ref-id').value.trim();
  const description = document.getElementById('evidence-description').value.trim();

  if (errBox) errBox.style.display = 'none';

  if (!referenceId || !description) {
    showFormError(errBox, 'Reference ID and description are mandatory.');
    return;
  }

  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.textContent = 'Attaching...';
  }

  try {
    const res = await fetch(`${API_BASE}/admin/incidents/${incId}/evidence`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify({
        evidence_type: evidenceType,
        reference_id: referenceId,
        description,
      }),
    });

    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
      showFormError(errBox, data.detail || 'Failed to attach evidence.');
      return;
    }

    closeAddEvidenceModal();
    showAlert(`Evidence ${referenceId} committed to incident chain of custody.`, 'success');
    await loadAuditConsoleData();

  } catch (err) {
    showFormError(errBox, 'Network communication error.');
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Attach Evidence';
    }
  }
}

// --- Modal 4: Close Security Incident ---
function openCloseIncidentModal(incId) {
  const modal = document.getElementById('modal-close-incident');
  const form = document.getElementById('form-close-incident');
  const errBox = document.getElementById('close-inc-error-msg');
  if (errBox) errBox.style.display = 'none';
  if (form) form.reset();
  document.getElementById('close-incident-id').value = incId;
  if (modal) modal.style.display = 'flex';
}

function closeCloseIncidentModal() {
  const modal = document.getElementById('modal-close-incident');
  if (modal) modal.style.display = 'none';
}

async function executeCloseIncident(e) {
  e.preventDefault();
  const token = localStorage.getItem('access_token');
  const errBox = document.getElementById('close-inc-error-msg');
  const submitBtn = document.getElementById('btn-submit-close-inc');

  const incId = document.getElementById('close-incident-id').value;
  const rootCause = document.getElementById('close-root-cause').value.trim();
  const remediation = document.getElementById('close-remediation').value.trim();
  const notes = document.getElementById('close-approval-notes').value.trim();

  if (errBox) errBox.style.display = 'none';

  if (!rootCause || !remediation || !notes) {
    showFormError(errBox, 'All closure fields are mandatory under institutional policy.');
    return;
  }

  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.textContent = 'Authorizing Closure...';
  }

  try {
    const res = await fetch(`${API_BASE}/admin/incidents/${incId}/close`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify({
        root_cause: rootCause,
        remediation_steps: remediation,
        closure_approval_notes: notes,
      }),
    });

    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
      showFormError(errBox, data.detail || 'Failed to close incident.');
      return;
    }

    closeCloseIncidentModal();
    showAlert(`Incident ${data.incident_code} formally resolved and closed.`, 'success');
    await loadAuditConsoleData();

  } catch (err) {
    showFormError(errBox, 'Network communication error.');
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Execute Authorized Closure';
    }
  }
}

// --- Modal 5: Resolve Alert ---
function openResolveAlertModal(alertId) {
  const modal = document.getElementById('modal-resolve-alert');
  const form = document.getElementById('form-resolve-alert');
  const errBox = document.getElementById('res-alert-error-msg');
  if (errBox) errBox.style.display = 'none';
  if (form) form.reset();
  document.getElementById('resolve-alert-id').value = alertId;
  if (modal) modal.style.display = 'flex';
}

function closeResolveAlertModal() {
  const modal = document.getElementById('modal-resolve-alert');
  if (modal) modal.style.display = 'none';
}

async function executeResolveAlert(e) {
  e.preventDefault();
  const token = localStorage.getItem('access_token');
  const errBox = document.getElementById('res-alert-error-msg');
  const submitBtn = document.getElementById('btn-submit-resolve-alert');

  const alertId = document.getElementById('resolve-alert-id').value;
  const notes = document.getElementById('alert-resolution-notes').value.trim();

  if (errBox) errBox.style.display = 'none';

  if (!notes) {
    showFormError(errBox, 'Resolution remarks are required.');
    return;
  }

  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.textContent = 'Resolving...';
  }

  try {
    const res = await fetch(`${API_BASE}/admin/alerts/${alertId}/resolve`, {
      method: 'PATCH',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify({ resolution_notes: notes }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      showFormError(errBox, err.detail || 'Failed to resolve alert.');
      return;
    }

    closeResolveAlertModal();
    showAlert(`Alert #${alertId} marked as resolved.`, 'success');
    await loadAuditConsoleData();

  } catch (err) {
    showFormError(errBox, 'Network communication error.');
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Resolve Alert';
    }
  }
}

// --- Modal 6: View Audit Detail ---
function openAuditDetailModal(eventId) {
  const evt = AuditState.auditEvents.find(e => e.id === eventId);
  if (!evt) return;

  const modal = document.getElementById('modal-audit-detail');
  const actionText = document.getElementById('detail-action-text');
  const timeText = document.getElementById('detail-timestamp-text');
  const jsonCode = document.getElementById('detail-json-code');

  if (actionText) actionText.textContent = evt.action;
  if (timeText) timeText.textContent = formatUtcTimestamp(evt.timestamp);

  let formattedJson = '{}';
  try {
    const parsed = evt.metadata_json ? JSON.parse(evt.metadata_json) : {};
    formattedJson = JSON.stringify({
      id: evt.id,
      timestamp: evt.timestamp,
      action: evt.action,
      outcome: evt.outcome,
      actor_id: evt.actor_id,
      actor_username: evt.actor_username,
      actor_email: evt.actor_email,
      ip_address: evt.ip_address,
      correlation_id: evt.correlation_id,
      entity_type: evt.entity_type,
      entity_id: evt.entity_id,
      metadata: parsed,
    }, null, 2);
  } catch {
    formattedJson = evt.metadata_json || '{}';
  }

  if (jsonCode) jsonCode.textContent = formattedJson;
  if (modal) modal.style.display = 'flex';
}

function closeAuditDetailModal() {
  const modal = document.getElementById('modal-audit-detail');
  if (modal) modal.style.display = 'none';
}

// =========================================================================
// 7. EXPORT CSV & AUTOMATED SCANS
// =========================================================================

async function executeExportCSV() {
  const token = localStorage.getItem('access_token');
  showAlert('Generating cryptographically audited CSV export...', 'info');

  try {
    const res = await fetch(`${API_BASE}/admin/audit-logs/export?limit=500`, {
      headers: {
        'Authorization': `Bearer ${token}`,
      },
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      showAlert(err.detail || 'Failed to export audit logs.', 'danger');
      return;
    }

    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `examos_audit_trail_${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);

    showAlert('Audit log export downloaded. Export event recorded in append-only ledger.', 'success');
    await loadAuditConsoleData();

  } catch (err) {
    showAlert('Network error downloading CSV export.', 'danger');
  }
}

async function executeAnomalyScan() {
  const token = localStorage.getItem('access_token');
  showAlert('Running automated heuristic anomaly sentry scan...', 'info');

  try {
    const res = await fetch(`${API_BASE}/admin/alerts/scan-anomalies`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/json',
      },
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      showAlert(err.detail || 'Anomaly scan failed.', 'danger');
      return;
    }

    const alerts = await res.json();
    showAlert(`Automated scan completed. ${alerts.length} new anomalous threat signals identified.`, 'warning');
    await loadAuditConsoleData();

  } catch (err) {
    showAlert('Network error executing anomaly scan.', 'danger');
  }
}

async function executeSimulateDrill() {
  const token = localStorage.getItem('access_token');
  showAlert('Simulating authorized synthetic security leak drill...', 'info');

  try {
    const res = await fetch(`${API_BASE}/admin/simulate-leak`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/json',
      },
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      showAlert(err.detail || 'Simulation failed.', 'danger');
      return;
    }

    showAlert('Simulation drill executed. Synthetic honeytoken trips logged in audit stream.', 'warning');
    await loadAuditConsoleData();

  } catch (err) {
    showAlert('Network error executing simulation drill.', 'danger');
  }
}

// =========================================================================
// 8. TAB SWITCHING & UI EVENT BINDINGS
// =========================================================================

function switchTab(tabName) {
  AuditState.activeTab = tabName;
  const btnLedger = document.getElementById('tab-btn-ledger');
  const btnInc = document.getElementById('tab-btn-incidents');
  const viewLedger = document.getElementById('view-audit-ledger');
  const viewInc = document.getElementById('view-incident-response');

  if (tabName === 'ledger') {
    if (btnLedger) btnLedger.classList.add('active');
    if (btnInc) btnInc.classList.remove('active');
    if (viewLedger) viewLedger.style.display = 'grid';
    if (viewInc) viewInc.style.display = 'none';
  } else {
    if (btnLedger) btnLedger.classList.remove('active');
    if (btnInc) btnInc.classList.add('active');
    if (viewLedger) viewLedger.style.display = 'none';
    if (viewInc) viewInc.style.display = 'flex';
  }
}

function bindUIEvents() {
  // Tabs
  const btnLedger = document.getElementById('tab-btn-ledger');
  const btnInc = document.getElementById('tab-btn-incidents');
  if (btnLedger) btnLedger.addEventListener('click', () => switchTab('ledger'));
  if (btnInc) btnInc.addEventListener('click', () => switchTab('incidents'));

  // Search input
  const searchInput = document.getElementById('search-audit-input');
  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      AuditState.filters.search = e.target.value.trim();
      AuditState.page = 1;
      loadAuditConsoleData();
    });
  }

  // Action filter
  const actionSelect = document.getElementById('filter-audit-action');
  if (actionSelect) {
    actionSelect.addEventListener('change', (e) => {
      AuditState.filters.action = e.target.value;
      AuditState.page = 1;
      loadAuditConsoleData();
    });
  }

  // Outcome filter
  const outcomeSelect = document.getElementById('filter-audit-outcome');
  if (outcomeSelect) {
    outcomeSelect.addEventListener('change', (e) => {
      AuditState.filters.outcome = e.target.value;
      AuditState.page = 1;
      loadAuditConsoleData();
    });
  }

  // Refresh Audits
  const refreshBtn = document.getElementById('btn-refresh-audits');
  if (refreshBtn) refreshBtn.addEventListener('click', loadAuditConsoleData);

  // Export CSV
  const exportBtn = document.getElementById('btn-export-audit-csv');
  if (exportBtn) exportBtn.addEventListener('click', executeExportCSV);

  // Pagination buttons
  const prevBtn = document.getElementById('btn-audit-prev');
  const nextBtn = document.getElementById('btn-audit-next');
  if (prevBtn) {
    prevBtn.addEventListener('click', () => {
      if (AuditState.page > 1) {
        AuditState.page--;
        loadAuditConsoleData();
      }
    });
  }
  if (nextBtn) {
    nextBtn.addEventListener('click', () => {
      AuditState.page++;
      loadAuditConsoleData();
    });
  }

  // Anomaly scan & drill buttons
  const scanBtn = document.getElementById('btn-scan-anomalies');
  if (scanBtn) scanBtn.addEventListener('click', executeAnomalyScan);

  const drillBtn = document.getElementById('btn-simulate-drill');
  if (drillBtn) drillBtn.addEventListener('click', executeSimulateDrill);

  // Modal open triggers
  const openIncBtn = document.getElementById('btn-open-new-incident-modal');
  if (openIncBtn) openIncBtn.addEventListener('click', openNewIncidentModal);

  // Modal close triggers
  const closeIncBtn = document.getElementById('btn-close-inc-modal');
  const cancelIncBtn = document.getElementById('btn-cancel-inc');
  if (closeIncBtn) closeIncBtn.addEventListener('click', closeNewIncidentModal);
  if (cancelIncBtn) cancelIncBtn.addEventListener('click', closeNewIncidentModal);

  const closeNoteBtn = document.getElementById('btn-close-note-modal');
  const cancelNoteBtn = document.getElementById('btn-cancel-note');
  if (closeNoteBtn) closeNoteBtn.addEventListener('click', closeAddNoteModal);
  if (cancelNoteBtn) cancelNoteBtn.addEventListener('click', closeAddNoteModal);

  const closeEvidenceBtn = document.getElementById('btn-close-evidence-modal');
  const cancelEvidenceBtn = document.getElementById('btn-cancel-evidence');
  if (closeEvidenceBtn) closeEvidenceBtn.addEventListener('click', closeAddEvidenceModal);
  if (cancelEvidenceBtn) cancelEvidenceBtn.addEventListener('click', closeAddEvidenceModal);

  const closeCloseIncBtn = document.getElementById('btn-close-close-inc-modal');
  const cancelCloseIncBtn = document.getElementById('btn-cancel-close-inc');
  if (closeCloseIncBtn) closeCloseIncBtn.addEventListener('click', closeCloseIncidentModal);
  if (cancelCloseIncBtn) cancelCloseIncBtn.addEventListener('click', closeCloseIncidentModal);

  const closeAlertResBtn = document.getElementById('btn-close-alert-res-modal');
  const cancelAlertResBtn = document.getElementById('btn-cancel-alert-res');
  if (closeAlertResBtn) closeAlertResBtn.addEventListener('click', closeResolveAlertModal);
  if (cancelAlertResBtn) cancelAlertResBtn.addEventListener('click', closeResolveAlertModal);

  const closeDetailBtn = document.getElementById('btn-close-detail-modal');
  const dismissDetailBtn = document.getElementById('btn-dismiss-detail');
  if (closeDetailBtn) closeDetailBtn.addEventListener('click', closeAuditDetailModal);
  if (dismissDetailBtn) dismissDetailBtn.addEventListener('click', closeAuditDetailModal);

  // Modal Form Submits
  const incForm = document.getElementById('form-open-incident');
  if (incForm) incForm.addEventListener('submit', executeOpenIncident);

  const noteForm = document.getElementById('form-add-note');
  if (noteForm) noteForm.addEventListener('submit', executeAddNote);

  const evidenceForm = document.getElementById('form-add-evidence');
  if (evidenceForm) evidenceForm.addEventListener('submit', executeAddEvidence);

  const closeIncForm = document.getElementById('form-close-incident');
  if (closeIncForm) closeIncForm.addEventListener('submit', executeCloseIncident);

  const resAlertForm = document.getElementById('form-resolve-alert');
  if (resAlertForm) resAlertForm.addEventListener('submit', executeResolveAlert);

  // Sign out button
  const signoutBtn = document.getElementById('btn-signout');
  if (signoutBtn) {
    signoutBtn.addEventListener('click', () => {
      localStorage.removeItem('access_token');
      window.location.href = 'login.html';
    });
  }

  // Alert close
  const alertClose = document.getElementById('audit-alert-close');
  if (alertClose) {
    alertClose.addEventListener('click', () => {
      const alertBox = document.getElementById('audit-alert');
      if (alertBox) alertBox.style.display = 'none';
    });
  }

  // Retry server
  const retryBtn = document.getElementById('btn-retry-server');
  if (retryBtn) retryBtn.addEventListener('click', initAuditConsole);

  // Escape key closes modals
  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      closeNewIncidentModal();
      closeAddNoteModal();
      closeAddEvidenceModal();
      closeCloseIncidentModal();
      closeResolveAlertModal();
      closeAuditDetailModal();
    }
  });
}

// =========================================================================
// 9. SYSTEM STATE MANAGEMENT & UTILS
// =========================================================================

function switchState(stateName) {
  const loadingEl = document.getElementById('state-loading');
  const deniedEl = document.getElementById('state-permission-denied');
  const serverErrorEl = document.getElementById('state-server-error');
  const consoleEl = document.getElementById('main-audit-console');

  if (loadingEl) loadingEl.style.display = (stateName === 'loading') ? 'block' : 'none';
  if (deniedEl) deniedEl.style.display = (stateName === 'denied') ? 'block' : 'none';
  if (serverErrorEl) serverErrorEl.style.display = (stateName === 'server-error') ? 'block' : 'none';
  if (consoleEl) consoleEl.style.display = (stateName === 'console') ? 'block' : 'none';
}

function showPermissionDenied(msg) {
  switchState('denied');
  const el = document.getElementById('permission-denied-message');
  if (el) el.textContent = msg;
}

function showServerError(msg) {
  switchState('server-error');
  const el = document.getElementById('server-error-message');
  if (el) el.textContent = msg;
}

function showAlert(text, type = 'info') {
  const alertBox = document.getElementById('audit-alert');
  const alertText = document.getElementById('audit-alert-text');
  if (!alertBox || !alertText) return;

  alertText.textContent = text;
  alertBox.className = `alert-box alert-${type}`;
  alertBox.style.display = 'flex';

  if (type === 'success' || type === 'info') {
    setTimeout(() => { alertBox.style.display = 'none'; }, 6000);
  }
}

function showFormError(container, msg) {
  if (!container) return;
  container.textContent = msg;
  container.style.display = 'block';
}

function escapeHtml(unsafe) {
  return (unsafe || '').toString().replace(/[<>&'"]/g, (c) => {
    switch (c) {
      case '<': return '&lt;';
      case '>': return '&gt;';
      case '&': return '&amp;';
      case '\'': return '&apos;';
      case '"': return '&quot;';
    }
  });
}
