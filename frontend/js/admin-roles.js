/**
 * ExamOS — Admin and Role Management Console Client Engine (Vanilla JS)
 * 
 * Features:
 * - Institutional RBAC permission verification
 * - Real-time directory querying with search and multi-criteria filters
 * - Live KPI metric aggregation (Total, Active, Locked, Inactive)
 * - User provisioning with server-side Argon2id password hashing
 * - Account unlock and credential reset workflows
 * - Role & Permission Matrix Inspector displaying active system boundaries
 * - Tamper-evident audit ledger health verification
 */

const API_BASE = (window.location.port === '8000') ? '/api/v1' : 'http://127.0.0.1:8000/api/v1';

const AdminState = {
  currentUser: null,
  users: [],
  rolesMatrix: [],
  selectedUserId: null,
  searchQuery: '',
  roleFilter: 'all',
  deptFilter: 'all',
};

document.addEventListener('DOMContentLoaded', () => {
  initAdminRolesConsole();
});

// =========================================================================
// 1. INITIALIZATION & SESSION AUTHENTICATION GUARD
// =========================================================================

async function initAdminRolesConsole() {
  bindUIEvents();

  const token = localStorage.getItem('access_token');
  if (!token) {
    showAlert('Unauthenticated administrative access. Redirecting to sign in...', 'danger');
    setTimeout(() => { window.location.href = 'login.html'; }, 800);
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

    AdminState.currentUser = await userRes.json();
    const role = (AdminState.currentUser.role || '').toLowerCase();

    // Verify Master Admin Authorization (Role: admin)
    if (role !== 'admin') {
      showPermissionDenied(
        `Your authenticated role (${AdminState.currentUser.role.toUpperCase()}) does not hold administrative directory management privileges.`
      );
      return;
    }

    renderAdminSession(AdminState.currentUser);
    await loadAdminDirectoryManifest();

  } catch (err) {
    console.error('Initialization error:', err);
    showServerError('Institutional node is unreachable. Verify backend server daemon is active.');
  }
}

function renderAdminSession(user) {
  const displayEl = document.getElementById('admin-user-display');
  if (displayEl) {
    displayEl.textContent = `${user.full_name || user.username} (${user.role.toUpperCase()}) - Active`;
  }
}

// =========================================================================
// 2. DATA MANIFEST LOADING & KPI AGGREGATION
// =========================================================================

async function loadAdminDirectoryManifest() {
  switchState('loading');
  const token = localStorage.getItem('access_token');

  try {
    const [usersRes, rolesRes, auditRes] = await Promise.all([
      fetch(`${API_BASE}/admin/users`, {
        headers: { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' },
      }),
      fetch(`${API_BASE}/admin/roles/permissions`, {
        headers: { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' },
      }),
      fetch(`${API_BASE}/vault/audit/verify`, {
        headers: { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' },
      }).catch(() => null),
    ]);

    if (!usersRes.ok) {
      if (usersRes.status === 403) {
        showPermissionDenied('Administrative access forbidden by institutional security gateway.');
        return;
      }
      throw new Error(`Failed to load user directory (HTTP ${usersRes.status})`);
    }

    AdminState.users = await usersRes.json();

    if (rolesRes.ok) {
      AdminState.rolesMatrix = await rolesRes.json();
    } else {
      AdminState.rolesMatrix = [];
    }

    // Update KPI strip
    renderKPIMetrics(auditRes);

    // Populate department filter dropdown
    populateDepartmentFilter(AdminState.users);

    // Render Master Table & Role Matrix
    renderMasterTable();
    renderRolesMatrixAccordion(AdminState.rolesMatrix);

    // Select first user if none selected
    if (AdminState.users.length > 0 && !AdminState.selectedUserId) {
      selectUser(AdminState.users[0].id);
    }

    switchState('console');

  } catch (err) {
    console.error('Manifest loading error:', err);
    showServerError(err.message || 'Error communicating with directory database.');
  }
}

function renderKPIMetrics(auditRes) {
  const now = new Date();
  const totalUsers = AdminState.users.length;

  let activeCount = 0;
  let lockedCount = 0;

  AdminState.users.forEach(u => {
    const isLocked = u.locked_until && new Date(u.locked_until) > now;
    if (isLocked) {
      lockedCount++;
    } else if (u.is_active) {
      activeCount++;
    }
  });

  const totalEl = document.getElementById('kpi-total-users');
  const activeEl = document.getElementById('kpi-active-count');
  const lockedEl = document.getElementById('kpi-locked-count');
  const rolesEl = document.getElementById('kpi-roles-count');
  const auditEl = document.getElementById('kpi-audit-health');

  if (totalEl) totalEl.textContent = totalUsers;
  if (activeEl) activeEl.textContent = activeCount;
  if (lockedEl) lockedEl.textContent = lockedCount;
  if (rolesEl) rolesEl.textContent = AdminState.rolesMatrix.length || 6;

  if (auditRes && auditRes.ok) {
    auditRes.json().then(data => {
      if (auditEl) {
        if (data.is_valid) {
          auditEl.textContent = '100% Intact';
          auditEl.style.color = '#166534';
        } else {
          auditEl.textContent = 'Tamper Alert';
          auditEl.style.color = '#dc2626';
        }
      }
    }).catch(() => {});
  }
}

function populateDepartmentFilter(users) {
  const select = document.getElementById('filter-dept-select');
  if (!select) return;

  const currentVal = select.value;
  const depts = new Set();
  users.forEach(u => {
    if (u.department && u.department.trim()) {
      depts.add(u.department.trim());
    }
  });

  const sortedDepts = Array.from(depts).sort();
  select.innerHTML = '<option value="all">All Departments</option>';
  sortedDepts.forEach(d => {
    const opt = document.createElement('option');
    opt.value = d;
    opt.textContent = d;
    select.appendChild(opt);
  });

  if (currentVal && Array.from(select.options).some(o => o.value === currentVal)) {
    select.value = currentVal;
  }
}

// =========================================================================
// 3. MASTER TABLE RENDERING & FILTERING
// =========================================================================

function renderMasterTable() {
  const tbody = document.getElementById('users-table-body');
  if (!tbody) return;

  const now = new Date();
  const q = AdminState.searchQuery.toLowerCase();
  const rFilter = AdminState.roleFilter.toLowerCase();
  const dFilter = AdminState.deptFilter;

  const filtered = AdminState.users.filter(u => {
    // Role filter
    if (rFilter !== 'all' && (u.role || '').toLowerCase() !== rFilter) {
      return false;
    }

    // Department filter
    if (dFilter !== 'all' && u.department !== dFilter) {
      return false;
    }

    // Search query
    if (q) {
      const name = (u.full_name || '').toLowerCase();
      const email = (u.email || '').toLowerCase();
      const uname = (u.username || '').toLowerCase();
      const dept = (u.department || '').toLowerCase();
      if (!name.includes(q) && !email.includes(q) && !uname.includes(q) && !dept.includes(q)) {
        return false;
      }
    }

    return true;
  });

  if (filtered.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="5" style="text-align: center; padding: 32px; color: var(--text-secondary);">
          No users match the active filter criteria. Click "Refresh" or reset filters.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = filtered.map(u => {
    const isLocked = u.locked_until && new Date(u.locked_until) > now;
    const isSelected = u.id === AdminState.selectedUserId;

    // Status Pill
    let statusPillHtml = '';
    if (isLocked) {
      statusPillHtml = `
        <span class="status-pill status-pill-locked" title="Failed login lockout active">
          <span class="status-dot-sm locked"></span>Locked
        </span>
      `;
    } else if (!u.is_active) {
      statusPillHtml = `
        <span class="status-pill status-pill-inactive" title="Account deactivated">
          <span class="status-dot-sm inactive"></span>Inactive
        </span>
      `;
    } else {
      statusPillHtml = `
        <span class="status-pill status-pill-active" title="Operational">
          <span class="status-dot-sm active"></span>Active
        </span>
      `;
    }

    // Role badge
    const roleSlug = (u.role || '').toLowerCase();
    const roleBadgeHtml = `<span class="role-badge role-badge-${roleSlug}">${escapeHtml(u.role || 'user')}</span>`;

    return `
      <tr class="${isSelected ? 'selected-row' : ''}" data-user-id="${u.id}" style="cursor: pointer;">
        <td>
          <div style="font-weight: 600; color: var(--text-primary);">${escapeHtml(u.full_name || u.username)}</div>
          <div style="font-size: 12px; color: var(--text-muted); font-family: var(--font-mono);">${escapeHtml(u.email)}</div>
        </td>
        <td>
          <span style="font-size: 13px; color: var(--text-secondary);">${escapeHtml(u.department || 'General')}</span>
        </td>
        <td>
          ${roleBadgeHtml}
        </td>
        <td>
          ${statusPillHtml}
        </td>
        <td style="text-align: right;" onclick="event.stopPropagation();">
          <div class="admin-action-group">
            <button
              type="button"
              class="btn-admin-action"
              onclick="openEditUserModal(${u.id})"
              title="Edit account details"
              aria-label="Edit account for ${escapeHtml(u.username)}"
            >
              Edit
            </button>
            <button
              type="button"
              class="btn-admin-action btn-admin-unlock"
              onclick="triggerUnlockUser(${u.id})"
              ${isLocked ? '' : 'disabled'}
              title="${isLocked ? 'Clear lockout and reset attempts' : 'Account is not locked'}"
              aria-label="Unlock account for ${escapeHtml(u.username)}"
            >
              Unlock
            </button>
            <button
              type="button"
              class="btn-admin-action"
              onclick="openResetPasswordModal(${u.id})"
              title="Set new temporary password"
              aria-label="Reset password for ${escapeHtml(u.username)}"
            >
              Reset
            </button>
          </div>
        </td>
      </tr>
    `;
  }).join('');

  // Row selection handler
  tbody.querySelectorAll('tr[data-user-id]').forEach(row => {
    row.addEventListener('click', () => {
      const uid = parseInt(row.getAttribute('data-user-id'), 10);
      selectUser(uid);
    });
  });
}

function selectUser(userId) {
  AdminState.selectedUserId = userId;

  // Update selected class on rows
  document.querySelectorAll('#users-table-body tr').forEach(r => {
    if (r.getAttribute('data-user-id') == userId) {
      r.classList.add('selected-row');
    } else {
      r.classList.remove('selected-row');
    }
  });

  const user = AdminState.users.find(u => u.id === userId);
  renderUserInspector(user);
}

function renderUserInspector(user) {
  const container = document.getElementById('inspector-user-content');
  if (!container) return;

  if (!user) {
    container.innerHTML = `
      <div style="font-size: 13px; color: var(--text-muted); font-style: italic; padding: 8px 0;">
        Select an institutional user to view security details.
      </div>
    `;
    return;
  }

  const now = new Date();
  const isLocked = user.locked_until && new Date(user.locked_until) > now;

  container.innerHTML = `
    <div style="margin-bottom: 12px;">
      <div style="font-size: 15px; font-weight: 700; color: var(--text-primary);">${escapeHtml(user.full_name || user.username)}</div>
      <div style="font-size: 12px; font-family: var(--font-mono); color: var(--text-muted);">${escapeHtml(user.email)}</div>
    </div>

    <div class="user-inspector-meta-row">
      <span class="user-inspector-meta-label">User ID:</span>
      <span class="user-inspector-meta-value font-mono">#${user.id}</span>
    </div>

    <div class="user-inspector-meta-row">
      <span class="user-inspector-meta-label">Username:</span>
      <span class="user-inspector-meta-value font-mono">${escapeHtml(user.username)}</span>
    </div>

    <div class="user-inspector-meta-row">
      <span class="user-inspector-meta-label">Role Tier:</span>
      <span class="user-inspector-meta-value">${escapeHtml(user.role.toUpperCase())}</span>
    </div>

    <div class="user-inspector-meta-row">
      <span class="user-inspector-meta-label">Department:</span>
      <span class="user-inspector-meta-value">${escapeHtml(user.department)}</span>
    </div>

    <div class="user-inspector-meta-row">
      <span class="user-inspector-meta-label">Account Status:</span>
      <span class="user-inspector-meta-value" style="color: ${isLocked ? '#dc2626' : user.is_active ? '#16a34a' : '#64748b'};">
        ${isLocked ? 'LOCKED (Quarantine)' : user.is_active ? 'ACTIVE' : 'DEACTIVATED'}
      </span>
    </div>

    <div class="user-inspector-meta-row">
      <span class="user-inspector-meta-label">Failed Attempts:</span>
      <span class="user-inspector-meta-value font-mono">${user.failed_login_attempts || 0} / 5</span>
    </div>

    <div class="user-inspector-meta-row">
      <span class="user-inspector-meta-label">Locked Until:</span>
      <span class="user-inspector-meta-value font-mono">${user.locked_until ? new Date(user.locked_until).toLocaleTimeString() : 'None'}</span>
    </div>

    <div class="user-inspector-meta-row">
      <span class="user-inspector-meta-label">Created At:</span>
      <span class="user-inspector-meta-value font-mono">${new Date(user.created_at).toLocaleDateString()}</span>
    </div>

    <div style="display: flex; gap: 8px; margin-top: 14px;">
      <button type="button" class="btn btn-secondary btn-sm" style="flex: 1;" onclick="openEditUserModal(${user.id})">
        Edit Account
      </button>
      <button type="button" class="btn btn-primary btn-sm" style="flex: 1;" onclick="openResetPasswordModal(${user.id})">
        Reset Pass
      </button>
    </div>
  `;
}

// =========================================================================
// 4. ROLE & PERMISSION MATRIX ACCORDION
// =========================================================================

function renderRolesMatrixAccordion(matrix) {
  const container = document.getElementById('roles-matrix-accordion');
  if (!container) return;

  if (!matrix || matrix.length === 0) {
    container.innerHTML = `
      <div style="padding: 12px; font-size: 13px; color: var(--text-muted);">
        Loading role permission boundaries...
      </div>
    `;
    return;
  }

  // Desired order of roles
  const order = ['admin', 'controller', 'hod', 'setter', 'printer', 'student'];
  const sorted = [...matrix].sort((a, b) => {
    const ai = order.indexOf((a.role || '').toLowerCase());
    const bi = order.indexOf((b.role || '').toLowerCase());
    return (ai !== -1 ? ai : 99) - (bi !== -1 ? bi : 99);
  });

  container.innerHTML = sorted.map((r, idx) => {
    const roleSlug = (r.role || '').toLowerCase();
    const roleTitle = r.role.charAt(0).toUpperCase() + r.role.slice(1);
    const isOpen = idx === 0; // Default first open

    const permsList = (r.permissions || []).map(p => `
      <div class="permission-checklist-item">
        <svg class="permission-check-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <polyline points="20 6 9 17 4 12"></polyline>
        </svg>
        <span style="font-family: var(--font-mono); font-weight: 500;">${escapeHtml(p)}</span>
      </div>
    `).join('');

    return `
      <div class="role-accordion-item" id="accordion-${roleSlug}">
        <button
          type="button"
          class="role-accordion-header"
          onclick="toggleRoleAccordion('${roleSlug}')"
          aria-expanded="${isOpen}"
          aria-controls="content-${roleSlug}"
        >
          <div style="display: flex; align-items: center; gap: 8px;">
            <span class="role-badge role-badge-${roleSlug}">${escapeHtml(roleTitle)}</span>
            <span style="font-size: 12px; color: var(--text-muted); font-weight: 400;">
              (${r.permissions.length} Permissions)
            </span>
          </div>
          <span style="font-size: 12px; color: var(--text-muted);" id="icon-${roleSlug}">
            ${isOpen ? '&#9650;' : '&#9660;'}
          </span>
        </button>

        <div
          class="role-accordion-content"
          id="content-${roleSlug}"
          style="display: ${isOpen ? 'flex' : 'none'};"
        >
          ${permsList}
        </div>
      </div>
    `;
  }).join('');
}

function toggleRoleAccordion(roleSlug) {
  const content = document.getElementById(`content-${roleSlug}`);
  const icon = document.getElementById(`icon-${roleSlug}`);
  const btn = document.querySelector(`#accordion-${roleSlug} .role-accordion-header`);

  if (!content || !icon || !btn) return;

  const isVisible = content.style.display !== 'none';
  if (isVisible) {
    content.style.display = 'none';
    icon.innerHTML = '&#9660;';
    btn.setAttribute('aria-expanded', 'false');
  } else {
    content.style.display = 'flex';
    icon.innerHTML = '&#9660;';
    btn.setAttribute('aria-expanded', 'true');
  }
}

// =========================================================================
// 5. PROVISION USER (CREATE) WORKFLOW
// =========================================================================

function openProvisionUserModal() {
  const modal = document.getElementById('modal-provision-user');
  const form = document.getElementById('form-provision-user');
  const errBox = document.getElementById('prov-error-msg');

  if (errBox) errBox.style.display = 'none';
  if (form) form.reset();
  if (modal) modal.style.display = 'flex';

  const fnInput = document.getElementById('prov-fullname');
  if (fnInput) setTimeout(() => fnInput.focus(), 50);
}

function closeProvisionUserModal() {
  const modal = document.getElementById('modal-provision-user');
  if (modal) modal.style.display = 'none';
}

async function executeProvisionUser(e) {
  e.preventDefault();
  const token = localStorage.getItem('access_token');
  const errBox = document.getElementById('prov-error-msg');
  const submitBtn = document.getElementById('btn-submit-provision');

  const fullName = document.getElementById('prov-fullname').value.trim();
  const username = document.getElementById('prov-username').value.trim();
  const email = document.getElementById('prov-email').value.trim();
  const role = document.getElementById('prov-role').value;
  const department = document.getElementById('prov-department').value.trim();
  const password = document.getElementById('prov-password').value;
  const isActive = document.getElementById('prov-active').checked;

  if (errBox) errBox.style.display = 'none';

  // Client validation
  if (!fullName || !username || !email || !department || !password) {
    showFormError(errBox, 'All mandatory fields marked with an asterisk must be completed.');
    return;
  }

  if (password.length < 8) {
    showFormError(errBox, 'Password must be at least 8 characters long to satisfy Argon2id entropy requirements.');
    return;
  }

  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.textContent = 'Provisioning...';
  }

  try {
    const res = await fetch(`${API_BASE}/admin/users`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify({
        email,
        username,
        password,
        full_name: fullName,
        department,
        role,
        is_active: isActive,
      }),
    });

    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
      const msg = data.detail || 'Failed to provision user account.';
      showFormError(errBox, msg);
      return;
    }

    closeProvisionUserModal();
    showAlert(`Institutional account for ${data.username} (${data.role.toUpperCase()}) created successfully.`, 'success');
    await loadAdminDirectoryManifest();
    selectUser(data.id);

  } catch (err) {
    showFormError(errBox, 'Network communication error connecting to administrative service.');
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Create Account';
    }
  }
}

// =========================================================================
// 6. EDIT USER WORKFLOW
// =========================================================================

function openEditUserModal(userId) {
  const user = AdminState.users.find(u => u.id === userId);
  if (!user) return;

  const modal = document.getElementById('modal-edit-user');
  const errBox = document.getElementById('edit-error-msg');

  if (errBox) errBox.style.display = 'none';

  document.getElementById('edit-user-id').value = user.id;
  document.getElementById('edit-fullname').value = user.full_name || '';
  document.getElementById('edit-role').value = (user.role || '').toLowerCase();
  document.getElementById('edit-department').value = user.department || '';
  document.getElementById('edit-is-active').checked = user.is_active;

  const now = new Date();
  const isLocked = user.locked_until && new Date(user.locked_until) > now;
  document.getElementById('edit-unlock-account').checked = isLocked;

  if (modal) modal.style.display = 'flex';
}

function closeEditUserModal() {
  const modal = document.getElementById('modal-edit-user');
  if (modal) modal.style.display = 'none';
}

async function executeEditUser(e) {
  e.preventDefault();
  const token = localStorage.getItem('access_token');
  const errBox = document.getElementById('edit-error-msg');
  const submitBtn = document.getElementById('btn-submit-edit');

  const userId = parseInt(document.getElementById('edit-user-id').value, 10);
  const fullName = document.getElementById('edit-fullname').value.trim();
  const role = document.getElementById('edit-role').value;
  const department = document.getElementById('edit-department').value.trim();
  const isActive = document.getElementById('edit-is-active').checked;
  const unlockAccount = document.getElementById('edit-unlock-account').checked;

  if (errBox) errBox.style.display = 'none';

  if (!fullName || !department) {
    showFormError(errBox, 'Full Name and Department cannot be empty.');
    return;
  }

  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.textContent = 'Saving...';
  }

  try {
    const payload = {
      full_name: fullName,
      role: role,
      department: department,
      is_active: isActive,
    };
    if (unlockAccount) {
      payload.unlock_account = true;
    }

    const res = await fetch(`${API_BASE}/admin/users/${userId}`, {
      method: 'PATCH',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify(payload),
    });

    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
      showFormError(errBox, data.detail || 'Failed to update user account.');
      return;
    }

    closeEditUserModal();
    showAlert(`User #${userId} (${data.username}) updated successfully.`, 'success');
    await loadAdminDirectoryManifest();
    selectUser(userId);

  } catch (err) {
    showFormError(errBox, 'Network error updating user record.');
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Save Changes';
    }
  }
}

// =========================================================================
// 7. UNLOCK ACCOUNT WORKFLOW
// =========================================================================

async function triggerUnlockUser(userId) {
  const token = localStorage.getItem('access_token');
  const user = AdminState.users.find(u => u.id === userId);
  const name = user ? user.username : `#${userId}`;

  showAlert(`Clearing failed login threshold for ${name}...`, 'info');

  try {
    const res = await fetch(`${API_BASE}/admin/users/${userId}`, {
      method: 'PATCH',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify({ unlock_account: true }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      showAlert(err.detail || 'Failed to unlock user account.', 'danger');
      return;
    }

    showAlert(`Account for ${name} unlocked successfully. Failed attempt counter cleared.`, 'success');
    await loadAdminDirectoryManifest();
    selectUser(userId);

  } catch (err) {
    showAlert('Network error unlocking user account.', 'danger');
  }
}

// =========================================================================
// 8. RESET PASSWORD WORKFLOW
// =========================================================================

function openResetPasswordModal(userId) {
  const user = AdminState.users.find(u => u.id === userId);
  if (!user) return;

  const modal = document.getElementById('modal-reset-password');
  const form = document.getElementById('form-reset-password');
  const errBox = document.getElementById('reset-error-msg');
  const targetLabel = document.getElementById('reset-target-user-name');

  if (errBox) errBox.style.display = 'none';
  if (form) form.reset();

  document.getElementById('reset-user-id').value = user.id;
  if (targetLabel) targetLabel.textContent = `${user.full_name || user.username} (${user.email})`;

  if (modal) modal.style.display = 'flex';

  const pwInput = document.getElementById('reset-new-password');
  if (pwInput) setTimeout(() => pwInput.focus(), 50);
}

function closeResetPasswordModal() {
  const modal = document.getElementById('modal-reset-password');
  if (modal) modal.style.display = 'none';
}

async function executeResetPassword(e) {
  e.preventDefault();
  const token = localStorage.getItem('access_token');
  const errBox = document.getElementById('reset-error-msg');
  const submitBtn = document.getElementById('btn-submit-reset');

  const userId = parseInt(document.getElementById('reset-user-id').value, 10);
  const newPw = document.getElementById('reset-new-password').value;
  const confirmPw = document.getElementById('reset-confirm-password').value;

  if (errBox) errBox.style.display = 'none';

  if (!newPw || !confirmPw) {
    showFormError(errBox, 'Both password fields are mandatory.');
    return;
  }

  if (newPw.length < 8) {
    showFormError(errBox, 'Password must be at least 8 characters long.');
    return;
  }

  if (newPw !== confirmPw) {
    showFormError(errBox, 'Passwords do not match.');
    return;
  }

  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.textContent = 'Updating...';
  }

  try {
    const res = await fetch(`${API_BASE}/admin/users/${userId}`, {
      method: 'PATCH',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify({ reset_password: newPw }),
    });

    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
      showFormError(errBox, data.detail || 'Failed to reset credentials.');
      return;
    }

    closeResetPasswordModal();
    showAlert(`Credentials reset for user #${userId} (${data.username}). Temporary password active.`, 'success');

  } catch (err) {
    showFormError(errBox, 'Network error resetting credentials.');
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Reset Password';
    }
  }
}

// =========================================================================
// 9. UI EVENT BINDINGS
// =========================================================================

function bindUIEvents() {
  // Search input
  const searchInput = document.getElementById('search-users-input');
  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      AdminState.searchQuery = e.target.value.trim();
      renderMasterTable();
    });
  }

  // Role filter select
  const roleSelect = document.getElementById('filter-role-select');
  if (roleSelect) {
    roleSelect.addEventListener('change', (e) => {
      AdminState.roleFilter = e.target.value;
      renderMasterTable();
    });
  }

  // Department filter select
  const deptSelect = document.getElementById('filter-dept-select');
  if (deptSelect) {
    deptSelect.addEventListener('change', (e) => {
      AdminState.deptFilter = e.target.value;
      renderMasterTable();
    });
  }

  // Refresh Button
  const refreshBtn = document.getElementById('btn-refresh-users');
  if (refreshBtn) refreshBtn.addEventListener('click', loadAdminDirectoryManifest);

  // Reset Filters Button
  const resetBtn = document.getElementById('btn-reset-filters');
  if (resetBtn) {
    resetBtn.addEventListener('click', () => {
      AdminState.searchQuery = '';
      AdminState.roleFilter = 'all';
      AdminState.deptFilter = 'all';
      if (searchInput) searchInput.value = '';
      if (roleSelect) roleSelect.value = 'all';
      if (deptSelect) deptSelect.value = 'all';
      renderMasterTable();
    });
  }

  // Retry Server Button
  const retryBtn = document.getElementById('btn-retry-server');
  if (retryBtn) retryBtn.addEventListener('click', initAdminRolesConsole);

  // Provision Modal Trigger
  const openProvBtn = document.getElementById('btn-open-provision-modal');
  if (openProvBtn) openProvBtn.addEventListener('click', openProvisionUserModal);

  const closeProvBtn = document.getElementById('btn-close-prov-modal');
  const cancelProvBtn = document.getElementById('btn-cancel-prov');
  if (closeProvBtn) closeProvBtn.addEventListener('click', closeProvisionUserModal);
  if (cancelProvBtn) cancelProvBtn.addEventListener('click', closeProvisionUserModal);

  const provForm = document.getElementById('form-provision-user');
  if (provForm) provForm.addEventListener('submit', executeProvisionUser);

  // Edit Modal Controls
  const closeEditBtn = document.getElementById('btn-close-edit-modal');
  const cancelEditBtn = document.getElementById('btn-cancel-edit');
  if (closeEditBtn) closeEditBtn.addEventListener('click', closeEditUserModal);
  if (cancelEditBtn) cancelEditBtn.addEventListener('click', closeEditUserModal);

  const editForm = document.getElementById('form-edit-user');
  if (editForm) editForm.addEventListener('submit', executeEditUser);

  // Reset Password Modal Controls
  const closeResetBtn = document.getElementById('btn-close-reset-modal');
  const cancelResetBtn = document.getElementById('btn-cancel-reset');
  if (closeResetBtn) closeResetBtn.addEventListener('click', closeResetPasswordModal);
  if (cancelResetBtn) cancelResetBtn.addEventListener('click', closeResetPasswordModal);

  const resetForm = document.getElementById('form-reset-password');
  if (resetForm) resetForm.addEventListener('submit', executeResetPassword);

  // Sign out button
  const signoutBtn = document.getElementById('btn-signout');
  if (signoutBtn) {
    signoutBtn.addEventListener('click', () => {
      localStorage.removeItem('access_token');
      window.location.href = 'login.html';
    });
  }

  // Global Alert Close
  const alertClose = document.getElementById('admin-alert-close');
  if (alertClose) {
    alertClose.addEventListener('click', () => {
      const alertBox = document.getElementById('admin-alert');
      if (alertBox) alertBox.style.display = 'none';
    });
  }

  // Keyboard navigation & modal closing
  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      closeProvisionUserModal();
      closeEditUserModal();
      closeResetPasswordModal();
    }
  });
}

// =========================================================================
// 10. SYSTEM STATE SWITCHING & HELPERS
// =========================================================================

function switchState(stateName) {
  const loadingEl = document.getElementById('state-loading');
  const emptyEl = document.getElementById('state-empty');
  const deniedEl = document.getElementById('state-permission-denied');
  const serverErrorEl = document.getElementById('state-server-error');
  const gridEl = document.getElementById('main-admin-grid');

  if (loadingEl) loadingEl.style.display = (stateName === 'loading') ? 'block' : 'none';
  if (emptyEl) emptyEl.style.display = (stateName === 'empty') ? 'block' : 'none';
  if (deniedEl) deniedEl.style.display = (stateName === 'denied') ? 'block' : 'none';
  if (serverErrorEl) serverErrorEl.style.display = (stateName === 'server-error') ? 'block' : 'none';
  if (gridEl) gridEl.style.display = (stateName === 'console') ? 'grid' : 'none';
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
  const alertBox = document.getElementById('admin-alert');
  const alertText = document.getElementById('admin-alert-text');
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
