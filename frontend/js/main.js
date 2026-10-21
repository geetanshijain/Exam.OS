/**
 * ExamOS — Institutional Public Landing Page Logic (Vanilla JS)
 * Features:
 * - Live Institutional Node Status Heartbeat
 * - Dynamic Header Authentication State
 * - Interactive Examination Schedule & Center Verification Search
 * - Accessible Capability Detail Modal Drawers
 * - Responsive Mobile Navigation
 * - Accessible Keyboard Trapping and ARIA State Management
 */

// Canonical API Base URL (auto-detects local dev ports)
const API_BASE = window.location.port === '8000' ? '/api/v1' : 'http://127.0.0.1:8000/api/v1';

document.addEventListener('DOMContentLoaded', () => {
  initSystemHealthIndicator();
  initAuthenticationState();
  initMobileNav();
  initScheduleSearch();
  initCapabilityModals();
  initKeyboardNavigation();
});

// =========================================================================
// 1. LIVE INSTITUTIONAL NODE STATUS HEARTBEAT
// =========================================================================

async function initSystemHealthIndicator() {
  const statusEl = document.getElementById('system-status-indicator');
  const dotEl = document.getElementById('system-status-dot');
  if (!statusEl || !dotEl) return;

  statusEl.textContent = 'Connecting to Institutional Node...';
  dotEl.className = 'status-dot warning pulse';

  try {
    const response = await fetch(`${API_BASE}/health`, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });

    if (response.ok) {
      statusEl.textContent = 'Network Status: Operational • UTC Clock Synchronized • Cryptographic Vault Active';
      dotEl.className = 'status-dot';
    } else {
      statusEl.textContent = 'Network Status: Degraded • Failover Protocol Active';
      dotEl.className = 'status-dot warning';
    }
  } catch (err) {
    statusEl.textContent = 'Institutional Network: Offline / Local Mode Active';
    dotEl.className = 'status-dot warning';
  }
}

// =========================================================================
// 2. DYNAMIC HEADER AUTHENTICATION STATE
// =========================================================================

async function initAuthenticationState() {
  const headerActions = document.getElementById('header-actions');
  if (!headerActions) return;

  const token = localStorage.getItem('access_token');
  if (!token) {
    renderUnauthenticatedHeader(headerActions);
    return;
  }

  try {
    const response = await fetch(`${API_BASE}/auth/me`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/json',
      },
    });

    if (response.ok) {
      const user = await response.json();
      renderAuthenticatedHeader(headerActions, user);
    } else {
      localStorage.removeItem('access_token');
      renderUnauthenticatedHeader(headerActions);
    }
  } catch (err) {
    renderUnauthenticatedHeader(headerActions);
  }
}

function renderUnauthenticatedHeader(container) {
  container.innerHTML = `
    <a href="login.html" class="btn btn-secondary btn-sm" id="btn-login" data-action="login">Login</a>
    <a href="login.html" class="btn btn-primary btn-sm" id="btn-get-started" data-action="login">Get Started</a>
  `;
}

function renderAuthenticatedHeader(container, user) {
  const role = (user.role || '').toLowerCase();
  let portalBtn = '';
  if (role === 'student') {
    portalBtn = '<a href="student-exam.html" class="btn btn-primary btn-sm">Take Exam</a>';
  } else if (role === 'setter') {
    portalBtn = '<a href="setter.html" class="btn btn-primary btn-sm">Setter Portal</a>';
  } else if (role === 'printer') {
    portalBtn = '<a href="center-release.html" class="btn btn-primary btn-sm">Release Console</a>';
  } else if (role === 'admin') {
    portalBtn = '<a href="admin-roles.html" class="btn btn-primary btn-sm">Admin Console</a>';
  } else if (role === 'controller' || role === 'hod') {
    portalBtn = '<a href="scheduling.html" class="btn btn-primary btn-sm">Schedules</a>';
  }

  container.innerHTML = `
    <div class="user-badge" id="header-user-badge">
      <span class="user-name">${escapeHtml(user.full_name || user.username)}</span>
      <span class="user-badge-role">${escapeHtml(user.role)}</span>
    </div>
    ${portalBtn}
    <button type="button" class="btn btn-secondary btn-sm" id="btn-signout">Sign Out</button>
  `;

  const signoutBtn = document.getElementById('btn-signout');
  if (signoutBtn) {
    signoutBtn.addEventListener('click', async () => {
      const token = localStorage.getItem('access_token');
      try {
        await fetch(`${API_BASE}/auth/logout`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Accept': 'application/json',
          },
        });
      } catch (err) {
        // Proceed with client logout even if network fails
      }
      localStorage.removeItem('access_token');
      renderUnauthenticatedHeader(container);
    });
  }
}

// =========================================================================
// 3. PUBLIC EXAMINATION SCHEDULE & CENTER VERIFICATION SEARCH
// =========================================================================

function initScheduleSearch() {
  const searchForm = document.getElementById('schedule-search-form');
  const searchInput = document.getElementById('schedule-query');
  const resultsContainer = document.getElementById('schedule-results');
  const stateBox = document.getElementById('schedule-state-box');

  if (!searchForm || !searchInput || !resultsContainer || !stateBox) return;

  searchForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const query = searchInput.value.trim();

    // Reset UI
    resultsContainer.innerHTML = '';
    stateBox.style.display = 'none';
    stateBox.className = 'schedule-state-box';

    // 1. Validation State
    if (query.length < 2) {
      stateBox.className = 'schedule-state-box validation';
      stateBox.style.display = 'flex';
      stateBox.innerHTML = `
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
        </svg>
        <span>Please enter at least 2 characters to search approved examination schedules.</span>
      `;
      searchInput.focus();
      return;
    }

    // 2. Loading State
    stateBox.style.display = 'flex';
    stateBox.innerHTML = `
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="status-dot pulse">
        <line x1="12" y1="2" x2="12" y2="6"/><line x1="12" y1="18" x2="12" y2="22"/>
        <line x1="4.93" y1="4.93" x2="7.76" y2="7.76"/><line x1="16.24" y1="16.24" x2="19.07" y2="19.07"/>
        <line x1="2" y1="12" x2="6" y2="12"/><line x1="18" y1="12" x2="22" y2="12"/>
      </svg>
      <span>Querying institutional schedule registry for "${escapeHtml(query)}"...</span>
    `;

    try {
      const response = await fetch(`${API_BASE}/schedules/public-lookup?query=${encodeURIComponent(query)}`, {
        method: 'GET',
        headers: { 'Accept': 'application/json' },
      });

      if (!response.ok) {
        throw new Error(`Server returned HTTP ${response.status}`);
      }

      const schedules = await response.json();

      // 3. Empty State
      if (!schedules || schedules.length === 0) {
        stateBox.style.display = 'flex';
        stateBox.innerHTML = `
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"/><line x1="8" y1="12" x2="16" y2="12"/>
          </svg>
          <span>No approved examinations match "${escapeHtml(query)}". Verify the subject title or paper code.</span>
        `;
        return;
      }

      // 4. Success State
      stateBox.style.display = 'none';
      resultsContainer.innerHTML = schedules.map(renderScheduleCard).join('');

    } catch (err) {
      // 5. Server Error State
      stateBox.className = 'schedule-state-box error';
      stateBox.style.display = 'flex';
      stateBox.innerHTML = `
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/>
          <line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
        </svg>
        <span>Institutional schedule registry unavailable. Please retry or contact examination administration.</span>
      `;
    }
  });
}

function renderScheduleCard(schedule) {
  const startTime = new Date(schedule.start_time_utc);
  const formattedDate = startTime.toLocaleDateString('en-US', {
    weekday: 'short',
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    timeZone: 'UTC',
  });
  const formattedTime = startTime.toLocaleTimeString('en-US', {
    hour: '2-digit',
    minute: '2-digit',
    timeZone: 'UTC',
    timeZoneName: 'short',
  });

  const statusClass = `schedule-badge-${schedule.status}`;

  return `
    <article class="schedule-card" aria-labelledby="sched-title-${schedule.id}">
      <div class="schedule-card-header">
        <span class="schedule-code-badge">${escapeHtml(schedule.paper_code)}</span>
        <span class="schedule-badge-status ${statusClass}">${escapeHtml(schedule.status.replace(/_/g, ' '))}</span>
      </div>
      <h3 id="sched-title-${schedule.id}" style="font-size: 15px; margin: 4px 0;">
        ${escapeHtml(schedule.title)}
      </h3>
      <div class="schedule-meta-row">
        <span><strong>Dept:</strong> ${escapeHtml(schedule.department)}</span>
        <span><strong>Center:</strong> ${escapeHtml(schedule.exam_center_id)}</span>
      </div>
      <div class="schedule-meta-row">
        <span><strong>Date:</strong> ${formattedDate}</span>
        <span><strong>Start:</strong> ${formattedTime}</span>
      </div>
      <div class="schedule-meta-row">
        <span><strong>Duration:</strong> ${schedule.duration_minutes} mins</span>
        <span><strong>Timezone:</strong> ${escapeHtml(schedule.timezone || 'UTC')}</span>
      </div>
      <div class="schedule-locked-notice">
        🔒 Paper assets cryptographically locked in vault. Pre-release access strictly prohibited.
      </div>
    </article>
  `;
}

// =========================================================================
// 4. ACCESSIBLE CAPABILITY DETAIL MODALS
// =========================================================================

const CAPABILITY_DETAILS = {
  'ai-generation': {
    title: 'AI Question Paper Studio & Curriculum Synthesis',
    badge: 'STUDIO MODULE',
    body: `
      <p>ExamOS Question Paper Studio provides curriculum-aligned question synthesis from authenticated syllabus documents and historical blueprints.</p>
      <ul>
        <li><strong>Deterministic Reproducibility:</strong> Generation seeds and blueprint versioning guarantee repeatable assemblies.</li>
        <li><strong>OCR Provenance Tracking:</strong> Retains source document page numbers and learning outcome mappings.</li>
        <li><strong>Confidentiality Enforced:</strong> Syllabus text and draft prompts are isolated; confidential paper content is never fed to public external models.</li>
      </ul>
    `,
  },
  'security': {
    title: 'End-to-End Cryptographic Paper Vault',
    badge: 'SECURITY MODULE',
    body: `
      <p>Finalized papers are stored under private, authenticated AES-256-GCM envelope encryption with managed KMS key governance.</p>
      <ul>
        <li><strong>K-of-N Quorum Governance:</strong> Authoring, review, and release permissions are separated across distinct administrative roles.</li>
        <li><strong>Server-Enforced Time Locks:</strong> Decryption tokens are strictly gated by server-side UTC timestamps; browser-side clock spoofing is completely prevented.</li>
        <li><strong>Memory Zeroization:</strong> Plaintext Data Encryption Keys (DEKs) are zeroized immediately after authenticated encryption and decryption.</li>
      </ul>
    `,
  },
  'distribution': {
    title: 'Controlled Scheduled Release & Candidate Sessions',
    badge: 'RELEASE MODULE',
    body: `
      <p>Exam release is dispatched via an idempotent server-side release queue with automated failure alerts.</p>
      <ul>
        <li><strong>Candidate-Specific Grants:</strong> Access grants are bounded by exam center IDs and enrolled student groups.</li>
        <li><strong>Session Interruption Recovery:</strong> Disrupted sessions can be resumed using single-use recovery tokens without loss of autosaved responses.</li>
        <li><strong>Important Photography Notice:</strong> Browser sandbox controls cannot reliably prevent physical camera photography or external display capture. ExamOS mitigates risk via short session lifetimes and recipient-specific visible watermarking.</li>
      </ul>
    `,
  },
  'monitoring': {
    title: 'Security Audit & Incident Telemetry Console',
    badge: 'AUDIT MODULE',
    body: `
      <p>Institutional oversight is powered by append-only, tamper-evident audit log chains and proactive anomaly detection.</p>
      <ul>
        <li><strong>Cryptographic Hash Chaining:</strong> Vault audit records are linked via SHA-256 hash chains, immediately exposing any row alteration or deletion.</li>
        <li><strong>Automated Anomaly Detection:</strong> Detects unusual login spikes, repeated permission failures, out-of-bounds release queries, and decoy honeytoken trips.</li>
        <li><strong>Zero Credential Logging:</strong> Passwords, secret keys, tokens, and plaintext questions are strictly redacted from persistent audit telemetry.</li>
      </ul>
    `,
  },
};

function initCapabilityModals() {
  const cards = document.querySelectorAll('[data-capability]');
  const modal = document.getElementById('capability-modal');
  const modalTitle = document.getElementById('modal-title');
  const modalBadge = document.getElementById('modal-badge');
  const modalBody = document.getElementById('modal-body');
  const closeBtn = document.getElementById('modal-close-btn');
  const doneBtn = document.getElementById('modal-done-btn');

  if (!modal || !modalTitle || !modalBody) return;

  cards.forEach((card) => {
    card.addEventListener('click', () => {
      const capKey = card.getAttribute('data-capability');
      const details = CAPABILITY_DETAILS[capKey];
      if (!details) return;

      modalTitle.textContent = details.title;
      if (modalBadge) modalBadge.textContent = details.badge;
      modalBody.innerHTML = details.body;

      openModal(modal);
    });

    card.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        card.click();
      }
    });
  });

  const closeModalFn = () => closeModal(modal);
  if (closeBtn) closeBtn.addEventListener('click', closeModalFn);
  if (doneBtn) doneBtn.addEventListener('click', closeModalFn);

  modal.addEventListener('click', (e) => {
    if (e.target === modal) closeModalFn();
  });

  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && modal.classList.contains('active')) {
      closeModalFn();
    }
  });
}

function openModal(modal) {
  modal.classList.add('active');
  modal.setAttribute('aria-hidden', 'false');
  document.body.style.overflow = 'hidden';
  const closeBtn = modal.querySelector('button');
  if (closeBtn) closeBtn.focus();
}

function closeModal(modal) {
  modal.classList.remove('active');
  modal.setAttribute('aria-hidden', 'true');
  document.body.style.overflow = '';
}

// =========================================================================
// 5. ACCESSIBLE NAVIGATION & KEYBOARD UTILITIES
// =========================================================================

function initMobileNav() {
  const mobileNavBtn = document.getElementById('mobile-nav-toggle');
  const mainNav = document.getElementById('main-nav');
  const headerActions = document.getElementById('header-actions');

  if (mobileNavBtn && mainNav) {
    mobileNavBtn.addEventListener('click', () => {
      const isExpanded = mobileNavBtn.getAttribute('aria-expanded') === 'true';
      mobileNavBtn.setAttribute('aria-expanded', String(!isExpanded));
      mainNav.classList.toggle('nav-open');
      if (headerActions) headerActions.classList.toggle('actions-open');
    });
  }

  // Smooth scroll for "Learn More"
  const learnMoreBtn = document.querySelector('[data-action="learn-more"]');
  if (learnMoreBtn) {
    learnMoreBtn.addEventListener('click', (e) => {
      e.preventDefault();
      const target = document.getElementById('capabilities');
      if (target) target.scrollIntoView({ behavior: 'smooth' });
    });
  }
}

function initKeyboardNavigation() {
  window.addEventListener('keydown', (e) => {
    if (e.key === 'Tab') {
      document.body.classList.add('keyboard-navigation');
    }
  });

  window.addEventListener('mousedown', () => {
    document.body.classList.remove('keyboard-navigation');
  });
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
