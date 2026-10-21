/**
 * ExamOS — Student Examination Portal Engine (Vanilla JavaScript)
 * 
 * Cryptographic Handshake, Time-Lock Compliance, Real-time Autosave,
 * Forensic Watermark Stamping, and Fail-Closed Security Implementation.
 */

// Canonical API Base URL (auto-detects local dev ports)
const API_BASE = (window.location.port === '8000') ? '/api/v1' : 'http://127.0.0.1:8000/api/v1';

// Global Assessment State
const ExamState = {
  user: null,
  schedule: null,
  sessionId: null,
  sessionToken: null,
  recoveryToken: null,
  questions: [],
  currentIndex: 0,
  answers: {},
  flagged: new Set(),
  expiresAt: null,
  remainingSeconds: 0,
  timerInterval: null,
  autosaveInterval: null,
  isSubmitting: false,
  isAutosaving: false,
  watermark: null,
};

document.addEventListener('DOMContentLoaded', () => {
  initExamPortal();
});

// =========================================================================
// 1. INITIALIZATION & SESSION HANDSHAKE
// =========================================================================

async function initExamPortal() {
  bindUIEvents();

  // 1. Check Authentication Token
  const token = localStorage.getItem('access_token');
  if (!token) {
    showAlert('Session unauthenticated. Redirecting to institutional sign in...', 'danger');
    setTimeout(() => {
      window.location.href = 'login.html';
    }, 1200);
    return;
  }

  // 2. Fetch User Profile
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

    ExamState.user = await userRes.json();
    renderCandidateBadge(ExamState.user);
  } catch (err) {
    showErrorState('Institutional authentication node is unreachable. Please verify network connection.');
    return;
  }

  // 3. Discover Available Schedules and Initiate Session
  await discoverAndStartSession();
}

async function discoverAndStartSession() {
  switchState('loading');
  const token = localStorage.getItem('access_token');

  try {
    const schedRes = await fetch(`${API_BASE}/schedules`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/json',
      },
    });

    if (!schedRes.ok) {
      if (schedRes.status === 403) {
        showPermissionDenied('You are not authorized to view examinations for this department or candidate group.');
        return;
      }
      throw new Error(`Schedule lookup returned HTTP ${schedRes.status}`);
    }

    const schedules = await schedRes.json();
    if (!Array.isArray(schedules) || schedules.length === 0) {
      switchState('empty');
      return;
    }

    // Pick active or first schedule
    const activeSched = schedules.find(s => s.status === 'active_in_progress') || schedules[0];
    ExamState.schedule = activeSched;
    renderExamHeader(activeSched);

    // Attempt to start candidate session
    await startCandidateSession(activeSched.id, activeSched.exam_center_id);

  } catch (err) {
    console.error('Error discovering schedules:', err);
    showErrorState('Failed to retrieve examination schedule. Ensure backend server is operational.');
  }
}

async function startCandidateSession(scheduleId, examCenterId) {
  const token = localStorage.getItem('access_token');
  const centerId = examCenterId || 'HALL-A1';

  try {
    const startRes = await fetch(`${API_BASE}/schedules/${scheduleId}/start`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify({ exam_center_id: centerId }),
    });

    // Handle Server Error Responses
    if (!startRes.ok) {
      const errData = await startRes.json().catch(() => ({}));
      const detail = errData.detail || 'Authorization failed.';

      // HTTP 425: Time-Lock / Early Access Boundary
      if (startRes.status === 425) {
        showTooEarlyState(detail, ExamState.schedule ? ExamState.schedule.start_time_utc : null);
        return;
      }

      // HTTP 403: Center or Student Ineligible or Unapproved Paper
      if (startRes.status === 403) {
        showPermissionDenied(detail);
        return;
      }

      // HTTP 410: Examination Window Closed
      if (startRes.status === 410) {
        switchState('expired');
        return;
      }

      showErrorState(detail);
      return;
    }

    // Success: Session Active
    const sessionData = await startRes.json();
    ExamState.sessionId = sessionData.session_id;
    ExamState.sessionToken = sessionData.session_token;
    ExamState.recoveryToken = sessionData.recovery_token;
    ExamState.questions = sessionData.questions || [];
    ExamState.remainingSeconds = sessionData.remaining_seconds || 10800;
    ExamState.expiresAt = new Date(sessionData.expires_at);
    ExamState.watermark = sessionData.watermark;

    // Restore any cached local drafts
    restoreCachedAnswers();

    // Render All Assessment Views
    renderWatermark(sessionData.watermark);
    renderSessionInfo(sessionData);
    renderQuestionPalette();
    renderCurrentQuestion();

    // Activate Real-time Timers
    startCountdownTimer();
    startAutosaveLoop();

    switchState('active');
    showAlert('Candidate assessment session authenticated and active.', 'success');

  } catch (err) {
    console.error('Candidate start error:', err);
    showErrorState('Connection failure during session handshake. Retrying may be attempted.');
  }
}

// =========================================================================
// 2. RENDERING UI COMPONENTS & WATERMARK
// =========================================================================

function renderCandidateBadge(user) {
  const nameEl = document.getElementById('candidate-name-display');
  const rollEl = document.getElementById('candidate-roll-display');
  if (nameEl) nameEl.textContent = user.full_name || user.username || 'Candidate';
  if (rollEl) rollEl.textContent = `#${user.id || 1042}`;
}

function renderExamHeader(sched) {
  const titleEl = document.getElementById('exam-course-title');
  if (titleEl) {
    titleEl.textContent = `${sched.paper_code} ${sched.title}`;
  }
}

function renderWatermark(watermark) {
  const overlay = document.getElementById('exam-watermark-overlay');
  if (!overlay || !watermark) return;

  const text = watermark.text || `EXAM-OS | ROLL: #${ExamState.user?.id || 1042} | SECURE`;
  
  // Create dynamic SVG data URI for seamless tiled repeating watermark
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="400" height="220">
    <text x="50" y="120" fill="#0f172a" font-size="12" font-family="monospace" font-weight="600" opacity="0.14" transform="rotate(-25 50 120)">
      ${escapeXml(text)}
    </text>
  </svg>`;
  
  const encoded = encodeURIComponent(svg);
  overlay.style.backgroundImage = `url("data:image/svg+xml;utf8,${encoded}")`;
}

function renderSessionInfo(sessionData) {
  const startEl = document.getElementById('session-info-start-time');
  const ipEl = document.getElementById('session-info-ip');
  const centerEl = document.getElementById('session-info-center');
  const recEl = document.getElementById('session-info-recovery-token');

  if (startEl && sessionData.started_at) {
    const d = new Date(sessionData.started_at);
    startEl.textContent = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }
  if (ipEl && ExamState.watermark) {
    ipEl.textContent = ExamState.watermark.exam_center_id || 'HALL-A1';
  }
  if (centerEl && ExamState.schedule) {
    centerEl.textContent = ExamState.schedule.exam_center_id || 'HALL-A1';
  }
  if (recEl && sessionData.recovery_token) {
    recEl.textContent = sessionData.recovery_token.slice(0, 12) + '...';
  }
}

function renderQuestionPalette() {
  const grid = document.getElementById('palette-grid');
  if (!grid) return;
  grid.innerHTML = '';

  const total = ExamState.questions.length;
  const totalDisplay = document.getElementById('total-questions-num');
  if (totalDisplay) totalDisplay.textContent = total;

  ExamState.questions.forEach((q, idx) => {
    const itemNum = q.item_number || (idx + 1);
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'palette-btn';
    btn.id = `palette-btn-${idx}`;
    btn.textContent = itemNum;
    btn.setAttribute('aria-label', `Navigate to Question ${itemNum}`);

    // Determine status classes
    const hasAnswer = (ExamState.answers[itemNum] && ExamState.answers[itemNum].trim().length > 0);
    const isFlagged = ExamState.flagged.has(itemNum);
    const isActive = (idx === ExamState.currentIndex);

    if (isActive) btn.classList.add('active');
    if (isFlagged) {
      btn.classList.add('flagged');
    } else if (hasAnswer) {
      btn.classList.add('answered');
    } else {
      btn.classList.add('unanswered');
    }

    btn.addEventListener('click', () => {
      saveCurrentAnswer();
      ExamState.currentIndex = idx;
      renderCurrentQuestion();
      renderQuestionPalette();
    });

    grid.appendChild(btn);
  });
}

function renderCurrentQuestion() {
  if (ExamState.questions.length === 0) return;
  const q = ExamState.questions[ExamState.currentIndex];
  if (!q) return;

  const itemNum = q.item_number || (ExamState.currentIndex + 1);

  // Question Title & Section
  const numEl = document.getElementById('current-question-num');
  const sectionEl = document.getElementById('question-section-title');
  const marksEl = document.getElementById('question-marks');
  const promptEl = document.getElementById('question-prompt-text');
  const codeBlockEl = document.getElementById('question-code-block');
  const textarea = document.getElementById('candidate-answer-input');
  const prevBtn = document.getElementById('btn-prev-question');
  const nextBtn = document.getElementById('btn-next-question');
  const flagBtn = document.getElementById('btn-flag-review');
  const flagBtnText = document.getElementById('flag-btn-text');

  if (numEl) numEl.textContent = itemNum;
  if (sectionEl) sectionEl.textContent = q.section || `Section ${Math.floor(ExamState.currentIndex / 4) + 1}`;
  if (marksEl) marksEl.textContent = q.marks || 10;

  // Split text if it contains code/example blocks (e.g. X = "BACDB")
  const rawText = q.text || '';
  if (rawText.includes('\n\n')) {
    const parts = rawText.split('\n\n');
    promptEl.textContent = parts[0];
    if (codeBlockEl) {
      codeBlockEl.textContent = parts.slice(1).join('\n\n');
      codeBlockEl.style.display = 'block';
    }
  } else {
    promptEl.textContent = rawText;
    if (codeBlockEl) {
      codeBlockEl.style.display = 'none';
    }
  }

  // Populate textarea with candidate's saved response
  const savedAns = ExamState.answers[itemNum] || '';
  if (textarea) {
    textarea.value = savedAns;
    textarea.setAttribute('aria-label', `Candidate response for Question ${itemNum}`);
    updateWordCount(savedAns);
    textarea.focus();
  }

  // Previous Button
  if (prevBtn) {
    prevBtn.disabled = (ExamState.currentIndex === 0);
  }

  // Next Button Label (Save & Next vs Save & Review on last question)
  if (nextBtn) {
    if (ExamState.currentIndex === ExamState.questions.length - 1) {
      nextBtn.innerHTML = 'Save &amp; Review &rarr;';
    } else {
      nextBtn.innerHTML = 'Save &amp; Next &rarr;';
    }
  }

  // Flag Button State
  const isFlagged = ExamState.flagged.has(itemNum);
  if (flagBtn && flagBtnText) {
    if (isFlagged) {
      flagBtn.classList.add('flagged');
      flagBtnText.textContent = 'Flagged';
    } else {
      flagBtn.classList.remove('flagged');
      flagBtnText.textContent = 'Mark for Review';
    }
  }

  renderQuestionPalette();
}

// =========================================================================
// 3. CANDIDATE RESPONSES & REAL-TIME AUTOSAVE
// =========================================================================

function saveCurrentAnswer() {
  if (ExamState.questions.length === 0) return;
  const q = ExamState.questions[ExamState.currentIndex];
  if (!q) return;

  const itemNum = q.item_number || (ExamState.currentIndex + 1);
  const textarea = document.getElementById('candidate-answer-input');
  if (!textarea) return;

  const val = textarea.value;
  ExamState.answers[itemNum] = val;

  // Persist locally in sessionStorage in case of abrupt network drops
  try {
    sessionStorage.setItem(`exam_ans_${ExamState.sessionId}`, JSON.stringify(ExamState.answers));
    sessionStorage.setItem(`exam_flagged_${ExamState.sessionId}`, JSON.stringify(Array.from(ExamState.flagged)));
  } catch (e) {
    // quota exceeded or private mode
  }
}

function restoreCachedAnswers() {
  try {
    const cached = sessionStorage.getItem(`exam_ans_${ExamState.sessionId}`);
    if (cached) {
      ExamState.answers = Object.assign({}, ExamState.answers, JSON.parse(cached));
    }
    const cachedFlags = sessionStorage.getItem(`exam_flagged_${ExamState.sessionId}`);
    if (cachedFlags) {
      const arr = JSON.parse(cachedFlags);
      ExamState.flagged = new Set(arr);
    }
  } catch (e) {
    console.warn('Could not restore cached answers:', e);
  }
}

function updateWordCount(text) {
  const wordsEl = document.getElementById('word-count-display');
  const charsEl = document.getElementById('char-count-display');
  if (!wordsEl || !charsEl) return;

  const trimmed = text.trim();
  const wordCount = trimmed ? trimmed.split(/\s+/).length : 0;
  const charCount = text.length;

  wordsEl.textContent = `${wordCount} words`;
  charsEl.textContent = `${charCount} chars`;
}

function startAutosaveLoop() {
  if (ExamState.autosaveInterval) clearInterval(ExamState.autosaveInterval);

  // Periodic autosave every 12 seconds
  ExamState.autosaveInterval = setInterval(() => {
    triggerAutosave();
  }, 12000);
}

async function triggerAutosave() {
  if (!ExamState.sessionToken || ExamState.isSubmitting || ExamState.isAutosaving) return;
  saveCurrentAnswer();

  const dot = document.getElementById('autosave-dot');
  const statusText = document.getElementById('autosave-status-text');

  if (dot) dot.className = 'autosave-dot saving';
  if (statusText) statusText.textContent = 'Saving...';
  ExamState.isAutosaving = true;

  try {
    const res = await fetch(`${API_BASE}/schedules/sessions/autosave`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify({
        session_token: ExamState.sessionToken,
        answers: ExamState.answers,
      }),
    });

    if (res.ok) {
      const data = await res.json();
      ExamState.remainingSeconds = data.remaining_seconds;
      if (dot) dot.className = 'autosave-dot';
      if (statusText) statusText.textContent = 'Autosaved';
    } else {
      if (res.status === 410) {
        // Session Expired
        switchState('expired');
        return;
      }
      if (dot) dot.className = 'autosave-dot error';
      if (statusText) statusText.textContent = 'Saved locally';
    }
  } catch (err) {
    if (dot) dot.className = 'autosave-dot error';
    if (statusText) statusText.textContent = 'Saved locally (Offline)';
  } finally {
    ExamState.isAutosaving = false;
  }
}

// =========================================================================
// 4. COUNTDOWN TIMER
// =========================================================================

function startCountdownTimer() {
  if (ExamState.timerInterval) clearInterval(ExamState.timerInterval);

  updateTimerDisplay();

  ExamState.timerInterval = setInterval(() => {
    ExamState.remainingSeconds -= 1;

    if (ExamState.remainingSeconds <= 0) {
      clearInterval(ExamState.timerInterval);
      ExamState.remainingSeconds = 0;
      updateTimerDisplay();
      // Auto-submit when time expires
      handleTimeExpiration();
    } else {
      updateTimerDisplay();
    }
  }, 1000);
}

function updateTimerDisplay() {
  const countdownEl = document.getElementById('timer-countdown');
  const timerPill = document.getElementById('timer-pill');
  if (!countdownEl || !timerPill) return;

  const sec = Math.max(0, ExamState.remainingSeconds);
  const hrs = Math.floor(sec / 3600);
  const mins = Math.floor((sec % 3600) / 60);
  const secs = sec % 60;

  countdownEl.textContent = `${padZero(hrs)}:${padZero(mins)}:${padZero(secs)}`;

  // Styling based on time remaining
  if (sec <= 300) { // < 5 mins
    timerPill.className = 'timer-pill critical';
  } else if (sec <= 900) { // < 15 mins
    timerPill.className = 'timer-pill warning';
  } else {
    timerPill.className = 'timer-pill';
  }
}

async function handleTimeExpiration() {
  showAlert('Assessment duration has ended. Finalizing automatic submission...', 'warning');
  await executeFinalSubmit(true);
}

// =========================================================================
// 5. SUBMISSION & RECOVERY WORKFLOW
// =========================================================================

function openSubmitModal() {
  saveCurrentAnswer();

  const total = ExamState.questions.length;
  let answered = 0;
  ExamState.questions.forEach((q, idx) => {
    const itemNum = q.item_number || (idx + 1);
    if (ExamState.answers[itemNum] && ExamState.answers[itemNum].trim().length > 0) {
      answered += 1;
    }
  });
  const flagged = ExamState.flagged.size;
  const unanswered = Math.max(0, total - answered);

  document.getElementById('modal-count-answered').textContent = answered;
  document.getElementById('modal-count-unanswered').textContent = unanswered;
  document.getElementById('modal-count-flagged').textContent = flagged;

  const chk = document.getElementById('chk-confirm-submit');
  const submitBtn = document.getElementById('btn-confirm-final-submit');
  if (chk) chk.checked = false;
  if (submitBtn) submitBtn.disabled = true;

  const modal = document.getElementById('modal-submit-exam');
  if (modal) modal.style.display = 'flex';
}

function closeSubmitModal() {
  const modal = document.getElementById('modal-submit-exam');
  if (modal) modal.style.display = 'none';
}

async function executeFinalSubmit(isForced = false) {
  if (ExamState.isSubmitting) return;
  ExamState.isSubmitting = true;
  saveCurrentAnswer();

  const submitBtn = document.getElementById('btn-confirm-final-submit');
  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.textContent = 'Submitting & Locking...';
  }

  // Clear Timers
  if (ExamState.timerInterval) clearInterval(ExamState.timerInterval);
  if (ExamState.autosaveInterval) clearInterval(ExamState.autosaveInterval);

  try {
    const res = await fetch(`${API_BASE}/schedules/sessions/submit`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify({
        session_token: ExamState.sessionToken,
        final_answers: ExamState.answers,
      }),
    });

    closeSubmitModal();

    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error(errData.detail || 'Final submission rejected by institutional server.');
    }

    const data = await res.json();
    showSubmittedState(data);

  } catch (err) {
    console.error('Final submit error:', err);
    showAlert(`Submission failed: ${err.message}. Your answers remain cached locally.`, 'danger');
    ExamState.isSubmitting = false;
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Confirm & Lock Submission';
    }
  }
}

function openRecoveryModal() {
  const modal = document.getElementById('modal-recover-session');
  if (modal) {
    modal.style.display = 'flex';
    const input = document.getElementById('recovery-token-input');
    if (input) input.focus();
  }
}

function closeRecoveryModal() {
  const modal = document.getElementById('modal-recover-session');
  if (modal) modal.style.display = 'none';
}

async function executeSessionRecovery(token) {
  const btn = document.getElementById('btn-submit-recovery');
  if (btn) {
    btn.disabled = true;
    btn.textContent = 'Restoring Session...';
  }

  try {
    const res = await fetch(`${API_BASE}/schedules/sessions/recover`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify({ recovery_token: token.trim() }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      showAlert(err.detail || 'Invalid or expired recovery token.', 'danger');
      if (btn) {
        btn.disabled = false;
        btn.textContent = 'Restore Examination Session';
      }
      return;
    }

    const data = await res.json();
    closeRecoveryModal();

    // Rehydrate state
    ExamState.sessionId = data.session_id;
    ExamState.sessionToken = data.new_session_token;
    ExamState.recoveryToken = data.recovery_token;
    ExamState.questions = data.questions || [];
    ExamState.answers = data.saved_answers || {};
    ExamState.remainingSeconds = data.remaining_seconds || 3600;
    ExamState.watermark = data.watermark;

    renderWatermark(data.watermark);
    renderQuestionPalette();
    renderCurrentQuestion();

    startCountdownTimer();
    startAutosaveLoop();

    switchState('active');
    showAlert('Session successfully restored. Continued under cryptographic monitoring.', 'success');

  } catch (err) {
    showAlert('Network error communicating with server during recovery.', 'danger');
    if (btn) {
      btn.disabled = false;
      btn.textContent = 'Restore Examination Session';
    }
  }
}

// =========================================================================
// 6. UI EVENT BINDINGS
// =========================================================================

function bindUIEvents() {
  // Previous Question
  const prevBtn = document.getElementById('btn-prev-question');
  if (prevBtn) {
    prevBtn.addEventListener('click', () => {
      saveCurrentAnswer();
      if (ExamState.currentIndex > 0) {
        ExamState.currentIndex -= 1;
        renderCurrentQuestion();
      }
    });
  }

  // Save & Next Question
  const nextBtn = document.getElementById('btn-next-question');
  if (nextBtn) {
    nextBtn.addEventListener('click', () => {
      saveCurrentAnswer();
      triggerAutosave();

      if (ExamState.currentIndex < ExamState.questions.length - 1) {
        ExamState.currentIndex += 1;
        renderCurrentQuestion();
      } else {
        // Reached end -> open submit dialog
        openSubmitModal();
      }
    });
  }

  // Mark for Review
  const flagBtn = document.getElementById('btn-flag-review');
  if (flagBtn) {
    flagBtn.addEventListener('click', () => {
      if (ExamState.questions.length === 0) return;
      const q = ExamState.questions[ExamState.currentIndex];
      const itemNum = q.item_number || (ExamState.currentIndex + 1);

      if (ExamState.flagged.has(itemNum)) {
        ExamState.flagged.delete(itemNum);
      } else {
        ExamState.flagged.add(itemNum);
      }

      renderCurrentQuestion();
    });
  }

  // Textarea Typing (Live Word Count)
  const textarea = document.getElementById('candidate-answer-input');
  if (textarea) {
    textarea.addEventListener('input', (e) => {
      updateWordCount(e.target.value);
    });
  }

  // Final Submit Modal Controls
  const openSubmitBtn = document.getElementById('btn-open-submit-modal');
  if (openSubmitBtn) {
    openSubmitBtn.addEventListener('click', openSubmitModal);
  }

  const closeSubmitBtn = document.getElementById('btn-close-submit-modal');
  const cancelSubmitBtn = document.getElementById('btn-cancel-submit');
  if (closeSubmitBtn) closeSubmitBtn.addEventListener('click', closeSubmitModal);
  if (cancelSubmitBtn) cancelSubmitBtn.addEventListener('click', closeSubmitModal);

  const confirmCheckbox = document.getElementById('chk-confirm-submit');
  const confirmSubmitBtn = document.getElementById('btn-confirm-final-submit');
  if (confirmCheckbox && confirmSubmitBtn) {
    confirmCheckbox.addEventListener('change', (e) => {
      confirmSubmitBtn.disabled = !e.target.checked;
    });
    confirmSubmitBtn.addEventListener('click', () => executeFinalSubmit(false));
  }

  // Recovery Modal Controls
  const openRecoverBtn = document.getElementById('btn-open-recover-modal');
  const closeRecoverBtn = document.getElementById('btn-close-recover-modal');
  const recoverForm = document.getElementById('form-recover-session');

  if (openRecoverBtn) openRecoverBtn.addEventListener('click', openRecoveryModal);
  if (closeRecoverBtn) closeRecoverBtn.addEventListener('click', closeRecoveryModal);
  if (recoverForm) {
    recoverForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const tokenInput = document.getElementById('recovery-token-input');
      if (tokenInput && tokenInput.value.trim()) {
        executeSessionRecovery(tokenInput.value.trim());
      }
    });
  }

  // Copy Recovery Token Quick Button
  const copyRecBtn = document.getElementById('btn-copy-recovery');
  if (copyRecBtn) {
    copyRecBtn.addEventListener('click', () => {
      if (ExamState.recoveryToken) {
        navigator.clipboard.writeText(ExamState.recoveryToken).then(() => {
          showAlert('Recovery token copied to clipboard.', 'info');
        }).catch(() => {
          showAlert(`Recovery Key: ${ExamState.recoveryToken}`, 'info');
        });
      }
    });
  }

  // Retry Lookup Buttons
  const emptyRetryBtn = document.getElementById('btn-empty-retry');
  if (emptyRetryBtn) emptyRetryBtn.addEventListener('click', discoverAndStartSession);

  const earlyRetryBtn = document.getElementById('btn-early-check-again');
  if (earlyRetryBtn) earlyRetryBtn.addEventListener('click', discoverAndStartSession);

  // Exit Portal
  const exitBtn = document.getElementById('btn-exit-exam');
  if (exitBtn) {
    exitBtn.addEventListener('click', () => {
      if (confirm('Are you sure you want to exit? Your answers are securely autosaved, but the exam countdown continues.')) {
        window.location.href = 'index.html';
      }
    });
  }

  // Accessible Keyboard Shortcuts
  window.addEventListener('keydown', (e) => {
    // Ctrl+Enter or Cmd+Enter: Save & Next
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      const nextBtn = document.getElementById('btn-next-question');
      if (nextBtn) nextBtn.click();
    }
    // Alt+F: Flag for Review
    if (e.altKey && (e.key === 'f' || e.key === 'F')) {
      e.preventDefault();
      const flagBtn = document.getElementById('btn-flag-review');
      if (flagBtn) flagBtn.click();
    }
    // Escape: Close Modals
    if (e.key === 'Escape') {
      closeSubmitModal();
      closeRecoveryModal();
    }
  });
}

// =========================================================================
// 7. SYSTEM STATE MANAGEMENT
// =========================================================================

function switchState(stateName) {
  const states = [
    'loading',
    'empty',
    'too-early',
    'permission-denied',
    'expired',
    'submitted',
  ];

  states.forEach(s => {
    const el = document.getElementById(`state-${s}`);
    if (el) el.style.display = 'none';
  });

  const activeLayout = document.getElementById('state-active-exam');
  if (activeLayout) {
    activeLayout.style.display = (stateName === 'active') ? 'grid' : 'none';
  }

  if (stateName !== 'active') {
    const target = document.getElementById(`state-${stateName}`);
    if (target) target.style.display = 'block';
  }
}

function showTooEarlyState(detailMessage, startTimeIso) {
  switchState('too-early');
  const msgEl = document.getElementById('too-early-message');
  if (msgEl) msgEl.textContent = detailMessage;

  const timerEl = document.getElementById('early-countdown-timer');
  if (!timerEl) return;

  if (startTimeIso) {
    const target = new Date(startTimeIso).getTime();
    const updateEarlyTimer = () => {
      const now = new Date().getTime();
      const diff = Math.max(0, Math.floor((target - now) / 1000));
      const hrs = Math.floor(diff / 3600);
      const mins = Math.floor((diff % 3600) / 60);
      const secs = diff % 60;
      timerEl.textContent = `${padZero(hrs)}:${padZero(mins)}:${padZero(secs)}`;
    };
    updateEarlyTimer();
    setInterval(updateEarlyTimer, 1000);
  }
}

function showPermissionDenied(reason) {
  switchState('permission-denied');
  const el = document.getElementById('permission-denied-reason');
  if (el) el.textContent = reason;
}

function showErrorState(msg) {
  switchState('permission-denied');
  const el = document.getElementById('permission-denied-reason');
  if (el) el.textContent = msg;
  showAlert(msg, 'danger');
}

function showSubmittedState(data) {
  switchState('submitted');
  const sessEl = document.getElementById('summary-session-id');
  const timeEl = document.getElementById('summary-submitted-at');
  const hashEl = document.getElementById('summary-forensic-hash');

  if (sessEl) sessEl.textContent = `#${data.session_id || ExamState.sessionId || '1042'}`;
  if (timeEl) {
    const d = data.submitted_at ? new Date(data.submitted_at) : new Date();
    timeEl.textContent = d.toUTCString();
  }
  if (hashEl && ExamState.watermark) {
    hashEl.textContent = ExamState.watermark.forensic_hash || 'SHA256-8F4E29';
  }
}

function showAlert(text, type = 'info') {
  const alertBox = document.getElementById('exam-alert');
  const alertText = document.getElementById('exam-alert-text');
  if (!alertBox || !alertText) return;

  alertText.textContent = text;
  alertBox.className = `alert-box alert-${type}`;
  alertBox.style.display = 'flex';

  if (type === 'success' || type === 'info') {
    setTimeout(() => {
      alertBox.style.display = 'none';
    }, 5000);
  }
}

function padZero(num) {
  return num < 10 ? `0${num}` : `${num}`;
}

function escapeXml(unsafe) {
  return unsafe.replace(/[<>&'"]/g, (c) => {
    switch (c) {
      case '<': return '&lt;';
      case '>': return '&gt;';
      case '&': return '&amp;';
      case '\'': return '&apos;';
      case '"': return '&quot;';
    }
  });
}
