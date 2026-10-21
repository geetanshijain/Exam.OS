import os
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.user import User, UserRole
from app.models.bank import BankQuestion, BankQuestionApprovalStatus
from app.models.studio import Examination, GeneratedQuestion, QuestionReviewStatus


@pytest.mark.asyncio
async def test_question_bank_backend_contracts_and_security(client: AsyncClient, db_session: AsyncSession):
    """
    Validates backend API contracts used by the Question Bank Repository page:
    1. Creating a new bank question with full curriculum metadata.
    2. Searching and multi-dimensional filtering (unit, difficulty, approval status, search term).
    3. Retrieval of individual question rubrics with IDOR checks.
    4. Updating question stems, marks, and rubric points.
    5. Departmental isolation: Cross-department access attempts are rejected with HTTP 403.
    6. Importing studio approved questions directly into the bank.
    7. Deletion of questions with owner/permission checks.
    """
    # 1. Create setter user (Computer Science)
    setter = User(
        email="setter_bank@examos.edu",
        username="setter_bank",
        full_name="Prof. Alex Setter",
        department="Computer Science",
        role=UserRole.setter,
        hashed_password=hash_password("Pass123!"),
        is_active=True,
    )
    db_session.add(setter)
    await db_session.commit()
    await db_session.refresh(setter)

    token, _, _ = create_access_token(
        subject=setter.id,
        role=setter.role.value,
        department=setter.department,
        mfa_verified=True,
    )
    auth_headers = {"Authorization": f"Bearer {token}"}

    # 2. Add Question to Bank
    create_payload = {
        "subject": "Operating Systems",
        "topic": "Process Synchronization Primitives",
        "unit": 1,
        "question_text": "Explain the bounded-buffer problem with counting semaphores and mutex locks.",
        "marks": 10,
        "difficulty": "medium",
        "question_type": "descriptive",
        "syllabus_version": "2026.1",
        "learning_outcome_code": "LO-1",
        "source_provenance": "Faculty Curated Pool",
        "expected_answer_points": ["Semaphore initialization", "Buffer isolation", "Deadlock avoidance"],
        "department": "Computer Science",
        "approval_status": "draft",
    }
    create_res = await client.post(
        "/api/v1/bank/questions",
        json=create_payload,
        headers=auth_headers,
    )
    assert create_res.status_code == 201
    created_q = create_res.json()
    q_id = created_q["id"]
    assert created_q["subject"] == "Operating Systems"
    assert created_q["marks"] == 10
    assert created_q["unit"] == 1

    # 3. Search and Filter Bank Questions
    # A) Search with query matching topic
    search_res = await client.get(
        "/api/v1/bank/questions?q=Synchronization&unit=1",
        headers=auth_headers,
    )
    assert search_res.status_code == 200
    search_data = search_res.json()
    assert search_data["total"] >= 1
    assert any(item["id"] == q_id for item in search_data["items"])

    # B) Search with non-matching unit filter
    no_match_res = await client.get(
        "/api/v1/bank/questions?unit=4",
        headers=auth_headers,
    )
    assert no_match_res.status_code == 200
    assert not any(item["id"] == q_id for item in no_match_res.json()["items"])

    # 4. Retrieve Question Details
    get_res = await client.get(
        f"/api/v1/bank/questions/{q_id}",
        headers=auth_headers,
    )
    assert get_res.status_code == 200
    assert get_res.json()["id"] == q_id
    assert len(get_res.json()["expected_answer_points"]) == 3

    # 5. Update Question (Edit stem & marks)
    update_res = await client.patch(
        f"/api/v1/bank/questions/{q_id}",
        json={
            "question_text": "Explain the classic bounded-buffer problem with strict POSIX mutex locking and starvation avoidance.",
            "marks": 15,
        },
        headers=auth_headers,
    )
    assert update_res.status_code == 200
    updated_q = update_res.json()
    assert updated_q["marks"] == 15
    assert "POSIX mutex locking" in updated_q["question_text"]

    # 6. Cross-department IDOR Protection
    civil_setter = User(
        email="setter_civil_bank@examos.edu",
        username="setter_civil_bank",
        full_name="Prof. Civil Examiner",
        department="Civil Engineering",
        role=UserRole.setter,
        hashed_password=hash_password("Pass123!"),
        is_active=True,
    )
    db_session.add(civil_setter)
    await db_session.commit()
    await db_session.refresh(civil_setter)

    civil_token, _, _ = create_access_token(
        subject=civil_setter.id,
        role=civil_setter.role.value,
        department=civil_setter.department,
        mfa_verified=True,
    )
    civil_headers = {"Authorization": f"Bearer {civil_token}"}

    # Cannot view question from other department
    forbidden_get = await client.get(
        f"/api/v1/bank/questions/{q_id}",
        headers=civil_headers,
    )
    assert forbidden_get.status_code == 403

    # Cannot patch question in other department
    forbidden_patch = await client.patch(
        f"/api/v1/bank/questions/{q_id}",
        json={"marks": 20},
        headers=civil_headers,
    )
    assert forbidden_patch.status_code == 403

    # 7. Import from Studio Examination
    exam = Examination(
        title="CS-501: OS Studio Exam",
        subject="Computer Science",
        course="B.Tech CSE",
        semester=5,
        department="Computer Science",
        syllabus_version="2026.1",
        total_marks=100,
        duration_minutes=180,
        created_by=setter.id,
    )
    db_session.add(exam)
    await db_session.commit()
    await db_session.refresh(exam)

    # Add an accepted studio question
    studio_q = GeneratedQuestion(
        examination_id=exam.id,
        unit_number=2,
        syllabus_topic="Virtual Memory",
        question_text="Derive the Effective Memory Access Time (EMAT) formula with two-level page tables and a TLB hit ratio of 95%.",
        marks=10,
        question_type="analytical",
        difficulty="medium",
        learning_outcome_code="LO-3",
        expected_answer_points_json='["EMAT formula", "Hit latency", "Miss penalty"]',
        provenance_basis="Studio Generation",
        duplicate_risk_score=0.10,
        validation_flags_json="[]",
        review_status=QuestionReviewStatus.setter_accepted,
    )
    db_session.add(studio_q)
    await db_session.commit()

    import_res = await client.post(
        f"/api/v1/bank/questions/import-from-studio/{exam.id}",
        json={"exam_id": exam.id, "promote_only_accepted": True},
        headers=auth_headers,
    )
    assert import_res.status_code == 201
    assert import_res.json()["imported_count"] == 1

    # 8. Delete Question
    delete_res = await client.delete(
        f"/api/v1/bank/questions/{q_id}",
        headers=auth_headers,
    )
    assert delete_res.status_code == 204

    # Verification of deletion
    verify_delete = await client.get(
        f"/api/v1/bank/questions/{q_id}",
        headers=auth_headers,
    )
    assert verify_delete.status_code == 404


def test_question_bank_page_html_and_reference_fidelity():
    """
    Verifies that frontend/question-bank.html implements all components,
    accessible attributes, responsive states, and visual requirements
    matching the approved reference design.
    """
    frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "..", "frontend")
    page_path = os.path.join(frontend_dir, "question-bank.html")
    assert os.path.exists(page_path), "frontend/question-bank.html must exist"

    with open(page_path, "r", encoding="utf-8") as f:
        html = f.read()

    # 1. Header Landmarks & Navigation
    assert '<header class="site-header"' in html
    assert 'Exam Governance' in html
    assert 'Question Bank Repository' in html
    assert 'id="bank-dept-headline"' in html
    assert 'Institutional Question Bank' in html

    # 2. Header Action Controls
    assert 'id="btn-open-add-modal"' in html
    assert '+ New Question' in html
    assert 'id="btn-open-import-modal"' in html
    assert 'Import from Studio' in html

    # 3. Four Metric KPI Cards (Matching Reference Design)
    assert 'id="kpi-total-bank"' in html
    assert 'id="kpi-approved-bank"' in html
    assert 'id="kpi-pending-bank"' in html
    assert 'id="kpi-syllabus-version"' in html
    assert 'Total Bank Questions' in html
    assert 'Approved &amp; Vetted' in html
    assert 'Pending Review' in html
    assert 'Active Syllabus' in html

    # 4. Multi-dimensional Filter Toolbar
    assert 'class="bank-filter-toolbar"' in html
    assert 'id="filter-subject-select"' in html
    assert 'id="filter-unit-all"' in html
    assert 'id="filter-diff-all"' in html
    assert 'id="filter-type-all"' in html
    assert 'id="filter-bank-status-all"' in html
    assert 'id="filter-bank-status-approved"' in html
    assert 'id="filter-bank-status-review"' in html
    assert 'id="bank-search-input"' in html

    # 5. Question Inventory Table Structure
    assert 'class="bank-table-container"' in html
    assert 'class="bank-table"' in html
    assert 'id="bank-table-body"' in html
    assert 'Question ID' in html
    assert 'Question stem' in html
    assert 'Topic/Unit' in html

    # 6. Modals
    assert 'id="modal-add-question"' in html
    assert 'id="modal-view-rubric"' in html
    assert 'id="modal-import-studio"' in html
    assert 'role="dialog"' in html
    assert 'aria-modal="true"' in html
    assert 'id="form-add-bank-question"' in html
    assert 'id="add-q-subject"' in html
    assert 'id="add-q-topic"' in html
    assert 'id="add-q-text"' in html

    # 7. Six UI States
    assert 'id="bank-loading-state"' in html
    assert 'id="bank-empty-state"' in html
    assert 'id="bank-permission-denied"' in html
    assert 'id="bank-alert"' in html
    assert 'id="btn-empty-add"' in html

    # 8. Bottom Pagination & Exam Assembly
    assert 'class="bank-pagination-bar"' in html
    assert 'id="pagination-summary"' in html
    assert 'id="btn-assemble-blueprint"' in html
    assert 'Assemble into Exam Blueprint' in html

    # 9. Institutional Banner Strip
    assert 'Departmental Isolation Enforced' in html
    assert 'DEV ENVIRONMENT' in html
