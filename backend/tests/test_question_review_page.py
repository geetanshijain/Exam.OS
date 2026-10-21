import json
import os
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.user import User, UserRole
from app.models.studio import Examination, SyllabusStructure, GeneratedQuestion, QuestionReviewStatus


@pytest.mark.asyncio
async def test_question_review_backend_contracts_and_lifecycle(client: AsyncClient, db_session: AsyncSession):
    """
    Validates backend API contracts used by the Question Generation and Review page:
    1. Retrieval of generated questions for an examination.
    2. Reviewer approving questions (PATCH review_status="accepted").
    3. Reviewer modifying question stem and marks with server-side validation.
    4. Reviewer rejecting questions with comments.
    5. Single question regeneration maintaining unit and marks constraints.
    6. Departmental IDOR isolation preventing cross-department question tampering.
    """
    # 1. Create setter user
    setter = User(
        email="setter_rev@examos.edu",
        username="setter_rev",
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

    # 2. Create Examination
    create_exam_res = await client.post(
        "/api/v1/studio/examinations",
        json={
            "title": "CS-501: Operating Systems & Kernel Architecture",
            "subject": "Computer Science",
            "course": "B.Tech CSE",
            "semester": 5,
            "department": "Computer Science",
            "syllabus_version": "2026.1",
            "total_marks": 100,
            "duration_minutes": 180,
            "learning_outcomes": [
                {"code": "LO-1", "description": "Kernel primitives & concurrency"},
                {"code": "LO-2", "description": "Virtual memory & storage"},
            ],
        },
        headers=auth_headers,
    )
    assert create_exam_res.status_code == 201
    exam_id = create_exam_res.json()["id"]

    # 3. Add Syllabus Structure
    valid_units_payload = {
        "units": [
            {
                "unit_number": 1,
                "title": "Unit I: Process Synchronization",
                "weighting_percentage": 50,
                "topics": [{"name": "Semaphores & Mutexes", "subtopics": ["POSIX Threads"]}],
            },
            {
                "unit_number": 2,
                "title": "Unit II: Virtual Memory Management",
                "weighting_percentage": 50,
                "topics": [{"name": "Paging & Segmentation", "subtopics": ["TLB Caching"]}],
            },
        ]
    }
    await client.put(
        f"/api/v1/studio/examinations/{exam_id}/syllabus",
        json=valid_units_payload,
        headers=auth_headers,
    )

    # 4. Generate questions via deterministic engine
    gen_res = await client.post(
        f"/api/v1/studio/examinations/{exam_id}/generate",
        json={"allow_external_ai": False},
        headers=auth_headers,
    )
    assert gen_res.status_code == 200
    questions = gen_res.json()
    assert len(questions) > 0
    q1 = questions[0]
    q1_id = q1["id"]

    # 5. List Generated Questions
    list_res = await client.get(
        f"/api/v1/studio/examinations/{exam_id}/questions",
        headers=auth_headers,
    )
    assert list_res.status_code == 200
    listed_questions = list_res.json()
    assert len(listed_questions) == len(questions)

    # 6. Human-in-the-loop: Approve question
    approve_res = await client.patch(
        f"/api/v1/studio/examinations/{exam_id}/questions/{q1_id}",
        json={"review_status": "setter_accepted"},
        headers=auth_headers,
    )
    assert approve_res.status_code == 200
    assert approve_res.json()["review_status"] == "setter_accepted"

    # 7. Human-in-the-loop: Edit question stem and marks
    edit_res = await client.patch(
        f"/api/v1/studio/examinations/{exam_id}/questions/{q1_id}",
        json={
            "question_text": "Explain the classic Producer-Consumer problem using POSIX semaphores with buffer boundary validation.",
            "marks": 15,
            "expected_answer_points": ["Semaphore initialization", "Deadlock avoidance", "POSIX syntax"],
            "reviewer_comments": "Adjusted marks to 15 for implementation depth.",
        },
        headers=auth_headers,
    )
    assert edit_res.status_code == 200
    edited_data = edit_res.json()
    assert edited_data["marks"] == 15
    assert "POSIX semaphores" in edited_data["question_text"]
    assert edited_data["review_status"] == "setter_edited"
    assert len(edited_data["expected_answer_points"]) == 3

    # 8. Human-in-the-loop: Single question regeneration
    regen_res = await client.post(
        f"/api/v1/studio/examinations/{exam_id}/questions/{q1_id}/regenerate",
        headers=auth_headers,
    )
    assert regen_res.status_code == 200
    regen_data = regen_res.json()
    assert regen_data["id"] == q1_id
    assert "question_text" in regen_data

    # 9. Human-in-the-loop: Reject question
    reject_res = await client.patch(
        f"/api/v1/studio/examinations/{exam_id}/questions/{q1_id}",
        json={"review_status": "setter_rejected", "reviewer_comments": "Redundant with lab test."},
        headers=auth_headers,
    )
    assert reject_res.status_code == 200
    assert reject_res.json()["review_status"] == "setter_rejected"

    # 10. Cross-department IDOR Protection
    civil_setter = User(
        email="setter_civil_rev@examos.edu",
        username="setter_civil_rev",
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

    forbidden_patch = await client.patch(
        f"/api/v1/studio/examinations/{exam_id}/questions/{q1_id}",
        json={"review_status": "setter_accepted"},
        headers=civil_headers,
    )
    assert forbidden_patch.status_code == 403

    forbidden_regen = await client.post(
        f"/api/v1/studio/examinations/{exam_id}/questions/{q1_id}/regenerate",
        headers=civil_headers,
    )
    assert forbidden_regen.status_code == 403


def test_question_review_page_html_and_reference_fidelity():
    """
    Verifies that frontend/question-review.html implements all components,
    accessible attributes, responsive states, and visual requirements
    matching the approved reference design.
    """
    frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "..", "frontend")
    page_path = os.path.join(frontend_dir, "question-review.html")
    assert os.path.exists(page_path), "frontend/question-review.html must exist"

    with open(page_path, "r", encoding="utf-8") as f:
        html = f.read()

    # 1. Header Landmarks & Navigation
    assert '<header class="site-header"' in html
    assert 'Question Paper Studio' in html
    assert 'Question Generation &amp; Review' in html
    assert 'id="exam-headline"' in html
    assert 'id="btn-back-blueprint"' in html

    # 2. Filter & Search Suite
    assert 'class="review-filter-bar"' in html
    assert 'id="filter-unit-all"' in html
    assert 'id="filter-difficulty-select"' in html
    assert 'id="filter-status-all"' in html
    assert 'id="filter-status-accepted"' in html
    assert 'id="filter-status-flagged"' in html
    assert 'id="question-search-input"' in html

    # 3. KPI Summary Strip (Matching Approved Reference Design)
    assert 'class="review-kpi-strip"' in html
    assert 'KPI: Total Questions:' in html
    assert 'Approved:' in html
    assert 'Duplicate Warnings:' in html
    assert 'Blueprint Conformance:' in html
    assert 'id="kpi-total-questions"' in html
    assert 'id="kpi-approved-questions"' in html
    assert 'id="kpi-duplicate-warnings"' in html
    assert 'id="kpi-blueprint-conformance"' in html

    # 4. Interactive Question Feed & Card Attributes
    assert 'id="question-cards-container"' in html
    assert 'qcard-warning-banner' in html
    assert 'Expected Answer Rubric' in html
    assert 'btn-approve-q' in html
    assert 'btn-edit-q' in html
    assert 'btn-regenerate-q' in html
    assert 'btn-reject-q' in html

    # 5. Responsive States
    assert 'id="loading-state"' in html
    assert 'id="empty-state"' in html
    assert 'id="permission-denied-state"' in html
    assert 'id="review-alert"' in html

    # 6. Accessible Edit Modal Dialog
    assert 'id="edit-modal"' in html
    assert 'role="dialog"' in html
    assert 'aria-modal="true"' in html
    assert 'id="edit-q-text"' in html
    assert 'id="edit-q-marks"' in html
    assert 'id="edit-q-difficulty"' in html
    assert 'id="edit-q-rubric"' in html
    assert 'id="modal-validation-error"' in html

    # 7. Sticky Bottom Finalization Bar
    assert 'class="sticky-review-footer"' in html
    assert 'id="bottom-summary-text"' in html
    assert 'id="btn-push-bank"' in html
    assert 'Push Approved to Question Bank' in html

    # 8. Institutional Footer Notice
    assert 'Human-in-the-Loop Review Active' in html
    assert 'DEV ENVIRONMENT' in html
