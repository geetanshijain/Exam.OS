import os
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.user import User, UserRole


@pytest.mark.asyncio
async def test_blueprint_and_analysis_backend_contracts(client: AsyncClient, db_session: AsyncSession):
    """
    Validates backend API contracts used by the AI Analysis and Blueprint page:
    1. Syllabus structure update with 100% weightage mathematical validation.
    2. Server rejects invalid unit weightings that do not sum to 100%.
    3. Query historical questions coverage and topic frequency analysis.
    4. Deterministic question generation according to the explicit examination blueprint.
    5. Departmental isolation prevents cross-department blueprint manipulation.
    """
    # 1. Create setter user
    setter = User(
        email="setter_bp@examos.edu",
        username="setter_bp",
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

    # 2. Create examination
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
                {"code": "LO-1", "description": "Kernel architecture & mode switches"},
                {"code": "LO-2", "description": "Process lifecycle & synchronization"},
                {"code": "LO-3", "description": "Memory virtualization & page replacement"},
                {"code": "LO-4", "description": "Storage systems & disk scheduling"},
            ],
        },
        headers=auth_headers,
    )
    assert create_exam_res.status_code == 201
    exam_id = create_exam_res.json()["id"]

    # 3. Test mathematical validation on Syllabus unit weights:
    # A) Invalid weightings (sum = 90% != 100%) -> Should be rejected with HTTP 400
    invalid_units_payload = {
        "units": [
            {"unit_number": 1, "title": "Unit I: OS Kernel", "weighting_percentage": 20, "topics": [{"name": "System Calls", "subtopics": []}]},
            {"unit_number": 2, "title": "Unit II: Concurrency", "weighting_percentage": 30, "topics": [{"name": "Deadlocks", "subtopics": []}]},
            {"unit_number": 3, "title": "Unit III: Memory", "weighting_percentage": 20, "topics": [{"name": "Paging", "subtopics": []}]},
            {"unit_number": 4, "title": "Unit IV: Storage", "weighting_percentage": 20, "topics": [{"name": "File Systems", "subtopics": []}]},
        ]
    }
    invalid_res = await client.put(
        f"/api/v1/studio/examinations/{exam_id}/syllabus",
        json=invalid_units_payload,
        headers=auth_headers,
    )
    assert invalid_res.status_code == 400
    assert "sum to 100%" in invalid_res.json()["detail"].lower()

    # B) Valid weightings (sum = 25 + 30 + 25 + 20 = 100%) -> Should succeed with HTTP 200
    valid_units_payload = {
        "units": [
            {"unit_number": 1, "title": "Unit I: OS Kernel Primitives & System Calls", "weighting_percentage": 25, "topics": [{"name": "System Calls", "subtopics": ["Context Switching"]}]},
            {"unit_number": 2, "title": "Unit II: Concurrency, Deadlocks & Synchronization", "weighting_percentage": 30, "topics": [{"name": "Banker's Algorithm", "subtopics": ["Deadlock Avoidance"]}]},
            {"unit_number": 3, "title": "Unit III: Virtual Memory & Page Replacement", "weighting_percentage": 25, "topics": [{"name": "Page Replacement", "subtopics": ["LRU", "FIFO"]}]},
            {"unit_number": 4, "title": "Unit IV: Storage & File Systems", "weighting_percentage": 20, "topics": [{"name": "Disk Scheduling", "subtopics": ["C-SCAN"]}]},
        ]
    }
    valid_res = await client.put(
        f"/api/v1/studio/examinations/{exam_id}/syllabus",
        json=valid_units_payload,
        headers=auth_headers,
    )
    assert valid_res.status_code == 200
    syl_res_data = valid_res.json()
    assert len(syl_res_data["units"]) == 4

    # 4. Query Historical Questions Analysis
    analysis_res = await client.get(
        f"/api/v1/studio/examinations/{exam_id}/analysis",
        headers=auth_headers,
    )
    assert analysis_res.status_code == 200
    analysis_data = analysis_res.json()
    assert "difficulty_distribution" in analysis_data
    assert "type_distribution" in analysis_data
    assert "unit_coverage" in analysis_data

    # 5. Deterministic Blueprint-driven Question Generation
    generate_res = await client.post(
        f"/api/v1/studio/examinations/{exam_id}/generate",
        json={
            "allow_external_ai": False,
            "blueprint": {
                "total_marks": 100,
                "sections": [
                    {"name": "Section A", "marks": 20, "question_count": 10},
                    {"name": "Section B", "marks": 40, "question_count": 5},
                    {"name": "Section C", "marks": 40, "question_count": 2},
                ],
                "target_difficulty": {"easy": 0.3, "medium": 0.5, "hard": 0.2},
            },
        },
        headers=auth_headers,
    )
    assert generate_res.status_code == 200
    generated_questions = generate_res.json()
    assert len(generated_questions) > 0
    first_q = generated_questions[0]
    assert "question_text" in first_q
    assert "marks" in first_q
    assert "unit_number" in first_q
    assert "difficulty" in first_q
    assert "duplicate_risk_score" in first_q

    # 6. Cross-department IDOR protection:
    other_setter = User(
        email="setter_civil@examos.edu",
        username="setter_civil",
        full_name="Prof. Civil Examiner",
        department="Civil Engineering",
        role=UserRole.setter,
        hashed_password=hash_password("Pass123!"),
        is_active=True,
    )
    db_session.add(other_setter)
    await db_session.commit()
    await db_session.refresh(other_setter)

    civil_token, _, _ = create_access_token(
        subject=other_setter.id,
        role=other_setter.role.value,
        department=other_setter.department,
        mfa_verified=True,
    )
    civil_headers = {"Authorization": f"Bearer {civil_token}"}

    forbidden_gen = await client.post(
        f"/api/v1/studio/examinations/{exam_id}/generate",
        json={"allow_external_ai": False},
        headers=civil_headers,
    )
    assert forbidden_gen.status_code == 403


def test_blueprint_page_html_and_reference_fidelity():
    """
    Verifies that frontend/blueprint.html implements all components,
    accessible attributes, and visual requirements from the approved reference design.
    """
    frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "..", "frontend")
    page_path = os.path.join(frontend_dir, "blueprint.html")
    assert os.path.exists(page_path), "frontend/blueprint.html must exist"

    with open(page_path, "r", encoding="utf-8") as f:
        html = f.read()

    # 1. Header Landmarks & Navigation
    assert '<header class="site-header"' in html
    assert 'Question Paper Studio' in html
    assert 'AI Analysis &amp; Blueprint Engine' in html
    assert 'id="exam-headline"' in html
    assert 'id="btn-back-uploads"' in html

    # 2. Four KPI Cards
    assert 'Total Examination Marks' in html
    assert 'Syllabus Competency Coverage' in html
    assert 'Historical PYQ Overlap' in html
    assert 'Difficulty Target' in html
    assert 'id="kpi-total-marks"' in html
    assert 'id="kpi-units-coverage"' in html
    assert 'id="kpi-pyq-overlap"' in html
    assert 'id="kpi-difficulty-dist"' in html

    # 3. Left Column: Syllabus Unit Weighting & Sliders
    assert 'Syllabus Unit Weighting &amp; Competency Distribution' in html
    assert 'id="units-table-body"' in html
    assert 'id="validation-bar"' in html
    assert 'Mathematically Validated' in html

    # 4. Right Column: Historical Repetition & Blueprint Sections
    assert 'Historical Topic Repetition &amp; Overlap Analysis' in html
    assert 'Examination Blueprint Architecture' in html
    assert 'Section A' in html
    assert 'Section B' in html
    assert 'Section C' in html

    # 5. Bottom Navigation Bar & Actions
    assert 'id="btn-generate-questions"' in html
    assert 'Generate Questions from Blueprint' in html
    assert 'id="generated-modal"' in html
    assert 'Deterministic Blueprint Engine' in html
    assert 'DEV ENVIRONMENT' in html
