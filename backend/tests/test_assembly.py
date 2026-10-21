import json
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.assembly.builder import assemble_paper_sections
from app.assembly.validator import validate_assembled_paper
from app.models.assembly import AssembledPaperStatus
from app.models.bank import BankQuestionApprovalStatus
from app.schemas.assembly import PaperBlueprintConfig, SectionRuleConfig


# =========================================================================
# 1. UNIT TESTS: ASSEMBLY BUILDER & REPRODUCIBILITY
# =========================================================================


def test_assembly_builder_deterministic_reproducibility():
    blueprint = PaperBlueprintConfig(
        total_marks=50,
        duration_minutes=120,
        sections=[
            SectionRuleConfig(
                section_id="sec_a",
                name="Section A (Compulsory)",
                selection_rule="all_compulsory",
                questions_to_answer=5,
                marks_per_question=2,
                total_section_marks=10,
            ),
            SectionRuleConfig(
                section_id="sec_b",
                name="Section B (Internal Choice)",
                selection_rule="internal_choice",
                questions_to_answer=4,
                marks_per_question=10,
                total_section_marks=40,
            ),
        ],
        seed=42,
    )

    bank_questions = [
        {"question_id": 1, "question_text": "What is a kernel?", "marks": 2, "difficulty": "easy", "question_type": "short_answer", "unit": 1, "topic": "Kernel", "learning_outcome_code": "CO1"},
        {"question_id": 2, "question_text": "Define process control block.", "marks": 2, "difficulty": "easy", "question_type": "short_answer", "unit": 1, "topic": "PCB", "learning_outcome_code": "CO1"},
        {"question_id": 3, "question_text": "Explain deadlock prevention.", "marks": 10, "difficulty": "medium", "question_type": "descriptive", "unit": 2, "topic": "Deadlock", "learning_outcome_code": "CO2"},
        {"question_id": 4, "question_text": "Analyze paging and segmentation.", "marks": 10, "difficulty": "hard", "question_type": "descriptive", "unit": 3, "topic": "Virtual Memory", "learning_outcome_code": "CO3"},
    ]

    # Run twice with the exact same seed=42
    run_1 = assemble_paper_sections(blueprint, bank_questions, seed=42)
    run_2 = assemble_paper_sections(blueprint, bank_questions, seed=42)

    assert len(run_1) == 2
    assert len(run_1[0]["questions"]) == 5
    assert len(run_1[1]["questions"]) == 4

    # Assert exact deterministic reproducibility across runs
    assert json.dumps(run_1) == json.dumps(run_2)


# =========================================================================
# 2. UNIT TESTS: VALIDATION SENTRY
# =========================================================================


def test_paper_validation_rules():
    # Valid sections
    valid_sections = [
        {
            "name": "Part A",
            "selection_rule": "all_compulsory",
            "questions_to_answer": 5,
            "marks_per_question": 2,
            "total_section_marks": 10,
            "questions": [
                {"item_number": 1, "has_internal_choice": False, "marks": 2, "choice_a": {"question_text": "What is a process control block in operating systems?", "topic": "Process", "unit": 1, "marks": 2}},
                {"item_number": 2, "has_internal_choice": False, "marks": 2, "choice_a": {"question_text": "State two key advantages of microkernel architectures over monolithic kernels.", "topic": "Kernel", "unit": 1, "marks": 2}},
                {"item_number": 3, "has_internal_choice": False, "marks": 2, "choice_a": {"question_text": "Differentiate between user level and kernel level execution threads.", "topic": "Threads", "unit": 1, "marks": 2}},
                {"item_number": 4, "has_internal_choice": False, "marks": 2, "choice_a": {"question_text": "Define translation lookaside buffer and state its operational purpose.", "topic": "TLB", "unit": 1, "marks": 2}},
                {"item_number": 5, "has_internal_choice": False, "marks": 2, "choice_a": {"question_text": "Explain the concept of mutual exclusion in critical section problems.", "topic": "Synchronization", "unit": 1, "marks": 2}},
            ],
        },
        {
            "name": "Part B",
            "selection_rule": "internal_choice",
            "questions_to_answer": 2,
            "marks_per_question": 10,
            "total_section_marks": 20,
            "questions": [
                {
                    "item_number": 6,
                    "has_internal_choice": True,
                    "marks": 10,
                    "choice_a": {"question_text": "Explain memory management schemes", "topic": "Memory", "unit": 2, "marks": 10},
                    "choice_b": {"question_text": "Derive paging page fault rate", "topic": "Paging", "unit": 2, "marks": 10},
                },
                {
                    "item_number": 7,
                    "has_internal_choice": True,
                    "marks": 10,
                    "choice_a": {"question_text": "Design deadlock avoidance strategy", "topic": "Deadlock", "unit": 3, "marks": 10},
                    "choice_b": {"question_text": "Compare Banker's algorithm with graph reduction", "topic": "Deadlock", "unit": 3, "marks": 10},
                },
            ],
        },
    ]

    # 1. Total marks valid (10 + 20 = 30)
    report_valid = validate_assembled_paper(
        target_total_marks=30,
        sections=valid_sections,
        mandatory_topics=["Memory", "Deadlock"],
    )
    assert report_valid.is_valid is True
    assert report_valid.total_marks_valid is True
    assert report_valid.mandatory_topics_covered is True
    assert report_valid.duplicate_check_passed is True

    # 2. Total marks mismatch
    report_mismatch = validate_assembled_paper(
        target_total_marks=100,  # Expected 100 but sections sum to 30
        sections=valid_sections,
    )
    assert report_mismatch.is_valid is False
    assert report_mismatch.total_marks_valid is False
    assert any("mismatch" in issue for issue in report_mismatch.issues)

    # 3. Missing mandatory topic
    report_missing_topic = validate_assembled_paper(
        target_total_marks=30,
        sections=valid_sections,
        mandatory_topics=["Quantum Cryptography"],
    )
    assert report_missing_topic.is_valid is False
    assert report_missing_topic.mandatory_topics_covered is False
    assert any("Quantum Cryptography" in issue for issue in report_missing_topic.issues)

    # 4. Duplicate questions detected
    dup_sections = [
        {
            "name": "Part A",
            "selection_rule": "all_compulsory",
            "questions_to_answer": 2,
            "marks_per_question": 5,
            "total_section_marks": 10,
            "questions": [
                {"item_number": 1, "choice_a": {"question_text": "Explain deadlock conditions in modern operating systems", "topic": "Deadlock", "unit": 1, "marks": 5}},
                {"item_number": 2, "choice_a": {"question_text": "Explain deadlock conditions in modern operating systems", "topic": "Deadlock", "unit": 1, "marks": 5}},
            ],
        }
    ]
    report_dup = validate_assembled_paper(target_total_marks=10, sections=dup_sections)
    assert report_dup.is_valid is False
    assert report_dup.duplicate_check_passed is False
    assert any("Near-duplicate" in issue for issue in report_dup.issues)


# =========================================================================
# 3. INTEGRATION TESTS: QUESTION BANK & ASSEMBLY ENDPOINTS
# =========================================================================


@pytest.mark.asyncio
async def test_question_bank_and_assembly_workflow(client: AsyncClient, db_session: AsyncSession):
    # 1. Register Setter and HOD (Reviewer) in Computer Science
    await client.post(
        "/api/v1/auth/register",
        json={"email": "setter_eng@examos.edu", "username": "setter_eng", "password": "ValidPassword123!", "full_name": "Setter Eng", "department": "Computer Science", "role": "setter"},
    )
    setter_login = await client.post("/api/v1/auth/login", json={"username_or_email": "setter_eng", "password": "ValidPassword123!"})
    setter_token = setter_login.json()["access_token"]
    setter_headers = {"Authorization": f"Bearer {setter_token}"}

    await client.post(
        "/api/v1/auth/register",
        json={"email": "hod_eng@examos.edu", "username": "hod_eng", "password": "ValidPassword123!", "full_name": "HOD Reviewer", "department": "Computer Science", "role": "hod"},
    )
    hod_login = await client.post("/api/v1/auth/login", json={"username_or_email": "hod_eng", "password": "ValidPassword123!"})
    hod_token = hod_login.json()["access_token"]
    hod_headers = {"Authorization": f"Bearer {hod_token}"}

    # 2. Add Questions to Question Bank
    q1_res = await client.post(
        "/api/v1/bank/questions",
        headers=setter_headers,
        json={
            "subject": "Distributed Systems",
            "topic": "Consensus Protocols",
            "unit": 1,
            "subtopics": ["Paxos", "Raft"],
            "question_text": "Explain the Raft leader election mechanism in detail.",
            "marks": 10,
            "difficulty": "medium",
            "question_type": "descriptive",
            "syllabus_version": "2026-v1",
            "learning_outcome_code": "CO1",
            "source_provenance": "Faculty Ingestion",
            "expected_answer_points": ["Leader heartbeat", "Candidate term increment", "Majority quorum vote"],
            "department": "Computer Science",
            "approval_status": "draft",
        },
    )
    assert q1_res.status_code == 201
    q1_data = q1_res.json()
    assert q1_data["approval_status"] == BankQuestionApprovalStatus.draft.value

    # HOD reviews and approves q1 in bank
    q1_approve = await client.patch(
        f"/api/v1/bank/questions/{q1_data['id']}",
        headers=hod_headers,
        json={"approval_status": "approved"},
    )
    assert q1_approve.status_code == 200
    assert q1_approve.json()["approval_status"] == BankQuestionApprovalStatus.approved.value

    # Search question bank with filters
    search_res = await client.get(
        "/api/v1/bank/questions?subject=Distributed&difficulty=medium&approval_status=approved",
        headers=setter_headers,
    )
    assert search_res.status_code == 200
    assert search_res.json()["total"] >= 1

    # 3. Assemble Paper
    paper_blueprint = {
        "paper_code": "CS-DS-401-2026",
        "title": "Distributed Systems Final Examination",
        "subject": "Distributed Systems",
        "course": "B.Tech Computer Science",
        "semester": 6,
        "department": "Computer Science",
        "syllabus_version": "2026-v1",
        "blueprint": {
            "total_marks": 20,
            "duration_minutes": 120,
            "seed": 99,
            "mandatory_topics": ["Consensus"],
            "sections": [
                {
                    "section_id": "sec_1",
                    "name": "Part A (Objective)",
                    "instructions": "Answer all questions in Part A.",
                    "selection_rule": "all_compulsory",
                    "questions_to_answer": 2,
                    "marks_per_question": 5,
                    "total_section_marks": 10,
                },
                {
                    "section_id": "sec_2",
                    "name": "Part B (Core Analytical)",
                    "instructions": "Answer any 1 question with internal choice.",
                    "selection_rule": "internal_choice",
                    "questions_to_answer": 1,
                    "marks_per_question": 10,
                    "total_section_marks": 10,
                },
            ],
        },
    }

    assemble_res = await client.post("/api/v1/assembly/papers", headers=setter_headers, json=paper_blueprint)
    assert assemble_res.status_code == 201
    paper_data = assemble_res.json()
    paper_id = paper_data["id"]
    assert paper_data["status"] == AssembledPaperStatus.draft.value
    assert paper_data["version"] == 1

    # 4. Validate Paper Endpoint
    val_endpoint_res = await client.post(f"/api/v1/assembly/papers/{paper_id}/validate", headers=setter_headers)
    assert val_endpoint_res.status_code == 200
    assert val_endpoint_res.json()["is_valid"] is True

    # 5. Review and Approve Paper (HOD)
    approve_res = await client.post(
        f"/api/v1/assembly/papers/{paper_id}/approve",
        headers=hod_headers,
        json={"comment": "Approved after committee review."},
    )
    assert approve_res.status_code == 200
    approved_paper = approve_res.json()
    assert approved_paper["status"] == AssembledPaperStatus.approved.value
    assert approved_paper["approved_by"] is not None

    # 6. CRITICAL RULE TEST: Edit After Approval Invalidates Previous Approval!
    edit_res = await client.put(
        f"/api/v1/assembly/papers/{paper_id}",
        headers=setter_headers,
        json={"title": "Distributed Systems Final Examination (Updated Syllabus Revision)", "change_reason": "Corrected subtitle terminology."},
    )
    assert edit_res.status_code == 200
    invalidated_paper = edit_res.json()

    # Status must drop back to review_pending, version increments, approved_by cleared!
    assert invalidated_paper["status"] == AssembledPaperStatus.review_pending.value
    assert invalidated_paper["version"] == 2
    assert invalidated_paper["approved_by"] is None
    # Approval history must record APPROVAL_INVALIDATED event
    history_events = [h["event"] for h in invalidated_paper["approval_history"]]
    assert "APPROVAL_INVALIDATED" in history_events

    # 7. Accessible Preview Endpoint
    preview_res = await client.get(f"/api/v1/assembly/papers/{paper_id}/preview", headers=setter_headers)
    assert preview_res.status_code == 200
    preview_data = preview_res.json()
    assert "html_preview" in preview_data
    assert "DRAFT (UNAPPROVED" in preview_data["html_preview"]

    # Re-approve version 2
    reapprove_res = await client.post(
        f"/api/v1/assembly/papers/{paper_id}/approve",
        headers=hod_headers,
        json={"comment": "Re-approved version 2 revisions."},
    )
    assert reapprove_res.status_code == 200
    reapproved_paper = reapprove_res.json()
    assert reapproved_paper["status"] == AssembledPaperStatus.approved.value
    assert reapproved_paper["version"] == 2

    # Check approved preview
    preview_approved_res = await client.get(f"/api/v1/assembly/papers/{paper_id}/preview", headers=setter_headers)
    assert "APPROVED VERSION" in preview_approved_res.json()["html_preview"]

    # 8. PDF Generation Endpoint
    pdf_res = await client.get(f"/api/v1/assembly/papers/{paper_id}/pdf", headers=setter_headers)
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"
    assert pdf_res.content.startswith(b"%PDF")

    # 9. Draft Protection Check: Students cannot view unapproved drafts of another paper
    draft_paper_payload = dict(paper_blueprint)
    draft_paper_payload["paper_code"] = "CS-DRAFT-999"
    draft_create = await client.post("/api/v1/assembly/papers", headers=setter_headers, json=draft_paper_payload)
    draft_paper_id = draft_create.json()["id"]

    await client.post(
        "/api/v1/auth/register",
        json={"email": "student_user@examos.edu", "username": "student_user", "password": "ValidPassword123!", "full_name": "Student User", "department": "Computer Science", "role": "student"},
    )
    student_login = await client.post("/api/v1/auth/login", json={"username_or_email": "student_user", "password": "ValidPassword123!"})
    student_headers = {"Authorization": f"Bearer {student_login.json()['access_token']}"}

    # Student attempting to access draft preview or PDF must receive 403 Forbidden!
    forbidden_preview = await client.get(f"/api/v1/assembly/papers/{draft_paper_id}/preview", headers=student_headers)
    assert forbidden_preview.status_code == 403

    forbidden_pdf = await client.get(f"/api/v1/assembly/papers/{draft_paper_id}/pdf", headers=student_headers)
    assert forbidden_pdf.status_code == 403
