from datetime import datetime, timedelta, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scheduling import ExamSchedule, ExamScheduleStatus
from app.models.user import User, UserRole


@pytest.mark.asyncio
async def test_landing_page_backend_contracts_and_security(client: AsyncClient, db_session: AsyncSession):
    """
    Tests backend contracts used by the Public Landing page:
    1. Live health heartbeat endpoint.
    2. Public schedule lookup validation (<2 chars).
    3. Public schedule lookup with search matches.
    4. Critical Security Guarantee: Zero pre-release paper questions or decrypted payload exposure.
    5. Empty state behavior.
    """
    now = datetime.now(timezone.utc)

    # 1. Live health heartbeat
    health_res = await client.get("/api/v1/health")
    assert health_res.status_code == 200
    assert health_res.json()["message"] == "ok"

    # 2. Validation check: query parameter < 2 chars fails validation with 422
    val_res = await client.get("/api/v1/schedules/public-lookup?query=a")
    assert val_res.status_code == 422

    # 3. Empty state: query non-existent subject
    empty_res = await client.get("/api/v1/schedules/public-lookup?query=NonExistentSubject999")
    assert empty_res.status_code == 200
    assert len(empty_res.json()) == 0

    # 4. Create an approved schedule
    sched = ExamSchedule(
        paper_code="CS-PUB-301",
        approved_paper_version=1,
        title="Operating Systems Public Scheduled Exam",
        department="Computer Science",
        exam_center_id="CTR-NORTH-HALL",
        eligible_group_id="GROUP-CS",
        timezone="UTC",
        start_time_utc=now + timedelta(days=5),
        duration_minutes=180,
        end_time_utc=now + timedelta(days=5, hours=3),
        grace_period_minutes=15,
        status=ExamScheduleStatus.scheduled,
        created_by=1,
    )
    db_session.add(sched)
    await db_session.commit()

    # Query matching schedule
    lookup_res = await client.get("/api/v1/schedules/public-lookup?query=CS-PUB")
    assert lookup_res.status_code == 200
    results = lookup_res.json()
    assert len(results) == 1
    match = results[0]
    assert match["paper_code"] == "CS-PUB-301"
    assert match["title"] == "Operating Systems Public Scheduled Exam"
    assert match["exam_center_id"] == "CTR-NORTH-HALL"

    # 5. Critical Pre-Release Protection: Assert no plaintext questions or storage keys exist
    assert "questions" not in match
    assert "answers" not in match
    assert "plaintext_questions" not in match
    assert "wrapped_dek" not in match
    assert "ciphertext_filename" not in match
