"""
ExamOS Database Seeder (Development / Testing Only).
Usage: python seed.py (from the backend/ directory)
"""

import asyncio
import os
import sys
from pathlib import Path

# Add backend to sys.path so app imports work when run standalone
sys.path.insert(0, str(Path(__file__).resolve().parent))

from sqlalchemy import select

from app.core.config import settings
from app.core.security import hash_password
from app.db.session import AsyncSessionLocal, engine
from app.models import Base, User, UserRole

SEED_USERS = [
    {
        "email": "setter@examos.com",
        "username": "alex_setter",
        "full_name": "Alex Setter",
        "department": "Computer Science",
        "role": UserRole.setter,
        "mfa_enabled": False,
    },
    {
        "email": "hod@examos.com",
        "username": "dr_hod",
        "full_name": "Dr. HOD Computer Science",
        "department": "Computer Science",
        "role": UserRole.hod,
        "mfa_enabled": False,
    },
    {
        "email": "controller@examos.com",
        "username": "sam_controller",
        "full_name": "Sam Controller",
        "department": "Administration",
        "role": UserRole.controller,
        "mfa_enabled": True,  # Privileged role
    },
    {
        "email": "printer@examos.com",
        "username": "pat_printer",
        "full_name": "Pat Printer",
        "department": "Print Division",
        "role": UserRole.printer,
        "mfa_enabled": False,
    },
    {
        "email": "admin@examos.com",
        "username": "system_admin",
        "full_name": "System Administrator",
        "department": "Administration",
        "role": UserRole.admin,
        "mfa_enabled": False,
    },
    {
        "email": "student@examos.com",
        "username": "rohan_student",
        "full_name": "Rohan Verma",
        "department": "Computer Science",
        "role": UserRole.student,
        "mfa_enabled": False,
    },
    {
        "email": "locked_setter@examos.com",
        "username": "karan_locked",
        "full_name": "Karan Locked (Flagged)",
        "department": "Mathematics",
        "role": UserRole.setter,
        "mfa_enabled": False,
        "locked": True,
    },
    {
        "email": "priya_examiner@examos.com",
        "username": "dr_priya",
        "full_name": "Dr. Priya Examiner",
        "department": "Electrical Engineering",
        "role": UserRole.controller,
        "mfa_enabled": True,
    },
    {
        "email": "deactivated_user@examos.com",
        "username": "inactive_staff",
        "full_name": "Former Staff Member",
        "department": "Humanities",
        "role": UserRole.setter,
        "mfa_enabled": False,
        "is_active": False,
    },
]

DEV_PASSWORD = "password123"


async def seed() -> None:
    import json
    from datetime import datetime, timedelta, timezone
    from app.models.assembly import AssembledPaper, AssembledPaperStatus
    from app.models.scheduling import ExamSchedule, ExamScheduleStatus, StudentGroupRegistration

    # Production Safeguard: Never seed in production
    if settings.ENVIRONMENT.lower() == "production" or os.environ.get("ENVIRONMENT", "").lower() == "production":
        raise RuntimeError("CRITICAL SECURITY ERROR: Demo account seeding is strictly forbidden in production!")

    print(f"[{settings.APP_NAME}] Seeding development environment accounts...")

    async with AsyncSessionLocal() as session:
        student_user = None
        controller_user = None

        for ud in SEED_USERS:
            existing = await session.scalar(select(User).where(User.email == ud["email"]))
            argon_pw = hash_password(DEV_PASSWORD)
            is_locked = ud.get("locked", False)
            is_act = ud.get("is_active", True)

            if existing:
                existing.username = ud["username"]
                existing.department = ud["department"]
                existing.role = ud["role"]
                existing.full_name = ud["full_name"]
                existing.hashed_password = argon_pw
                existing.mfa_enabled = ud["mfa_enabled"]
                existing.is_active = is_act
                if is_locked:
                    existing.failed_login_attempts = 5
                    existing.locked_until = datetime.now(timezone.utc) + timedelta(hours=2)
                else:
                    existing.failed_login_attempts = 0
                    existing.locked_until = None
                user_obj = existing
                print(f"  [UPDATED] {ud['email']} -> {ud['username']} [{ud['role'].value}] ({ud['department']})")
            else:
                user_obj = User(
                    email=ud["email"],
                    username=ud["username"],
                    full_name=ud["full_name"],
                    department=ud["department"],
                    role=ud["role"],
                    hashed_password=argon_pw,
                    mfa_enabled=ud["mfa_enabled"],
                    is_active=is_act,
                    failed_login_attempts=5 if is_locked else 0,
                    locked_until=datetime.now(timezone.utc) + timedelta(hours=2) if is_locked else None,
                )
                session.add(user_obj)
                print(f"  [CREATED] {ud['email']} -> {ud['username']} [{ud['role'].value}] ({ud['department']})")

            if ud["role"] == UserRole.student:
                student_user = user_obj
            elif ud["role"] == UserRole.controller:
                controller_user = user_obj

        await session.flush()

        # Seed Assembled Paper for CS-401 (12 Questions matching reference mockup)
        asm = await session.scalar(select(AssembledPaper).where(AssembledPaper.paper_code == "CS-401"))
        sections_data = [
            {
                "title": "Section 1: Asymptotic Analysis & Recurrences",
                "questions": [
                    {
                        "item_number": 1,
                        "marks": 8,
                        "topic": "Recurrence Relations",
                        "text": "State and solve the Master Theorem for the recurrence relation T(n) = 2T(n/2) + O(n). Provide detailed step-by-step induction analysis.",
                    },
                    {
                        "item_number": 2,
                        "marks": 8,
                        "topic": "Divide and Conquer",
                        "text": "Explain the Divide-and-Conquer paradigm for finding the closest pair of 2D points in O(n log n) time. Detail why brute-force comparison is avoided.",
                    },
                ],
            },
            {
                "title": "Section 2: Dynamic Programming & Sequence Optimization",
                "questions": [
                    {
                        "item_number": 3,
                        "marks": 10,
                        "topic": "Dynamic Programming",
                        "text": "Implement an efficient algorithm to find the longest common subsequence (LCS) of two given strings, X and Y. Analyze its time complexity.\n\nX = \"BACDB\"\nY = \"BDCB\"",
                    },
                    {
                        "item_number": 4,
                        "marks": 8,
                        "topic": "Graph Algorithms",
                        "text": "Compare and contrast Dijkstra's algorithm with the Bellman-Ford algorithm for single-source shortest paths on weighted directed graphs. When does Dijkstra fail?",
                    },
                    {
                        "item_number": 5,
                        "marks": 8,
                        "topic": "Greedy Algorithms",
                        "text": "Define the Minimum Spanning Tree (MST) problem. Formulate Kruskal's algorithm using the Disjoint Set Union (Union-Find) data structure.",
                    },
                    {
                        "item_number": 6,
                        "marks": 10,
                        "topic": "Knapsack Optimization",
                        "text": "Formulate the 0/1 Knapsack problem using dynamic programming. Contrast its solution complexity with the Fractional Knapsack greedy approach.",
                    },
                ],
            },
            {
                "title": "Section 3: Network Flows, Intractability & Advanced Structures",
                "questions": [
                    {
                        "item_number": 7,
                        "marks": 8,
                        "topic": "Network Flow",
                        "text": "Explain the Ford-Fulkerson method and the Edmonds-Karp algorithm for maximum network flow. State the Max-Flow Min-Cut Theorem.",
                    },
                    {
                        "item_number": 8,
                        "marks": 10,
                        "topic": "NP-Completeness",
                        "text": "Define the complexity classes P, NP, NP-Complete, and NP-Hard. Provide the formal reduction from 3-SAT to Vertex Cover.",
                    },
                    {
                        "item_number": 9,
                        "marks": 8,
                        "topic": "Amortized Analysis",
                        "text": "Explain the amortized analysis techniques (Aggregate analysis, Accounting method, and Potential method) with the dynamic table expansion example.",
                    },
                    {
                        "item_number": 10,
                        "marks": 8,
                        "topic": "Balanced Search Trees",
                        "text": "Describe the structural invariants and rebalancing rotations of Red-Black Trees during node insertion and deletion.",
                    },
                    {
                        "item_number": 11,
                        "marks": 8,
                        "topic": "Randomized Algorithms",
                        "text": "Discuss randomized algorithms: Compare Las Vegas and Monte Carlo algorithms using Randomized QuickSort and Miller-Rabin Primality Testing.",
                    },
                    {
                        "item_number": 12,
                        "marks": 6,
                        "topic": "Approximation Algorithms",
                        "text": "Formulate an approximation algorithm for the Metric Traveling Salesperson Problem (TSP) using MST doubling and explain why it achieves a 2-approximation factor.",
                    },
                ],
            },
        ]

        if not asm:
            creator_id = controller_user.id if controller_user else 1
            asm = AssembledPaper(
                paper_code="CS-401",
                title="CS-401 Advanced Algorithms",
                subject="Algorithms & Complexity",
                course="B.Tech Computer Science",
                semester=6,
                department="Computer Science",
                total_marks=100,
                duration_minutes=180,
                syllabus_version="2026-v1",
                blueprint_json=json.dumps({"sections": 3, "total_marks": 100}),
                sections_json=json.dumps(sections_data),
                version=1,
                status=AssembledPaperStatus.approved,
                created_by=creator_id,
                last_edited_by=creator_id,
                approved_by=creator_id,
                approved_at=datetime.now(timezone.utc),
            )
            session.add(asm)
            print("  [CREATED] AssembledPaper CS-401 (Approved, 12 Questions)")
        else:
            asm.status = AssembledPaperStatus.approved
            asm.sections_json = json.dumps(sections_data)
            asm.version = 1
            print("  [UPDATED] AssembledPaper CS-401 (Approved, 12 Questions)")

        # Seed Student Group Registration
        if student_user:
            reg = await session.scalar(
                select(StudentGroupRegistration).where(
                    StudentGroupRegistration.student_id == student_user.id,
                    StudentGroupRegistration.group_id == "CS-UG-2026",
                    StudentGroupRegistration.exam_center_id == "HALL-A1",
                )
            )
            if not reg:
                reg = StudentGroupRegistration(
                    student_id=student_user.id,
                    group_id="CS-UG-2026",
                    exam_center_id="HALL-A1",
                    is_eligible=True,
                )
                session.add(reg)
                print(f"  [CREATED] Registration for student #{student_user.id} in group CS-UG-2026 at center HALL-A1")

        # Seed Active ExamSchedule (CS-401, started 15 min ago, active)
        sched = await session.scalar(select(ExamSchedule).where(ExamSchedule.paper_code == "CS-401"))
        now_utc = datetime.now(timezone.utc)
        start_utc = now_utc - timedelta(minutes=15)
        end_utc = start_utc + timedelta(minutes=180)

        if not sched:
            creator_id = controller_user.id if controller_user else 1
            sched = ExamSchedule(
                paper_code="CS-401",
                approved_paper_version=1,
                title="CS-401 Advanced Algorithms",
                department="Computer Science",
                exam_center_id="HALL-A1",
                eligible_group_id="CS-UG-2026",
                timezone="Asia/Kolkata",
                start_time_utc=start_utc,
                duration_minutes=180,
                end_time_utc=end_utc,
                grace_period_minutes=15,
                status=ExamScheduleStatus.active_in_progress,
                created_by=creator_id,
            )
            session.add(sched)
            print("  [CREATED] ExamSchedule CS-401 (Active in Progress)")
        else:
            sched.start_time_utc = start_utc
            sched.end_time_utc = end_utc
            sched.status = ExamScheduleStatus.active_in_progress
            sched.approved_paper_version = 1
            print("  [UPDATED] ExamSchedule CS-401 (Active in Progress)")

        # Seed Encrypted Vault Papers & Audit Entries for Examination Center Custodian
        from app.models.vault import VaultPaper, VaultStatus
        from app.vault.crypto import encrypt_paper_envelope
        from app.vault.kms import kms_client
        from app.vault.tamper_evident_audit import record_vault_audit

        vault_dir = Path(__file__).resolve().parent.parent / "vault" / "encrypted_objects"
        vault_dir.mkdir(parents=True, exist_ok=True)

        # 1. CS-401 Vault Paper (Extraction window open now)
        vp_401 = await session.scalar(select(VaultPaper).where(VaultPaper.paper_code == "CS-401"))
        sample_pdf_bytes = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>\nendobj\n4 0 obj\n<< /Length 53 >>\nstream\nBT /F1 12 Tf 100 700 Td (CS-401 Final Exam Paper) Tj ET\nendstream\nendobj\nxref\n0 5\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n0000000204 00000 n \ntrailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n308\n%%EOF"
        
        meta_401 = {
            "paper_code": "CS-401",
            "department": "Computer Science",
            "version": 1,
            "title": "CS-401 Advanced Algorithms",
        }
        ct_bytes_401, env_401 = encrypt_paper_envelope(sample_pdf_bytes, meta_401, kms_client)
        ct_file_401 = "CS-401_enc_payload.bin"
        (vault_dir / ct_file_401).write_bytes(ct_bytes_401)

        creator_id = controller_user.id if controller_user else 1
        approvals_data = [
            {"approver_id": 2, "approver_email": "hod@examos.com", "role": "hod", "timestamp": now_utc.isoformat(), "comment": "Syllabus compliance verified."},
            {"approver_id": 3, "approver_email": "controller@examos.com", "role": "controller", "timestamp": now_utc.isoformat(), "comment": "Dual-custody release approved."},
        ]

        if not vp_401:
            vp_401 = VaultPaper(
                paper_code="CS-401",
                title="CS-401 Advanced Algorithms",
                department="Computer Science",
                version=1,
                status=VaultStatus.approved_locked,
                ciphertext_filename=ct_file_401,
                wrapped_dek=env_401["wrapped_dek"],
                kek_version=env_401["kek_version"],
                nonce_b64=env_401["nonce_b64"],
                tag_b64=env_401["tag_b64"],
                aad_json=env_401["aad_json"],
                payload_sha256=env_401["payload_sha256"],
                approval_threshold=2,
                current_approvals_count=2,
                approvals_json=json.dumps(approvals_data),
                scheduled_release_start=now_utc - timedelta(minutes=15),
                scheduled_release_end=now_utc + timedelta(minutes=45),
                created_by=creator_id,
            )
            session.add(vp_401)
            await session.flush()
            print("  [CREATED] VaultPaper CS-401 (Approved & Locked, Window Open)")
        else:
            vp_401.scheduled_release_start = now_utc - timedelta(minutes=15)
            vp_401.scheduled_release_end = now_utc + timedelta(minutes=45)
            vp_401.status = VaultStatus.approved_locked
            vp_401.ciphertext_filename = ct_file_401
            vp_401.wrapped_dek = env_401["wrapped_dek"]
            vp_401.kek_version = env_401["kek_version"]
            vp_401.nonce_b64 = env_401["nonce_b64"]
            vp_401.tag_b64 = env_401["tag_b64"]
            vp_401.aad_json = env_401["aad_json"]
            vp_401.payload_sha256 = env_401["payload_sha256"]
            print("  [UPDATED] VaultPaper CS-401 (Approved & Locked, Window Open)")

        sched.vault_paper_id = vp_401.id

        # 2. CS-501 Vault Paper (Time-Locked: T-25 min remaining)
        vp_501 = await session.scalar(select(VaultPaper).where(VaultPaper.paper_code == "CS-501"))
        meta_501 = {
            "paper_code": "CS-501",
            "department": "Computer Science",
            "version": 1,
            "title": "CS-501 Operating Systems Final",
        }
        ct_bytes_501, env_501 = encrypt_paper_envelope(sample_pdf_bytes, meta_501, kms_client)
        ct_file_501 = "CS-501_enc_payload.bin"
        (vault_dir / ct_file_501).write_bytes(ct_bytes_501)

        if not vp_501:
            vp_501 = VaultPaper(
                paper_code="CS-501",
                title="CS-501 Operating Systems Final",
                department="Computer Science",
                version=1,
                status=VaultStatus.approved_locked,
                ciphertext_filename=ct_file_501,
                wrapped_dek=env_501["wrapped_dek"],
                kek_version=env_501["kek_version"],
                nonce_b64=env_501["nonce_b64"],
                tag_b64=env_501["tag_b64"],
                aad_json=env_501["aad_json"],
                payload_sha256=env_501["payload_sha256"],
                approval_threshold=2,
                current_approvals_count=2,
                approvals_json=json.dumps(approvals_data),
                scheduled_release_start=now_utc + timedelta(minutes=25),
                scheduled_release_end=now_utc + timedelta(minutes=85),
                created_by=creator_id,
            )
            session.add(vp_501)
            await session.flush()
            print("  [CREATED] VaultPaper CS-501 (Approved & Locked, Time-Locked T-25m)")
        else:
            vp_501.scheduled_release_start = now_utc + timedelta(minutes=25)
            vp_501.scheduled_release_end = now_utc + timedelta(minutes=85)
            vp_501.status = VaultStatus.approved_locked
            vp_501.ciphertext_filename = ct_file_501
            vp_501.wrapped_dek = env_501["wrapped_dek"]
            vp_501.kek_version = env_501["kek_version"]
            vp_501.nonce_b64 = env_501["nonce_b64"]
            vp_501.tag_b64 = env_501["tag_b64"]
            vp_501.aad_json = env_501["aad_json"]
            vp_501.payload_sha256 = env_501["payload_sha256"]
            print("  [UPDATED] VaultPaper CS-501 (Approved & Locked, Time-Locked T-25m)")

        # Record Initial Audit Logs
        await record_vault_audit(
            session=session,
            actor_id=creator_id,
            actor_email="controller@examos.com",
            action="SEEDED_INITIAL_RECORDS",
            vault_paper_id=vp_401.id,
            paper_version=1,
            metadata={"center": "HALL-A1"},
        )

        # Seed Multi-dimensional AuditLog entries
        from sqlalchemy import func
        from app.models.audit_log import AuditLog
        from app.models.alert import Alert, AlertSeverity
        from app.models.incident import SecurityIncident, IncidentSeverity, IncidentStatus

        existing_audit_count = await session.scalar(select(func.count(AuditLog.id)))
        if not existing_audit_count or existing_audit_count < 5:
            audit_samples = [
                AuditLog(
                    actor_id=creator_id,
                    action="VAULT_RELEASE",
                    entity_type="VaultPaper",
                    entity_id=vp_401.id,
                    metadata_json=json.dumps({"paper_code": "CS-401", "center": "HALL-A1"}),
                    outcome="SUCCESS",
                    correlation_id="corr-rel-9941",
                    ip_address="197.18.63.23",
                    timestamp=now_utc - timedelta(minutes=14),
                ),
                AuditLog(
                    actor_id=creator_id,
                    action="HONEYTOKEN_TRIP",
                    entity_type="VaultPaper",
                    entity_id=vp_501.id,
                    metadata_json=json.dumps({"trap": "early_access_decoy", "paper_code": "CS-501"}),
                    outcome="FAILURE",
                    correlation_id="corr-trap-8420",
                    ip_address="197.18.53.23",
                    timestamp=now_utc - timedelta(minutes=22),
                ),
                AuditLog(
                    actor_id=5, # system_admin
                    action="USER_LOGIN",
                    entity_type="User",
                    entity_id=5,
                    metadata_json=json.dumps({"auth_type": "argon2id_mfa"}),
                    outcome="SUCCESS",
                    correlation_id="corr-auth-1092",
                    ip_address="197.18.53.23",
                    timestamp=now_utc - timedelta(minutes=35),
                ),
                AuditLog(
                    actor_id=7, # karan_locked
                    action="USER_LOGIN",
                    entity_type="User",
                    entity_id=7,
                    metadata_json=json.dumps({"error": "invalid_password", "attempt": 5}),
                    outcome="FAILURE",
                    correlation_id="corr-auth-0055",
                    ip_address="197.193.1.1",
                    timestamp=now_utc - timedelta(minutes=48),
                ),
                AuditLog(
                    actor_id=creator_id,
                    action="USER_CREATED",
                    entity_type="User",
                    entity_id=8,
                    metadata_json=json.dumps({"username": "dr_priya", "role": "controller"}),
                    outcome="SUCCESS",
                    correlation_id="corr-usr-4412",
                    ip_address="192.168.1.93",
                    timestamp=now_utc - timedelta(minutes=60),
                ),
            ]
            session.add_all(audit_samples)
            print("  [CREATED] Seeded multi-dimensional AuditLog entries")

        # Seed Security Alerts
        existing_alert = await session.scalar(select(Alert).where(Alert.message.contains("Honeytoken")))
        if not existing_alert:
            alert1 = Alert(
                severity=AlertSeverity.critical,
                message="Honeytoken triggered - Unauthorized early vault access attempt for paper CS-501 by external node",
                actor_id=creator_id,
                resolved=False,
                created_at=now_utc - timedelta(minutes=22),
            )
            alert2 = Alert(
                severity=AlertSeverity.high,
                message="Repeated failed login threshold reached: Account 'karan_locked' quarantined",
                actor_id=7,
                resolved=False,
                created_at=now_utc - timedelta(minutes=48),
            )
            session.add_all([alert1, alert2])
            print("  [CREATED] Seeded active Security Alerts")

        # Seed Security Incident matching reference mockup INC-202610-84AF21
        existing_inc = await session.scalar(select(SecurityIncident).where(SecurityIncident.incident_code == "INC-202610-84AF21"))
        if not existing_inc:
            inc_notes = [
                {
                    "author_id": creator_id,
                    "author_email": "controller@examos.com",
                    "timestamp_utc": (now_utc - timedelta(minutes=20)).isoformat(),
                    "note": "Honeytoken Access Attempt Detected by automated honeypot trap on encrypted object CS-501.",
                },
                {
                    "author_id": creator_id,
                    "author_email": "controller@examos.com",
                    "timestamp_utc": (now_utc - timedelta(minutes=15)).isoformat(),
                    "note": "Perimeter firewall quarantined origin IP 197.18.53.23. Decoy payload dispatched.",
                },
                {
                    "author_id": creator_id,
                    "author_email": "controller@examos.com",
                    "timestamp_utc": (now_utc - timedelta(minutes=10)).isoformat(),
                    "note": "Investigation ongoing. Cross-referencing physical center access badges.",
                },
            ]
            inc_evidence = [
                {
                    "evidence_type": "AUDIT_LOG_REF",
                    "reference_id": "corr-trap-8420",
                    "description": "Honeytoken breach failure audit event log",
                    "added_by_id": creator_id,
                    "added_at_utc": (now_utc - timedelta(minutes=18)).isoformat(),
                },
                {
                    "evidence_type": "IP_CAPTURE",
                    "reference_id": "197.18.53.23",
                    "description": "Source reverse proxy IP capture header",
                    "added_by_id": creator_id,
                    "added_at_utc": (now_utc - timedelta(minutes=18)).isoformat(),
                },
            ]
            inc = SecurityIncident(
                incident_code="INC-202610-84AF21",
                title="Honeytoken Access Attempt Detected",
                severity=IncidentSeverity.critical,
                status=IncidentStatus.investigating,
                category="Data Leak Prevention",
                description="Automated tripwire intercepted an unauthorized early decryption attempt for paper CS-501 from external network node.",
                assigned_to_id=creator_id,
                related_paper_code="CS-501",
                investigation_notes_json=json.dumps(inc_notes),
                evidence_references_json=json.dumps(inc_evidence),
                created_by_id=creator_id,
                created_at=now_utc - timedelta(minutes=22),
            )
            session.add(inc)
            print("  [CREATED] Seeded SecurityIncident INC-202610-84AF21")

        await session.commit()
    print("Seeding complete with Argon2id credentials, audit entries, and incidents.")


if __name__ == "__main__":
    asyncio.run(seed())
