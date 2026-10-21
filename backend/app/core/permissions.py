import enum
from fastapi import HTTPException, status

from app.models.question_paper import QuestionPaper
from app.models.user import User, UserRole


class Permission(str, enum.Enum):
    CREATE_QUESTIONS = "create_questions"
    REVIEW_PAPERS = "review_papers"
    APPROVE_RELEASE = "approve_release"
    MANAGE_USERS = "manage_users"
    VIEW_AUDITS = "view_audits"
    PRINT_PAPERS = "print_papers"
    ATTEMPT_EXAM = "attempt_exam"
    MANAGE_INCIDENTS = "manage_incidents"
    MANAGE_SYSTEM = "manage_system"


# Default Role-Permission Matrix
ROLE_PERMISSIONS: dict[UserRole, set[Permission]] = {
    UserRole.admin: {
        Permission.CREATE_QUESTIONS,
        Permission.REVIEW_PAPERS,
        Permission.APPROVE_RELEASE,
        Permission.MANAGE_USERS,
        Permission.VIEW_AUDITS,
        Permission.PRINT_PAPERS,
        Permission.ATTEMPT_EXAM,
        Permission.MANAGE_INCIDENTS,
        Permission.MANAGE_SYSTEM,
    },
    UserRole.controller: {
        Permission.REVIEW_PAPERS,
        Permission.APPROVE_RELEASE,
        Permission.VIEW_AUDITS,
        Permission.PRINT_PAPERS,
        Permission.MANAGE_INCIDENTS,
        Permission.MANAGE_SYSTEM,
    },
    UserRole.hod: {
        Permission.REVIEW_PAPERS,
        Permission.CREATE_QUESTIONS,
    },
    UserRole.setter: {
        Permission.CREATE_QUESTIONS,
    },
    UserRole.printer: {
        Permission.PRINT_PAPERS,
    },
    UserRole.student: {
        Permission.ATTEMPT_EXAM,
    },
}


def has_permission(role: UserRole, permission: Permission) -> bool:
    """Check if role holds the specified permission."""
    return permission in ROLE_PERMISSIONS.get(role, set())


def verify_object_access(
    user: User,
    resource_department: str,
    resource_owner_id: int | None = None,
    require_owner: bool = False,
) -> None:
    """
    Object-level authorization gate (IDOR Prevention).
    Enforces that users cannot access resources belonging to another
    department or owner by manipulating IDs in URLs/requests.
    """
    # 1. Global administrators and institutional controllers have cross-department audit & approval oversight
    if user.role in {UserRole.admin, UserRole.controller}:
        return

    # 2. Strict department-level boundary check
    if user.department.strip().lower() != resource_department.strip().lower():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Cross-department resource isolation enforced.",
        )

    # 3. Ownership check when required (e.g. setter modifying own drafts)
    if require_owner and user.role == UserRole.setter:
        if resource_owner_id is not None and user.id != resource_owner_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: Operation restricted to document author.",
            )


def verify_paper_object_access(
    user: User,
    paper: QuestionPaper,
    require_owner: bool = False,
) -> None:
    """Convenience helper to verify access against a QuestionPaper record."""
    verify_object_access(
        user=user,
        resource_department=paper.department,
        resource_owner_id=paper.created_by,
        require_owner=require_owner,
    )
