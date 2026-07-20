from datetime import datetime

from pydantic import BaseModel

from app.models.approval import ApprovalStatus


class ApprovalAction(BaseModel):
    status: ApprovalStatus
    comment: str | None = None


class ApprovalRead(BaseModel):
    id: int
    paper_id: int
    approver_id: int
    status: ApprovalStatus
    comment: str | None
    approved_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}
