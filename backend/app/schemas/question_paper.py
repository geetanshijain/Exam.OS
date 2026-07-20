from datetime import datetime

from pydantic import BaseModel

from app.models.question_paper import PaperStatus


class QuestionPaperCreate(BaseModel):
    title: str
    subject: str
    exam_date: datetime
    description: str | None = None


class QuestionPaperRead(BaseModel):
    id: int
    title: str
    subject: str
    exam_date: datetime
    status: PaperStatus
    created_by: int
    created_at: datetime
    description: str | None

    model_config = {"from_attributes": True}
