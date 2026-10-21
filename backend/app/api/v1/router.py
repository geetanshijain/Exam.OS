from fastapi import APIRouter

from app.api.v1.auth import router as auth_router
from app.schemas.common import MessageResponse

router = APIRouter()

router.include_router(auth_router)


@router.get("/health", response_model=MessageResponse, tags=["system"])
async def health() -> MessageResponse:
    return MessageResponse(message="ok")
