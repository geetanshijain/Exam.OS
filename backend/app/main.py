from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.admin import alerts_router, router as admin_router
from app.api.v1.assembly import router as assembly_router
from app.api.v1.bank import router as bank_router
from app.api.v1.papers import router as papers_router
from app.api.v1.router import router as v1_router
from app.api.v1.scheduling import router as scheduling_router
from app.api.v1.studio import router as studio_router
from app.api.v1.vault import router as vault_router
from app.core.config import settings
from app.core.middleware import SecurityHeadersMiddleware
from app.db.session import engine
from app.models import Base  # noqa: F401 — registers all table metadata


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield


app = FastAPI(
    title=settings.APP_NAME,
    version="0.3.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

# Apply Institutional Security Headers Middleware
app.add_middleware(SecurityHeadersMiddleware)

# CORS Policy
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(v1_router, prefix="/api/v1")
app.include_router(papers_router, prefix="/api/v1")
app.include_router(admin_router, prefix="/api/v1")
app.include_router(alerts_router, prefix="/api/v1")
app.include_router(studio_router, prefix="/api/v1")
app.include_router(bank_router, prefix="/api/v1")
app.include_router(assembly_router, prefix="/api/v1")
app.include_router(vault_router, prefix="/api/v1")
app.include_router(scheduling_router, prefix="/api/v1")
