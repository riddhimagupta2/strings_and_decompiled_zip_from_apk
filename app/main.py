from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import os

from app.db.session import init_db
from app.api.routes.analysis import router as analysis_router
from app.api.routes.intel    import router as intel_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    os.makedirs("storage/uploads",   exist_ok=True)
    os.makedirs("storage/artifacts", exist_ok=True)
    init_db()
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title       = "APK Extraction Service",
        description = (
            "Static analysis extraction layer for Android APK files.\n\n"
            "Provides: hashes, manifest, permissions, hardcoded strings/IOCs, "
            "API call patterns, certificate/signature info, risk scoring, "
            "and decompiled source as a downloadable zip.\n\n"
            "Designed to be consumed by a downstream GenAI analysis service."
        ),
        version     = "1.0.0",
        lifespan    = lifespan,
        docs_url    = "/docs",
        redoc_url   = "/redoc",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins  = ["*"],
        allow_methods  = ["*"],
        allow_headers  = ["*"],
    )

    app.include_router(analysis_router)
    app.include_router(intel_router)

    @app.get("/health", tags=["Health"])
    def health():
        return {"status": "ok", "service": "apk-extraction-layer"}

    return app


app = create_app()
