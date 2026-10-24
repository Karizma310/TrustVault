from contextlib import asynccontextmanager
from collections.abc import AsyncGenerator
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text

from app.api import admin, audit, auth, documents, google_auth, notifications, permissions
from app.config import get_settings
from app.database import initialize_database

APP_ROOT = Path(__file__).resolve().parent


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    initialize_database()
    yield


app = FastAPI(
    title="TrustVault API",
    description="Private document storage and sharing API.",
    version="0.1.0",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        origin.strip()
        for origin in get_settings().cors_origins.split(",")
        if origin.strip()
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)
app.include_router(auth.router)
app.include_router(google_auth.router)
app.include_router(documents.router)
app.include_router(permissions.router)
app.include_router(notifications.router)
app.include_router(audit.router)
app.include_router(admin.router)
app.mount("/app/static", StaticFiles(directory=APP_ROOT / "static"), name="frontend-static")
app.mount(
    "/app/templates",
    StaticFiles(directory=APP_ROOT / "templates", html=True),
    name="frontend-pages",
)


@app.get("/", include_in_schema=False)
def frontend_home() -> RedirectResponse:
    return RedirectResponse("/app/templates/landing.html")


@app.get("/health", tags=["health"])
def health_check() -> dict[str, str]:
    from app.database import get_engine

    with get_engine().connect() as connection:
        connection.execute(text("SELECT 1"))
    return {"status": "ok"}