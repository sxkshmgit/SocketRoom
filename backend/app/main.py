from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text

from app.config import settings
from app.database import Base, engine
from app import models  # noqa: F401  (registers User on Base.metadata before create_all)
from app.routers import auth

FRONTEND_DIR = Path(__file__).resolve().parents[2] / "frontend"


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(title=settings.app_name, debug=settings.debug, lifespan=lifespan)


@app.get("/health")
def health() -> dict[str, str]:
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
    return {"status": "ok", "app": settings.app_name}

app.include_router(auth.router)

# Must stay last: serves the frontend at "/"
app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")