import os
import shutil
import tempfile
from pathlib import Path

import pytest

# Must run BEFORE any `app` import so settings use a throwaway database
# and a test-only secret. The developer's socketroom.db is never touched.
_TMP_DIR = tempfile.mkdtemp(prefix="socketroom_test_")
os.environ["DATABASE_URL"] = f"sqlite:///{(Path(_TMP_DIR) / 'test.db').as_posix()}"
os.environ["SECRET_KEY"] = "test-secret-key-for-pytest-only-0123456789"
os.environ["ACCESS_TOKEN_EXPIRE_MINUTES"] = "60"

from fastapi.testclient import TestClient  # noqa: E402

from app.database import Base, SessionLocal, engine, get_db  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _cleanup_tmp_dir():
    yield
    engine.dispose()
    shutil.rmtree(_TMP_DIR, ignore_errors=True)


@pytest.fixture(autouse=True)
def _fresh_tables():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield


def _override_get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def client():
    app.dependency_overrides[get_db] = _override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture
def user_payload():
    return {
        "username": "alice",
        "email": "alice@example.com",
        "password": "correct-horse-battery",
    }


@pytest.fixture
def registered_user(client, user_payload):
    res = client.post("/auth/register", json=user_payload)
    assert res.status_code == 201
    return res.json()


@pytest.fixture
def auth_headers(client, registered_user, user_payload):
    res = client.post(
        "/auth/login",
        json={"username": user_payload["username"], "password": user_payload["password"]},
    )
    return {"Authorization": f"Bearer {res.json()['access_token']}"}