import os
import pytest
from fastapi.testclient import TestClient

# Ensure test environment is configured before any app or database modules are imported.
os.environ.setdefault("TESTING", "1")
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("DB_HOST", "localhost")
os.environ.setdefault("REDIS_URL", "redis://127.0.0.1:6379/0")
os.environ.setdefault("REDIS_HOST", "localhost")
os.environ.setdefault("REDIS_PORT", "6379")
os.environ.setdefault("API_KEYS", "demo")
os.environ.setdefault("HONEYPOT_HOSTNAME", "localhost")


def pytest_configure(config=None):
    """Ensure tests run with local, self-contained dependencies."""
    # This hook ensures pytest itself sees the same defaults, but the actual app import
    # should happen after the environment is already configured above.
    pass


@pytest.fixture(scope="session", autouse=True)
def app_lifespan():
    """Trigger FastAPI startup/shutdown lifecycle once for the test session."""
    from app import app

    with TestClient(app):
        yield
