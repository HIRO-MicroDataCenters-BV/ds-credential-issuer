"""CORS must wrap the auth middleware: a browser's preflight carries no token."""
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.main import add_cors

SITE = "https://dev.nextgen.hiro-develop.nl"


class RefuseWithoutToken(BaseHTTPMiddleware):
    """Stands in for ds-auth: no bearer token → 401."""

    async def dispatch(self, request, call_next):
        if not request.headers.get("authorization"):
            return JSONResponse({"detail": "missing token"}, status_code=401)
        return await call_next(request)


def _app(origins_csv: str) -> FastAPI:
    app = FastAPI()

    @app.post("/credentials")
    def issue() -> dict[str, str]:
        return {"ok": "yes"}

    app.add_middleware(RefuseWithoutToken)  # like main.py: auth first,
    add_cors(app, origins_csv)              # CORS last (outermost)
    return app


def _preflight(client: TestClient, origin: str):
    return client.options("/credentials", headers={
        "Origin": origin,
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type,authorization",
    })


def test_preflight_passes_auth():
    r = _preflight(TestClient(_app("*")), SITE)
    assert r.status_code == 200
    assert r.headers["access-control-allow-origin"] == SITE


def test_auth_errors_carry_cors_headers():
    r = TestClient(_app("*")).post("/credentials", headers={"Origin": SITE})
    assert r.status_code == 401
    # "*" without cookies, or the site itself: either lets the browser read it
    assert r.headers["access-control-allow-origin"] in ("*", SITE)


def test_listed_origins_only():
    client = TestClient(_app(f"{SITE}, https://nextgen.hiro-develop.nl"))
    assert _preflight(client, SITE).status_code == 200
    r = _preflight(client, "https://any.example")
    assert r.status_code == 400
    assert "access-control-allow-origin" not in r.headers


def test_empty_means_no_cors():
    r = _preflight(TestClient(_app("")), SITE)
    assert r.status_code == 401
    assert "access-control-allow-origin" not in r.headers
