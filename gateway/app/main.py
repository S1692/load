import os
import re
import json
import logging
from datetime import datetime
from typing import Optional

import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from starlette.responses import JSONResponse

# ----------------------------------------------------------------------------
# Logging setup
# ----------------------------------------------------------------------------
logger = logging.getLogger("gateway")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()

    class EmojiFormatter(logging.Formatter):
        def format(self, record):
            log_message = super().format(record)
            if "request.downstream" in record.msg:
                return f"↘️  {log_message}"
            if "response.upstream" in record.msg:
                return f"↖️  {log_message}"
            if "request" in record.msg:
                return f"➡️  {log_message}"
            if "response" in record.msg:
                return f"⬅️  {log_message}"
            return f"ℹ️  {log_message}"

    handler.setFormatter(EmojiFormatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    logger.addHandler(handler)


def log_event(event: str, **kwargs):
    parts = [f"event='{event}'"]
    for k, v in kwargs.items():
        parts.append(f"{k}='{v}'")
    logger.info(" ".join(parts))


# ----------------------------------------------------------------------------
# Service configuration
# ----------------------------------------------------------------------------
# 예: USER_SERVICE_URL = "https://user-service-production-xxxx.up.railway.app"
# 또는 같은 프로젝트 내부 네트워크: "http://user-service:8080"
USER_SERVICE_URL = os.getenv("USER_SERVICE_URL", "").strip()

PUBLIC_URL = (os.getenv("PUBLIC_URL") or os.getenv("RAILWAY_PUBLIC_DOMAIN") or "").strip()

def _norm(u: str) -> str:
    return (u or "").replace("https://", "").replace("http://", "").strip("/")

if not USER_SERVICE_URL:
    logger.error("[FATAL] USER_SERVICE_URL is empty")
    raise SystemExit(1)

if PUBLIC_URL and _norm(PUBLIC_URL) == _norm(USER_SERVICE_URL):
    logger.error(f"[FATAL] USER_SERVICE_URL points to myself: {USER_SERVICE_URL}")
    raise SystemExit(1)


# ----------------------------------------------------------------------------
# FastAPI app
# ----------------------------------------------------------------------------
app = FastAPI(title="Gateway Service")

# CORS: 프로덕션 도메인은 정확히, 프리뷰는 정규식으로 허용
ALLOWED_ORIGINS = [
    "https://load-sigma.vercel.app",  # ← 끝 슬래시( / ) 금지
]
ALLOW_ORIGIN_REGEX = r"^https:\/\/[a-z0-9-]+\.vercel\.app$"  # 모든 Vercel 프리뷰 허용

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex=ALLOW_ORIGIN_REGEX,
    allow_credentials=True,     # 쿠키/세션 사용 시 True
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)


# ----------------------------------------------------------------------------
# Schemas
# ----------------------------------------------------------------------------
class RegisterRequest(BaseModel):
    username: str
    password: str
    email: EmailStr
    full_name: Optional[str] = None


class LoginRequest(BaseModel):
    username: str
    password: str


# ----------------------------------------------------------------------------
# HTTP client (startup/shutdown lifecycle)
# ----------------------------------------------------------------------------
TIMEOUT = httpx.Timeout(connect=5.0, read=15.0, write=5.0, pool=5.0)

@app.on_event("startup")
async def on_startup():
    # 전역 클라이언트를 재사용하여 커넥션 풀 이점 확보
    app.state.client = httpx.AsyncClient(timeout=TIMEOUT)
    log_event("startup.httpx_client_ready")

@app.on_event("shutdown")
async def on_shutdown():
    client: httpx.AsyncClient = app.state.client
    try:
        await client.aclose()
    except Exception:
        pass
    log_event("shutdown.httpx_client_closed")


def _match_cors_origin(origin: Optional[str]) -> bool:
    if not origin:
        return False
    if origin in ALLOWED_ORIGINS:
        return True
    if ALLOW_ORIGIN_REGEX and re.match(ALLOW_ORIGIN_REGEX, origin):
        return True
    return False


def _corsify_response(resp: JSONResponse, request: Request) -> JSONResponse:
    origin = request.headers.get("origin")
    if _match_cors_origin(origin):
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
        resp.headers["Access-Control-Expose-Headers"] = "*"
    return resp


async def proxy_request(
    request: Request,
    method: str,
    path: str,
    params: dict | None = None,
    json_data: dict | None = None,
):
    url = f"{USER_SERVICE_URL}{path}"
    log_event("request.downstream", method=method, url=url)

    client: httpx.AsyncClient = app.state.client
    last_err = None

    for attempt in range(3):  # 단순 리트라이 3회
        try:
            r = await client.request(method, url, params=params, json=json_data)
            log_event("response.upstream", status=r.status_code, url=url)
            # 상태코드가 4xx/5xx인 경우 raise_for_status로 분기
            r.raise_for_status()
            try:
                payload = r.json()
            except ValueError:
                payload = {"raw": r.text}
            return _corsify_response(JSONResponse(status_code=r.status_code, content=payload), request)

        except httpx.HTTPStatusError as e:
            # 응답은 왔지만 4xx/5xx
            try:
                body = e.response.json()
            except ValueError:
                body = {"detail": e.response.text[:500]}
            log_event("response.upstream.error", status=e.response.status_code, body=str(body))
            resp = JSONResponse(status_code=e.response.status_code, content={"detail": body.get("detail")})
            return _corsify_response(resp, request)

        except (httpx.ConnectError, httpx.ReadTimeout) as e:
            last_err = e
            log_event("request.downstream.error", error=str(e), url=url)

    # 리트라이 후에도 실패
    resp = JSONResponse(status_code=503, content={"detail": f"Service unavailable: {type(last_err).__name__}"})
    return _corsify_response(resp, request)


# ----------------------------------------------------------------------------
# Routes (Proxy to user-service)
# ----------------------------------------------------------------------------
@app.post("/register")
async def register(payload: RegisterRequest, request: Request):
    log_event("request.register", body=payload.model_dump())
    return await proxy_request(request, "POST", "/register", json_data=payload.model_dump())


@app.post("/login")
async def login(payload: LoginRequest, request: Request):
    log_event("request.login", body=payload.model_dump())
    return await proxy_request(request, "POST", "/login", json_data=payload.model_dump())


@app.get("/check-username")
async def check_username(username: str, request: Request):
    log_event("request.check_username", username=username)
    return await proxy_request(request, "GET", "/check-username", params={"username": username})


@app.get("/users")
async def list_users(request: Request):
    log_event("request.users")
    return await proxy_request(request, "GET", "/users")


# ----------------------------------------------------------------------------
# Health
# ----------------------------------------------------------------------------
@app.get("/health")
async def health():
    log_event("health.check")
    return {"status": "ok", "time": datetime.utcnow().isoformat() + "Z"}

@app.get("/healthz")
async def healthz():
    log_event("healthz.check")
    return {"status": "ok", "time": datetime.utcnow().isoformat() + "Z"}


# ----------------------------------------------------------------------------
# Ensure CORS on HTTPException as well
# ----------------------------------------------------------------------------
@app.exception_handler(HTTPException)
async def http_exc_handler(request: Request, exc: HTTPException):
    resp = JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    return _corsify_response(resp, request)

