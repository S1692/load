import os
import json
import logging
from datetime import datetime
from typing import Optional

import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr

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
            if "request.downstream" in record.msg: return f"↘️  {log_message}"
            if "response.upstream" in record.msg: return f"↖️  {log_message}"
            if "request" in record.msg: return f"➡️  {log_message}"
            if "response" in record.msg: return f"⬅️  {log_message}"
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
USER_SERVICE_URL = os.getenv("USER_SERVICE_URL", "http://localhost:8001")

# ----------------------------------------------------------------------------
# FastAPI app
# ----------------------------------------------------------------------------
app = FastAPI(title="Gateway Service")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------------------------------------------------------------------
# Schemas (for validation, even if logic is in user-service)
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
# Routes (Proxying to user-service)
# ----------------------------------------------------------------------------
async def proxy_request(method: str, path: str, params: dict = None, json_data: dict = None):
    url = f"{USER_SERVICE_URL}{path}"
    log_event(f"request.downstream", method=method, url=url)
    async with httpx.AsyncClient() as client:
        try:
            response = await client.request(method, url, params=params, json=json_data, timeout=5.0)
            response.raise_for_status()
            log_event(f"response.upstream", status=response.status_code, url=url)
            return response.json()
        except httpx.HTTPStatusError as e:
            log_event(f"response.upstream.error", status=e.response.status_code, body=e.response.text)
            raise HTTPException(status_code=e.response.status_code, detail=e.response.json().get("detail"))
        except httpx.RequestError as e:
            log_event(f"request.downstream.error", error=str(e), url=url)
            raise HTTPException(status_code=503, detail="Service unavailable")

@app.post("/register")
async def register(payload: RegisterRequest):
    log_event("request.register", body=payload.model_dump())
    return await proxy_request("POST", "/register", json_data=payload.model_dump())

@app.post("/login")
async def login(payload: LoginRequest):
    log_event("request.login", body=payload.model_dump())
    return await proxy_request("POST", "/login", json_data=payload.model_dump())

@app.get("/check-username")
async def check_username(username: str):
    log_event("request.check_username", username=username)
    return await proxy_request("GET", "/check-username", params={"username": username})

@app.get("/users")
async def list_users():
    log_event("request.users")
    return await proxy_request("GET", "/users")

@app.get("/health")
async def health():
    log_event("health.check")
    return {"status": "ok", "time": datetime.utcnow().isoformat() + "Z"}